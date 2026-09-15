// EIP-1186 상태 증거 테스트.
//
// anvil 을 띄워 **실제 eth_getProof 응답으로 왕복**한다. 손으로 만든 고정값으로
// 테스트하면 헤더 RLP 필드 순서가 틀려도 통과한다.
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import type { Hex } from "viem";
import {
  blockHashOf,
  checkEvidence,
  verifyAccount,
  verifyStorageSlot,
  slotValueToBigInt,
  stateProofRoot,
  stateSlotChecker,
  StateProofError,
  type StateEvidence,
} from "../lib/state-proof.ts";

const PORT = 8900 + Math.floor(Math.random() * 90);
const RPC = `http://127.0.0.1:${PORT}`;
const ACC = "0x0000000071727de22e5e9d8baf0edac6f37da032" as Hex;
const SLOT = ("0x" + "00".repeat(31) + "01") as Hex;
const DEPOSIT = 5n * 10n ** 18n;

let anvil: ChildProcess;
let evidence: StateEvidence;
let canonicalHash: Hex;

const rpc = async (method: string, params: unknown[]): Promise<unknown> => {
  const r = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const j = (await r.json()) as { result?: unknown; error?: { message: string } };
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
};

before(async () => {
  anvil = spawn("anvil", ["--port", String(PORT), "--silent"], { stdio: "ignore" });
  for (let i = 0; i < 80; i++) {
    try {
      await rpc("eth_chainId", []);
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  await rpc("anvil_setStorageAt", [ACC, SLOT, "0x" + DEPOSIT.toString(16).padStart(64, "0")]);
  await rpc("anvil_setBalance", [ACC, "0x2386f26fc10000"]);
  await rpc("anvil_mine", ["0x1"]);

  const n = Number((await rpc("eth_blockNumber", [])) as string);
  const tag = `0x${n.toString(16)}`;
  const account = (await rpc("eth_getProof", [ACC, [SLOT], tag])) as never;
  const header = (await rpc("eth_getBlockByNumber", [tag, false])) as Record<string, Hex>;
  canonicalHash = header.hash;
  evidence = { block_number: n, header: header as never, account };
});

after(() => anvil?.kill());

// ---------- 왕복 ----------

test("상태 증거 — 실제 eth_getProof 응답으로 왕복한다", async () => {
  const r = await checkEvidence(evidence, SLOT);
  assert.equal(r.slotValue, DEPOSIT);
  assert.equal(r.stateRoot, evidence.header.stateRoot);
});

test("헤더 — RLP 인코딩이 정본 블록 해시를 재현한다", () => {
  assert.equal(blockHashOf(evidence.header), canonicalHash);
});

// ---------- 변조 ----------

test("헤더 — 필드를 하나 바꾸면 블록 해시가 어긋난다", () => {
  for (const f of ["stateRoot", "timestamp", "gasUsed", "parentHash"] as const) {
    const h = { ...evidence.header };
    const v = h[f] as string;
    h[f] = (v.slice(0, -1) + (v.endsWith("0") ? "1" : "0")) as never;
    assert.notEqual(blockHashOf(h), canonicalHash, `필드 ${f}`);
  }
});

test("계정 증거 — stateRoot 를 바꾸면 검증이 실패한다", async () => {
  const wrong = ("0x" + "11".repeat(32)) as Hex;
  await assert.rejects(
    () => verifyAccount(wrong, evidence.account.address, evidence.account.accountProof),
    StateProofError,
  );
});

test("계정 증거 — 증거 노드를 한 바이트 바꾸면 실패한다", async () => {
  const proof = [...evidence.account.accountProof];
  const last = proof[proof.length - 1];
  proof[proof.length - 1] = (last.slice(0, -1) + (last.endsWith("0") ? "1" : "0")) as Hex;
  await assert.rejects(
    () => verifyAccount(evidence.header.stateRoot, evidence.account.address, proof),
    StateProofError,
  );
});

test("스토리지 증거 — storageHash 를 바꾸면 실패한다", async () => {
  const sp = evidence.account.storageProof[0];
  await assert.rejects(
    () => verifyStorageSlot(("0x" + "22".repeat(32)) as Hex, sp.key, sp.proof),
    StateProofError,
  );
});

test("스토리지 증거 — 값을 바꿔치기해도 루트가 막는다", async () => {
  // 게이트웨이가 값만 바꿔 적어도 소용없다. 값은 증거에서 복원되지
  // storageProof.value 를 읽는 것이 아니다.
  const forged: StateEvidence = {
    ...evidence,
    account: {
      ...evidence.account,
      storageProof: [{ ...evidence.account.storageProof[0], value: "0x1" as Hex }],
    },
  };
  const r = await checkEvidence(forged, SLOT);
  assert.equal(r.slotValue, DEPOSIT, "RPC 가 적어준 value 가 아니라 트라이에서 복원한 값이다");
});

// ---------- 비존재 ----------

test("계정 증거 — 존재하지 않는 계정의 비포함이 증명된다", async () => {
  const ghost = "0x00000000000000000000000000000000deadbeef" as Hex;
  const n = evidence.block_number;
  const p = (await rpc("eth_getProof", [ghost, [], `0x${n.toString(16)}`])) as {
    accountProof: Hex[];
  };
  const out = await verifyAccount(evidence.header.stateRoot, ghost, p.accountProof);
  assert.equal(out, null, "MPT 는 비존재도 증명한다");
});

test("스토리지 증거 — 쓰지 않은 슬롯은 0 으로 복원된다", async () => {
  const empty = ("0x" + "00".repeat(31) + "09") as Hex;
  const n = evidence.block_number;
  const p = (await rpc("eth_getProof", [ACC, [empty], `0x${n.toString(16)}`])) as {
    storageHash: Hex;
    storageProof: { key: Hex; proof: Hex[] }[];
  };
  const raw = await verifyStorageSlot(p.storageHash, p.storageProof[0].key, p.storageProof[0].proof);
  assert.equal(slotValueToBigInt(raw), 0n);
});

// ---------- 커밋 ----------

test("상태 커밋 — 증거가 한 글자라도 바뀌면 커밋이 달라진다", () => {
  const before = stateProofRoot(evidence);
  const after = stateProofRoot({ ...evidence, block_number: evidence.block_number + 1 });
  assert.notEqual(before, after);
});

test("묶음 — 요청한 슬롯의 증거가 없으면 거부한다", async () => {
  await assert.rejects(
    () => checkEvidence(evidence, ("0x" + "00".repeat(31) + "07") as Hex),
    StateProofError,
  );
});

// ---------- 감사에서 나온 것 ----------

test("상태 커밋 — 키 순서가 바뀌어도 같은 커밋이 나온다", () => {
  // JSON.stringify 를 쓰면 키 순서를 따라간다. 증거가 어딘가에서 재직렬화되면
  // 커밋이 어긋나고 "증거가 사후에 바뀌었다" 라는 엉뚱한 판정이 나온다.
  const reordered: StateEvidence = {
    account: evidence.account,
    header: Object.fromEntries(Object.entries(evidence.header).reverse()) as never,
    block_number: evidence.block_number,
  };
  assert.equal(stateProofRoot(reordered), stateProofRoot(evidence));
});

test("동적 사유 — 정수가 아닌 값을 커밋해도 크래시하지 않는다", async () => {
  // 공개된 값은 게이트웨이가 커밋한 것이지 정수라는 보장이 없다. 감싸지 않으면
  // 예외가 검증기 밖으로 새어나가 판정 대신 크래시가 된다.
  const check = stateSlotChecker(evidence, async () => canonicalHash);
  const verdict = await check({
    leaf: {
      decided_at_block: evidence.block_number,
      state_proof_root: stateProofRoot(evidence),
      state_root: evidence.header.stateRoot,
    },
    disclosures: [["0x" + "00".repeat(32), "value", "일억원"]],
    rule: {
      rule_id: "X", description: "", severity: "block", verifiability: "verifiable",
      predicate: { kind: "state_slot", account: ACC, slot: SLOT, op: "lt", operand: "value" },
    },
    policy: { version: 2, rules: [] },
  } as never);
  assert.equal(verdict.status, "fail");
  assert.match(verdict.detail, /정수가 아님/);
});
