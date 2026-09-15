// 로그 저장소 테스트.
import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import type { Address } from "viem";
import { buildLeafBody, leafHash, type Leaf } from "../lib/record.ts";
import { domain, signLeaf, verifyLogAck } from "../lib/sign.ts";
import { LogStore, LogError } from "../lib/log-store.ts";
import { rootFromInclusionProof, verifyConsistency } from "../lib/merkle.ts";

const gk = privateKeyToAccount(("0x" + "11".repeat(32)) as `0x${string}`);
const op = privateKeyToAccount(("0x" + "22".repeat(32)) as `0x${string}`);
const evil = privateKeyToAccount(("0x" + "33".repeat(32)) as `0x${string}`);
const ANCHOR = "0x5555555555555555555555555555555555555555" as Address;
const D = domain(84532, ANCHOR);

const NOW = 1757203200;

function newStore(overrides: Partial<ConstructorParameters<typeof LogStore>[0]> = {}) {
  return new LogStore({
    path: ":memory:",
    domain: D,
    operator: op,
    isRegistered: async (a) => a.toLowerCase() === gk.address.toLowerCase(),
    now: () => NOW,
    ...overrides,
  });
}

let counter = 0;
async function makeLeaf(
  signer = gk,
  claimed: Address = gk.address,
  issuedAt = NOW,
): Promise<Leaf> {
  counter++;
  const { body } = buildLeafBody({
    gateway: claimed,
    policyHash: "0x" + "9a".repeat(32),
    fields: {
      requester: "0xabc0000000000000000000000000000000000001",
      target: "0xdef0000000000000000000000000000000000002",
      value: String(counter),
      calldata_hash: "0x" + "cd".repeat(32),
      rule_id: "DENYLIST_SANCTIONED",
      severity: "block",
      verifiability: "verifiable",
    },
    issuedAt,
  });
  return signLeaf(body, signer, D);
}

// ---------- 접수 검증 ----------

test("접수 — 정상 리프를 받고 서명된 접수 확인을 돌려준다", async () => {
  const s = newStore();
  const leaf = await makeLeaf();
  const { leaf_hash, log_ack } = await s.submit(leaf);
  assert.equal(leaf_hash, "0x" + leafHash(leaf).toString("hex"));
  assert.ok(await verifyLogAck(log_ack, op.address, D));
  assert.equal(log_ack.promised_by, log_ack.received_at + 3600, "MMD 기본값");
  assert.equal(s.size(), 1);
  s.close();
});

test("접수 — 서명이 gateway 로 안 붙으면 거부한다", async () => {
  const s = newStore();
  const leaf = await makeLeaf(evil, gk.address); // gk 를 주장, 실제는 evil 서명
  await assert.rejects(s.submit(leaf), (e: LogError) => e.status === 400);
  assert.equal(s.size(), 0);
  s.close();
});

test("접수 — 구조가 깨진 리프를 거부한다", async () => {
  const s = newStore();
  const leaf = await makeLeaf();
  const broken = { ...leaf, keys: leaf.keys.slice(0, 5) };
  await assert.rejects(s.submit(broken as Leaf), (e: LogError) => e.status === 400);
  s.close();
});

test("접수 — 등록되지 않은 게이트웨이를 거부한다", async () => {
  const s = newStore({ isRegistered: async () => false });
  await assert.rejects(s.submit(await makeLeaf()), (e: LogError) => e.status === 403);
  s.close();
});

test("접수 — 레지스트리 조회는 로컬 검사를 모두 통과한 뒤에만 일어난다", async () => {
  let calls = 0;
  const s = newStore({
    isRegistered: async () => {
      calls++;
      return true;
    },
  });
  const leaf = await makeLeaf(evil, gk.address); // 서명 불일치로 먼저 걸려야 함
  await assert.rejects(s.submit(leaf));
  assert.equal(calls, 0, "위조 요청에 노드 호출이 나가면 안 된다");
  await s.submit(await makeLeaf());
  assert.equal(calls, 1);
  s.close();
});

test("접수 — issued_at 이 허용 오차를 벗어나면 거부한다", async () => {
  const s = newStore();
  await assert.rejects(
    s.submit(await makeLeaf(gk, gk.address, NOW - 4000)),
    (e: LogError) => e.status === 400,
  );
  s.close();
});

test("접수 — 같은 leaf 재전송은 idempotent 하다", async () => {
  const s = newStore();
  const leaf = await makeLeaf();
  const a = await s.submit(leaf);
  const b = await s.submit(leaf);
  assert.equal(a.leaf_hash, b.leaf_hash);
  assert.equal(s.size(), 1, "중복 삽입되면 안 된다");
  s.close();
});

test("접수 — 같은 nonce 로 다른 leaf 를 내면 거부한다", async () => {
  const s = newStore();
  const first = await makeLeaf();
  await s.submit(first);
  const second = await makeLeaf();
  const reused = await signLeaf({ ...second, nonce: first.nonce }, gk, D);
  await assert.rejects(s.submit(reused), (e: LogError) => e.status === 409);
  s.close();
});

// ---------- 트리와 앵커 ----------

test("트리 — 머리가 리프 수에 따라 자란다", async () => {
  const s = newStore();
  assert.equal(s.head().tree_size, 0);
  await s.submit(await makeLeaf());
  const h1 = s.head();
  await s.submit(await makeLeaf());
  const h2 = s.head();
  assert.equal(h2.tree_size, 2);
  assert.notEqual(h1.root, h2.root);
  s.close();
});

test("앵커 — 로컬 트리와 다른 루트는 기록하지 않는다", async () => {
  const s = newStore();
  await s.submit(await makeLeaf());
  assert.throws(
    () => s.recordAnchor(1, ("0x" + "ff".repeat(32)) as `0x${string}`),
    (e: LogError) => e.status === 409,
  );
  s.close();
});

// ---------- 증명 ----------

test("증명 — 서버가 리프를 덮는 가장 이른 앵커를 고른다", async () => {
  const s = newStore();
  const leaves: Leaf[] = [];
  for (let i = 0; i < 5; i++) {
    const l = await makeLeaf();
    leaves.push(l);
    await s.submit(l);
  }
  s.recordAnchor(2, s.rootAt(2));
  s.recordAnchor(5, s.rootAt(5));

  // 인덱스 0 은 크기 2 앵커가 이미 덮는다
  assert.equal(s.inclusionProof("0x" + leafHash(leaves[0]).toString("hex")).anchor.tree_size, 2);
  // 인덱스 3 은 크기 5 앵커가 처음 덮는다
  assert.equal(s.inclusionProof("0x" + leafHash(leaves[3]).toString("hex")).anchor.tree_size, 5);
  s.close();
});

test("증명 — 포함 증명이 앵커된 루트로 재계산된다", async () => {
  const s = newStore();
  const leaves: Leaf[] = [];
  for (let i = 0; i < 7; i++) {
    const l = await makeLeaf();
    leaves.push(l);
    await s.submit(l);
  }
  s.recordAnchor(7, s.rootAt(7));

  for (let i = 0; i < 7; i++) {
    const h = leafHash(leaves[i]);
    const p = s.inclusionProof("0x" + h.toString("hex"));
    const root = rootFromInclusionProof(
      p.index,
      p.anchor.tree_size,
      h,
      p.audit_path.map((x) => Buffer.from(x.slice(2), "hex")),
    );
    assert.ok(root !== null && "0x" + root.toString("hex") === p.anchor.root, `리프 ${i}`);
  }
  s.close();
});

test("증명 — 앵커되지 않은 리프는 409 를 돌려준다 (D2 시연의 자리)", async () => {
  const s = newStore();
  const leaf = await makeLeaf();
  await s.submit(leaf);
  assert.throws(
    () => s.inclusionProof("0x" + leafHash(leaf).toString("hex")),
    (e: LogError) => e.status === 409,
  );
  s.close();
});

test("증명 — 로그에 없는 리프는 404 를 돌려준다", async () => {
  const s = newStore();
  assert.throws(
    () => s.inclusionProof("0x" + "ab".repeat(32)),
    (e: LogError) => e.status === 404,
  );
  s.close();
});

test("증명 — 일관성 증명이 두 앵커 사이에서 검증된다", async () => {
  const s = newStore();
  for (let i = 0; i < 9; i++) await s.submit(await makeLeaf());
  s.recordAnchor(4, s.rootAt(4));
  s.recordAnchor(9, s.rootAt(9));

  const p = s.consistencyProof(4, 9);
  assert.ok(
    verifyConsistency(
      4,
      9,
      Buffer.from(p.from_anchor.root.slice(2), "hex"),
      Buffer.from(p.to_anchor.root.slice(2), "hex"),
      p.path.map((x) => Buffer.from(x.slice(2), "hex")),
    ),
  );
  s.close();
});

test("증명 — 리프를 직접 고치면 일관성 증명이 깨진다 (D3 시연)", async () => {
  const s = newStore();
  for (let i = 0; i < 6; i++) await s.submit(await makeLeaf());
  s.recordAnchor(3, s.rootAt(3));
  const honestOldRoot = s.anchorAt(3)!.root;

  // 운영자가 과거 리프를 직접 수정한 뒤 새 루트를 앵커한다.
  // @ts-expect-error 시연을 위해 내부 db 에 직접 접근한다.
  s.db.prepare("UPDATE leaves SET leaf_bytes = ? WHERE idx = 1").run(Buffer.from("TAMPERED"));
  const newRoot = s.rootAt(6);

  const p = consistencyPathAfterTamper(s, 3, 6);
  assert.equal(
    verifyConsistency(
      3,
      6,
      Buffer.from(honestOldRoot.slice(2), "hex"),
      Buffer.from(newRoot.slice(2), "hex"),
      p,
    ),
    false,
    "정직한 옛 루트와 조작된 새 트리는 일관성 증명이 실패해야 한다",
  );
  s.close();
});

function consistencyPathAfterTamper(s: LogStore, from: number, to: number): Buffer[] {
  // 조작 후에는 recordAnchor 가 막히므로 증명 경로만 직접 만든다.
  // @ts-expect-error 내부 접근
  const data = s.data(to) as Buffer[];
  return consistencyProofRaw(from, data);
}

import { consistencyProof as consistencyProofRaw } from "../lib/merkle.ts";

// ---------- 감사: 리프가 사라진 상태 ----------

test("리프 유실 — 앵커된 크기만큼 리프가 없으면 명확한 오류를 낸다", async () => {
  // 운영자가 리프를 지우면 앵커는 크기 N 으로 박혀 있는데 리프는 그보다 적다.
  // 막지 않으면 머클 재귀가 끝나지 않아 스택 오버플로로 프로세스가 죽는다.
  const { DatabaseSync } = await import("node:sqlite");
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");

  const dir = mkdtempSync(join(tmpdir(), "ocdl-loss-"));
  const path = join(dir, "log.db");
  const s = newStore({ path });
  try {
    for (let i = 0; i < 6; i++) await s.submit(await makeLeaf());
    s.recordAnchor(6, s.rootAt(6));

    const db = new DatabaseSync(path);
    db.prepare("DELETE FROM leaves WHERE idx IN (2, 4)").run();
    db.close();

    assert.equal(s.size(), 4);
    // 스택 오버플로가 아니라 LogError 여야 한다
    assert.throws(() => s.rootAt(6), LogError);
    assert.throws(() => s.consistencyProof(6, 6), LogError);
    assert.throws(() => s.inclusionProof("0x" + "11".repeat(32), 6), LogError);
  } finally {
    s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("머클 — 크기 밖 인덱스로 증명을 만들려 하면 즉시 거부된다", async () => {
  const { inclusionPath } = await import("../lib/merkle.ts");
  const d = [Buffer.alloc(4), Buffer.alloc(4)];
  assert.throws(() => inclusionPath(2, d), RangeError);
  assert.throws(() => inclusionPath(-1, d), RangeError);
});
