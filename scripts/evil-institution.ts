// 기관 쪽 코드를 전부 악의적으로 바꿔놓고 검증기가 잡는지 본다.
// SDK 와 log-store 를 안 쓰고 리프·서명·트리를 직접 만든다.
import { createHash } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import { domain, signLeaf, signLogAck } from "../lib/sign.ts";
import { buildLeafBody, leafHash, policyHash, ZERO32, type Leaf, type PolicyDocument, type PolicyRule } from "../lib/record.ts";
import { canonicalBytes } from "../lib/jcs.ts";
import { mth, inclusionPath } from "../lib/merkle.ts";
import { rootOfList, sortedSetChecker, policyDataRootChecker } from "../lib/sorted-merkle.ts";
import { verifyReceipt, type ProofSource, type VerifyChain } from "../lib/verify.ts";
import type { Receipt } from "../lib/receipt.ts";

const gw = privateKeyToAccount(("0x"+"11".repeat(32)) as Hex);
const op = privateKeyToAccount(("0x"+"22".repeat(32)) as Hex);
const evil = privateKeyToAccount(("0x"+"33".repeat(32)) as Hex);
const ANCHOR = "0x5555555555555555555555555555555555555555" as Address;
const D = domain(84532, ANCHOR);
const NOW = 1757203200;
const OUTSIDE = "0x000000000000000000000000000000000000cafe" as Address;
const LIST = ["0x000000000000000000000000000000000000beef"];

const MISS: PolicyRule = { rule_id: "WHITELIST_MISS", description: "허용 목록 밖",
  severity: "review", verifiability: "verifiable",
  predicate: { kind: "not_in_set", field: "target", set: "allowedTargets" } };
const HOLD: PolicyRule = { rule_id: "MANUAL_REVIEW_HOLD", description: "수동 검토",
  severity: "hold", verifiability: "discretionary" };
const POLICY: PolicyDocument = { version: 2, rules: [MISS, HOLD], data_sets: { allowedTargets: LIST } };

/** 규칙 없는 트리. 리프를 아무거나 넣고 루트를 만든다. */
class EvilLog {
  leaves: Buffer[] = [];
  anchors = new Map<number, Hex>();
  add(leaf: Leaf) { this.leaves.push(canonicalBytes(leaf as never)); return this.leaves.length - 1; }
  anchor() { const n = this.leaves.length; this.anchors.set(n, `0x${mth(this.leaves).toString("hex")}`); return n; }
  proofFor(i: number, n: number) {
    return { anchor: { tree_size: n, root: this.anchors.get(n)! }, index: i,
      audit_path: inclusionPath(i, this.leaves.slice(0, n)).map(b => `0x${b.toString("hex")}` as Hex) };
  }
  chain(): VerifyChain {
    return { isRegistered: async (a) => a.toLowerCase() === gw.address.toLowerCase(),
      rootByTreeSize: async (s) => (this.anchors.get(s) ?? ZERO32) as Hex,
      anchoredAt: async (s) => (this.anchors.has(s) ? NOW : 0),
      logOperator: async () => op.address };
  }
}

const sha = (b: Buffer) => `0x${createHash("sha256").update(b).digest("hex")}`;

let caught = 0, missed = 0;
const report = (label: string, ok: boolean, note: string) => {
  console.log(`  ${ok ? "드러남" : "!! 숨음"}  ${label}  (${note})`);
  ok ? caught++ : missed++;
};

async function attempt(
  label: string,
  build: (log: EvilLog) => Promise<{ receipt: Receipt; log: EvilLog; policy?: PolicyDocument }>,
) {
  const log = new EvilLog();
  const { receipt, policy } = await build(log);
  const idx = log.leaves.findIndex(b => b.equals(canonicalBytes(receipt.leaf as never)));
  const n = log.anchor();
  const proofs: ProofSource = {
    inclusion: async () => log.proofFor(idx < 0 ? 0 : idx, n) as never,
    consistency: async () => { throw new Error("없음"); },
    laterAnchorThan: async () => null,
  };
  const r = await verifyReceipt({ receipt, domain: D, chain: log.chain(), proofs,
    policy: policy ?? POLICY, policyDataProof: policyDataRootChecker(),
    staticCheck: sortedSetChecker(), now: () => NOW });
  const flagged = !r.ok || !r.reasonChecked || r.selfLogged || (r.antedatedBy ?? 0) > 86_400;
  const note = !r.ok ? `${r.failedAt}단계 실패`
    : [!r.reasonChecked ? "사유 미검증 표시" : null, r.selfLogged ? "자가 로깅 경고" : null,
       (r.antedatedBy ?? 0) > 86_400 ? `사후 생성 경고 ${Math.floor((r.antedatedBy ?? 0)/86400)}일` : null]
        .filter(Boolean).join(" + ") || `통과. 판정 불가 ${r.unverifiable.join(",")||"없음"}`;
  report(label, flagged, note);
  return r;
}

const mkLeaf = async (over: Partial<Leaf> = {}, fields: Record<string,string> = {}, signer = gw) => {
  const { body, disclosures } = buildLeafBody({
    gateway: gw.address, policyHash: policyHash(POLICY),
    policyDataRoot: rootOfList(LIST) as Hex,
    fields: { calldata_hash: "0x"+"cd".repeat(32), requester: gw.address.toLowerCase(),
      rule_id: "WHITELIST_MISS", severity: "review", target: OUTSIDE.toLowerCase(),
      value: "1", verifiability: "verifiable", ...fields },
    issuedAt: NOW,
  });
  const leaf = await signLeaf({ ...body, ...over } as never, signer, D);
  return { leaf, disclosures };
};
const ack = async (h: Hex) => signLogAck({ leaf_hash: h, received_at: NOW, promised_by: NOW+3600,
  log_operator: op.address }, op, D);

console.log("\n악의적 기관 구현\n");

// 1. 로그가 서명 검증을 건너뛰고 위조 리프를 받는다
await attempt("로그가 다른 키로 서명된 리프를 수락", async (log) => {
  const { leaf, disclosures } = await mkLeaf({}, {}, evil);
  log.add(leaf);
  return { receipt: { leaf, leaf_hash: sha(Buffer.concat([Buffer.from([0]), canonicalBytes(leaf as never)])) as Hex,
    disclosures, log_ack: await ack(sha(Buffer.concat([Buffer.from([0]), canonicalBytes(leaf as never)])) as Hex) }, log };
});

// 2. 게이트웨이가 등록되지 않은 주소로 발급
await attempt("등록 안 된 게이트웨이가 발급", async (log) => {
  const { body, disclosures } = buildLeafBody({ gateway: evil.address, policyHash: policyHash(POLICY),
    policyDataRoot: rootOfList(LIST) as Hex,
    fields: { calldata_hash: "0x"+"cd".repeat(32), requester: evil.address.toLowerCase(),
      rule_id: "WHITELIST_MISS", severity: "review", target: OUTSIDE.toLowerCase(), value: "1",
      verifiability: "verifiable" }, issuedAt: NOW });
  const leaf = await signLeaf(body, evil, D);
  log.add(leaf);
  const h = `0x${leafHash(leaf).toString("hex")}` as Hex;
  return { receipt: { leaf, leaf_hash: h, disclosures, log_ack: await ack(h) }, log };
});

// 3. 로그가 접수 서명만 하고 트리에 안 넣는다
await attempt("접수 서명만 하고 트리에 미편입", async (log) => {
  const { leaf, disclosures } = await mkLeaf();
  log.add(await (await mkLeaf({}, { value: "999" })).leaf);  // 엉뚱한 리프만 넣는다
  const h = `0x${leafHash(leaf).toString("hex")}` as Hex;
  return { receipt: { leaf, leaf_hash: h, disclosures, log_ack: await ack(h) }, log };
});

// 4. 게이트웨이가 규칙 정의와 다른 verifiability 를 적는다
await attempt("verifiable 규칙에 discretionary 표시", async (log) => {
  const { leaf, disclosures } = await mkLeaf({}, { verifiability: "discretionary" });
  log.add(leaf);
  const h = `0x${leafHash(leaf).toString("hex")}` as Hex;
  return { receipt: { leaf, leaf_hash: h, disclosures, log_ack: await ack(h) }, log };
});

// 5. 게이트웨이가 발급 시각을 과거로 적는다
await attempt("발급 시각을 1년 전으로 위조", async (log) => {
  const { body, disclosures } = buildLeafBody({ gateway: gw.address, policyHash: policyHash(POLICY),
    policyDataRoot: rootOfList(LIST) as Hex,
    fields: { calldata_hash: "0x"+"cd".repeat(32), requester: gw.address.toLowerCase(),
      rule_id: "WHITELIST_MISS", severity: "review", target: OUTSIDE.toLowerCase(), value: "1",
      verifiability: "verifiable" }, issuedAt: NOW - 365*86400 });
  const leaf = await signLeaf(body, gw, D);
  log.add(leaf);
  const h = `0x${leafHash(leaf).toString("hex")}` as Hex;
  return { receipt: { leaf, leaf_hash: h, disclosures, log_ack: await ack(h) }, log };
});

// 6. 재량 사유 뒤에 숨는다
await attempt("전부 재량 사유로 발급", async (log) => {
  const { body, disclosures } = buildLeafBody({ gateway: gw.address, policyHash: policyHash(POLICY),
    fields: { calldata_hash: "0x"+"cd".repeat(32), requester: gw.address.toLowerCase(),
      rule_id: "MANUAL_REVIEW_HOLD", severity: "hold", target: OUTSIDE.toLowerCase(), value: "1",
      verifiability: "discretionary" }, issuedAt: NOW });
  const leaf = await signLeaf(body, gw, D);
  log.add(leaf);
  const h = `0x${leafHash(leaf).toString("hex")}` as Hex;
  return { receipt: { leaf, leaf_hash: h, disclosures, log_ack: await ack(h) }, log };
});

// 7. 요청자가 아무것도 공개하지 않는다
await attempt("공개 필드 0개", async (log) => {
  const { leaf } = await mkLeaf();
  log.add(leaf);
  const h = `0x${leafHash(leaf).toString("hex")}` as Hex;
  return { receipt: { leaf, leaf_hash: h, disclosures: [], log_ack: await ack(h) }, log };
});

// 8. 로그 운영자가 곧 게이트웨이
await attempt("로그 운영자와 게이트웨이가 같은 주체", async (log) => {
  const { body, disclosures } = buildLeafBody({ gateway: op.address, policyHash: policyHash(POLICY),
    policyDataRoot: rootOfList(LIST) as Hex,
    fields: { calldata_hash: "0x"+"cd".repeat(32), requester: op.address.toLowerCase(),
      rule_id: "WHITELIST_MISS", severity: "review", target: OUTSIDE.toLowerCase(), value: "1",
      verifiability: "verifiable" }, issuedAt: NOW });
  const leaf = await signLeaf(body, op, D);
  log.add(leaf);
  const h = `0x${leafHash(leaf).toString("hex")}` as Hex;
  const l2 = new EvilLog();
  l2.chain = () => ({ isRegistered: async () => true,
    rootByTreeSize: async (s) => (log.anchors.get(s) ?? ZERO32) as Hex, logOperator: async () => op.address });
  Object.assign(log, { chain: l2.chain });
  return { receipt: { leaf, leaf_hash: h, disclosures, log_ack: await ack(h) }, log };
});

console.log(`\n${caught} 잡음, ${missed} 놓침\n`);
