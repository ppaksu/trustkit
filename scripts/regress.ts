// 감사 회귀 확인. 이번에 찾은 공격 전부를 다시 돌려 막혔는지 본다.
//
// 테스트 스위트와 별개로 두는 이유. 여기 있는 것들은 "고친 뒤에도 여전히
// 막히는가" 를 한 화면에서 보려는 목적이고, 정직한 경로가 여전히 통과하는지도
// 같이 본다. 고치다가 전부 거부하게 만들면 테스트는 통과하고 제품은 죽는다.
import { privateKeyToAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import { domain } from "../lib/sign.ts";
import { ZERO32, leafHash, type PolicyDocument, type PolicyRule } from "../lib/record.ts";
import { rootOfList, sortedSetChecker, policyDataRootChecker } from "../lib/sorted-merkle.ts";
import { LogStore } from "../lib/log-store.ts";
import { Gateway } from "../sdk/gateway.ts";
import { verifyReceipt, type ProofSource, type VerifyChain } from "../lib/verify.ts";
import { assembleBundle, bundleProofSource, receiptOf, parseBundle, serializeBundle, BundleError } from "../lib/bundle.ts";

const gw = privateKeyToAccount(("0x" + "11".repeat(32)) as Hex);
const op = privateKeyToAccount(("0x" + "22".repeat(32)) as Hex);
const ANCHOR = "0x5555555555555555555555555555555555555555" as Address;
const D = domain(84532, ANCHOR);
const NOW = 1757203200;
const ALICE = "0x000000000000000000000000000000000000beef" as Address;
const OUTSIDE = "0x000000000000000000000000000000000000cafe" as Address;
const REAL = [ALICE.toLowerCase(), "0x00000000000000000000000000000000000000aa"];

const MISS: PolicyRule = {
  rule_id: "WHITELIST_MISS", description: "허용 목록 밖", severity: "review",
  verifiability: "verifiable",
  predicate: { kind: "not_in_set", field: "target", set: "allowedTargets" },
};
const POLICY: PolicyDocument = { version: 2, rules: [MISS], data_sets: { allowedTargets: REAL } };

let pass = 0, fail = 0;
const check = (label: string, ok: boolean, note = "") => {
  console.log(`  ${ok ? "막힘" : "!! 뚫림"}  ${label}${note ? `  (${note})` : ""}`);
  ok ? pass++ : fail++;
};
const expectOk = (label: string, ok: boolean, note = "") => {
  console.log(`  ${ok ? "통과" : "!! 막힘"}  ${label}${note ? `  (${note})` : ""}`);
  ok ? pass++ : fail++;
};

async function fresh(committedList: string[], publishList?: string[], dataRoot?: Hex) {
  const policy: PolicyDocument = { ...POLICY, data_sets: { allowedTargets: committedList } };
  const store = new LogStore({
    path: ":memory:", domain: D, operator: op,
    isRegistered: async () => true, clockSkewSec: 10 ** 9, now: () => NOW,
  });
  const g = new Gateway({ account: gw, domain: D, policy, policyDataRoot: dataRoot, now: () => NOW });
  let upd = null;
  if (publishList) {
    upd = await g.publishPolicyData(publishList);
    upd.log_ack = (await store.submit(upd.leaf)).log_ack;
    if (dataRoot) (g as never as { o: { policyDataRoot: Hex } }).o.policyDataRoot = dataRoot;
  }
  return { store, g, policy, upd };
}

async function decide(ctxIn: Awaited<ReturnType<typeof fresh>>, target: Address) {
  const r = await ctxIn.g.handle({
    request: { requester: gw.address, target, value: 1n, calldata: "0x" as Hex },
    forceRule: MISS,
  });
  const receipt = r.receipt!;
  receipt.log_ack = (await ctxIn.store.submit(receipt.leaf)).log_ack;
  const n = ctxIn.store.size();
  ctxIn.store.recordAnchor(n, ctxIn.store.rootAt(n));
  return receipt;
}

function chainOf(store: LogStore): VerifyChain {
  return {
    isRegistered: async () => true,
    rootByTreeSize: async (s) => (store.anchorAt(s)?.root ?? ZERO32) as Hex,
    logOperator: async () => op.address,
  };
}

async function run(
  ctxIn: Awaited<ReturnType<typeof fresh>>,
  receipt: Awaited<ReturnType<typeof decide>>,
  proofs?: ProofSource,
) {
  const { store, policy, upd } = ctxIn;
  return verifyReceipt({
    receipt, domain: D, chain: chainOf(store),
    proofs: proofs ?? {
      inclusion: async (h) => store.inclusionProof(h) as never,
      consistency: async (f, t) => store.consistencyProof(f, t) as never,
      laterAnchorThan: async () => null,
    },
    policy,
    policyUpdate: upd
      ? { leaf: upd.leaf, leaf_hash: upd.leaf_hash, inclusion_proof: store.proofHalf(upd.leaf_hash).inclusion_proof as never }
      : undefined,
    policyDataProof: policyDataRootChecker(),
    staticCheck: sortedSetChecker(),
    now: () => NOW,
  });
}

console.log("\n검증 우회 시도\n");

// 1. 피해자별 목록 위조
{
  const c = await fresh(["0x00000000000000000000000000000000000000aa"], REAL,
    rootOfList(["0x00000000000000000000000000000000000000aa"]) as Hex);
  const r = await run(c, await decide(c, ALICE));
  check("피해자만 뺀 목록을 지어내 거절", !r.ok, `${r.failedAt}단계`);
  c.store.close();
}

// 2. 목록 루트를 아예 커밋하지 않음
{
  const c = await fresh(REAL);
  const r = await run(c, await decide(c, ALICE));
  check("목록 루트 미커밋으로 10단계 면제 시도", !r.ok, `${r.failedAt}단계`);
  c.store.close();
}

// 3. leaf_hash 바꿔치기
{
  const c = await fresh(REAL, REAL, rootOfList(REAL) as Hex);
  const a = await decide(c, OUTSIDE);
  const b = await decide(c, OUTSIDE);
  a.leaf_hash = b.leaf_hash;
  const r = await run(c, a);
  check("본문은 A, leaf_hash 는 트리에 있는 B", !r.ok, `${r.failedAt}단계`);
  c.store.close();
}

// 4. 일관성 증명 구간 바꿔치기
{
  const c = await fresh(REAL, REAL, rootOfList(REAL) as Hex);
  const victim = await decide(c, OUTSIDE);
  const at = c.store.size();
  await decide(c, OUTSIDE);
  const later = c.store.size();
  const evil: ProofSource = {
    inclusion: async (h) => c.store.inclusionProof(h, at) as never,
    consistency: async () => c.store.consistencyProof(at, at) as never,
    laterAnchorThan: async () => later,
  };
  const r = await run(c, victim, evil);
  check("요청하지 않은 구간의 일관성 증명", !r.ok, `${r.failedAt}단계`);
  c.store.close();
}

// 5. 미앵커 구간으로 일관성 통과 시도
{
  const c = await fresh(REAL, REAL, rootOfList(REAL) as Hex);
  const victim = await decide(c, OUTSIDE);
  const evil: ProofSource = {
    inclusion: async (h) => c.store.inclusionProof(h) as never,
    consistency: async () => ({ from_anchor: { tree_size: 1, root: ZERO32 }, to_anchor: { tree_size: 9999, root: ZERO32 }, path: [] }) as never,
    laterAnchorThan: async () => 9999,
  };
  const r = await run(c, victim, evil);
  check("앵커되지 않은 구간으로 일관성 통과", !r.ok, `${r.failedAt}단계`);
  c.store.close();
}

// 6. 공표보다 늦은 판단으로 끼워맞추기
{
  const c = await fresh(REAL, REAL, rootOfList(REAL) as Hex);
  const receipt = await decide(c, OUTSIDE);
  // 갱신 레코드가 판단보다 나중인 것처럼 보이게 한다
  const forged = { ...c.upd!, leaf: { ...c.upd!.leaf, issued_at: receipt.leaf.issued_at + 1 } };
  forged.leaf_hash = `0x${leafHash(forged.leaf).toString("hex")}` as Hex;
  const r = await verifyReceipt({
    receipt, domain: D, chain: chainOf(c.store),
    proofs: { inclusion: async (h) => c.store.inclusionProof(h) as never,
      consistency: async (f, t) => c.store.consistencyProof(f, t) as never, laterAnchorThan: async () => null },
    policy: c.policy,
    policyUpdate: { leaf: forged.leaf, leaf_hash: forged.leaf_hash,
      inclusion_proof: c.store.proofHalf(c.upd!.leaf_hash).inclusion_proof as never },
    policyDataProof: policyDataRootChecker(), staticCheck: sortedSetChecker(), now: () => NOW,
  });
  check("갱신 공표를 판단보다 나중으로 위조", !r.ok, `${r.failedAt}단계`);
  c.store.close();
}

console.log("\n낯선 입력\n");
{
  const c = await fresh(REAL, REAL, rootOfList(REAL) as Hex);
  const receipt = await decide(c, OUTSIDE);
  const bundle = assembleBundle({
    receipt, proofs: c.store.proofHalf(receipt.leaf_hash) as never,
    anchor: { chain_id: 84532, address: ANCHOR }, policy: c.policy,
    policyUpdate: { leaf: c.upd!.leaf, leaf_hash: c.upd!.leaf_hash,
      inclusion_proof: c.store.proofHalf(c.upd!.leaf_hash).inclusion_proof as never },
  });
  const POISON = [undefined, null, 0, -1, 1.5, NaN, "", "0x", "0xzz", true, [], {}, 2 ** 60, "0x" + "aa".repeat(31)];
  const paths: string[][] = [];
  const walk = (o: unknown, p: string[]) => {
    if (o === null || typeof o !== "object" || p.length > 6) return;
    for (const k of Object.keys(o as object)) { paths.push([...p, k]); walk((o as never)[k], [...p, k]); }
  };
  walk(bundle, []);
  let crashes = 0, tried = 0;
  for (const path of paths) for (const poison of POISON) {
    const copy = JSON.parse(JSON.stringify(bundle));
    let cur = copy;
    for (const k of path.slice(0, -1)) { if (cur == null) break; cur = cur[k]; }
    if (cur == null || typeof cur !== "object") continue;
    cur[path[path.length - 1]] = poison;
    tried++;
    try {
      let parsed;
      try { parsed = parseBundle(serializeBundle(copy)); }
      catch (e) { if (e instanceof BundleError) continue; throw e; }
      await verifyReceipt({ receipt: receiptOf(parsed), domain: D, chain: chainOf(c.store),
        proofs: bundleProofSource(parsed), policy: parsed.policy_document ?? undefined,
        policyUpdate: parsed.policy_update ?? undefined,
        policyDataProof: policyDataRootChecker(), staticCheck: sortedSetChecker(), now: () => NOW });
    } catch { crashes++; }
  }
  check(`번들 필드 ${tried}가지 변형에서 크래시 0`, crashes === 0, `크래시 ${crashes}건`);
  c.store.close();
}

console.log("\n정직한 경로는 여전히 통과하는가\n");
{
  const c = await fresh(REAL, REAL, rootOfList(REAL) as Hex);
  const r = await run(c, await decide(c, OUTSIDE));
  expectOk("진짜 목록 밖 수신자 거절", r.ok, `판정 불가 ${r.unverifiable.join(",") || "없음"}`);
  expectOk("9단계가 사전 공표를 확인", r.steps.find((s) => s.step === 9)!.status === "pass");
  expectOk("10단계가 비포함을 확인", r.steps.find((s) => s.step === 10)!.status === "pass");
  c.store.close();
}

console.log(`\n${pass} 확인, ${fail} 실패\n`);
process.exit(fail === 0 ? 0 : 1);
