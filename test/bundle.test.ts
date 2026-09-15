// 번들 조립과 파싱 테스트.
//
// 검증 도구가 낯선 파일을 먹는다. 형태가 깨진 입력에서 11단계 중간에 죽지
// 않아야 하고, 무엇보다 **번들이 말한 값을 그냥 믿으면 안 된다.**
import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import { domain, signRequestIntent, type RequestIntent } from "../lib/sign.ts";
import { Gateway } from "../sdk/gateway.ts";
import { DEMO_POLICY } from "../sdk/demo-policy.ts";
import { LogStore } from "../lib/log-store.ts";
import { rootOfList } from "../lib/sorted-merkle.ts";
import {
  assembleBundle,
  parseBundle,
  serializeBundle,
  receiptOf,
  bundleProofSource,
  describeBundle,
  BundleError,
  type Bundle,
} from "../lib/bundle.ts";

const gw = privateKeyToAccount(("0x" + "11".repeat(32)) as `0x${string}`);
const op = privateKeyToAccount(("0x" + "22".repeat(32)) as `0x${string}`);
const requester = privateKeyToAccount(("0x" + "44".repeat(32)) as `0x${string}`);
const ANCHOR = "0x5555555555555555555555555555555555555555" as Address;
const D = domain(84532, ANCHOR);
const NOW = 1757203200;
const SANCTIONED = "0x000000000000000000000000000000000000dead" as Address;

async function make(): Promise<Bundle> {
  const store = new LogStore({
    path: ":memory:",
    domain: D,
    operator: op,
    isRegistered: async () => true,
    now: () => NOW,
  });
  const g = new Gateway({
    account: gw,
    domain: D,
    policy: DEMO_POLICY,
    policyDataRoot: rootOfList(DEMO_POLICY.data_sets!.allowedTargets) as Hex,
    now: () => NOW,
  });
  const intent: RequestIntent = {
    requester: requester.address,
    gateway: gw.address,
    target: SANCTIONED,
    value: "1",
    calldata_hash: ("0x" + "cd".repeat(32)) as Hex,
    issued_at: NOW,
    nonce: ("0x" + "55".repeat(32)) as Hex,
  };
  const intentSig = await signRequestIntent(intent, requester, D);
  const r = await g.handle({
    request: { requester: requester.address, target: SANCTIONED, value: 1n, calldata: "0x" as Hex },
    intent,
    intentSig,
  });
  const receipt = r.receipt!;
  receipt.log_ack = (await store.submit(receipt.leaf)).log_ack;
  const n = store.size();
  store.recordAnchor(n, store.rootAt(n));
  const half = store.proofHalf(receipt.leaf_hash);
  store.close();
  return assembleBundle({
    receipt,
    proofs: half as never,
    anchor: { chain_id: 84532, address: ANCHOR },
    policy: DEMO_POLICY,
  });
}

test("조립 — 왕복 직렬화가 같은 번들을 낸다", async () => {
  const b = await make();
  const back = parseBundle(serializeBundle(b));
  assert.deepEqual(back, b);
});

test("조립 — 접수 확인이 없으면 만들 수 없다", async () => {
  const b = await make();
  assert.throws(
    () =>
      assembleBundle({
        receipt: { ...receiptOf(b), log_ack: null },
        proofs: { inclusion_proof: b.inclusion_proof, consistency_proof: null },
        anchor: b.anchor,
      }),
    BundleError,
  );
});

test("조립 — 정책 문서 해시가 리프와 다르면 거부한다", async () => {
  const b = await make();
  assert.throws(
    () =>
      assembleBundle({
        receipt: receiptOf(b),
        proofs: { inclusion_proof: b.inclusion_proof, consistency_proof: null },
        anchor: b.anchor,
        policy: { ...DEMO_POLICY, version: 99 },
      }),
    BundleError,
  );
});

test("조립 — discloseKeys 로 고른 필드만 들어간다", async () => {
  const b = await make();
  const trimmed = assembleBundle({
    receipt: receiptOf(b),
    proofs: { inclusion_proof: b.inclusion_proof, consistency_proof: null },
    anchor: b.anchor,
    discloseKeys: ["rule_id", "severity"],
  });
  assert.deepEqual(trimmed.disclosures.map((d) => d[1]).sort(), ["rule_id", "severity"]);
});

test("조립 — includeIntent=false 면 의도가 빠진다", async () => {
  const b = await make();
  const sealed = assembleBundle({
    receipt: receiptOf(b),
    proofs: { inclusion_proof: b.inclusion_proof, consistency_proof: null },
    anchor: b.anchor,
    includeIntent: false,
  });
  assert.equal(sealed.request_intent, null);
  assert.equal(sealed.request_sig, null);
});

test("요약 — 봉인 필드를 의도가 흘리면 경고한다", async () => {
  const b = await make();
  const leaky = assembleBundle({
    receipt: receiptOf(b),
    proofs: { inclusion_proof: b.inclusion_proof, consistency_proof: null },
    anchor: b.anchor,
    discloseKeys: ["rule_id"],
  });
  assert.match(describeBundle(leaky), /의도 구조체가 봉인 필드를 원문으로 드러냄/);
  const clean = assembleBundle({
    receipt: receiptOf(b),
    proofs: { inclusion_proof: b.inclusion_proof, consistency_proof: null },
    anchor: b.anchor,
    discloseKeys: ["rule_id"],
    includeIntent: false,
  });
  assert.doesNotMatch(describeBundle(clean), /주의/);
});

// ---------- 파싱은 믿지 않는다 ----------

test("파싱 — leaf_hash 를 번들이 말한 대로 믿지 않는다", async () => {
  const b = await make();
  const forged = { ...b, leaf_hash: ("0x" + "ab".repeat(32)) as Hex };
  assert.throws(() => parseBundle(JSON.stringify(forged)), BundleError);
});

test("파싱 — 리프를 고치면 leaf_hash 와 어긋나 거부된다", async () => {
  const b = await make();
  const forged = { ...b, leaf: { ...b.leaf, issued_at: b.leaf.issued_at + 1 } };
  assert.throws(() => parseBundle(JSON.stringify(forged)), BundleError);
});

test("파싱 — 깨진 JSON, 빈 객체, 잘못된 버전을 거부한다", () => {
  assert.throws(() => parseBundle("{"), BundleError);
  assert.throws(() => parseBundle("{}"), BundleError);
  assert.throws(() => parseBundle('{"v":1}'), BundleError);
});

test("파싱 — 앵커 주소가 없거나 형식이 틀리면 거부한다", async () => {
  const b = await make();
  assert.throws(
    () => parseBundle(JSON.stringify({ ...b, anchor: { chain_id: 1, address: "0xzz" } })),
    BundleError,
  );
});

// ---------- 증명 공급자 ----------

test("증명 공급자 — 번들 밖 리프를 요구하면 거부한다", async () => {
  const b = await make();
  const src = bundleProofSource(b);
  await assert.rejects(() => src.inclusion(("0x" + "99".repeat(32)) as Hex), BundleError);
});

test("증명 공급자 — 없는 일관성 증명을 지어내지 않는다", async () => {
  const b = await make();
  const src = bundleProofSource({ ...b, consistency_proof: null });
  assert.equal(await src.laterAnchorThan!(1), null);
  await assert.rejects(() => src.consistency(1, 2), BundleError);
});


// ---------- 감사: 낯선 입력 ----------
//
// 검증 도구는 누가 보냈는지 모르는 파일을 먹는다. 필드 하나하나를 망가뜨려
// 3,510가지를 돌려본 결과 크래시가 0건이어야 한다. 아래는 그때 나왔던 유형들이다.

const BROKEN: [string, (b: Bundle) => void][] = [
  ["leaf_hash 가 숫자", (b) => ((b as never as Record<string, unknown>).leaf_hash = 0)],
  ["disclosure 가 세 쌍이 아님", (b) => (b.disclosures = [["0x00"] as never])],
  ["disclosure 원소가 문자열이 아님", (b) => (b.disclosures = [[1, 2, 3] as never])],
  ["log_ack 필드 누락", (b) => ((b.log_ack as never as Record<string, unknown>).log_operator = undefined)],
  ["log_ack 시각이 정수가 아님", (b) => ((b.log_ack as never as Record<string, unknown>).received_at = "어제")],
  ["inclusion_proof 가 통째로 깨짐", (b) => ((b as never as Record<string, unknown>).inclusion_proof = {})],
  ["audit_path 원소가 문자열이 아님", (b) => (b.inclusion_proof.audit_path = [42 as never])],
  ["consistency_proof 가 깨짐", (b) => ((b as never as Record<string, unknown>).consistency_proof = { path: 1 })],
  ["policy_update 가 깨짐", (b) => ((b as never as Record<string, unknown>).policy_update = { leaf: null })],
  ["anchor 주소가 숫자", (b) => ((b.anchor as never as Record<string, unknown>).address = 1)],
];

for (const [label, breakIt] of BROKEN) {
  test(`낯선 입력 — ${label} 은 BundleError 로 거절된다`, async () => {
    const b = await make();
    breakIt(b);
    assert.throws(() => parseBundle(JSON.stringify(b)), BundleError, label);
  });
}
