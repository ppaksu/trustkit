// 검증 11단계 테스트.
//
// 핵심은 두 가지다. 조작이 어느 단계에서 걸리는가, 그리고 판정 불가와 거짓이
// 구분되는가.
import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import { domain, signRequestIntent, requestIntentHash, type RequestIntent } from "../lib/sign.ts";
import { ZERO32, leafHash, type PolicyDocument, type PolicyRule } from "../lib/record.ts";
import { LogStore } from "../lib/log-store.ts";
import { Gateway, type TxRequest } from "../sdk/gateway.ts";
import { verifyReceipt, type ProofSource, type VerifyChain, type PolicyUpdateProof } from "../lib/verify.ts";
import { rootOfList, sortedSetChecker, policyDataRootChecker } from "../lib/sorted-merkle.ts";
import type { Receipt } from "../lib/receipt.ts";

const gw = privateKeyToAccount(("0x" + "11".repeat(32)) as `0x${string}`);
const op = privateKeyToAccount(("0x" + "22".repeat(32)) as `0x${string}`);
const requester = privateKeyToAccount(("0x" + "44".repeat(32)) as `0x${string}`);
const ANCHOR = "0x5555555555555555555555555555555555555555" as Address;
const D = domain(84532, ANCHOR);
const NOW = 1757203200;

const SANCTIONED = "0x000000000000000000000000000000000000dead" as Address;
const NORMAL = "0x000000000000000000000000000000000000beef" as Address;
const CAP = "1000000000000000000";

const RULES: Record<string, PolicyRule> = {
  denylist: {
    rule_id: "DENYLIST_SANCTIONED",
    description: "수신자가 제재 목록에 있음",
    severity: "block",
    verifiability: "verifiable",
    predicate: { kind: "in_set", field: "target", set: "denylist" },
  },
  cap: {
    rule_id: "AMOUNT_CAP_EXCEEDED",
    description: "금액이 한도를 초과함",
    severity: "hold",
    verifiability: "verifiable",
    predicate: { kind: "gt", field: "value", limit: CAP },
  },
  manual: {
    rule_id: "MANUAL_REVIEW_HOLD",
    description: "담당자 수동 검토 보류",
    severity: "hold",
    verifiability: "discretionary",
  },
  screening: {
    rule_id: "SANCTIONS_SCREENING_HIT",
    description: "외부 제재 스크리닝 적중",
    severity: "block",
    verifiability: "external",
  },
};

const POLICY: PolicyDocument = {
  version: 2,
  rules: [RULES.denylist, RULES.cap, RULES.manual, RULES.screening],
  data_sets: { denylist: [SANCTIONED], allowedTargets: [NORMAL] },
};

const req = (over: Partial<TxRequest> = {}): TxRequest => ({
  requester: requester.address,
  target: NORMAL,
  value: 1n,
  calldata: "0xa9059cbb" as Hex,
  ...over,
});

/** 로그 하나, 게이트웨이 하나, 체인 대역 하나. 앵커까지 올린 상태를 만든다. */
async function setup(
  request: TxRequest,
  forceRule?: PolicyRule,
  withIntent = true,
  policyDataRoot?: Hex,
): Promise<{
  receipt: Receipt;
  chain: VerifyChain;
  proofs: ProofSource;
  store: LogStore;
}> {
  const store = new LogStore({
    path: ":memory:",
    domain: D,
    operator: op,
    isRegistered: async () => true,
    now: () => NOW,
  });
  const g = new Gateway({ account: gw, domain: D, policy: POLICY, policyDataRoot, now: () => NOW });

  let intent: RequestIntent | undefined;
  let intentSig: Hex | undefined;
  if (withIntent) {
    intent = {
      requester: request.requester,
      gateway: gw.address,
      target: request.target,
      value: request.value.toString(),
      calldata_hash: ("0x" + "cd".repeat(32)) as Hex,
      issued_at: NOW,
      nonce: ("0x" + "55".repeat(32)) as Hex,
    };
    intentSig = await signRequestIntent(intent, requester, D);
  }

  const r = await g.handle({ request, intent, intentSig, forceRule });
  const receipt = r.receipt!;
  const out = await store.submit(receipt.leaf);
  receipt.log_ack = out.log_ack;

  const n = store.size();
  store.recordAnchor(n, store.rootAt(n));

  const chain: VerifyChain = {
    isRegistered: async () => true,
    rootByTreeSize: async (size) => (store.anchorAt(size)?.root ?? ZERO32) as Hex,
    logOperator: async () => op.address,
  };
  const proofs: ProofSource = {
    inclusion: async (h) => store.inclusionProof(h) as never,
    consistency: async (from, to) => store.consistencyProof(from, to) as never,
    laterAnchorThan: async () => null,
  };
  return { receipt, chain, proofs, store };
}

const run = (s: Awaited<ReturnType<typeof setup>>, extra: Record<string, unknown> = {}) =>
  verifyReceipt({
    receipt: s.receipt,
    domain: D,
    chain: s.chain,
    proofs: s.proofs,
    policy: POLICY,
    now: () => NOW,
    ...extra,
  });

const stepOf = (r: Awaited<ReturnType<typeof run>>, n: number) =>
  r.steps.find((x) => x.step === n)!;

// ---------- 정상 경로 ----------

test("검증 — 한도 초과 거절이 11단계를 통과한다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  const r = await run(s);
  assert.equal(r.failedAt, null, JSON.stringify(r.steps, null, 2));
  assert.ok(r.ok);
  assert.equal(stepOf(r, 10).status, "pass", "gt 술어는 외부 데이터 없이 판정된다");
  s.store.close();
});

test("검증 — 6단계가 로그가 아니라 체인에서 읽은 루트와 대조한다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  // 체인이 다른 루트를 들고 있으면 로그가 뭘 주든 통과할 수 없다.
  const lying: VerifyChain = { ...s.chain, rootByTreeSize: async () => ("0x" + "99".repeat(32)) as Hex };
  const r = await run({ ...s, chain: lying });
  assert.equal(r.failedAt, 6);
  s.store.close();
});

// ---------- 조작 탐지 ----------

test("검증 — 리프를 한 글자 고치면 2단계에서 걸린다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  s.receipt.leaf.policy_hash = ("0x" + "ee".repeat(32)) as Hex;
  // leaf_hash 도 같이 맞춰준다. 안 그러면 1단계의 결속 검사에서 먼저 걸려서
  // 정작 보려던 "서명이 정책 해시를 덮는가" 를 확인하지 못한다.
  s.receipt.leaf_hash = `0x${leafHash(s.receipt.leaf).toString("hex")}` as Hex;
  const r = await run(s);
  assert.equal(r.failedAt, 2, "서명이 정책 해시를 덮는다");
  s.store.close();
});

test("검증 — 요청자 의도를 바꿔치기하면 4단계에서 걸린다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  s.receipt.request_intent = { ...s.receipt.request_intent!, value: "1" };
  const r = await run(s);
  assert.equal(r.failedAt, 4);
  s.store.close();
});

test("검증 — 접수 확인이 없으면 5단계에서 걸린다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  s.receipt.log_ack = null;
  const r = await run(s);
  assert.equal(r.failedAt, 5);
  assert.equal(r.fault, "게이트웨이가 제출 안 함");
  s.store.close();
});

test("검증 — 공개한 값이 그 자리 커밋과 다르면 8단계에서 걸린다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  const i = s.receipt.disclosures.findIndex((d) => d[1] === "rule_id");
  s.receipt.disclosures[i] = [s.receipt.disclosures[i][0], "rule_id", "다른 규칙"];
  const r = await run(s);
  assert.equal(r.failedAt, 8);
  s.store.close();
});

test("검증 — 커밋된 문서에 없는 규칙을 인용하면 9단계에서 걸린다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  const thinned: PolicyDocument = { ...POLICY, rules: POLICY.rules.slice(0, 1) };
  // 정책 문서가 바뀌면 해시부터 어긋나므로, 해시는 맞고 규칙만 없는 상황을
  // 만들려면 리프의 policy_hash 를 바꾼 문서에 맞춰야 한다. 서명이 깨지지
  // 않도록 9단계만 따로 본다.
  const r = await verifyReceipt({
    receipt: s.receipt,
    domain: D,
    chain: s.chain,
    proofs: s.proofs,
    policy: thinned,
    now: () => NOW,
  });
  assert.equal(r.failedAt, 9, "해시 불일치로 먼저 걸린다");
  s.store.close();
});

// ---------- 거짓 사유 ----------

test("검증 — 한도 이하인데 한도 초과를 사유로 대면 10단계에서 거짓으로 판정된다", async () => {
  // 게이트웨이가 규칙을 강제 지정해 거짓 사유를 만든다.
  const s = await setup(req({ value: 1n }), RULES.cap);
  const r = await run(s);
  assert.equal(r.failedAt, 10);
  assert.match(stepOf(r, 10).detail, /거짓 정적 사유/);
  s.store.close();
});

// ---------- 판정 불가와 거짓의 구분 ----------

test("검증 — 재량 사유는 판정 불가이지 실패가 아니다", async () => {
  const s = await setup(req(), RULES.manual);
  const r = await run(s);
  assert.equal(r.failedAt, null);
  assert.ok(r.ok, "검증 자체는 통과한다");
  assert.equal(stepOf(r, 10).status, "unverifiable");
  assert.equal(stepOf(r, 11).status, "unverifiable");
  assert.ok(r.unverifiable.includes(10));
  s.store.close();
});

test("검증 — 외부 데이터 의존 사유도 판정 불가다", async () => {
  const s = await setup(req(), RULES.screening);
  const r = await run(s);
  assert.ok(r.ok);
  assert.match(stepOf(r, 10).detail, /외부 데이터/);
  s.store.close();
});

test("검증 — 집합 소속 사유는 검사기가 없으면 판정 불가다", async () => {
  // 루트는 커밋된 상태여야 한다. 커밋 안 했으면 그건 판정 불가가 아니라 실패다.
  const s = await setup(req({ target: SANCTIONED }), undefined, true, rootOfList([SANCTIONED]) as Hex);
  const r = await run(s);
  assert.equal(stepOf(r, 10).status, "unverifiable");
  assert.match(stepOf(r, 10).detail, /정렬 머클/);
  s.store.close();
});

test("검증 — 요청자 서명이 없으면 4단계가 판정 불가다", async () => {
  const s = await setup(req({ value: 10n ** 19n }), undefined, false);
  const r = await run(s);
  assert.equal(r.failedAt, null);
  assert.equal(stepOf(r, 4).status, "unverifiable");
  assert.equal(s.receipt.leaf.request_intent_hash, ZERO32);
  s.store.close();
});

test("검증 — 비교할 나중 앵커가 없으면 7단계가 판정 불가다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  const r = await run(s);
  assert.equal(stepOf(r, 7).status, "unverifiable");
  s.store.close();
});


// ---------- 목록 사전 공표 ----------
//
// 이게 없으면 게이트웨이가 피해자별로 목록을 지어낼 수 있다. 목록도 루트도
// 게이트웨이가 고르니 자기들끼리 앞뒤가 맞고, 10단계가 공허해진다.

const IN_LIST = "0x000000000000000000000000000000000000beef" as Address;
const OTHER = "0x00000000000000000000000000000000000000aa";
const REAL_LIST = [IN_LIST.toLowerCase(), OTHER];
const FAKE_LIST = [OTHER];

const MISS: PolicyRule = {
  rule_id: "WHITELIST_MISS",
  description: "허용 목록 밖",
  severity: "review",
  verifiability: "verifiable",
  predicate: { kind: "not_in_set", field: "target", set: "allowedTargets" },
};

async function withPublishedList(
  published: readonly string[],
  committed: readonly string[],
  target: Address,
) {
  const policy: PolicyDocument = {
    version: 2,
    rules: [MISS],
    data_sets: { allowedTargets: [...committed] },
  };
  const store = new LogStore({
    path: ":memory:", domain: D, operator: op,
    isRegistered: async () => true, now: () => NOW,
  });
  const g = new Gateway({ account: gw, domain: D, policy, now: () => NOW });

  const upd = await g.publishPolicyData(published);
  upd.log_ack = (await store.submit(upd.leaf)).log_ack;
  // 공표한 것과 다른 루트를 커밋하는 상황을 만든다
  (g as never as { o: { policyDataRoot: Hex } }).o.policyDataRoot = rootOfList(committed) as Hex;

  const r = await g.handle({
    request: { requester: requester.address, target, value: 1n, calldata: "0x" as Hex },
    forceRule: MISS,
  });
  const receipt = r.receipt!;
  receipt.log_ack = (await store.submit(receipt.leaf)).log_ack;
  const n = store.size();
  store.recordAnchor(n, store.rootAt(n));

  const policyUpdate: PolicyUpdateProof = {
    leaf: upd.leaf,
    leaf_hash: upd.leaf_hash,
    inclusion_proof: store.proofHalf(upd.leaf_hash).inclusion_proof as never,
  };

  const report = await verifyReceipt({
    receipt, domain: D,
    chain: {
      isRegistered: async () => true,
      rootByTreeSize: async (size) => (store.anchorAt(size)?.root ?? ZERO32) as Hex,
      logOperator: async () => op.address,
    },
    proofs: {
      inclusion: async () => store.inclusionProof(receipt.leaf_hash) as never,
      consistency: async (f, t) => store.consistencyProof(f, t) as never,
      laterAnchorThan: async () => null,
    },
    policy, policyUpdate,
    policyDataProof: policyDataRootChecker(),
    staticCheck: sortedSetChecker(),
    now: () => NOW,
  });
  store.close();
  return { report, policyUpdate, policy, store };
}

test("사전 공표 — 공표한 목록과 다른 루트로 거절하면 9단계에서 걸린다", async () => {
  const { report } = await withPublishedList(REAL_LIST, FAKE_LIST, IN_LIST);
  assert.equal(report.failedAt, 9);
  assert.match(report.steps.find((s) => s.step === 9)!.detail, /공표된 루트와 다르다/);
});

test("사전 공표 — 공표와 커밋이 같으면 통과한다", async () => {
  const { report } = await withPublishedList(REAL_LIST, REAL_LIST, "0x000000000000000000000000000000000000cafe" as Address);
  assert.equal(report.failedAt, null);
  assert.equal(report.steps.find((s) => s.step === 9)!.status, "pass");
});

test("사전 공표 — 갱신 레코드가 없으면 9단계가 판정 불가다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  const r = await run(s);
  const step9 = r.steps.find((x) => x.step === 9)!;
  assert.notEqual(step9.status, "fail");
  s.store.close();
});


// ---------- 감사에서 나온 것들 ----------
//
// 아래 넷은 실제로 뚫렸던 경로다. 고친 뒤 회귀를 막으려고 남긴다.

test("감사 — leaf_hash 가 리프 본문과 안 맞으면 1단계에서 걸린다", async () => {
  // 본문은 A 인데 leaf_hash 는 트리에 실재하는 B 를 가리키는 번들. 안 묶어두면
  // 5단계까지 통과하고 6단계에서 "누락" 으로 잘못 진단된다.
  const a = await setup(req({ value: 10n ** 19n }));
  const b = await setup(req({ value: 2n * 10n ** 19n }));
  a.receipt.leaf_hash = b.receipt.leaf_hash;
  const r = await run(a);
  assert.equal(r.failedAt, 1);
  assert.match(stepOf(r, 1).detail, /leaf_hash/);
  a.store.close();
  b.store.close();
});

test("감사 — 요청하지 않은 구간의 일관성 증명은 7단계에서 거부된다", async () => {
  // 공급자가 아무 유효한 구간의 증명이나 돌려줘도 통과하면 안 된다. 그러면 정작
  // 이 리프가 속한 구간은 검증되지 않은 채 7단계가 통과한다.
  const s = await setup(req({ value: 10n ** 19n }));
  const store = s.store;
  const anchoredAt = store.size(); // setup 이 여기까지 앵커해뒀다

  // 리프를 더 쌓고 다시 앵커해 비교할 나중 구간을 만든다
  const g2 = new Gateway({ account: gw, domain: D, policy: POLICY, now: () => NOW });
  for (let i = 0; i < 3; i++) {
    const x = await g2.handle({
      request: { requester: requester.address, target: NORMAL, value: BigInt(i + 2), calldata: "0x" as Hex },
      forceRule: RULES.cap,
    });
    await store.submit(x.receipt!.leaf);
  }
  const later = store.size();
  store.recordAnchor(later, store.rootAt(later));

  const evil = {
    ...s,
    proofs: {
      ...s.proofs,
      // 요청은 (anchoredAt → later) 인데 (anchoredAt → anchoredAt) 를 돌려준다
      consistency: async () => store.consistencyProof(anchoredAt, anchoredAt) as never,
      laterAnchorThan: async () => later,
    },
  };
  const r = await run(evil);
  assert.equal(r.failedAt, 7);
  assert.match(stepOf(r, 7).detail, /요청한 구간이 아님/);
  store.close();
});

test("감사 — 앵커되지 않은 구간으로는 일관성이 통과하지 않는다", async () => {
  const s = await setup(req({ value: 10n ** 19n }));
  const evil = {
    ...s,
    proofs: {
      ...s.proofs,
      consistency: async () => ({
        from_anchor: { tree_size: 1, root: ZERO32 },
        to_anchor: { tree_size: 9999, root: ZERO32 },
        path: [],
      }) as never,
      laterAnchorThan: async () => 9999,
    },
  };
  const r = await run(evil);
  assert.equal(r.failedAt, 7);
  s.store.close();
});

test("감사 — severity 를 규칙 정의보다 낮게 적으면 9단계에서 걸린다", async () => {
  // 게이트웨이가 차단(block) 규칙을 인용하면서 리프에는 검토(review) 로 적는다.
  // 두 값 다 서명 안에 있지만 서로 대조하지 않으면 통과한다.
  const forged: PolicyRule = { ...RULES.denylist, severity: "review" };
  const s = await setup(req({ target: SANCTIONED }), forged, true, rootOfList([SANCTIONED]) as Hex);
  const rep = await verifyReceipt({
    receipt: s.receipt, domain: D, chain: s.chain, proofs: s.proofs,
    policy: POLICY, policyDataProof: policyDataRootChecker(),
    staticCheck: sortedSetChecker(), now: () => NOW,
  });
  assert.equal(rep.ok, false);
  assert.equal(rep.failedAt, 9);
  s.store.close();
});

test("감사 — 목록 사유를 인용하고 루트를 커밋 안 하면 10단계에서 실패한다", async () => {
  // 판정 불가로 넘기면 루트를 아예 커밋하지 않는 게이트웨이가 영구 면제를 받는다.
  const policy: PolicyDocument = {
    version: 2, rules: [MISS], data_sets: { allowedTargets: [...REAL_LIST] },
  };
  const store = new LogStore({
    path: ":memory:", domain: D, operator: op,
    isRegistered: async () => true, now: () => NOW,
  });
  // policyDataRoot 를 주지 않는다
  const g = new Gateway({ account: gw, domain: D, policy, now: () => NOW });
  const receipt = (await g.handle({
    request: { requester: requester.address, target: IN_LIST, value: 1n, calldata: "0x" as Hex },
    forceRule: MISS,
  })).receipt!;
  receipt.log_ack = (await store.submit(receipt.leaf)).log_ack;
  const n = store.size();
  store.recordAnchor(n, store.rootAt(n));

  assert.equal(receipt.leaf.policy_data_root, ZERO32);

  const report = await verifyReceipt({
    receipt, domain: D,
    chain: {
      isRegistered: async () => true,
      rootByTreeSize: async (size) => (store.anchorAt(size)?.root ?? ZERO32) as Hex,
      logOperator: async () => op.address,
    },
    proofs: {
      inclusion: async () => store.inclusionProof(receipt.leaf_hash) as never,
      consistency: async (f, t) => store.consistencyProof(f, t) as never,
      laterAnchorThan: async () => null,
    },
    policy,
    policyDataProof: policyDataRootChecker(),
    staticCheck: sortedSetChecker(),
    now: () => NOW,
  });
  assert.equal(report.failedAt, 10);
  assert.match(report.steps.find((s) => s.step === 10)!.detail, /커밋하지 않았다/);
  store.close();
});
