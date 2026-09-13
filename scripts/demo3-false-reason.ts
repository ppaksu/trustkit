// 데모 3 — 거짓 정적 사유 판정.
//
// 배점에는 없지만 심사에서 갈리는 지점이다. 여기까지 오기 전의 모든 장치는
// **판단이 있었다는 사실**만 증명한다. 게이트웨이가 아무 사유나 대고 서명하면
// 서명은 멀쩡하다. 검열하는 기관을 못 잡는다.
//
// 목록을 정렬 머클 트리로 커밋하면 그 거짓말이 잡힌다. "없다" 는 주장에는
// 포함 증명이 반박이 된다. 온체인 절차도 대기 시간도 없다.
import type { Address, Hex } from "viem";
import { withStack, step, heading, resetSteps, type Stack } from "./harness.ts";
import { verifyReceipt, formatReport } from "../lib/verify.ts";
import { bundleProofSource, receiptOf } from "../lib/bundle.ts";
import {
  buildSortedTree,
  sortedRoot,
  proveNonMembership,
  proveMembership,
  verifyMembership,
  SortedMerkleError,
  sortedSetChecker,
  policyDataRootChecker,
} from "../lib/sorted-merkle.ts";
import { DEMO_POLICY, KNOWN_TARGET } from "../sdk/demo-policy.ts";
import type { PolicyRule } from "../lib/record.ts";

const OUTSIDE = "0x000000000000000000000000000000000000cafe" as Address;

const WHITELIST_MISS = DEMO_POLICY.rules.find((r) => r.rule_id === "WHITELIST_MISS")!;

const req = (target: Address, requester: Address) => ({
  requester,
  target,
  value: 1n,
  calldata: "0xa9059cbb" as Hex,
});

/** 앵커 한 번. 포함 증명이 나오려면 트리가 체인에 고정되어 있어야 한다. */
async function anchor(s: Stack): Promise<void> {
  const n = s.store.size();
  const root = s.store.rootAt(n);
  await s.chain.submitRoot(root, n);
  s.store.recordAnchor(n, root);
}

async function verify(s: Stack, receipt: Awaited<ReturnType<Stack["reject"]>>) {
  const bundle = await s.bundleFor(receipt);
  return verifyReceipt({
    receipt: receiptOf(bundle),
    domain: s.domain,
    chain: s.verifyChain,
    proofs: bundleProofSource(bundle),
    policy: bundle.policy_document ?? undefined,
    policyUpdate: bundle.policy_update ?? undefined,
    policyDataProof: policyDataRootChecker(),
    staticCheck: sortedSetChecker(),
    now: () => s.clock.now,
  });
}

async function run(s: Stack): Promise<void> {
  const list = DEMO_POLICY.data_sets!.allowedTargets;
  const tree = buildSortedTree(list);

  heading("0부 — 게이트웨이가 무엇을 커밋했는가");

  // 목록을 판단보다 먼저 공표한다. 이 순서가 지켜져야 정적 사유 검증이 의미를 갖는다.
  await s.publishList(list);
  await anchor(s);
  step("허용 목록 공표", `${list.length}건, 갱신 레코드를 로그에 박음`);
  step("허용 목록", list.join(", "));
  step("정렬 머클 루트", sortedRoot(tree));
  step("리프에 커밋된 policy_data_root", s.policyDataRoot);
  step(
    "일치 여부",
    sortedRoot(tree) === s.policyDataRoot.toLowerCase() ? "일치" : "!!! 불일치",
  );

  // ---------- 1부: 정직한 거절 ----------
  heading("1부 — 진짜로 목록 밖인 수신자를 막았을 때");

  const honest = await s.reject(req(OUTSIDE, s.requester.address));
  await anchor(s);
  step("거절 발급", `사유 ${WHITELIST_MISS.rule_id}, 수신자 ${OUTSIDE}`);

  const p = proveNonMembership(tree, OUTSIDE);
  step("비포함 증명 형태", p.kind);

  const r1 = await verify(s, honest);
  step("11단계 검증", r1.ok ? "통과" : `${r1.failedAt}단계 실패`);
  console.log();
  console.log(formatReport(r1));

  // ---------- 2부: 거짓 사유 ----------
  heading("2부 — 목록 안에 있는 수신자를 목록 밖이라고 했을 때");

  step("수신자", `${KNOWN_TARGET} — 허용 목록 인덱스 ${tree.values.indexOf(KNOWN_TARGET)}`);

  // 게이트웨이가 규칙을 강제 지정한다. 정책 엔진을 거치지 않고 거짓 사유를 단다.
  const lie = await s.reject(req(KNOWN_TARGET as Address, s.requester.address), WHITELIST_MISS as PolicyRule);
  await anchor(s);
  step("거절 발급", `사유 ${WHITELIST_MISS.rule_id} — 거짓`);

  // 게이트웨이가 이 거짓말을 증명으로 뒷받침하려 해도 만들 수가 없다.
  let forge = "";
  try {
    proveNonMembership(tree, KNOWN_TARGET);
    forge = "!!! 만들어짐 (설계 실패)";
  } catch (e) {
    forge = e instanceof SortedMerkleError ? "거부 — 목록에 있는 값이다" : "거부";
  }
  step("게이트웨이가 비포함 증명 위조 시도", forge);

  // 반박은 포함 증명이다. 누구나 커밋된 목록에서 직접 만든다.
  const refute = proveMembership(tree, KNOWN_TARGET);
  step(
    "반박용 포함 증명",
    `인덱스 ${refute.index}, 루트 대조 ${verifyMembership(sortedRoot(tree), refute) ? "통과" : "실패"}`,
  );

  // 뒤에 앵커가 하나 더 쌓여야 일관성 증명이 나온다. 실제 운영에서는 주기
  // 앵커가 알아서 쌓이는 자리다.
  await s.reject(req(OUTSIDE, s.requester.address));
  await anchor(s);
  step("이후 앵커 추가", `트리 크기 ${s.store.size()}`);

  const r2 = await verify(s, lie);
  step("11단계 검증", r2.ok ? "!!! 통과 (설계 실패)" : `${r2.failedAt}단계에서 실패`);
  console.log();
  console.log(formatReport(r2));

  console.log();
  console.log("  1~9 단계는 전부 통과했다. 서명도 포함도 정책 인용도 정상이다.");
  console.log("  거짓말은 10단계에서만 드러난다. 그 자리가 이 설계의 값어치다.");
  console.log("  도전 기간도 담보도 온체인 판정도 없다. 검증기 하나로 끝난다.");
}

await withStack(async (s) => {
  console.log("\n데모 3 — 거짓 정적 사유 판정");
  resetSteps();
  await run(s);
  console.log();
});
