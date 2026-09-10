// D2. 로그가 접수만 하고 트리에 넣지 않는다. (공격자 A1 + A2)
//
// 접수 확인은 서명해 주되 기록은 조용히 버린다. 얼마나 막고 있는지를 숨기려는
// 동기다. 서명된 약속과 그 뒤의 부재가 책임을 가른다.
//
// 이것은 운영 책임성 신호이지 수학적 non-membership 증명이 아니다.
//
// 실행: npm run attack:d2
import type { Address, Hex } from "viem";
import { withStack, step, heading } from "./harness.ts";
import { anchorOnce } from "../lib/anchor-job.ts";
import { verifyReceipt, formatReport } from "../lib/verify.ts";
import { assignFault } from "../lib/receipt.ts";
import { SANCTIONED } from "../sdk/demo-policy.ts";

await withStack(async (s) => {
  heading("D2  로그가 누락한다");

  const r = await s.gatekeeper.handle({
    requester: "0xabc0000000000000000000000000000000000002" as Address,
    target: SANCTIONED as Address,
    value: 7_000_000_000_000_000n,
    calldata: "0xa9059cbb" as Hex,
  });
  const receipt = r.receipt!;
  step("거절 발생, 로그가 접수", `약속 시각까지 ${receipt.log_ack!.promised_by - receipt.log_ack!.received_at}초`);
  step("요청자가 영수증과 접수 확인 보유", "두 서명 모두 유효");

  // 로그 운영자가 접수 확인을 준 뒤 기록을 조용히 지운다.
  // 저장소 API 에는 이런 경로가 없다. 공격자는 DB 를 직접 만진다.
  // @ts-expect-error 시연을 위해 내부 db 에 직접 접근한다.
  s.store.db.prepare("DELETE FROM leaves WHERE leaf_hash = ?")
    .run(Buffer.from(receipt.leaf_hash.slice(2), "hex"));
  step("로그 운영자가 기록을 삭제", `트리 크기 ${s.store.size()}`);

  // 다른 기록 몇 건을 넣고 앵커해 로그는 정상처럼 굴러간다.
  for (let i = 0; i < 3; i++) {
    await s.gatekeeper.handle({
      requester: `0xabc000000000000000000000000000000000000${i}` as Address,
      target: SANCTIONED as Address,
      value: BigInt(1000 + i),
      calldata: "0xdead" as Hex,
    });
  }
  await anchorOnce({ store: s.store, chain: s.chain });
  step("로그는 정상 운영을 이어감", `앵커 tree_size=${s.store.size()}`);

  console.log("\n  — 약속 시각 전 —");
  let report = await verifyReceipt({
    receipt, domain: s.domain, chain: s.verifyChain, proofs: s.proofs,
    now: () => receipt.log_ack!.received_at + 10,
  });
  console.log(formatReport(report));
  console.log("\n  아직 편입 기한 안이므로 과실로 단정하지 않는다.");

  console.log("\n  — 약속 시각 경과 후 —");
  s.clock.now = receipt.log_ack!.promised_by + 1;
  report = await verifyReceipt({
    receipt, domain: s.domain, chain: s.verifyChain, proofs: s.proofs,
    now: () => s.clock.now,
  });
  console.log(formatReport(report));

  if (report.failedAt !== 5) throw new Error(`5단계에서 실패해야 하는데 ${report.failedAt} 단계였다`);
  if (report.fault !== "로그 운영자 과실") throw new Error(`책임 판정이 틀렸다: ${report.fault}`);
  step("누락 적발", "서명된 약속을 지키지 않았음이 드러남");

  // 책임 분리. 게이트키퍼가 아예 제출하지 않은 경우와 구분된다.
  const neverSubmitted = { ...receipt, log_ack: null };
  const otherFault = assignFault(neverSubmitted, false, s.clock.now);
  step("책임 구분", `접수 확인이 없었다면 판정은 "${otherFault}"`);

  console.log("\n  결론: 두 서명이 분리되어 있어 로그 과실과 게이트키퍼 과실이 갈린다.");
  console.log("  한계: 모든 누락을 암호학적으로 증명하는 것은 아니다. 운영 책임성 신호다.\n");
});
