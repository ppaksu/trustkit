// D1. 게이트키퍼가 거절 사실을 부인한다. (공격자 A1)
//
// 커스터디가 출금을 막아놓고 나중에 "그런 요청은 없었다" 고 주장한다.
// 요청자가 들고 있는 서명된 영수증이 그 주장을 무너뜨린다.
//
// 실행: npm run attack:d1
import type { Address, Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { withStack, step, heading } from "./harness.ts";
import { anchorOnce } from "../lib/anchor-job.ts";
import { verifyReceipt, formatReport } from "../lib/verify.ts";
import { signLeaf, verifyLeafSignature } from "../lib/sign.ts";
import { SANCTIONED } from "../sdk/demo-policy.ts";

await withStack(async (s) => {
  heading("D1  게이트키퍼가 부인한다");

  const r = await s.gatekeeper.handle({
    requester: "0xabc0000000000000000000000000000000000001" as Address,
    target: SANCTIONED as Address,
    value: 5_000_000_000_000_000n,
    calldata: "0xa9059cbb" as Hex,
  });
  const receipt = r.receipt!;
  step("게이트키퍼가 출금을 차단", `사유 ${(r.decision as { rule_id: string }).rule_id}`);
  step("요청자가 서명된 영수증 보관", receipt.leaf_hash.slice(0, 18) + "…");

  await anchorOnce({ store: s.store, chain: s.chain });
  step("로그가 앵커됨", `tree_size=${s.store.size()}`);

  console.log("\n  — 며칠 뒤, 게이트키퍼가 부인한다 —");
  console.log('  게이트키퍼: "그런 요청을 받은 적도, 막은 적도 없습니다."\n');

  const report = await verifyReceipt({
    receipt,
    domain: s.domain,
    chain: s.verifyChain,
    proofs: s.proofs,
    now: () => s.clock.now,
  });
  console.log(formatReport(report));

  if (!report.ok) throw new Error("정직한 영수증이 검증에 실패했다");
  step("부인 실패", "서명이 게이트키퍼 주소로 복원됨");

  // 반대편도 확인한다. 다른 키로 만든 영수증은 통과하면 안 된다.
  const evil = privateKeyToAccount(("0x" + "99".repeat(32)) as Hex);
  const forged = await signLeaf(
    { ...receipt.leaf, nonce: ("0x" + "ab".repeat(32)) as Hex },
    evil,
    s.domain,
  );
  if (await verifyLeafSignature(forged, s.domain)) {
    throw new Error("위조 영수증이 통과했다");
  }
  step("반대 방향 확인", "게이트키퍼를 사칭한 영수증은 2단계에서 걸림");

  console.log("\n  결론: 서명은 사후 부인이 불가능하다. 검증 2단계가 이를 증명한다.\n");
});
