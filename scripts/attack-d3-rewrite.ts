// D3. 로그 운영자가 과거 기록을 고친다. (공격자 A2)
//
// 이미 앵커된 뒤에 불리한 거절 기록의 내용을 바꾸고 새 루트를 올린다.
// 일관성 증명이 이를 잡는다. 이 프로젝트의 기술적 하이라이트다.
//
// 실행: npm run attack:d3
import type { Address, Hex } from "viem";
import { withStack, step, heading } from "./harness.ts";
import { anchorOnce } from "../lib/anchor-job.ts";
import { verifyConsistency } from "../lib/merkle.ts";
import { consistencyProof } from "../lib/merkle.ts";
import { SANCTIONED } from "../sdk/demo-policy.ts";

const unhex = (s: string) => Buffer.from(s.replace(/^0x/, ""), "hex");

await withStack(async (s) => {
  heading("D3  로그가 역사를 고친다");

  for (let i = 0; i < 4; i++) {
    await s.gatekeeper.handle({
      requester: `0xabc000000000000000000000000000000000000${i}` as Address,
      target: SANCTIONED as Address,
      value: BigInt(1_000_000 + i),
      calldata: "0xa9059cbb" as Hex,
    });
  }
  const first = await anchorOnce({ store: s.store, chain: s.chain });
  const oldSize = first.treeSize!;
  const oldRootOnChain = await s.chain.rootByTreeSize(oldSize);
  step("거절 4건 적재 후 앵커", `tree_size=${oldSize}`);
  step("감사자가 이 시점의 루트를 기록", oldRootOnChain.slice(0, 18) + "…");

  console.log("\n  — 운영자가 과거 기록 하나를 고친다 —\n");

  // 저장소 API 로는 불가능하다. DB 를 직접 만진다.
  // @ts-expect-error 시연을 위해 내부 db 에 직접 접근한다.
  s.store.db.prepare("UPDATE leaves SET leaf_bytes = ? WHERE idx = 1")
    .run(Buffer.from('{"tampered":true}', "utf8"));
  step("인덱스 1의 거절 기록을 조작", "사유를 바꾼 것과 같은 효과");

  // 조작 후에는 정직한 앵커링이 막힌다. recordAnchor 가 루트를 대조하기 때문이다.
  const newRootAfterTamper = s.store.rootAt(oldSize);
  if (newRootAfterTamper === oldRootOnChain) throw new Error("조작인데 루트가 그대로다");
  step("같은 크기의 루트가 달라짐", "옛 루트와 불일치");

  // 운영자는 새 기록을 더 쌓고 새 크기로 앵커해 정상처럼 보이려 한다.
  for (let i = 0; i < 3; i++) {
    await s.gatekeeper.handle({
      requester: `0xdef000000000000000000000000000000000000${i}` as Address,
      target: SANCTIONED as Address,
      value: BigInt(2_000_000 + i),
      calldata: "0xbeef" as Hex,
    });
  }
  const newSize = s.store.size();
  const newRoot = s.store.rootAt(newSize);
  await s.chain.submitRoot(newRoot, newSize);
  step("조작된 트리로 새 루트를 앵커", `tree_size=${newSize}`);

  console.log("\n  — 감사자가 두 앵커 사이의 일관성을 확인한다 —\n");

  const newRootOnChain = await s.chain.rootByTreeSize(newSize);
  // @ts-expect-error 내부 접근. 운영자가 만들 수 있는 최선의 증명을 준다.
  const data = s.store.data(newSize) as Buffer[];
  const path = consistencyProof(oldSize, data);

  const consistent = verifyConsistency(
    oldSize,
    newSize,
    unhex(oldRootOnChain),
    unhex(newRootOnChain),
    path,
  );
  console.log(`  옛 루트 (체인, tree_size=${oldSize})  ${oldRootOnChain}`);
  console.log(`  새 루트 (체인, tree_size=${newSize})  ${newRootOnChain}`);
  console.log(`  일관성 증명 원소 ${path.length}개`);
  console.log(`\n  검증 6단계: ${consistent ? "통과" : "실패"}`);

  if (consistent) throw new Error("조작을 못 잡았다");
  step("조작 적발", "새 트리가 옛 트리의 순수 확장이 아님");

  // 대조군. 조작이 없었다면 같은 절차가 통과한다.
  await withCleanRun();

  console.log("\n  결론: 서명만 있는 로그는 이 공격을 막지 못한다.");
  console.log("  append-only 자료구조와 두 시점의 온체인 루트가 함께 있어야 잡힌다.\n");
});

/** 대조군. 조작 없이 같은 절차를 밟으면 일관성 증명이 통과한다. */
async function withCleanRun(): Promise<void> {
  await withStack(async (s) => {
    for (let i = 0; i < 4; i++) {
      await s.gatekeeper.handle({
        requester: `0xabc000000000000000000000000000000000000${i}` as Address,
        target: SANCTIONED as Address,
        value: BigInt(1_000_000 + i),
        calldata: "0xa9059cbb" as Hex,
      });
    }
    const a = await anchorOnce({ store: s.store, chain: s.chain });
    for (let i = 0; i < 3; i++) {
      await s.gatekeeper.handle({
        requester: `0xdef000000000000000000000000000000000000${i}` as Address,
        target: SANCTIONED as Address,
        value: BigInt(2_000_000 + i),
        calldata: "0xbeef" as Hex,
      });
    }
    const b = await anchorOnce({ store: s.store, chain: s.chain });
    const c = await s.proofs.consistency(a.treeSize!, b.treeSize!);
    const okay = verifyConsistency(
      a.treeSize!,
      b.treeSize!,
      unhex(await s.chain.rootByTreeSize(a.treeSize!)),
      unhex(await s.chain.rootByTreeSize(b.treeSize!)),
      c.path.map(unhex),
    );
    if (!okay) throw new Error("정직한 로그가 일관성 검증에 실패했다");
    step("대조군", `조작이 없으면 ${a.treeSize} → ${b.treeSize} 통과`);
  });
}
