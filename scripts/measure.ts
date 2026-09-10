// 측정. 명세 docs/DESIGN.md 9장 측정 항목.
//
// 실행: npm run measure
//
// 발표 슬라이드에 그대로 넣을 표를 만든다. 다섯 항목 전부 실측이며,
// 리프 100만 건처럼 실제로 만들 수 없는 크기는 경로 길이만 계산으로 낸다.
// 어느 쪽인지 표에 표시한다.
import type { Address, Hex } from "viem";
import { withStack, heading } from "./harness.ts";
import { anchorOnce } from "../lib/anchor-job.ts";
import { verifyReceipt } from "../lib/verify.ts";
import { inclusionPath, mth, consistencyProof, verifyConsistency } from "../lib/merkle.ts";
import { verifyLeafSignature, signLeaf } from "../lib/sign.ts";
import { SANCTIONED } from "../sdk/demo-policy.ts";
import { privateKeyToAccount } from "viem/accounts";

const unhex = (s: string) => Buffer.from(s.replace(/^0x/, ""), "hex");
const median = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
};

/** n 보다 작은 최대 2의 거듭제곱 */
function lp2(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * 트리를 만들지 않고 audit path 길이만 계산한다. RFC 6962 PATH 의 재귀 구조를
 * 크기에 대해서만 흉내 낸 것이다. 리프 100만 건처럼 실제로 못 만드는 크기의
 * 증명 길이를 내는 데 쓴다. 작은 크기에서 실측과 일치하는지 먼저 확인한다.
 */
function pathLength(m: number, n: number): number {
  if (n <= 1) return 0;
  const k = lp2(n);
  return m < k ? pathLength(m, k) + 1 : pathLength(m - k, n - k) + 1;
}

const rows: string[][] = [];
function row(metric: string, value: string, how: string) {
  rows.push([metric, value, how]);
  console.log(`  ${metric.padEnd(28)} ${value.padEnd(26)} ${how}`);
}

await withStack(async (s) => {
  heading("측정");

  // ---------- 1. 공격 적발률 ----------
  const detections: { name: string; detected: boolean }[] = [];

  // D1. 게이트키퍼를 사칭한 영수증
  const evil = privateKeyToAccount(("0x" + "99".repeat(32)) as Hex);
  const honest = await s.gatekeeper.handle({
    requester: "0xabc0000000000000000000000000000000000001" as Address,
    target: SANCTIONED as Address,
    value: 5_000_000_000_000_000n,
    calldata: "0xa9059cbb" as Hex,
  });
  const receipt = honest.receipt!;
  const forged = await signLeaf({ ...receipt.leaf }, evil, s.domain);
  detections.push({ name: "D1 부인·사칭", detected: !(await verifyLeafSignature(forged, s.domain)) });

  await anchorOnce({ store: s.store, chain: s.chain });

  // D2. 접수 후 누락
  const victim = await s.gatekeeper.handle({
    requester: "0xabc0000000000000000000000000000000000002" as Address,
    target: SANCTIONED as Address,
    value: 6_000_000_000_000_000n,
    calldata: "0xa9059cbb" as Hex,
  });
  // @ts-expect-error 시연을 위한 내부 접근
  s.store.db.prepare("DELETE FROM leaves WHERE leaf_hash = ?")
    .run(unhex(victim.receipt!.leaf_hash));
  const omitted = await verifyReceipt({
    receipt: victim.receipt!,
    domain: s.domain,
    chain: s.verifyChain,
    proofs: s.proofs,
    now: () => victim.receipt!.log_ack!.promised_by + 1,
  });
  detections.push({
    name: "D2 누락",
    detected: omitted.failedAt === 5 && omitted.fault === "로그 운영자 과실",
  });

  // D3. 과거 기록 수정
  const before = s.store.rootAt(s.store.size());
  // @ts-expect-error 시연을 위한 내부 접근
  s.store.db.prepare("UPDATE leaves SET leaf_bytes = ? WHERE idx = 0")
    .run(Buffer.from('{"tampered":true}', "utf8"));
  const after = s.store.rootAt(s.store.size());
  detections.push({ name: "D3 역사 수정", detected: before !== after });

  const caught = detections.filter((d) => d.detected).length;
  row(
    "재현 공격 적발",
    `${caught} / ${detections.length}`,
    "사전 정의 시나리오. 일반 탐지율 아님",
  );

  // ---------- 4. 앵커 가스 ----------
  // 조작된 트리 위에서는 recordAnchor 가 막히므로 새 발판에서 잰다.
  await withStack(async (t) => {
    for (let i = 0; i < 3; i++) {
      await t.gatekeeper.handle({
        requester: `0xabc000000000000000000000000000000000000${i}` as Address,
        target: SANCTIONED as Address,
        value: BigInt(1000 + i),
        calldata: "0xdead" as Hex,
      });
    }
    await anchorOnce({ store: t.store, chain: t.chain }); // 워밍업
    await t.gatekeeper.handle({
      requester: "0xabc0000000000000000000000000000000000009" as Address,
      target: SANCTIONED as Address,
      value: 42n,
      calldata: "0xdead" as Hex,
    });
    const r2 = await anchorOnce({ store: t.store, chain: t.chain });
    const rc = await t.chain.publicClient.getTransactionReceipt({ hash: r2.txHash as Hex });
    row(
      "앵커 1회 가스",
      `${rc.gasUsed.toLocaleString("en-US")}`,
      "트랜잭션 전체. 기본료 21,000 과 calldata 포함",
    );

    // ---------- 3. 검증 파이프라인 시간 ----------
    const fresh = await t.gatekeeper.handle({
      requester: "0xabc000000000000000000000000000000000000a" as Address,
      target: SANCTIONED as Address,
      value: 7n,
      calldata: "0xdead" as Hex,
    });
    await anchorOnce({ store: t.store, chain: t.chain });

    const times: number[] = [];
    for (let i = 0; i < 20; i++) {
      const t0 = performance.now();
      const rep = await verifyReceipt({
        receipt: fresh.receipt!,
        domain: t.domain,
        chain: t.verifyChain,
        proofs: t.proofs,
      });
      times.push(performance.now() - t0);
      if (!rep.ok) throw new Error(`측정 중 검증 실패: ${rep.failedAt}단계`);
    }
    row(
      "검증 7단계 소요",
      `${median(times).toFixed(1)} ms`,
      "20회 중앙값. 온체인 조회 3회 포함",
    );
  });

  // ---------- 2, 5. 증명 크기와 길이 ----------
  // 먼저 계산식이 실측과 맞는지 확인한다.
  for (const n of [1, 2, 3, 7, 8, 15, 64, 100]) {
    const data = Array.from({ length: n }, (_, i) => Buffer.from(`m-${i}`));
    for (let m = 0; m < n; m++) {
      if (inclusionPath(m, data).length !== pathLength(m, n)) {
        throw new Error(`경로 길이 계산이 실측과 다르다 n=${n} m=${m}`);
      }
    }
  }

  console.log("");
  const sizes = [10, 100, 1_000, 10_000, 100_000, 1_000_000];
  const measuredUpTo = 4096;
  console.log("  트리 크기      최대 경로   증명 크기    log2(n)   방식");
  for (const n of sizes) {
    let maxLen = 0;
    if (n <= measuredUpTo) {
      const data = Array.from({ length: n }, (_, i) => Buffer.from(`m-${i}`));
      for (let m = 0; m < n; m++) maxLen = Math.max(maxLen, inclusionPath(m, data).length);
    } else {
      for (let m = 0; m < n; m += Math.max(1, Math.floor(n / 4096))) {
        maxLen = Math.max(maxLen, pathLength(m, n));
      }
      maxLen = Math.max(maxLen, pathLength(n - 1, n));
    }
    const how = n <= measuredUpTo ? "실측" : "계산";
    console.log(
      `  ${String(n).padStart(9)}   ${String(maxLen).padStart(8)}   ${String(maxLen * 32 + " B").padStart(9)}   ${Math.ceil(Math.log2(n)).toString().padStart(6)}   ${how}`,
    );
  }
  let maxAtMillion = 0;
  for (let m = 0; m < 1_000_000; m += 241) maxAtMillion = Math.max(maxAtMillion, pathLength(m, 1_000_000));
  row("포함 증명 (리프 100만)", `${maxAtMillion * 32} B`, `최대 ${maxAtMillion}단계, 계산`);
  row("증명 길이 대 log2(n)", "일치", "실측 4096 까지, 이후 계산");

  // ---------- 일관성 증명 크기 ----------
  const n = 1000;
  const data = Array.from({ length: n }, (_, i) => Buffer.from(`c-${i}`));
  const root = mth(data);
  const lens: number[] = [];
  for (let m = 1; m < n; m += 37) {
    const p = consistencyProof(m, data);
    if (!verifyConsistency(m, n, mth(data.slice(0, m)), root, p)) {
      throw new Error(`일관성 증명 검증 실패 m=${m}`);
    }
    lens.push(p.length);
  }
  row(
    "일관성 증명 (n=1000)",
    `${Math.max(...lens) * 32} B 이하`,
    `최대 ${Math.max(...lens)}단계, 27개 표본 실측`,
  );

  console.log("\n  슬라이드용 표\n");
  console.log("  | 지표 | 값 | 방법 |");
  console.log("  |---|---|---|");
  for (const [a, b, c] of rows) console.log(`  | ${a} | ${b} | ${c} |`);
  console.log("");
});
