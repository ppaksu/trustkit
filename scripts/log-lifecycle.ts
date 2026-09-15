// 로그 수명주기 검사. 정상 → 수정 → 삭제 순으로 검증기가 뭘 보는지 본다.
//
// 로그 DB 를 파일로 두고 운영자가 SQLite 에 직접 쓴다. HTTP 도 서명 검증도 안 탄다.
// 로그 운영자가 할 수 있는 최대한의 조작이다.
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Address, Hex } from "viem";
import { withStack, heading, type Stack } from "./harness.ts";
import { verifyReceipt } from "../lib/verify.ts";
import { sortedSetChecker, policyDataRootChecker } from "../lib/sorted-merkle.ts";
import { leafHash } from "../lib/record.ts";
import { verifyConsistency } from "../lib/merkle.ts";
import { DEMO_POLICY } from "../sdk/demo-policy.ts";
import { assignFault } from "../lib/receipt.ts";
import type { Receipt } from "../lib/receipt.ts";

const OUTSIDE = "0x000000000000000000000000000000000000cafe" as Address;
const unhex = (s: string) => Buffer.from(s.replace(/^0x/, ""), "hex");

/** 한 건을 검증하고 한 줄로 요약한다. */
async function check(s: Stack, r: Receipt): Promise<string> {
  try {
    const bundle = await s.bundleFor(r);
    const report = await verifyReceipt({
      receipt: { ...bundle, log_ack: bundle.log_ack, disclosures: bundle.disclosures,
        request_intent: bundle.request_intent ?? undefined, request_sig: bundle.request_sig ?? undefined },
      domain: s.domain, chain: s.verifyChain,
      proofs: {
        inclusion: async (h) => {
          const res = await fetch(`${s.base}/api/log/proof/inclusion?leaf_hash=${h}`);
          if (!res.ok) throw new Error(`${res.status}`);
          return (await res.json()) as never;
        },
        consistency: async (f, t) => {
          const res = await fetch(`${s.base}/api/log/proof/consistency?from=${f}&to=${t}`);
          if (!res.ok) throw new Error(`${res.status}`);
          return (await res.json()) as never;
        },
        laterAnchorThan: async (n) => s.store.anchors().find((a) => a.tree_size > n)?.tree_size ?? null,
      },
      policy: bundle.policy_document ?? undefined,
      policyUpdate: bundle.policy_update ?? undefined,
      policyDataProof: policyDataRootChecker(),
      staticCheck: sortedSetChecker(),
      now: () => s.clock.now,
    });
    if (report.ok) return `통과${report.reasonChecked ? " (사유까지)" : " (사유 미검증)"}`;
    const st = report.steps.find((x) => x.step === report.failedAt)!;
    return `${report.failedAt}단계 실패 — ${st.detail.slice(0, 44)}`;
  } catch (e) {
    return `증명 못 받음 — ${(e as Error).message.slice(0, 40)}`;
  }
}

async function run(s: Stack, storePath: string): Promise<void> {
  // ---------- 1. 로그 예시 만들기 ----------
  heading("1. 로그 예시를 만든다");

  await s.publishList(DEMO_POLICY.data_sets!.allowedTargets);
  const records: Receipt[] = [];
  for (let i = 0; i < 5; i++) {
    records.push(await s.reject({ requester: s.requester.address, target: OUTSIDE,
      value: BigInt(i + 1), calldata: "0x" as Hex }));
  }
  const n1 = s.store.size();
  await s.chain.submitRoot(s.store.rootAt(n1), n1);
  s.store.recordAnchor(n1, s.store.rootAt(n1));

  // 앵커 뒤에 두 건 더 쌓고 다시 앵커한다. 일관성 증명이 나오려면 앵커가 둘이어야 한다.
  for (let i = 0; i < 2; i++) {
    records.push(await s.reject({ requester: s.requester.address, target: OUTSIDE,
      value: BigInt(100 + i), calldata: "0x" as Hex }));
  }
  const n2 = s.store.size();
  await s.chain.submitRoot(s.store.rootAt(n2), n2);
  s.store.recordAnchor(n2, s.store.rootAt(n2));

  // 리프 0 은 목록 공표 레코드다. 거절 기록 7건은 리프 1~7 에 있다.
  const leafIndexOf = (recordNo: number) => recordNo;

  console.log(`  거절 기록 ${records.length}건 + 목록 공표 1건 = 리프 ${n2}개`);
  console.log(`  앵커 2회: size=${n1}, size=${n2}`);
  console.log(`  체인 루트 ${n2}: ${(await s.chain.rootByTreeSize(n2)).slice(0, 26)}…`);

  // ---------- 2. 정상 검증 ----------
  heading("2. 정상 로그로 검증한다");
  const clean: string[] = [];
  for (let i = 0; i < records.length; i++) {
    clean.push(await check(s, records[i]));
    console.log(`  기록 ${i + 1}  ${clean[i]}`);
  }

  // ---------- 3. 7건 중 3건만 수정 ----------
  const TAMPER = [2, 4, 6]; // 기록 번호
  heading(`3. 운영자가 7건 중 3건만 고친다 (기록 ${TAMPER.join(", ")})`);

  const db = new DatabaseSync(storePath);
  for (const no of TAMPER) {
    const idx = leafIndexOf(no);
    const row = db.prepare("SELECT leaf_bytes FROM leaves WHERE idx = ?").get(idx) as { leaf_bytes: Uint8Array };
    const leaf = JSON.parse(Buffer.from(row.leaf_bytes).toString("utf8")) as Record<string, unknown>;
    leaf.issued_at = (leaf.issued_at as number) - 86_400;
    // leaf_hash 색인은 그대로 둔다. 고치면 증명 요청이 404 로 떠서 바로 티가 난다.
    db.prepare("UPDATE leaves SET leaf_bytes = ? WHERE idx = ?")
      .run(Buffer.from(JSON.stringify(leaf), "utf8"), idx);
    console.log(`  기록 ${no} (리프 ${idx}) 발급 시각 하루 앞당김`);
  }
  db.close();
  console.log(`  같은 크기 ${n2} 루트 재계산: ${s.store.rootAt(n2).slice(0, 26)}…`);
  console.log(`  체인에 박힌 루트는 그대로: ${(await s.chain.rootByTreeSize(n2)).slice(0, 26)}…`);
  console.log();

  const tampered: string[] = [];
  for (let i = 0; i < records.length; i++) {
    tampered.push(await check(s, records[i]));
    const mark = TAMPER.includes(i + 1) ? "고침" : "  · ";
    console.log(`  ${mark}  기록 ${i + 1}  ${tampered[i]}`);
  }

  const c = s.store.consistencyProof(n1, n2);
  console.log(`\n  일관성 증명 ${n1} → ${n2}: ${
    verifyConsistency(n1, n2, unhex(await s.chain.rootByTreeSize(n1)),
      unhex(await s.chain.rootByTreeSize(n2)), c.path.map(unhex)) ? "!! 통과" : "실패 — 역사 조작 탐지"}`);

  // ---------- 4. 고친 3건을 삭제 ----------
  heading(`4. 운영자가 고쳤던 3건을 지운다 (기록 ${TAMPER.join(", ")})`);

  const db2 = new DatabaseSync(storePath);
  for (const no of TAMPER) db2.prepare("DELETE FROM leaves WHERE idx = ?").run(leafIndexOf(no));
  db2.close();
  console.log(`  남은 리프 ${s.store.size()}개. 앵커는 ${n2} 로 박혀 있다`);
  console.log();

  const deleted: string[] = [];
  for (let i = 0; i < records.length; i++) {
    deleted.push(await check(s, records[i]));
    const mark = TAMPER.includes(i + 1) ? "지움" : "  · ";
    console.log(`  ${mark}  기록 ${i + 1}  ${deleted[i]}`);
  }

  // ---------- 요약 ----------
  heading("요약");
  console.log("  기록   상태     2. 정상        3. 3건 수정 후     4. 3건 삭제 후");
  for (let i = 0; i < records.length; i++) {
    const mark = TAMPER.includes(i + 1) ? "대상" : "무관";
    const short = (t: string) =>
      t.startsWith("통과") ? "통과"
      : t.includes("404") ? "리프 없음"
      : t.includes("409") ? "트리 못 만듦"
      : t.startsWith("증명 못") ? "증명 없음"
      : t.split(" —")[0];
    console.log(`  ${String(i + 1).padStart(4)}   ${mark}     ${short(clean[i]).padEnd(12)}   ${short(tampered[i]).padEnd(16)}   ${short(deleted[i])}`);
  }

  const victims = TAMPER.map((n) => records[n - 1]);
  const ack = victims[0].log_ack!;
  console.log();
  console.log("  3단계. 건드리지 않은 4건도 전부 깨진다. 남의 기록을 고치면 내 audit path 가");
  console.log("  그 해시를 지나가기 때문이다. 조작을 국소적으로 숨길 수 없다.");
  console.log();
  console.log("  4단계. 지운 3건은 404, 남은 4건은 409 다. 이유가 다르다.");
  console.log("  404 는 그 리프가 없다는 뜻이고, 409 는 앵커된 크기만큼의 트리를 만들 수");
  console.log("  없다는 뜻이다. 로그가 자기 과거를 재현하지 못하는 상태 자체가 증거다.");
  console.log();
  console.log("  지워진 3건의 요청자는 접수 확인 서명을 그대로 들고 있다. 회수할 수 없다.");
  console.log(`    기한 전 책임 판정: ${assignFault(victims[0], false, ack.promised_by - 1)}`);
  console.log(`    기한 후 책임 판정: ${assignFault(victims[0], false, ack.promised_by + 1)}`);
  console.log();
  console.log("  수정과 삭제가 다르게 잡힌다. 수정은 루트가 어긋나 6·7단계에서,");
  console.log("  삭제는 증명 자체가 안 나온다. 어느 쪽이든 조용히 빠져나갈 길이 없다.");
}

const dir = mkdtempSync(join(tmpdir(), "ocdl-lifecycle-"));
const storePath = join(dir, "log.db");
try {
  await withStack(async (s) => {
    console.log("\n로그 수명주기 검사 — 정상 / 수정 / 삭제");
    await run(s, storePath);
    console.log();
  }, { storePath });
} finally {
  rmSync(dir, { recursive: true, force: true });
}
