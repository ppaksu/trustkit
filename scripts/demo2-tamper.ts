// 데모 2 — 사후 조작·삭제·누락 탐지. 필수 제출물.
//
// 평가 축 둘을 친다. 불변성과 완전성.
//
// 로그 운영자가 악의적이라고 가정한다. DB 에 직접 쓸 수 있고 앵커도 자기가
// 올린다. 그런데도 과거를 고치면 드러난다. 왜냐하면 검증자가 대조하는 루트가
// 로그가 말한 값이 아니라 체인에서 읽은 값이기 때문이다.
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Address, Hex } from "viem";
import { withStack, step, heading, resetSteps, type Stack } from "./harness.ts";
import { verifyReceipt, formatReport } from "../lib/verify.ts";
import { bundleProofSource, receiptOf, assembleBundle } from "../lib/bundle.ts";
import { assignFault } from "../lib/receipt.ts";
import { leafHash } from "../lib/record.ts";
import { verifyConsistency } from "../lib/merkle.ts";

const SANCTIONED = "0x000000000000000000000000000000000000dead" as Address;
const STRANGER = "0x000000000000000000000000000000000000cafe" as Address;

const unhex = (s: string) => Buffer.from(s.replace(/^0x/, ""), "hex");

const req = (target: Address, value: bigint) => ({
  requester: "0x0000000000000000000000000000000000000000" as Address,
  target,
  value,
  calldata: "0xa9059cbb" as Hex,
});

async function part1(s: Stack): Promise<void> {
  heading("1부 — 과거 리프를 고치면 일관성 증명이 깨진다");

  const kept = [];
  for (let i = 0; i < 3; i++) {
    kept.push(await s.reject({ ...req(SANCTIONED, 1n), requester: s.requester.address }));
  }
  step("거절 3건 접수", `트리 크기 ${s.store.size()}`);

  const root3 = s.store.rootAt(3);
  await s.chain.submitRoot(root3, 3);
  s.store.recordAnchor(3, root3);
  step("앵커 1", `size=3 root=${root3.slice(0, 18)}…`);

  for (let i = 0; i < 2; i++) {
    await s.reject({ ...req(STRANGER, 1n), requester: s.requester.address });
  }
  const root5 = s.store.rootAt(5);
  await s.chain.submitRoot(root5, 5);
  s.store.recordAnchor(5, root5);
  step("앵커 2", `size=5 root=${root5.slice(0, 18)}…`);

  // 조작 전 상태를 확인해 둔다. 이게 통과해야 비교가 의미를 가진다.
  const before = s.store.consistencyProof(3, 5);
  const okBefore = verifyConsistency(
    3,
    5,
    unhex(await s.chain.rootByTreeSize(3)),
    unhex(await s.chain.rootByTreeSize(5)),
    before.path.map(unhex),
  );
  step("조작 전 일관성 증명", okBefore ? "통과" : "실패");

  const target = kept[1];
  const bundleBefore = await s.bundleFor(target);
  const reportBefore = await verifyReceipt({
    receipt: receiptOf(bundleBefore),
    domain: s.domain,
    chain: s.verifyChain,
    proofs: bundleProofSource(bundleBefore),
    policy: bundleBefore.policy_document ?? undefined,
    now: () => s.clock.now,
  });
  step("조작 전 11단계 검증", reportBefore.ok ? "통과" : `${reportBefore.failedAt}단계 실패`);

  // ---------- 운영자가 DB 에 직접 쓴다 ----------
  //
  // API 를 거치지 않는다. 서명 검증도 접수 검증도 안 탄다. 로그 운영자가
  // 할 수 있는 최대한의 조작이다.
  // 요청자가 검증할 기록은 인덱스 1 이다. 운영자는 그 옆 리프를 고친다.
  // 남의 기록만 건드렸으니 내 기록은 멀쩡할 것 같지만, audit path 가 이웃의
  // 해시를 지나가므로 내 포함 증명이 먼저 깨진다.
  const db = new DatabaseSync(s.storePath);
  const row = db.prepare("SELECT leaf_bytes FROM leaves WHERE idx = 0").get() as {
    leaf_bytes: Uint8Array;
  };
  const leaf = JSON.parse(Buffer.from(row.leaf_bytes).toString("utf8")) as Record<string, unknown>;
  const originalIssuedAt = leaf.issued_at as number;
  leaf.issued_at = originalIssuedAt - 86_400; // 하루 앞당긴다
  const forged = Buffer.from(JSON.stringify(leaf), "utf8");
  // leaf_hash 색인은 건드리지 않는다. 고치면 포함 증명 요청이 404 로 떠서 바로
  // 티가 난다. 색인을 그대로 두면 증명은 계속 나온다. 더 교활한 쪽이다.
  db.prepare("UPDATE leaves SET leaf_bytes = ? WHERE idx = 0").run(forged);
  db.close();
  step("운영자가 리프 0 의 발급 시각을 하루 앞당김", "DB 직접 수정, 색인은 그대로");
  step("바뀐 리프의 진짜 해시", `${`0x${leafHash(leaf as never).toString("hex")}`.slice(0, 18)}… (색인과 불일치)`);

  // 같은 크기로 트리를 다시 계산하면 다른 루트가 나온다.
  const root3After = s.store.rootAt(3);
  step("같은 크기 3 의 루트 재계산", root3After === root3 ? "그대로" : `달라짐 ${root3After.slice(0, 18)}…`);

  // 1) 체인 루트는 그대로다. 운영자는 과거 앵커를 못 고친다.
  const chainRoot3 = await s.chain.rootByTreeSize(3);
  step("체인에 박힌 size=3 루트", chainRoot3 === root3 ? "변화 없음" : "!!! 바뀜");

  // 2) 일관성 증명이 깨진다.
  const after = s.store.consistencyProof(3, 5);
  const okAfter = verifyConsistency(
    3,
    5,
    unhex(chainRoot3),
    unhex(await s.chain.rootByTreeSize(5)),
    after.path.map(unhex),
  );
  step("조작 후 일관성 증명", okAfter ? "!!! 통과 (설계 실패)" : "실패 — 역사 조작 탐지");

  // 3) 운영자가 새 루트를 앵커해도 소용없다. 컨트랙트가 같은 크기 재앵커를 막는다.
  let reanchor = "";
  try {
    await s.chain.submitRoot(root3After, 3);
    reanchor = "!!! 성공 (설계 실패)";
  } catch {
    reanchor = "거부 — treeSize 단조 증가 위반";
  }
  step("조작된 루트를 size=3 으로 재앵커 시도", reanchor);

  // 4) 요청자가 들고 있는 영수증으로 11단계를 다시 돌린다.
  const half = await fetch(`${s.base}/api/log/bundle?leaf_hash=${target.leaf_hash}`);
  if (half.ok) {
    const bundleAfter = assembleBundle({
      receipt: target,
      proofs: (await half.json()) as never,
      anchor: { chain_id: s.chainId, address: s.anchorAddress },
    });
    const r = await verifyReceipt({
      receipt: receiptOf(bundleAfter),
      domain: s.domain,
      chain: s.verifyChain,
      proofs: bundleProofSource(bundleAfter),
      now: () => s.clock.now,
    });
    step("조작 후 11단계 검증", r.ok ? "!!! 통과 (설계 실패)" : `${r.failedAt}단계에서 실패`);
    console.log();
    console.log(formatReport(r));
    console.log();
    console.log("  검증기는 리프 원문을 로그에서 받지 않는다. 요청자가 들고 있는 것을 쓴다.");
    console.log("  그래서 조작된 트리에서 뽑은 audit path 로는 체인의 루트가 재현되지 않는다.");
  } else {
    // 리프 해시가 바뀌었으므로 로그가 원본을 못 찾는다. 이것도 탐지다.
    step("조작 후 포함 증명 요청", `${half.status} — 로그가 원본 리프를 더 이상 갖고 있지 않다`);
  }
}

async function part2(s: Stack): Promise<void> {
  heading("2부 — 접수해놓고 트리에서 뺀 건은 책임이 갈린다");

  const dropped = await s.reject({ ...req(SANCTIONED, 2n), requester: s.requester.address });
  const ack = dropped.log_ack!;
  step("거절 1건 추가 접수", `편입 기한 ${ack.promised_by - ack.received_at}초 뒤`);

  // 운영자가 트리에서 뺀다. 접수 서명은 이미 요청자 손에 있다.
  const db = new DatabaseSync(s.storePath);
  db.prepare("DELETE FROM leaves WHERE leaf_hash = ?").run(unhex(dropped.leaf_hash));
  db.close();
  step("운영자가 그 리프를 DB 에서 삭제", "접수 서명은 회수할 수 없다");

  const res = await fetch(`${s.base}/api/log/bundle?leaf_hash=${dropped.leaf_hash}`);
  step("포함 증명 요청", `${res.status} — 증명이 나오지 않는다`);

  // 기한 전에는 아직 과실이 아니다. 트리 편입은 원래 비동기다.
  step("기한 전 책임 판정", assignFault(dropped, false, ack.promised_by - 1));
  // 기한이 지나면 서명된 약속을 어긴 것이다.
  step("기한 후 책임 판정", assignFault(dropped, false, ack.promised_by + 1));

  console.log();
  console.log("  접수 서명이 따로 있어서 게이트웨이가 제출을 안 한 경우와");
  console.log("  로그가 버린 경우가 갈린다. 이 구분이 완전성의 실체다.");
}

const dir = mkdtempSync(join(tmpdir(), "ocdl-demo2-"));
try {
  await withStack(
    async (s) => {
      console.log("\n데모 2 — 조작·삭제·누락 탐지 (불변성 · 완전성)");
      resetSteps();
      await part1(s);
      await part2(s);
      console.log();
    },
    { storePath: join(dir, "log.db") },
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}
