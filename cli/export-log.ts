#!/usr/bin/env node
// 로그를 공개 가능한 파일로 내보낸다.
//
//   node cli/export-log.ts --db ./log.db --out ./public-log
//
// 운영 키를 받지 않는다. sqlite 를 읽기만 하므로 서명 키를 쥔 프로세스와 분리해서
// 돌릴 수 있다.
//
// 리프에는 원문이 없다. 필드는 난수를 섞어 해시한 커밋만 들어 있고, 원문은 요청자
// 번들에만 있다. 공개되는 것은 게이트웨이 주소, 정책 해시, 발급 시각, 커밋 값이다.
// 거절이 언제 몇 건 있었는지는 드러난다. 투명성 로그라 그게 목적이다.
import { DatabaseSync } from "node:sqlite";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { arg, installErrorHandler } from "./args.ts";

installErrorHandler();

const out = arg("out", "./public-log");
const db = new DatabaseSync(arg("db"));
mkdirSync(out, { recursive: true });

const leaves = db
  .prepare("SELECT idx, leaf_bytes FROM leaves ORDER BY idx")
  .all() as { idx: number; leaf_bytes: Uint8Array }[];

// 인덱스가 곧 트리 위치다. 구멍이 있으면 감사자가 루트를 못 맞춘다.
for (let i = 0; i < leaves.length; i++) {
  if (leaves[i].idx !== i) {
    console.error(`인덱스 ${i} 자리에 ${leaves[i].idx} 가 있다. 리프가 빠졌다.`);
    process.exit(1);
  }
}

// JSON 배열 하나로 묶으면 큰 로그에서 통째로 파싱해야 한다. 한 줄에 리프 하나.
const jsonl = leaves.map((r) => Buffer.from(r.leaf_bytes).toString("utf8")).join("\n");
writeFileSync(join(out, "leaves.jsonl"), jsonl + (jsonl ? "\n" : ""));

const anchors = db
  .prepare("SELECT tree_size, root, tx_hash, anchored_at FROM anchors ORDER BY tree_size")
  .all() as { tree_size: number; root: Uint8Array; tx_hash: string | null; anchored_at: number }[];

writeFileSync(
  join(out, "anchors.json"),
  JSON.stringify(
    anchors.map((a) => ({
      tree_size: a.tree_size,
      root: `0x${Buffer.from(a.root).toString("hex")}`,
      tx_hash: a.tx_hash,
      anchored_at: a.anchored_at,
    })),
    null,
    2,
  ) + "\n",
);
db.close();

console.log(`내보냄  ${out}`);
console.log(`  리프   ${leaves.length.toLocaleString()}건  leaves.jsonl`);
console.log(`  앵커   ${anchors.length}건  anchors.json`);
console.log("\n감사: node cli/audit-log.ts --dir <경로> --anchor 0x… --rpc <URL>");
