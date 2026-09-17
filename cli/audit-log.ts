#!/usr/bin/env node
// 공개된 로그 전체를 감사한다. 로그 서버를 부르지 않는다.
//
//   node cli/audit-log.ts --dir ./public-log --anchor 0x… --rpc http://127.0.0.1:8545
//   node cli/audit-log.ts --leaves /경로/leaves.jsonl --anchors /경로/anchors.json …
//
// 거절 한 건을 확인하는 건 cli/verify-rejection.ts 의 몫이다. 이쪽은 반대로 로그
// 전체가 정직한지 본다. 리프를 전부 받아 루트를 직접 계산하고 체인에 박힌 값과
// 맞춰본다. 증명을 받아 검증하는 게 아니라 트리를 처음부터 다시 만든다.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createPublicClient, defineChain, http, type Address, type Hex } from "viem";
import { canonicalBytes, type JsonValue } from "../lib/jcs.ts";
import { mth } from "../lib/merkle.ts";
import { domain, verifyLeafSignature } from "../lib/sign.ts";
import { connectAnchor } from "../lib/chain.ts";
import type { Leaf } from "../lib/record.ts";
import { arg, installErrorHandler } from "./args.ts";

installErrorHandler();

const dir = arg("dir", "./public-log");
const rpc = arg("rpc", "http://127.0.0.1:8545");
const anchorAddr = arg("anchor") as Address;
// --dir 는 두 파일이 기본 이름으로 나란히 있을 때의 축약이다. 위치나 이름이
// 다르면 --leaves 와 --anchors 로 각각 지정한다.
const leavesPath = arg("leaves", join(dir, "leaves.jsonl"));
const anchorsPath = arg("anchors", join(dir, "anchors.json"));

const lines = readFileSync(leavesPath, "utf8").split("\n").filter((l) => l.length > 0);
const anchors = JSON.parse(readFileSync(anchorsPath, "utf8")) as {
  tree_size: number;
  root: Hex;
  tx_hash: string | null;
  anchored_at: number;
}[];

const client = createPublicClient({ transport: http(rpc) });
const chainId = await client.getChainId();
const chain = defineChain({
  id: chainId,
  name: `chain-${chainId}`,
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [rpc] } },
});
const onchain = connectAnchor({ rpcUrl: rpc, chain, address: anchorAddr });
const D = domain(chainId, anchorAddr);

let failed = 0;
// 진행 표시를 \r 로 덮어쓰기 때문에 결과 줄을 그냥 찍으면 다음 진행 표시가
// 그 위를 지운다. 먼저 그 줄을 비우고 찍는다.
const line = (m: string): void => console.log(`\r${" ".repeat(30)}\r${m}`);
const fail = (m: string): void => {
  line(`  실패  ${m}`);
  failed++;
};
const pass = (m: string): void => line(`  통과  ${m}`);

console.log(`\n로그 전체 감사  리프 ${lines.length.toLocaleString()}건  앵커 ${anchors.length}건\n`);

// 저장된 바이트가 곧 트리의 리프다. JCS 를 다시 돌려 정규형인지도 같이 본다.
const data: Buffer[] = [];
const leaves: Leaf[] = [];
for (let i = 0; i < lines.length; i++) {
  const leaf = JSON.parse(lines[i]) as Leaf;
  const canon = canonicalBytes(leaf as unknown as JsonValue);
  if (canon.toString("utf8") !== lines[i]) {
    fail(`리프 ${i} 가 JCS 정규형이 아니다`);
  }
  leaves.push(leaf);
  data.push(canon);
}
if (failed === 0) pass("모든 리프가 JCS 정규형");

// 리프마다 발급자 서명을 복원하고 그 주소가 온체인 레지스트리에 있는지 본다.
// 등록 조회는 주소당 한 번만 한다.
const registered = new Map<string, boolean>();
let badSig = 0;
let unregistered = 0;
for (let i = 0; i < leaves.length; i++) {
  if (!(await verifyLeafSignature(leaves[i], D))) {
    if (badSig === 0) fail(`리프 ${i} 의 서명이 gateway 로 복원되지 않는다`);
    badSig++;
  }
  const gw = leaves[i].gateway.toLowerCase();
  if (!registered.has(gw)) registered.set(gw, await onchain.isRegistered(gw as Address));
  if (!registered.get(gw)) {
    if (unregistered === 0) fail(`리프 ${i} 의 발급자 ${gw} 가 등록되지 않았다`);
    unregistered++;
  }
  if (i > 0 && i % 2000 === 0) process.stdout.write(`\r  리프 검사 ${i.toLocaleString()}…`);
}
if (lines.length > 2000) process.stdout.write("\r".padEnd(30) + "\r");
if (badSig === 0 && unregistered === 0) {
  pass(`리프 ${lines.length.toLocaleString()}건 전부 등록된 게이트웨이의 서명`);
} else {
  if (badSig > 1) line(`        서명 불일치 ${badSig}건`);
  if (unregistered > 1) line(`        미등록 발급자 ${unregistered}건`);
}

// 앵커마다 그 크기까지의 루트를 직접 계산해 체인 값과 맞춘다. anchors.json 의
// 루트는 참고용이다. 기준은 언제나 체인이다.
//
// 앵커 사이 일관성 증명은 돌리지 않는다. 같은 리프 배열의 접두사로 두 루트를
// 모두 재계산했으므로 덧붙이기만 했다는 게 이미 증명돼 있다. 증명은 리프를
// 갖지 못한 쪽이 쓰는 도구다.
for (const a of anchors) {
  if (a.tree_size > data.length) {
    fail(`앵커 크기 ${a.tree_size} 인데 공개된 리프는 ${data.length}건뿐이다`);
    continue;
  }
  const local = `0x${mth(data.slice(0, a.tree_size)).toString("hex")}`;
  const chainRoot = (await onchain.rootByTreeSize(a.tree_size)).toLowerCase();
  if (chainRoot === `0x${"00".repeat(32)}`) {
    fail(`크기 ${a.tree_size} 가 체인에 앵커되지 않았다`);
  } else if (local !== chainRoot) {
    fail(`크기 ${a.tree_size} 의 루트가 체인과 다르다: ${local} != ${chainRoot}`);
  } else if (local !== a.root.toLowerCase()) {
    fail(`크기 ${a.tree_size} 의 anchors.json 루트가 틀렸다`);
  } else {
    // 로컬은 앵커를 기록할 때의 시각을, 체인은 블록 시각을 쓴다. 몇 초 차이는
    // 정상이다. 분 단위로 벌어지면 기록을 나중에 손본 것이다.
    const at = await onchain.anchoredAt(a.tree_size);
    const gap = at > 0 ? Math.abs(at - a.anchored_at) : 0;
    const drift = gap > 60 ? `  (기록 ${a.anchored_at} vs 체인 ${at}, ${gap}초 차)` : "";
    pass(`크기 ${a.tree_size} 루트가 체인과 일치${drift}`);
  }
}

const last = anchors.length > 0 ? anchors[anchors.length - 1].tree_size : 0;
if (data.length > last) {
  console.log(`\n  ${data.length - last}건이 아직 앵커되지 않았다. 이 구간은 판정하지 않는다.`);
}

console.log(failed === 0 ? "\n감사 통과. 조작 흔적 없음.\n" : `\n${failed}건 실패.\n`);
process.exit(failed === 0 ? 0 : 1);
