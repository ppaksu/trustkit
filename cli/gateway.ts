#!/usr/bin/env node
// 게이트웨이. 요청 하나를 판단하고 거절이면 번들을 파일로 쓴다.
//
//   node cli/gateway.ts publish-list --anchor 0x... --rpc ... --gateway-key 0x...
//   node cli/gateway.ts reject  --target 0x... --value ... --out receipt.json
//   node cli/gateway.ts bundle  --receipt receipt.json --out bundle.json
//
// 순서가 셋인 이유가 있다.
//
// publish-list 가 먼저다. 참조 목록을 판단보다 먼저 공표해야 검증 9단계가 통과한다.
//
// reject 와 bundle 이 나뉜 것은 앵커가 주기적이기 때문이다. 거절 직후에는 그 리프를
// 덮는 앵커가 아직 없어서 포함 증명이 안 나온다. 요청자는 영수증을 먼저 받아두고
// 앵커가 올라간 뒤에 번들을 굳힌다. 로그가 서명한 편입 기한이 그 대기 시간의 상한이다.
import { readFileSync, writeFileSync } from "node:fs";
import { createPublicClient, defineChain, http, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Gateway } from "../sdk/gateway.ts";
import { DEMO_POLICY } from "../sdk/demo-policy.ts";
import { domain, signRequestIntent, type RequestIntent } from "../lib/sign.ts";
import { rootOfList } from "../lib/sorted-merkle.ts";
import { assembleBundle, serializeBundle, describeBundle } from "../lib/bundle.ts";
import { randomBytes } from "node:crypto";

const arg = (k: string, d?: string): string => {
  const i = process.argv.indexOf(`--${k}`);
  const v = i >= 0 ? process.argv[i + 1] : process.env[`OCDL_${k.toUpperCase().replace(/-/g, "_")}`];
  if (v === undefined && d === undefined) throw new Error(`--${k} 가 필요하다`);
  return v ?? d!;
};

const cmd = process.argv[2];
if (cmd !== "reject" && cmd !== "publish-list" && cmd !== "bundle") {
  console.error("사용법: node cli/gateway.ts <publish-list|reject|bundle> [옵션]");
  process.exit(2);
}

const rpc = arg("rpc", "http://127.0.0.1:8545");
const anchorAddr = arg("anchor") as Address;
const logUrl = arg("log", "http://127.0.0.1:8787");
const gwKey = privateKeyToAccount(arg("gateway-key") as Hex);

const client = createPublicClient({ transport: http(rpc) });
const chainId = await client.getChainId();
const D = domain(chainId, anchorAddr);
const list = DEMO_POLICY.data_sets!.allowedTargets;

const g = new Gateway({
  account: gwKey, domain: D, policy: DEMO_POLICY,
  policyDataRoot: rootOfList(list) as Hex, logUrl,
});

if (cmd === "publish-list") {
  const r = await g.publishPolicyData(list);
  // 영수증을 파일로 남긴다. 나중에 bundle 명령이 이 리프의 포함 증명을 붙여야
  // 검증 9단계가 "목록이 판단보다 먼저 공표됐다" 를 확인할 수 있다.
  const path = arg("out", "policy-update.json");
  writeFileSync(path, JSON.stringify(r, null, 2));
  console.log(`목록 공표  ${list.length}건`);
  console.log(`  루트     ${rootOfList(list)}`);
  console.log(`  리프     ${r.leaf_hash}`);
  console.log(`  접수     ${r.log_ack ? "확인됨" : "실패"}`);
  console.log(`  영수증   ${path}`);
  process.exit(0);
}

// ---------- bundle ----------
if (cmd === "bundle") {
  const receipt = JSON.parse(readFileSync(arg("receipt"), "utf8"));
  const half = await fetch(`${logUrl}/api/log/bundle?leaf_hash=${receipt.leaf_hash}`);
  if (!half.ok) {
    console.error(`증명을 받지 못했다: ${half.status} ${await half.text()}`);
    console.error("이 리프를 덮는 앵커가 아직 없다. cli/anchor.ts 를 돌린 뒤 다시 시도.");
    process.exit(1);
  }
  // 목록 갱신 레코드의 포함 증명도 같이 싣는다. 없으면 9단계가 판정 불가가 된다.
  let policyUpdate;
  const updPath = arg("policy-update", "policy-update.json");
  try {
    const upd = JSON.parse(readFileSync(updPath, "utf8"));
    const p = await fetch(`${logUrl}/api/log/bundle?leaf_hash=${upd.leaf_hash}`);
    if (p.ok) {
      policyUpdate = {
        leaf: upd.leaf,
        leaf_hash: upd.leaf_hash,
        inclusion_proof: ((await p.json()) as { inclusion_proof: unknown }).inclusion_proof,
      };
    } else {
      console.error(`목록 갱신 증명을 못 받았다 (${p.status}). 9단계가 판정 불가가 된다.`);
    }
  } catch {
    console.error(`${updPath} 이 없다. publish-list 를 먼저 돌려야 9단계가 통과한다.`);
  }

  const bundle = assembleBundle({
    receipt,
    proofs: (await half.json()) as never,
    anchor: { chain_id: chainId, address: anchorAddr },
    policy: DEMO_POLICY,
    policyUpdate: policyUpdate as never,
    discloseKeys: arg("disclose", "rule_id,severity,value,verifiability").split(","),
  });
  const out = arg("out", "bundle.json");
  writeFileSync(out, serializeBundle(bundle));
  console.log(describeBundle(bundle));
  console.log(`\n번들 저장  ${out}  (${serializeBundle(bundle).length.toLocaleString()} 바이트)`);
  console.log("이 파일 하나와 공개 RPC 만으로 검증이 끝난다. 로그 서버는 필요 없다.");
  process.exit(0);
}

// ---------- reject ----------
const target = arg("target", "0x000000000000000000000000000000000000cafe") as Address;
const value = BigInt(arg("value", "1"));
const out = arg("out", "receipt.json");
const requester = privateKeyToAccount(arg("requester-key") as Hex);

const intent: RequestIntent = {
  requester: requester.address, gateway: gwKey.address, target,
  value: value.toString(),
  calldata_hash: `0x${randomBytes(32).toString("hex")}` as Hex,
  issued_at: Math.floor(Date.now() / 1000),
  nonce: `0x${randomBytes(32).toString("hex")}` as Hex,
};
const intentSig = await signRequestIntent(intent, requester, D);

const r = await g.handle({
  request: { requester: requester.address, target, value, calldata: "0x" as Hex },
  intent, intentSig,
});
if (r.decision.allow) {
  console.log("통과. 이 로그는 거절만 기록한다.");
  process.exit(0);
}
const receipt = r.receipt!;
if (r.submitError) {
  console.error(`로그 제출 실패: ${r.submitError}`);
  console.error("레코드는 유효하다. 나중에 책임 분리로 드러난다.");
}
writeFileSync(out, JSON.stringify(receipt, null, 2));

console.log(`거절  사유 ${r.decision.rule.rule_id}  심각도 ${r.decision.rule.severity}`);
console.log(`  리프      ${receipt.leaf_hash}`);
console.log(`  접수 확인 ${receipt.log_ack ? "받음" : "없음"}`);
if (receipt.log_ack) {
  const wait = receipt.log_ack.promised_by - receipt.log_ack.received_at;
  console.log(`  편입 기한 ${wait}초 안에 트리에 넣겠다는 로그의 서명된 약속`);
}
console.log(`  영수증    ${out}`);
console.log("\n앵커가 이 리프를 덮은 뒤 bundle 명령으로 번들을 굳힌다.");
