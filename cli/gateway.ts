#!/usr/bin/env node
// 게이트웨이. 요청 하나를 판단하고 거절이면 번들을 파일로 쓴다.
//
//   node cli/gateway.ts publish-list --anchor 0x... --rpc ... --gateway-key 0x...
//   node cli/gateway.ts reject  --target 0x... --value ... --out receipt.json
//                              [--rule MANUAL_REVIEW_HOLD]
//   node cli/gateway.ts bundle  --receipt receipt.json --out bundle.json --wait 120
//
// 순서가 셋인 이유가 있다.
//
// publish-list 가 먼저다. 참조 목록을 판단보다 먼저 공표해야 검증 9단계가 통과한다.
//
// reject 와 bundle 이 나뉜 것은 앵커가 주기적이기 때문이다. 거절 직후에는 그 리프를
// 덮는 앵커가 아직 없어서 포함 증명이 안 나온다. 요청자는 영수증을 먼저 받아두고
// 앵커가 올라간 뒤에 번들을 굳힌다. 로그가 서명한 편입 기한이 그 대기 시간의 상한이고,
// bundle --wait 가 그때까지 폴링한다.
import { readFileSync, writeFileSync } from "node:fs";
import { createPublicClient, defineChain, http, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Gateway } from "../sdk/gateway.ts";
import { DEMO_POLICY } from "../sdk/demo-policy.ts";
import { domain, signRequestIntent, type RequestIntent } from "../lib/sign.ts";
import { rootOfList } from "../lib/sorted-merkle.ts";
import { assembleBundle, serializeBundle, describeBundle } from "../lib/bundle.ts";
import { randomBytes } from "node:crypto";
import { arg, installErrorHandler } from "./args.ts";

installErrorHandler();

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
const sets = DEMO_POLICY.data_sets ?? {};
// 목록마다 루트가 다르다. 거절 레코드는 자기 사유가 인용하는 목록의 루트를 커밋한다.
const roots = Object.fromEntries(
  Object.entries(sets).map(([name, values]) => [name, rootOfList(values) as Hex]),
);

const g = new Gateway({
  account: gwKey, domain: D, policy: DEMO_POLICY,
  policyDataRoot: roots.allowedTargets, policyDataRoots: roots, logUrl,
});

if (cmd === "publish-list") {
  // 정책이 참조하는 목록을 전부 공표한다. 하나만 올리면 다른 목록을 인용한 거절이
  // 검증 9단계에서 실패한다.
  const out: Record<string, unknown> = {};
  for (const [name, values] of Object.entries(sets)) {
    const r = await g.publishPolicyData(values, name);
    out[name] = r;
    console.log(`목록 공표  ${name}  ${values.length}건`);
    console.log(`  루트     ${roots[name]}`);
    console.log(`  리프     ${r.leaf_hash}`);
    console.log(`  접수     ${r.log_ack ? "확인됨" : "실패"}`);
  }
  // 영수증을 파일로 남긴다. 나중에 bundle 명령이 이 리프의 포함 증명을 붙여야
  // 검증 9단계가 "목록이 판단보다 먼저 공표됐다" 를 확인할 수 있다.
  const path = arg("out", "policy-update.json");
  writeFileSync(path, JSON.stringify(out, null, 2));
  console.log(`  영수증   ${path}`);
  process.exit(0);
}

// ---------- bundle ----------
if (cmd === "bundle") {
  const receipt = JSON.parse(readFileSync(arg("receipt"), "utf8"));

  // 앵커는 주기적이라 거절 직후에는 증명이 없다. 로그는 409 를 돌려준다.
  // --wait 초를 주면 앵커가 이 리프를 덮을 때까지 기다린다. 409 말고 다른
  // 상태는 기다려도 안 바뀌므로 즉시 던진다.
  const waitMs = Number(arg("wait", "0")) * 1000;
  const proofHalf = async (leafHash: string): Promise<unknown> => {
    const deadline = Date.now() + waitMs;
    let waited = false;
    for (;;) {
      const r = await fetch(`${logUrl}/api/log/bundle?leaf_hash=${leafHash}`);
      if (r.ok) {
        if (waited) process.stdout.write("\n");
        return await r.json();
      }
      const body = await r.text();
      if (r.status !== 409 || Date.now() >= deadline) {
        if (waited) process.stdout.write("\n");
        throw new Error(`${r.status} ${body}`);
      }
      waited = true;
      process.stdout.write(`\r앵커 대기  ${Math.ceil((deadline - Date.now()) / 1000)}초 남음 `);
      await new Promise((f) => setTimeout(f, 2000));
    }
  };

  let half;
  try {
    half = await proofHalf(receipt.leaf_hash);
  } catch (e) {
    const msg = (e as Error).message;
    console.error(`증명을 받지 못했다: ${msg}`);
    // 404 는 기다려도 안 바뀐다. 로그가 이 리프를 받은 적이 없다는 뜻이다.
    console.error(
      msg.startsWith("404")
        ? "로그가 이 리프를 받은 적이 없다. 거절 당시 제출이 실패했는지 영수증의 log_ack 를 봐라."
        : "이 리프를 덮는 앵커가 아직 없다. cli/anchor.ts 를 돌리거나 --wait 를 주고 다시 시도.",
    );
    process.exit(1);
  }
  // 요청자가 실제로 기다린 시간. 로그가 서명한 편입 기한이 이 값의 상한이다.
  if (receipt.log_ack) {
    const actual = Math.floor(Date.now() / 1000) - receipt.log_ack.received_at;
    const bound = receipt.log_ack.promised_by - receipt.log_ack.received_at;
    console.log(`편입까지 ${actual}초  (로그가 서명한 상한 ${bound}초)`);
  }

  // 목록 갱신 레코드의 포함 증명도 같이 싣는다. 없으면 9단계가 판정 불가가 된다.
  // 거절보다 먼저 들어간 리프라 거절이 앵커됐으면 이쪽도 이미 앵커돼 있다.
  //
  // 정책에 목록이 여럿이면 갱신 레코드도 여럿이다. 이 거절이 커밋한 루트와 같은
  // 루트를 공표한 레코드를 고른다. 다른 목록의 갱신을 실으면 9단계에서 걸린다.
  let policyUpdate;
  const updPath = arg("policy-update", "policy-update.json");
  try {
    const file = JSON.parse(readFileSync(updPath, "utf8"));
    const all = file.leaf_hash ? [file] : Object.values(file);
    const want = (receipt.leaf.policy_data_root as string).toLowerCase();
    const upd = (all as { leaf: { policy_data_root: string }; leaf_hash: string }[]).find(
      (u) => u.leaf.policy_data_root.toLowerCase() === want,
    );
    if (!upd) throw new Error(`루트 ${want} 를 공표한 갱신 레코드가 ${updPath} 에 없다`);
    const p = (await proofHalf(upd.leaf_hash)) as { inclusion_proof: unknown };
    policyUpdate = { leaf: upd.leaf, leaf_hash: upd.leaf_hash, inclusion_proof: p.inclusion_proof };
  } catch (e) {
    console.error(`목록 갱신 증명을 못 실었다 (${(e as Error).message}). 9단계가 판정 불가가 된다.`);
  }

  const bundle = assembleBundle({
    receipt,
    proofs: half as never,
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

// --rule 은 evaluate 를 건너뛰고 지정한 규칙으로 거절한다. 술어로 표현되지 않는
// 사유(재량, 외부 데이터)를 내거나, 기존 심사 엔진의 판단을 그대로 실어보낼 때 쓴다.
const forced = arg("rule", "");
const forceRule = forced ? DEMO_POLICY.rules.find((x) => x.rule_id === forced) : undefined;
if (forced && !forceRule) {
  console.error(`규칙 ${forced} 가 정책에 없다`);
  process.exit(2);
}

const r = await g.handle({
  request: { requester: requester.address, target, value, calldata: "0x" as Hex },
  intent, intentSig, forceRule,
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
console.log("\n앵커가 이 리프를 덮으면 번들이 나온다. bundle --wait 로 기다릴 수 있다.");
