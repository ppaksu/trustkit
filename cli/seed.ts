#!/usr/bin/env node
// 시연용 대량 로그를 미리 만든다.
//
//   node cli/seed.ts --count 20000 --anchor 0x... --rpc ... --gateway-key 0x... --log ...
//
// 서명이 대부분이라 2만 건에 30초쯤 걸린다. 시연 중에 만들면 안 되고 미리 돌려둔다.
// 로그가 클수록 시연이 산다. 리프가 4배여도 증명은 1.0KB 에서 1.2KB 다.
import { createPublicClient, http, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Gateway } from "../sdk/gateway.ts";
import { DEMO_POLICY } from "../sdk/demo-policy.ts";
import { domain } from "../lib/sign.ts";
import { rootOfList } from "../lib/sorted-merkle.ts";

const arg = (k: string, d?: string): string => {
  const i = process.argv.indexOf(`--${k}`);
  const v = i >= 0 ? process.argv[i + 1] : process.env[`OCDL_${k.toUpperCase().replace(/-/g, "_")}`];
  if (v === undefined && d === undefined) throw new Error(`--${k} 가 필요하다`);
  return v ?? d!;
};

const rpc = arg("rpc", "http://127.0.0.1:8545");
const anchorAddr = arg("anchor") as Address;
const logUrl = arg("log", "http://127.0.0.1:8787");
const count = Number(arg("count", "20000"));
const gwKey = privateKeyToAccount(arg("gateway-key") as Hex);

const chainId = await createPublicClient({ transport: http(rpc) }).getChainId();
const list = DEMO_POLICY.data_sets!.allowedTargets;
const g = new Gateway({
  account: gwKey, domain: domain(chainId, anchorAddr), policy: DEMO_POLICY,
  policyDataRoot: rootOfList(list) as Hex, logUrl,
});

// 목록 공표가 먼저다. 이게 없으면 검증 9단계가 판정 불가가 된다.
const upd = await g.publishPolicyData(list);
const updOut = arg("policy-update-out", "policy-update.json");
(await import("node:fs")).writeFileSync(updOut, JSON.stringify(upd, null, 2));
console.log(`목록 공표 완료  ${list.length}건  영수증 ${updOut}`);

const addr = (n: number) => `0x${n.toString(16).padStart(40, "0")}` as Address;
const t0 = Date.now();
let failed = 0;
for (let i = 0; i < count; i++) {
  const r = await g.handle({
    request: { requester: addr(i + 1), target: addr(0xcafe0000 + i), value: BigInt(i + 1), calldata: "0x" as Hex },
  });
  if (r.submitError) failed++;
  if ((i + 1) % 1000 === 0) {
    const rate = (i + 1) / ((Date.now() - t0) / 1000);
    process.stdout.write(`\r  ${i + 1}/${count}  ${rate.toFixed(0)}건/초  실패 ${failed}`);
  }
}
console.log(`\n적재 완료  ${count}건  ${((Date.now() - t0) / 1000).toFixed(1)}초  실패 ${failed}`);
