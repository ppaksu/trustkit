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
import { DEMO_POLICY, SANCTIONED, KNOWN_TARGET } from "../sdk/demo-policy.ts";
import { domain } from "../lib/sign.ts";
import { rootOfList } from "../lib/sorted-merkle.ts";
import { arg, installErrorHandler } from "./args.ts";

installErrorHandler();

const rpc = arg("rpc", "http://127.0.0.1:8545");
const anchorAddr = arg("anchor") as Address;
const logUrl = arg("log", "http://127.0.0.1:8787");
const count = Number(arg("count", "20000"));
const gwKey = privateKeyToAccount(arg("gateway-key") as Hex);

const chainId = await createPublicClient({ transport: http(rpc) }).getChainId();
const sets = DEMO_POLICY.data_sets ?? {};
const g = new Gateway({
  account: gwKey, domain: domain(chainId, anchorAddr), policy: DEMO_POLICY,
  policyDataRoot: rootOfList(sets.allowedTargets) as Hex, logUrl,
});

// 목록 공표가 먼저다. 이게 없으면 검증 9단계가 판정 불가가 된다.
// 정책이 참조하는 목록을 전부 올린다. 사유마다 인용하는 목록이 다르다.
const updates: Record<string, unknown> = {};
for (const [name, values] of Object.entries(sets)) {
  updates[name] = await g.publishPolicyData(values, name);
}
const updOut = arg("policy-update-out", "policy-update.json");
(await import("node:fs")).writeFileSync(updOut, JSON.stringify(updates, null, 2));
console.log(`목록 공표 완료  ${Object.keys(sets).length}종  영수증 ${updOut}`);

const addr = (n: number) => `0x${n.toString(16).padStart(40, "0")}` as Address;
const mix = process.argv.includes("--mix");
const byId = (id: string) => DEMO_POLICY.rules.find((r) => r.rule_id === id)!;

/**
 * --mix 는 사유를 섞는다. 전부 같은 규칙인 로그는 재량 사유 비율 같은 걸 볼 수
 * 없어서 공개 데이터로는 쓸모가 적다. 술어가 없는 두 규칙은 evaluate 가 평가하지
 * 못하므로 forceRule 로 넘긴다. 기존 심사 엔진이 판단한 경우와 같은 경로다.
 */
function request(i: number) {
  if (!mix) {
    return { req: { requester: addr(i + 1), target: addr(0xcafe0000 + i), value: BigInt(i + 1), calldata: "0x" as Hex } };
  }
  const requester = addr(i + 1);
  switch (i % 8) {
    case 0:
    case 4:
      return { req: { requester, target: SANCTIONED as Address, value: 1n, calldata: "0x" as Hex } };
    case 1:
    case 5:
      return { req: { requester, target: KNOWN_TARGET as Address, value: 5_000_000_000_000_000_000n, calldata: "0x" as Hex } };
    case 2:
    case 6:
      return { req: { requester, target: addr(0xcafe0000 + i), value: 1n, calldata: "0x" as Hex } };
    case 3:
      return {
        req: { requester, target: KNOWN_TARGET as Address, value: 1n, calldata: "0x" as Hex },
        forceRule: byId("MANUAL_REVIEW_HOLD"),
      };
    default:
      return {
        req: { requester, target: KNOWN_TARGET as Address, value: 1n, calldata: "0x" as Hex },
        forceRule: byId("SANCTIONS_SCREENING_HIT"),
      };
  }
}
const t0 = Date.now();
let failed = 0;
for (let i = 0; i < count; i++) {
  const { req, forceRule } = request(i);
  const r = await g.handle({ request: req, forceRule });
  if (r.submitError) failed++;
  if ((i + 1) % 1000 === 0) {
    const rate = (i + 1) / ((Date.now() - t0) / 1000);
    process.stdout.write(`\r  ${i + 1}/${count}  ${rate.toFixed(0)}건/초  실패 ${failed}`);
  }
}
console.log(`\n적재 완료  ${count}건  ${((Date.now() - t0) / 1000).toFixed(1)}초  실패 ${failed}`);
