#!/usr/bin/env node
// 앵커링. 로그의 현재 트리 루트를 체인에 올린다.
//
//   node cli/anchor.ts --db ./log.db --anchor 0x... --rpc ... --operator-key 0x...
//   node cli/anchor.ts ... --watch 30      (30초마다 반복)
//
// 이 작업은 차단 경로 밖에 있다. 체인이 멈춰도 게이트웨이는 계속 판단한다.
import { createPublicClient, defineChain, http, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { LogStore } from "../lib/log-store.ts";
import { connectAnchor } from "../lib/chain.ts";
import { anchorOnce, reconcile, startAnchorJob } from "../lib/anchor-job.ts";
import { domain } from "../lib/sign.ts";

const arg = (k: string, d?: string): string => {
  const i = process.argv.indexOf(`--${k}`);
  const v = i >= 0 ? process.argv[i + 1] : process.env[`OCDL_${k.toUpperCase().replace(/-/g, "_")}`];
  if (v === undefined && d === undefined) throw new Error(`--${k} 가 필요하다`);
  return v ?? d!;
};

const rpc = arg("rpc", "http://127.0.0.1:8545");
const anchorAddr = arg("anchor") as Address;
const operator = privateKeyToAccount(arg("operator-key") as Hex);
const client = createPublicClient({ transport: http(rpc) });
const chainId = await client.getChainId();
const chain = defineChain({
  id: chainId, name: `chain-${chainId}`,
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [rpc] } },
});

const store = new LogStore({
  path: arg("db"), domain: domain(chainId, anchorAddr), operator,
  isRegistered: async () => true, // 앵커링은 접수를 하지 않는다
});
const anchorChain = connectAnchor({ rpcUrl: rpc, chain, address: anchorAddr, operator });

// 프로세스가 submitRoot 직후에 죽었으면 체인이 로컬보다 앞서 있다. 먼저 메운다.
const rec = await reconcile({ store, chain: anchorChain });
if (rec.anchored) console.log(`복구  size=${rec.treeSize} 를 로컬에 기록`);

const show = (r: Awaited<ReturnType<typeof anchorOnce>>) => {
  if (r.anchored) console.log(`앵커  size=${r.treeSize}  root=${r.root?.slice(0, 20)}…  tx=${r.txHash?.slice(0, 20)}…`);
  else console.log(`건너뜀  ${r.reason}`);
};

const watch = process.argv.indexOf("--watch");
if (watch >= 0) {
  const sec = Number(process.argv[watch + 1] ?? "30");
  console.log(`${sec}초마다 앵커한다. Ctrl-C 로 멈춤.`);
  const job = startAnchorJob({ store, chain: anchorChain, intervalMs: sec * 1000,
    onResult: show, onError: (e) => console.error(`앵커 실패: ${e}`) });
  process.on("SIGINT", () => { job.stop(); store.close(); process.exit(0); });
} else {
  show(await anchorOnce({ store, chain: anchorChain }));
  store.close();
}
