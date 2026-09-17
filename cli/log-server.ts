#!/usr/bin/env node
// 로그 서버를 띄운다.
//
//   node cli/log-server.ts --db ./log.db --port 8787 \
//     --anchor 0x... --rpc http://127.0.0.1:8545 --operator-key 0x...
//
// 운영자 키로 접수 확인에 서명한다. 그 키는 컨트랙트에 박힌 logOperator 와 같아야 한다.
import { createPublicClient, defineChain, http, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { LogStore } from "../lib/log-store.ts";
import { createLogServer } from "../lib/log-server.ts";
import { LOG_ANCHOR_ABI } from "../lib/chain.ts";
import { domain } from "../lib/sign.ts";
import { arg, installErrorHandler } from "./args.ts";

installErrorHandler();

const rpc = arg("rpc", "http://127.0.0.1:8545");
const anchor = arg("anchor") as Address;
const port = Number(arg("port", "8787"));
const dbPath = arg("db", ":memory:");
const operator = privateKeyToAccount(arg("operator-key") as Hex);

const client = createPublicClient({ transport: http(rpc) });
const chainId = await client.getChainId();
const chain = defineChain({
  id: chainId, name: `chain-${chainId}`,
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [rpc] } },
});

// 컨트랙트가 아는 운영자와 우리 키가 같은지 먼저 본다. 다르면 발급한 접수 확인이
// 전부 검증에 실패하는데, 그 사실을 몇 시간 뒤에야 알게 된다.
const onchain = (await client.readContract({
  address: anchor, abi: LOG_ANCHOR_ABI, functionName: "logOperator",
})) as Address;
if (onchain.toLowerCase() !== operator.address.toLowerCase()) {
  throw new Error(`컨트랙트의 logOperator 는 ${onchain} 인데 우리 키는 ${operator.address} 다`);
}

const store = new LogStore({
  path: dbPath,
  domain: domain(chainId, anchor),
  operator,
  isRegistered: (gw) =>
    client.readContract({ address: anchor, abi: LOG_ANCHOR_ABI, functionName: "gateways", args: [gw] }) as Promise<boolean>,
  maxMergeDelaySec: Number(arg("merge-delay", "3600")),
});

const server = createLogServer(store);
server.listen(port, "127.0.0.1", () => {
  console.log(`로그 서버  http://127.0.0.1:${port}`);
  console.log(`  체인      ${chainId} @ ${rpc}`);
  console.log(`  앵커      ${anchor}`);
  console.log(`  운영자    ${operator.address}`);
  console.log(`  저장소    ${dbPath}  (현재 리프 ${store.size()}개)`);
  console.log(`  편입 기한 ${arg("merge-delay", "3600")}초`);
});

const shutdown = () => {
  console.log("\n로그 서버 종료");
  server.close();
  store.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
