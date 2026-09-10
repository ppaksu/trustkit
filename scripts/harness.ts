// 시연 공용 발판. anvil 기동, 컨트랙트 배포, 로그 서버와 게이트키퍼 연결.
// e2e 와 공격 3종이 모두 이 파일을 쓴다.
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { createPublicClient, createWalletClient, http, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";

import { domain } from "../lib/sign.ts";
import { LogStore } from "../lib/log-store.ts";
import { createLogServer } from "../lib/log-server.ts";
import { connectAnchor, LOG_ANCHOR_ABI } from "../lib/chain.ts";
import { Gatekeeper } from "../sdk/gatekeeper.ts";
import { DEMO_POLICY } from "../sdk/demo-policy.ts";
import type { ProofSource, VerifyChain } from "../lib/verify.ts";

// anvil 기본 계정. 로컬 전용 키이며 실제 자금과 무관하다.
const OWNER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const OPERATOR_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const GATEKEEPER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;
const ARTIFACT = "contracts/out/LogAnchor.sol/LogAnchor.json";

export interface Stack {
  rpc: string;
  base: string;
  anchorAddress: Address;
  domain: ReturnType<typeof domain>;
  store: LogStore;
  chain: ReturnType<typeof connectAnchor>;
  gatekeeper: Gatekeeper;
  verifyChain: VerifyChain;
  proofs: ProofSource;
  clock: { now: number };
}

let stepNo = 0;
export function step(msg: string, detail = ""): void {
  console.log(`  ${String(++stepNo).padStart(2, "0")}  ${msg}${detail ? `  ${detail}` : ""}`);
}
export function resetSteps(): void {
  stepNo = 0;
}
export function heading(title: string): void {
  console.log(`\n${title}\n`);
}

async function waitForRpc(url: string, tries = 60): Promise<void> {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId" }),
      });
      if (r.ok) return;
    } catch {
      /* 아직 */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("anvil 이 뜨지 않았다");
}

/** 발판을 올리고 fn 을 돌린 뒤 반드시 정리한다. */
export async function withStack(fn: (s: Stack) => Promise<void>): Promise<void> {
  if (!existsSync(ARTIFACT)) {
    execFileSync("forge", ["build"], { cwd: "contracts", stdio: "inherit" });
  }
  const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8")) as { bytecode: { object: Hex } };

  const port = 8545 + Math.floor(Math.random() * 500);
  const rpc = `http://127.0.0.1:${port}`;
  let anvil: ChildProcess | null = null;
  let server: ReturnType<typeof createLogServer> | null = null;
  let store: LogStore | null = null;

  try {
    anvil = spawn("anvil", ["--port", String(port), "--silent"], { stdio: "ignore" });
    await waitForRpc(rpc);

    const owner = privateKeyToAccount(OWNER_KEY);
    const operator = privateKeyToAccount(OPERATOR_KEY);
    const gkAccount = privateKeyToAccount(GATEKEEPER_KEY);

    const publicClient = createPublicClient({ chain: foundry, transport: http(rpc) });
    const deployer = createWalletClient({ account: owner, chain: foundry, transport: http(rpc) });
    const hash = await deployer.deployContract({
      abi: LOG_ANCHOR_ABI,
      bytecode: artifact.bytecode.object,
      args: [operator.address],
      chain: foundry,
      account: owner,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const anchorAddress = receipt.contractAddress as Address;

    const chain = connectAnchor({ rpcUrl: rpc, chain: foundry, address: anchorAddress, operator });
    await chain.setGatekeeper(gkAccount.address, true, owner);

    const D = domain(foundry.id, anchorAddress);
    const clock = { now: Math.floor(Date.now() / 1000) };

    store = new LogStore({
      path: ":memory:",
      domain: D,
      operator,
      isRegistered: chain.isRegistered,
      maxMergeDelaySec: 3600,
      clockSkewSec: 86_400, // 시계를 앞당기는 시연이 있어 넉넉히 둔다
      now: () => clock.now,
    });
    server = createLogServer(store);
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const gatekeeper = new Gatekeeper({
      account: gkAccount,
      domain: D,
      policy: DEMO_POLICY,
      logUrl: base,
      now: () => clock.now,
    });

    const verifyChain: VerifyChain = {
      isRegistered: chain.isRegistered,
      rootByTreeSize: chain.rootByTreeSize,
      logOperator: chain.logOperator,
    };

    const s = store;
    const proofs: ProofSource = {
      async inclusion(leafHash) {
        const r = await fetch(`${base}/api/log/proof/inclusion?leaf_hash=${leafHash}`);
        if (!r.ok) throw new Error(`${r.status} ${(await r.json() as { error: string }).error}`);
        return r.json() as never;
      },
      async consistency(from, to) {
        const r = await fetch(`${base}/api/log/proof/consistency?from=${from}&to=${to}`);
        if (!r.ok) throw new Error(`${r.status} ${(await r.json() as { error: string }).error}`);
        return r.json() as never;
      },
      async laterAnchorThan(treeSize) {
        const later = s.anchors().find((a) => a.tree_size > treeSize);
        return later ? later.tree_size : null;
      },
    };

    await fn({
      rpc,
      base,
      anchorAddress,
      domain: D,
      store,
      chain,
      gatekeeper,
      verifyChain,
      proofs,
      clock,
    });
  } finally {
    server?.close();
    store?.close();
    anvil?.kill();
  }
}
