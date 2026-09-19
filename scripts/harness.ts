// 데모 공용 발판. anvil, 컨트랙트 배포, 로그 서버, 게이트웨이를 한 번에 띄운다.
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
import { Gateway, type TxRequest } from "../sdk/gateway.ts";
import { DEMO_POLICY } from "../sdk/demo-policy.ts";
import { rootOfList } from "../lib/sorted-merkle.ts";
import type { StateEvidence } from "../lib/state-proof.ts";
import { signRequestIntent, type RequestIntent } from "../lib/sign.ts";
import { assembleBundle, type Bundle } from "../lib/bundle.ts";
import type { PolicyRule } from "../lib/record.ts";
import type { Receipt } from "../lib/receipt.ts";
import type { ProofSource, VerifyChain } from "../lib/verify.ts";

// anvil 기본 계정. 로컬 전용 키이며 실제 자금과 무관하다.
const OWNER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const OPERATOR_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const GATEWAY_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;
const REQUESTER_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex;
const ARTIFACT = "contracts/out/LogAnchor.sol/LogAnchor.json";

export interface Stack {
  rpc: string;
  base: string;
  anchorAddress: Address;
  chainId: number;
  domain: ReturnType<typeof domain>;
  store: LogStore;
  storePath: string;
  chain: ReturnType<typeof connectAnchor>;
  gateway: Gateway;
  requester: ReturnType<typeof privateKeyToAccount>;
  policyDataRoot: Hex;
  verifyChain: VerifyChain;
  proofs: ProofSource;
  clock: { now: number };
  /** 요청자 의도 서명부터 로그 제출까지 한 번에. */
  reject(req: TxRequest, forceRule?: PolicyRule, state?: StateEvidence): Promise<Receipt>;
  /** 영수증과 로그의 증명 절반을 합쳐 번들을 만든다. */
  bundleFor(
    receipt: Receipt,
    discloseKeys?: readonly string[],
    stateProof?: StateEvidence,
    includeIntent?: boolean,
  ): Promise<Bundle>;
  /** anvil 에 슬롯 값을 심고 그 블록의 EIP-1186 증거를 모은다. */
  stateEvidenceFor(account: Address, slot: Hex, value: bigint): Promise<StateEvidence>;
  /** 목록을 공표한다. 거절보다 먼저 불려야 한다. */
  publishList(values: readonly string[]): Promise<void>;
  /** 로그 서버를 내린다. 데모 1이 쓴다. */
  closeLog(): Promise<void>;
  rpcCall(method: string, params: unknown[]): Promise<unknown>;
}

export interface StackOptions {
  /** 기본은 ":memory:". DB 를 밖에서 직접 조작하는 데모는 파일 경로를 준다. */
  storePath?: string;
}

// 시연 녹화용 속도 조절. OCDL_DEMO_DELAY=600 이면 한 줄마다 600ms 쉰다.
// 데모가 1초에 끝나서 그대로 찍으면 화면에 아무것도 안 남는다.
// step 과 heading 이 동기 함수라 호출부를 안 건드리려고 Atomics 로 막는다.
const DEMO_DELAY = Number(process.env.OCDL_DEMO_DELAY ?? "0");
const blocker = new Int32Array(new SharedArrayBuffer(4));
function pause(ms = DEMO_DELAY): void {
  if (ms > 0) Atomics.wait(blocker, 0, 0, ms);
}

let stepNo = 0;
export function step(msg: string, detail = ""): void {
  console.log(`  ${String(++stepNo).padStart(2, "0")}  ${msg}${detail ? `  ${detail}` : ""}`);
  pause();
}
export function resetSteps(): void {
  stepNo = 0;
}
export function heading(title: string): void {
  console.log(`\n${title}\n`);
  pause(DEMO_DELAY * 2);
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

/** 발판을 올리고 fn 을 돌린 뒤 반드시 정리한다. 안 그러면 anvil 이 남는다. */
export async function withStack(
  fn: (s: Stack) => Promise<void>,
  opts: StackOptions = {},
): Promise<void> {
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
    const gwAccount = privateKeyToAccount(GATEWAY_KEY);
    const requester = privateKeyToAccount(REQUESTER_KEY);

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
    await chain.setGateway(gwAccount.address, true, owner);

    const D = domain(foundry.id, anchorAddress);
    const clock = { now: Math.floor(Date.now() / 1000) };

    const storePath = opts.storePath ?? ":memory:";
    store = new LogStore({
      path: storePath,
      domain: D,
      operator,
      isRegistered: chain.isRegistered,
      maxMergeDelaySec: 3600,
      clockSkewSec: 86_400, // 시각을 앞당기는 데모가 있어 넉넉히 둔다
      now: () => clock.now,
    });
    server = createLogServer(store);
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    // 허용 목록의 정렬 머클 루트. 정적 사유 검증의 기준점이다.
    const policyDataRoot = rootOfList(DEMO_POLICY.data_sets!.allowedTargets) as Hex;

    const gateway = new Gateway({
      account: gwAccount,
      domain: D,
      policy: DEMO_POLICY,
      policyDataRoot,
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

    const rpcCall = async (method: string, params: unknown[]): Promise<unknown> => {
      const r = await fetch(rpc, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const j = (await r.json()) as { result?: unknown; error?: { message: string } };
      if (j.error) throw new Error(`${method}: ${j.error.message}`);
      return j.result;
    };

    const stateEvidenceFor = async (
      account: Address,
      slot: Hex,
      value: bigint,
    ): Promise<StateEvidence> => {
      await rpcCall("anvil_setStorageAt", [
        account,
        slot,
        "0x" + value.toString(16).padStart(64, "0"),
      ]);
      await rpcCall("anvil_setBalance", [account, "0x2386f26fc10000"]);
      await rpcCall("anvil_mine", ["0x1"]);
      const n = Number((await rpcCall("eth_blockNumber", [])) as string);
      const tag = `0x${n.toString(16)}`;
      const acct = (await rpcCall("eth_getProof", [account, [slot], tag])) as never;
      const header = (await rpcCall("eth_getBlockByNumber", [tag, false])) as never;
      return { block_number: n, header, account: acct };
    };

    const closeLog = async (): Promise<void> => {
      const srv = server;
      server = null;
      if (srv) await new Promise<void>((r) => srv.close(() => r()));
    };

    const reject = async (
      req: TxRequest,
      forceRule?: PolicyRule,
      state?: StateEvidence,
    ): Promise<Receipt> => {
      const intent: RequestIntent = {
        requester: requester.address,
        gateway: gwAccount.address,
        target: req.target,
        value: req.value.toString(),
        calldata_hash: ("0x" + "cd".repeat(32)) as Hex,
        issued_at: clock.now,
        nonce: ("0x" + Math.random().toString(16).slice(2).padEnd(64, "0").slice(0, 64)) as Hex,
      };
      const intentSig = await signRequestIntent(intent, requester, D);
      const r = await gateway.handle({ request: req, intent, intentSig, forceRule, state });
      if (!r.receipt) throw new Error("통과된 요청이라 레코드가 없다");
      if (r.submitError) throw new Error(`로그 제출 실패: ${r.submitError}`);
      return r.receipt;
    };

    // 공표된 갱신 레코드. 번들마다 이 증거를 같이 싣는다.
    let policyUpdate: Awaited<ReturnType<typeof gateway.publishPolicyData>> | null = null;

    const publishList = async (values: readonly string[]): Promise<void> => {
      policyUpdate = await gateway.publishPolicyData(values);
    };

    const bundleFor = async (
      receipt: Receipt,
      discloseKeys?: readonly string[],
      stateProof?: StateEvidence,
      includeIntent = true,
    ) => {
      const res = await fetch(`${base}/api/log/bundle?leaf_hash=${receipt.leaf_hash}`);
      if (!res.ok) throw new Error(`증명 조회 실패: ${res.status} ${await res.text()}`);
      const half = (await res.json()) as never;
      return assembleBundle({
        receipt,
        proofs: half,
        anchor: { chain_id: foundry.id, address: anchorAddress },
        policy: DEMO_POLICY,
        policyUpdate: policyUpdate
          ? {
              leaf: policyUpdate.leaf,
              leaf_hash: policyUpdate.leaf_hash,
              inclusion_proof: (
                await (await fetch(`${base}/api/log/bundle?leaf_hash=${policyUpdate.leaf_hash}`)).json()
              ).inclusion_proof,
            }
          : undefined,
        stateProof,
        discloseKeys,
        includeIntent,
      });
    };

    await fn({
      rpc,
      base,
      anchorAddress,
      chainId: foundry.id,
      domain: D,
      store,
      storePath,
      chain,
      gateway,
      requester,
      policyDataRoot,
      verifyChain,
      proofs,
      clock,
      reject,
      bundleFor,
      publishList,
      stateEvidenceFor,
      closeLog,
      rpcCall,
    });
  } finally {
    server?.close();
    store?.close();
    anvil?.kill();
  }
}
