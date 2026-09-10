// 정상 경로 관통. 명세 docs/CHECKLIST.md 의 9/13 게이트를 이 스크립트가 증명한다.
//
// 실행: npm run e2e   (foundry 의 anvil 이 필요하다)
//
// 거절 판정부터 온체인 앵커, 포함 증명 검증까지 한 번에 지나간다.
// 마지막 검증은 로그 서버의 응답을 믿지 않고 체인에서 루트를 다시 읽어서 한다.
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import type { AddressInfo } from "node:net";
import { createPublicClient, createWalletClient, http, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";

import { buildLeafBody, leafHash } from "../lib/record.ts";
import { domain, signLeaf, verifyLeafSignature, verifyLogAck } from "../lib/sign.ts";
import { LogStore } from "../lib/log-store.ts";
import { createLogServer } from "../lib/log-server.ts";
import { connectAnchor, LOG_ANCHOR_ABI } from "../lib/chain.ts";
import { anchorOnce } from "../lib/anchor-job.ts";
import { rootFromInclusionProof, verifyConsistency } from "../lib/merkle.ts";

// anvil 기본 계정. 로컬 전용 키이며 실제 자금과 무관하다.
const OWNER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const OPERATOR_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const GATEKEEPER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;

const PORT = 8545 + Math.floor(Math.random() * 500);
const RPC = `http://127.0.0.1:${PORT}`;
const ARTIFACT = "contracts/out/LogAnchor.sol/LogAnchor.json";

let step = 0;
const ok = (msg: string, detail = "") =>
  console.log(`  ${String(++step).padStart(2, "0")}  ${msg}${detail ? `  ${detail}` : ""}`);

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
      /* 아직 안 떴다 */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("anvil 이 뜨지 않았다");
}

async function main() {
  if (!existsSync(ARTIFACT)) {
    console.log("컨트랙트 아티팩트가 없어 forge build 를 먼저 돌린다");
    execFileSync("forge", ["build"], { cwd: "contracts", stdio: "inherit" });
  }
  const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8")) as {
    bytecode: { object: Hex };
  };

  let anvil: ChildProcess | null = null;
  let server: ReturnType<typeof createLogServer> | null = null;
  let store: LogStore | null = null;

  try {
    console.log("\n정상 경로 관통\n");

    anvil = spawn("anvil", ["--port", String(PORT), "--silent"], { stdio: "ignore" });
    await waitForRpc(RPC);
    ok("anvil 기동", RPC);

    const owner = privateKeyToAccount(OWNER_KEY);
    const operator = privateKeyToAccount(OPERATOR_KEY);
    const gatekeeper = privateKeyToAccount(GATEKEEPER_KEY);

    const publicClient = createPublicClient({ chain: foundry, transport: http(RPC) });
    const deployer = createWalletClient({ account: owner, chain: foundry, transport: http(RPC) });

    const deployHash = await deployer.deployContract({
      abi: LOG_ANCHOR_ABI,
      bytecode: artifact.bytecode.object,
      args: [operator.address],
      chain: foundry,
      account: owner,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash: deployHash });
    const anchorAddress = receipt.contractAddress as Address;
    ok("LogAnchor 배포", anchorAddress);

    const chain = connectAnchor({
      rpcUrl: RPC,
      chain: foundry,
      address: anchorAddress,
      operator,
    });

    const onchainOperator = await chain.logOperator();
    if (onchainOperator.toLowerCase() !== operator.address.toLowerCase()) {
      throw new Error("logOperator 불일치");
    }
    ok("logOperator 확인", "immutable, 배포 시 고정");

    await chain.setGatekeeper(gatekeeper.address, true, owner);
    if (!(await chain.isRegistered(gatekeeper.address))) throw new Error("등록 실패");
    ok("게이트키퍼 레지스트리 등록", gatekeeper.address);

    // 서명 도메인은 이 체인과 이 컨트랙트에 묶인다.
    const D = domain(foundry.id, anchorAddress);

    store = new LogStore({
      path: ":memory:",
      domain: D,
      operator,
      isRegistered: chain.isRegistered,
      maxMergeDelaySec: 3600,
    });
    server = createLogServer(store);
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    ok("로그 서버 기동", base);

    // ---- 다른 거절 기록 몇 건을 먼저 쌓는다. 증명 경로에 깊이를 준다 ----
    for (let i = 0; i < 5; i++) {
      const other = buildLeafBody({
        gatekeeper: gatekeeper.address,
        policyHash: ("0x" + "9a".repeat(32)) as Hex,
        fields: {
          requester: `0xabc000000000000000000000000000000000000${i}`,
          target: "0x000000000000000000000000000000000000beef",
          value: String(1000 + i),
          calldata_hash: ("0x" + "ef".repeat(32)) as Hex,
          rule_id: "AMOUNT_CAP_EXCEEDED",
          severity: "hold",
        },
        issuedAt: Math.floor(Date.now() / 1000),
      });
      await store.submit(await signLeaf(other.body, gatekeeper, D));
    }
    ok("다른 거절 기록 적재", `${store.size()}건`);

    // ---- 게이트키퍼가 거절을 판정하고 영수증을 발급한다 ----
    const { body, disclosures } = buildLeafBody({
      gatekeeper: gatekeeper.address,
      policyHash: ("0x" + "9a".repeat(32)) as Hex,
      fields: {
        requester: "0xabc0000000000000000000000000000000000001",
        target: "0x000000000000000000000000000000000000dead",
        value: "1000000000000000000",
        calldata_hash: ("0x" + "cd".repeat(32)) as Hex,
        rule_id: "DENYLIST_SANCTIONED",
        severity: "block",
      },
      issuedAt: Math.floor(Date.now() / 1000),
    });
    const leaf = await signLeaf(body, gatekeeper, D);
    if (!(await verifyLeafSignature(leaf, D))) throw new Error("자체 서명 검증 실패");
    ok("거절 영수증 서명", `필드 ${disclosures.length}개 커밋`);

    // ---- 로그 서버에 제출하고 접수 확인을 받는다 ----
    const submitRes = await fetch(`${base}/api/log/submit`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ leaf }),
    });
    if (!submitRes.ok) throw new Error(`제출 실패: ${submitRes.status} ${await submitRes.text()}`);
    const { leaf_hash, log_ack } = (await submitRes.json()) as {
      leaf_hash: Hex;
      log_ack: Parameters<typeof verifyLogAck>[0];
    };
    if (leaf_hash !== `0x${leafHash(leaf).toString("hex")}`) throw new Error("leaf_hash 불일치");
    if (!(await verifyLogAck(log_ack, operator.address, D))) throw new Error("접수 확인 검증 실패");
    ok("접수 확인 수신", `약속 시각까지 ${log_ack.promised_by - log_ack.received_at}초`);

    // ---- 앵커 전에는 포함 증명이 나오지 않는다 ----
    const early = await fetch(`${base}/api/log/proof/inclusion?leaf_hash=${leaf_hash}`);
    if (early.status !== 409) throw new Error(`앵커 전 응답이 409 가 아님: ${early.status}`);
    ok("앵커 전 포함 증명 요청", "409, 두 번째 시연이 서는 자리");

    // ---- 앵커링 ----
    const anchored = await anchorOnce({ store, chain });
    if (!anchored.anchored) throw new Error(`앵커 실패: ${anchored.reason}`);
    ok("온체인 앵커", `tree_size=${anchored.treeSize} tx=${anchored.txHash?.slice(0, 12)}…`);

    // ---- 포함 증명 ----
    const proofRes = await fetch(`${base}/api/log/proof/inclusion?leaf_hash=${leaf_hash}`);
    if (!proofRes.ok) throw new Error(`증명 요청 실패: ${proofRes.status}`);
    const proof = (await proofRes.json()) as {
      anchor: { tree_size: number; root: Hex };
      index: number;
      audit_path: Hex[];
    };
    ok("포함 증명 수신", `index=${proof.index}/${proof.anchor.tree_size} path=${proof.audit_path.length}단계`);

    // ---- 검증자는 서버 응답을 믿지 않고 체인에서 루트를 다시 읽는다 ----
    const chainRoot = await chain.rootByTreeSize(proof.anchor.tree_size);
    if (chainRoot.toLowerCase() !== proof.anchor.root.toLowerCase()) {
      throw new Error("서버가 준 앵커와 체인의 루트가 다르다");
    }
    ok("체인에서 루트 재조회", `rootByTreeSize(${proof.anchor.tree_size})`);

    const recomputed = rootFromInclusionProof(
      proof.index,
      proof.anchor.tree_size,
      leafHash(leaf),
      proof.audit_path.map((h) => Buffer.from(h.slice(2), "hex")),
    );
    if (!recomputed || `0x${recomputed.toString("hex")}` !== chainRoot) {
      throw new Error("포함 증명이 체인의 루트로 재계산되지 않는다");
    }
    ok("포함 증명 검증", "체인 루트와 일치");

    // ---- 일관성 증명. 앵커 두 개 사이에서 이력이 안 고쳐졌음을 본다 ----
    const beforeSize = proof.anchor.tree_size;
    for (let i = 0; i < 3; i++) {
      const more = buildLeafBody({
        gatekeeper: gatekeeper.address,
        policyHash: ("0x" + "9a".repeat(32)) as Hex,
        fields: {
          requester: `0xabc00000000000000000000000000000000000f${i}`,
          target: "0x000000000000000000000000000000000000cafe",
          value: String(2000 + i),
          calldata_hash: ("0x" + "ab".repeat(32)) as Hex,
          rule_id: "UNKNOWN_CONTRACT",
          severity: "review",
        },
        issuedAt: Math.floor(Date.now() / 1000),
      });
      await store.submit(await signLeaf(more.body, gatekeeper, D));
    }
    const second = await anchorOnce({ store, chain });
    if (!second.anchored) throw new Error(`두 번째 앵커 실패: ${second.reason}`);
    ok("두 번째 앵커", `tree_size=${second.treeSize}`);

    const consRes = await fetch(
      `${base}/api/log/proof/consistency?from=${beforeSize}&to=${second.treeSize}`,
    );
    if (!consRes.ok) throw new Error(`일관성 증명 요청 실패: ${consRes.status}`);
    const cons = (await consRes.json()) as {
      from_anchor: { root: Hex };
      to_anchor: { root: Hex };
      path: Hex[];
    };
    const oldChainRoot = await chain.rootByTreeSize(beforeSize);
    const newChainRoot = await chain.rootByTreeSize(second.treeSize!);
    const consistent = verifyConsistency(
      beforeSize,
      second.treeSize!,
      Buffer.from(oldChainRoot.slice(2), "hex"),
      Buffer.from(newChainRoot.slice(2), "hex"),
      cons.path.map((h) => Buffer.from(h.slice(2), "hex")),
    );
    if (!consistent) throw new Error("일관성 증명이 두 온체인 루트로 검증되지 않는다");
    ok("일관성 증명 검증", `${beforeSize} -> ${second.treeSize}, 두 온체인 루트로 확인`);

    // ---- 선택적 공개 ----
    const { verifyDisclosure } = await import("../lib/record.ts");
    const ruleId = disclosures.find((d) => d[1] === "rule_id")!;
    if (!verifyDisclosure(leaf, ruleId)) throw new Error("선택적 공개 검증 실패");
    const forged = [ruleId[0], ruleId[1], "SOMETHING_ELSE"] as typeof ruleId;
    if (verifyDisclosure(leaf, forged)) throw new Error("위조된 공개가 통과했다");
    ok("선택적 공개", "rule_id 하나만 공개, 나머지는 해시만");

    console.log("\n관통 성공. 9/13 게이트 충족.\n");
  } finally {
    server?.close();
    store?.close();
    anvil?.kill();
  }
}

main().catch((e) => {
  console.error("\n관통 실패:", e instanceof Error ? e.message : e, "\n");
  process.exitCode = 1;
});
