#!/usr/bin/env node
// 독립 검증 도구.
//
//   node cli/verify-rejection.ts <bundle.json> --rpc <URL>
//
// 기관 서버는 부르지 않는다. 외부 접촉은 온체인 읽기 다섯 번뿐이다.
// 종료 코드 0 통과, 1 실패, 2 번들 오류.
import { readFileSync } from "node:fs";
import { createPublicClient, defineChain, http, type Address, type Hex } from "viem";
import { parseBundle, receiptOf, bundleProofSource, describeBundle, BundleError } from "../lib/bundle.ts";
import { LOG_ANCHOR_ABI } from "../lib/chain.ts";
import { domain } from "../lib/sign.ts";
import { verifyReceipt, formatReport, type VerifyChain } from "../lib/verify.ts";
import { sortedSetChecker, policyDataRootChecker } from "../lib/sorted-merkle.ts";
import { stateSlotChecker } from "../lib/state-proof.ts";

interface Args {
  file: string;
  rpc: string;
  json: boolean;
}

function parseArgs(argv: string[]): Args {
  const rest: string[] = [];
  let rpc = process.env.OCDL_RPC ?? "";
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--rpc") rpc = argv[++i] ?? "";
    else if (argv[i] === "--json") json = true;
    else rest.push(argv[i]);
  }
  if (rest.length !== 1 || !rpc) {
    throw new Error("사용법: verify-rejection <bundle.json> --rpc <URL> [--json]");
  }
  return { file: rest[0], rpc, json };
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const bundle = parseBundle(readFileSync(args.file, "utf8"));

  // 체인과 컨트랙트는 번들이 알려준다. 서명 도메인도 같은 값에서 나온다.
  const chainId = bundle.anchor.chain_id;
  const client = createPublicClient({
    chain: defineChain({
      id: chainId,
      name: `chain-${chainId}`,
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: { default: { http: [args.rpc] } },
    }),
    transport: http(args.rpc),
  });

  const actual = await client.getChainId();
  if (actual !== chainId) {
    // 이걸 안 보면 엉뚱한 체인에서 앵커가 전부 0 으로 읽혀 "누락" 으로 오판한다.
    throw new Error(`RPC 의 체인 ID 가 번들과 다르다: ${actual} != ${chainId}`);
  }

  const read = <T>(functionName: string, a: readonly unknown[] = []) =>
    client.readContract({
      address: bundle.anchor.address as Address,
      abi: LOG_ANCHOR_ABI,
      functionName,
      args: a,
    } as never) as Promise<T>;

  const chain: VerifyChain = {
    isRegistered: (gw) => read<boolean>("gateways", [gw]),
    rootByTreeSize: (size) => read<Hex>("rootByTreeSize", [BigInt(size)]),
    logOperator: () => read<Address>("logOperator"),
  };

  // 11단계에서만 불린다.
  const getBlockHash = async (n: number): Promise<Hex> => {
    const b = await client.getBlock({ blockNumber: BigInt(n) });
    if (!b.hash) throw new Error(`블록 ${n} 의 해시가 없다`);
    return b.hash;
  };

  const report = await verifyReceipt({
    receipt: receiptOf(bundle),
    domain: domain(chainId, bundle.anchor.address),
    chain,
    proofs: bundleProofSource(bundle),
    policy: bundle.policy_document ?? undefined,
    policyUpdate: bundle.policy_update ?? undefined,
    policyDataProof: policyDataRootChecker(),
    staticCheck: sortedSetChecker(),
    stateCheck: stateSlotChecker(bundle.state_proof, getBlockHash),
  });

  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`\n거절 레코드 독립 검증\n`);
    console.log(describeBundle(bundle));
    console.log(`  RPC           ${args.rpc}\n`);
    console.log(formatReport(report));
    console.log("");
  }
  return report.ok ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(e instanceof BundleError ? `번들 오류: ${e.message}` : `오류: ${(e as Error).message}`);
    process.exit(2);
  },
);
