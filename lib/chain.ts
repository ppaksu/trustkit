// 앵커 컨트랙트 접속부. 루트 읽기·쓰기와 게이트웨이 레지스트리 조회.
import {
  createPublicClient,
  createWalletClient,
  http,
  type Address,
  type Chain,
  type Hex,
} from "viem";
import type { Account } from "viem/accounts";

export const LOG_ANCHOR_ABI = [
  {
    type: "constructor",
    inputs: [{ type: "address", name: "_logOperator" }],
    stateMutability: "nonpayable",
  },
  {
    type: "event",
    name: "RootAnchored",
    inputs: [
      { type: "uint64", name: "treeSize", indexed: true },
      { type: "bytes32", name: "root", indexed: false },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "GatewaySet",
    inputs: [
      { type: "address", name: "gateway", indexed: true },
      { type: "bool", name: "allowed", indexed: false },
    ],
    anonymous: false,
  },
  { type: "error", name: "NotAuthorized", inputs: [] },
  { type: "error", name: "TreeSizeNotIncreasing", inputs: [] },
  { type: "error", name: "InvalidRoot", inputs: [] },
  { type: "error", name: "InvalidAddress", inputs: [] },
  { type: "function", name: "owner", inputs: [], outputs: [{ type: "address" }], stateMutability: "view" },
  { type: "function", name: "logOperator", inputs: [], outputs: [{ type: "address" }], stateMutability: "view" },
  { type: "function", name: "lastTreeSize", inputs: [], outputs: [{ type: "uint64" }], stateMutability: "view" },
  {
    type: "function",
    name: "rootByTreeSize",
    inputs: [{ type: "uint64" }],
    outputs: [{ type: "bytes32" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "gateways",
    inputs: [{ type: "address" }],
    outputs: [{ type: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "latestRoot",
    inputs: [],
    outputs: [{ type: "uint64", name: "treeSize" }, { type: "bytes32", name: "root" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "submitRoot",
    inputs: [{ type: "bytes32", name: "root" }, { type: "uint64", name: "treeSize" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "setGateway",
    inputs: [{ type: "address" }, { type: "bool" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

/** 앵커링 작업이 쓰는 최소 인터페이스. 테스트가 대역을 끼울 수 있게 좁게 잡았다. */
export interface AnchorChain {
  lastTreeSize(): Promise<number>;
  rootByTreeSize(treeSize: number): Promise<Hex>;
  submitRoot(root: Hex, treeSize: number): Promise<string>;
}

export interface ChainOptions {
  rpcUrl: string;
  chain: Chain;
  address: Address;
  /** submitRoot 를 보낼 계정. 컨트랙트의 logOperator 와 같아야 한다. */
  operator?: Account;
}

export function connectAnchor(o: ChainOptions) {
  const publicClient = createPublicClient({ chain: o.chain, transport: http(o.rpcUrl) });
  const wallet = o.operator
    ? createWalletClient({ account: o.operator, chain: o.chain, transport: http(o.rpcUrl) })
    : null;

  const read = <T>(functionName: string, args: readonly unknown[] = []) =>
    publicClient.readContract({
      address: o.address,
      abi: LOG_ANCHOR_ABI,
      functionName,
      args,
    } as never) as Promise<T>;

  const api: AnchorChain & {
    isRegistered(gk: Address): Promise<boolean>;
    logOperator(): Promise<Address>;
    setGateway(gk: Address, allowed: boolean, owner: Account): Promise<string>;
  } = {
    async lastTreeSize() {
      return Number(await read<bigint>("lastTreeSize"));
    },
    async rootByTreeSize(treeSize) {
      return read<Hex>("rootByTreeSize", [BigInt(treeSize)]);
    },
    async submitRoot(root, treeSize) {
      if (!wallet) throw new Error("operator 계정이 없어 submitRoot 를 보낼 수 없다");
      const hash = await wallet.writeContract({
        address: o.address,
        abi: LOG_ANCHOR_ABI,
        functionName: "submitRoot",
        args: [root, BigInt(treeSize)],
        chain: o.chain,
        account: wallet.account,
      });
      await publicClient.waitForTransactionReceipt({ hash });
      return hash;
    },
    /** 로그 서버와 검증기가 모두 이 함수를 쓴다. */
    async isRegistered(gk) {
      return read<boolean>("gateways", [gk]);
    },
    async logOperator() {
      return read<Address>("logOperator");
    },
    async setGateway(gk, allowed, owner) {
      const w = createWalletClient({ account: owner, chain: o.chain, transport: http(o.rpcUrl) });
      const hash = await w.writeContract({
        address: o.address,
        abi: LOG_ANCHOR_ABI,
        functionName: "setGateway",
        args: [gk, allowed],
        chain: o.chain,
        account: owner,
      });
      await publicClient.waitForTransactionReceipt({ hash });
      return hash;
    },
  };

  return { publicClient, wallet, ...api };
}
