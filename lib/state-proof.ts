// EIP-1186 상태 증거 검증. 판단 시점의 체인 상태를 사후에 확인한다.
//
// MPT 증거는 stateRoot 에 자기 인증된다. 값을 조작하면 재계산한 루트가 헤더와
// 어긋나므로, 게이트웨이가 자기 증거를 만들어 넣어도 위조가 안 된다. 고를 수
// 있는 건 어느 슬롯을 증명할지뿐이다.
//
// 트라이 walk 은 직접 구현하지 않는다. 표준 형식 파서이지 이 프로젝트의 주장이
// 걸린 자료구조가 아니다.
import { createHash } from "node:crypto";
import { verifyMerkleProof } from "@ethereumjs/mpt";
import { hexToBytes, bytesToHex } from "@ethereumjs/util";
import { keccak256, toRlp, type Hex } from "viem";

export class StateProofError extends Error {}

/** eth_getProof 응답 그대로. 필드 이름도 RPC 와 같게 둔다. */
export interface AccountProof {
  address: Hex;
  accountProof: Hex[];
  balance: Hex;
  codeHash: Hex;
  nonce: Hex;
  storageHash: Hex;
  storageProof: { key: Hex; value: Hex; proof: Hex[] }[];
}

/** eth_getBlockByNumber 응답에서 헤더 필드만 뽑은 것. */
export interface BlockHeader {
  parentHash: Hex;
  sha3Uncles: Hex;
  miner: Hex;
  stateRoot: Hex;
  transactionsRoot: Hex;
  receiptsRoot: Hex;
  logsBloom: Hex;
  difficulty: Hex;
  number: Hex;
  gasLimit: Hex;
  gasUsed: Hex;
  timestamp: Hex;
  extraData: Hex;
  mixHash: Hex;
  nonce: Hex;
  baseFeePerGas?: Hex;
  withdrawalsRoot?: Hex;
  blobGasUsed?: Hex;
  excessBlobGas?: Hex;
  parentBeaconBlockRoot?: Hex;
  requestsHash?: Hex;
}

/** RLP 수량 표기. 앞의 0 을 떼고 0 은 빈 바이트열로. 틀리면 블록 해시가 안 나온다. */
function quantity(v: Hex | undefined): Hex {
  if (v === undefined) return "0x";
  const trimmed = v.replace(/^0x0*/, "");
  return trimmed === "" ? "0x" : (`0x${trimmed.length % 2 ? "0" + trimmed : trimmed}` as Hex);
}

/**
 * 필드 순서가 합의 규칙이다. 손대면 블록 해시가 안 나온다.
 * 뒤쪽 선택 필드는 하드포크마다 늘어나므로 있는 데까지만 넣는다.
 */
export function encodeHeader(h: BlockHeader): Hex {
  const fields: Hex[] = [
    h.parentHash,
    h.sha3Uncles,
    h.miner,
    h.stateRoot,
    h.transactionsRoot,
    h.receiptsRoot,
    h.logsBloom,
    quantity(h.difficulty),
    quantity(h.number),
    quantity(h.gasLimit),
    quantity(h.gasUsed),
    quantity(h.timestamp),
    h.extraData,
    h.mixHash,
    h.nonce,
  ];
  for (const opt of [
    h.baseFeePerGas,
    h.withdrawalsRoot,
    h.blobGasUsed,
    h.excessBlobGas,
    h.parentBeaconBlockRoot,
    h.requestsHash,
  ]) {
    if (opt === undefined) break; // 중간이 비면 뒤도 못 넣는다
    fields.push(
      opt.length === 66 ? opt : quantity(opt), // 해시는 그대로, 수량은 다듬어서
    );
  }
  return toRlp(fields);
}

/** 검증자가 체인에 물어보는 유일한 값. */
export function blockHashOf(h: BlockHeader): Hex {
  return keccak256(encodeHeader(h));
}

const trieKey = (b: Uint8Array): Uint8Array => hexToBytes(keccak256(bytesToHex(b)));

/** stateRoot 에 대한 계정 증거. null 이면 계정 비존재 증명이다. */
export async function verifyAccount(
  stateRoot: Hex,
  address: Hex,
  accountProof: Hex[],
): Promise<Uint8Array | null> {
  try {
    return await verifyMerkleProof(
      trieKey(hexToBytes(address)),
      accountProof.map(hexToBytes),
      { root: hexToBytes(stateRoot) } as never,
    );
  } catch (e) {
    throw new StateProofError(`계정 증거 검증 실패: ${(e as Error).message}`);
  }
}

/**
 * 기준이 stateRoot 가 아니라 계정의 storageHash 다. 그 storageHash 는 위의 계정
 * 증거로 stateRoot 에 묶인다. 두 단계를 안 이으면 아무 스토리지 트라이나 통과한다.
 */
export async function verifyStorageSlot(
  storageHash: Hex,
  key: Hex,
  proof: Hex[],
): Promise<Uint8Array | null> {
  const padded = (`0x${key.replace(/^0x/, "").padStart(64, "0")}`) as Hex;
  try {
    return await verifyMerkleProof(trieKey(hexToBytes(padded)), proof.map(hexToBytes), {
      root: hexToBytes(storageHash),
    } as never);
  } catch (e) {
    throw new StateProofError(`스토리지 증거 검증 실패: ${(e as Error).message}`);
  }
}

/** 트라이에서 나온 RLP 값을 정수로. 빈 값은 0 이다. */
export function slotValueToBigInt(raw: Uint8Array | null): bigint {
  if (!raw || raw.length === 0) return 0n;
  // 스토리지 값은 RLP 로 감싸인 최소 바이트열이다.
  const bytes = raw[0] >= 0x80 && raw.length > 1 ? raw.slice(1) : raw;
  return bytes.length === 0 ? 0n : BigInt(bytesToHex(bytes));
}

/** 번들에 그대로 들어가는 증거 묶음. */
export interface StateEvidence {
  block_number: number;
  header: BlockHeader;
  account: AccountProof;
}

/** 리프의 state_proof_root. 증거 바꿔치기를 막는다. */
export function stateProofRoot(e: StateEvidence): Hex {
  const body = JSON.stringify([e.block_number, e.header, e.account]);
  return `0x${createHash("sha256").update(Buffer.from(body, "utf8")).digest("hex")}`;
}

export interface StateCheckResult {
  blockHash: Hex;
  stateRoot: Hex;
  slotValue: bigint;
  balance: bigint;
}

/**
 * 묶음을 끝까지 검증한다. 호출부는 여기서 나온 blockHash 를 공개 RPC 의 정본
 * 해시와 대조해야 한다. 그 한 번이 유일한 외부 접촉이다.
 */
export async function checkEvidence(
  e: StateEvidence,
  slotKey: Hex,
): Promise<StateCheckResult> {
  const blockHash = blockHashOf(e.header);
  const stateRoot = e.header.stateRoot;

  const account = await verifyAccount(stateRoot, e.account.address, e.account.accountProof);
  if (!account) throw new StateProofError("계정이 존재하지 않는다는 증명이 나왔다");

  const sp = e.account.storageProof.find(
    (s) => BigInt(s.key) === BigInt(slotKey),
  );
  if (!sp) throw new StateProofError(`슬롯 ${slotKey} 의 증거가 묶음에 없다`);

  const raw = await verifyStorageSlot(e.account.storageHash, sp.key, sp.proof);
  return {
    blockHash,
    stateRoot,
    slotValue: slotValueToBigInt(raw),
    balance: BigInt(e.account.balance),
  };
}

// ---------- 검증기 붙임부 ----------

import { ZERO32, disclosedValue } from "./record.ts";
import type { PredicateContext, Verdict } from "./verify.ts";

/**
 * 검증 11단계 검사기.
 *
 * 아래 순서가 방어 논리다. 커밋 대조 → 헤더 정본 확인 → stateRoot 신뢰 → 술어 적용.
 * 헤더 확인을 뒤로 미루면 지어낸 헤더 위에서 모든 게 앞뒤가 맞아버린다.
 */
export function stateSlotChecker(
  evidence: StateEvidence | null,
  getBlockHash: (blockNumber: number) => Promise<Hex>,
): (ctx: PredicateContext) => Promise<Verdict> {
  return async (ctx) => {
    const p = ctx.rule.predicate;
    if (!p || p.kind !== "state_slot") {
      return { status: "unverifiable", detail: "상태 슬롯 술어가 아니다" };
    }
    if (!evidence) {
      return { status: "unverifiable", detail: "번들에 상태 증거가 없다" };
    }

    // 리프가 커밋한 것과 동봉된 증거가 같은 것인지부터.
    if (ctx.leaf.decided_at_block !== evidence.block_number) {
      return { status: "fail", detail: "판단 블록 번호가 커밋과 다르다" };
    }
    if (ctx.leaf.state_proof_root !== stateProofRoot(evidence)) {
      return { status: "fail", detail: "상태 증거가 사후에 바뀌었다" };
    }
    if (ctx.leaf.state_root.toLowerCase() !== evidence.header.stateRoot.toLowerCase()) {
      return { status: "fail", detail: "헤더의 stateRoot 가 커밋과 다르다" };
    }
    if (ctx.leaf.state_root === ZERO32) {
      return { status: "fail", detail: "동적 사유인데 stateRoot 를 커밋하지 않았다" };
    }

    // 헤더가 정본인가. 여기가 유일한 외부 접촉이다.
    const computed = blockHashOf(evidence.header);
    let canonical: Hex;
    try {
      canonical = await getBlockHash(evidence.block_number);
    } catch (e) {
      return { status: "unverifiable", detail: `블록 해시를 조회하지 못했다: ${(e as Error).message}` };
    }
    if (computed.toLowerCase() !== canonical.toLowerCase()) {
      return { status: "fail", detail: `헤더가 정본이 아니다. ${computed} != ${canonical}` };
    }

    if (evidence.account.address.toLowerCase() !== p.account.toLowerCase()) {
      return { status: "fail", detail: "증거가 규칙이 가리키는 계정의 것이 아니다" };
    }

    let result: StateCheckResult;
    try {
      result = await checkEvidence(evidence, p.slot as Hex);
    } catch (e) {
      return { status: "fail", detail: (e as Error).message };
    }

    const operand = disclosedValue(ctx.disclosures, p.operand);
    if (operand === undefined) {
      return { status: "unverifiable", detail: `${p.operand} 가 공개되지 않았다` };
    }

    const rhs = BigInt(operand);
    const holds = p.op === "lt" ? result.slotValue < rhs : result.slotValue >= rhs;
    const sign = p.op === "lt" ? "<" : ">=";
    const detail = `블록 ${evidence.block_number} 슬롯 값 ${result.slotValue} ${sign} ${rhs} 가 ${holds ? "참" : "거짓"}`;

    return holds
      ? { status: "pass", detail: `${detail}. 사유가 참` }
      : { status: "fail", detail: `거짓 동적 사유. ${detail}` };
  };
}
