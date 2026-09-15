// EIP-712 서명 세 개. 요청자, 게이트웨이, 로그가 각자 막는 부인이 다르다.
//
// DOMAIN_NAME 과 DOMAIN_VERSION 을 바꾸면 그 전에 발급한 서명이 전부 검증
// 실패한다. 배포 후 건드리지 말 것.
import { createHash } from "node:crypto";
import {
  hashTypedData,
  recoverTypedDataAddress,
  type Address,
  type Hex,
  type TypedDataDomain,
} from "viem";
import type { Account } from "viem/accounts";
import {
  keysRoot,
  fieldsRoot,
  validateLeafStructure,
  ZERO32,
  type Leaf,
  type LeafBody,
} from "./record.ts";

/**
 * 프로토콜 식별자. **프로젝트 이름이 아니다.**
 *
 * 일부러 브랜드와 끊어놨다. 이 값이 서명 도메인에 섞이므로 배포 후에 바꾸면 그
 * 전에 발급한 서명이 전부 검증 실패한다. 브랜드명을 여기 넣으면 이름을 바꿀 때마다
 * 과거 레코드가 죽는다.
 *
 * 값은 하는 일을 적어둔 고정 문구다. 지갑이 서명 창에 이 문자열을 띄우므로 사람이
 * 읽을 수 있어야 한다. 요청자가 무엇에 서명하는지 보고 판단할 수 있어야 하기 때문이다.
 */
export const DOMAIN_NAME = "off-chain decision log";
export const DOMAIN_VERSION = "1";

export class SignatureError extends Error {}

/**
 * chainId 와 verifyingContract 가 교차 체인·교차 배포본 재사용을 막는다.
 * 둘 중 하나만 빼도 같은 서명이 다른 곳에서 유효해진다.
 */
export function domain(chainId: number, verifyingContract: Address): TypedDataDomain {
  return {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId,
    verifyingContract,
  };
}

const hex32 = (b: Buffer): Hex => `0x${b.toString("hex")}`;
const sha256 = (b: Buffer): Buffer => createHash("sha256").update(b).digest();

// ---------- 1. RequestIntent — 요청자 ----------

/**
 * 요청자 의도. **유효한 트랜잭션이 아니다.**
 *
 * 실제 트랜잭션에 서명시키면 게이트웨이가 거절해놓고 나중에 자기가 브로드캐스트할
 * 수 있다. EIP-712 서명은 0x19 0x01 로 시작해 RLP 트랜잭션으로 재해석되지 않는다.
 */
export const REQUEST_INTENT_TYPES = {
  RequestIntent: [
    { name: "requester", type: "address" },
    { name: "gateway", type: "address" },
    { name: "target", type: "address" },
    { name: "value", type: "uint256" },
    { name: "calldataHash", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

export interface RequestIntent {
  requester: Address;
  gateway: Address;
  target: Address;
  /** wei. 직렬화는 10진 문자열로 한다. */
  value: string;
  calldata_hash: Hex;
  issued_at: number;
  nonce: Hex;
}

function intentMessage(i: RequestIntent) {
  return {
    requester: i.requester,
    gateway: i.gateway,
    target: i.target,
    value: BigInt(i.value),
    calldataHash: i.calldata_hash,
    issuedAt: BigInt(i.issued_at),
    nonce: i.nonce,
  };
}

/** 리프의 request_intent_hash. 원문을 넣으면 수신자와 금액이 로그에 드러난다. */
export function requestIntentHash(i: RequestIntent, d: TypedDataDomain): Hex {
  return hashTypedData({
    domain: d,
    types: REQUEST_INTENT_TYPES,
    primaryType: "RequestIntent",
    message: intentMessage(i),
  });
}

/**
 * 리프의 requester_sig_hash.
 *
 * 의도 해시와 따로 두는 이유. 의도만 묶으면 "이런 요청이 있었다" 까지이고,
 * 서명까지 묶어야 "그 요청에 이 키가 서명한 그 건" 이 된다.
 */
export function requesterSigHash(signature: Hex): Hex {
  return hex32(sha256(Buffer.from(signature.replace(/^0x/, ""), "hex")));
}

export async function signRequestIntent(
  intent: RequestIntent,
  account: Account,
  d: TypedDataDomain,
): Promise<Hex> {
  if (!account.signTypedData) throw new SignatureError("서명할 수 없는 계정");
  return account.signTypedData({
    domain: d,
    types: REQUEST_INTENT_TYPES,
    primaryType: "RequestIntent",
    message: intentMessage(intent),
  });
}

/** 복원 주소가 intent.requester 와 같은지. 리프 커밋과의 대조는 verify.ts 가 한다. */
export async function verifyRequestIntent(
  intent: RequestIntent,
  signature: Hex,
  d: TypedDataDomain,
): Promise<boolean> {
  if (!intent || typeof intent.requester !== "string" || typeof signature !== "string") {
    return false;
  }
  let recovered: Address;
  try {
    recovered = await recoverTypedDataAddress({
      domain: d,
      types: REQUEST_INTENT_TYPES,
      primaryType: "RequestIntent",
      message: intentMessage(intent),
      signature,
    });
  } catch {
    return false;
  }
  return recovered.toLowerCase() === intent.requester.toLowerCase();
}

// ---------- 2. RejectionRecord — 게이트웨이 ----------

export const REJECTION_TYPES = {
  RejectionRecord: [
    { name: "schemaVersion", type: "uint8" },
    { name: "gateway", type: "address" },
    { name: "policyHash", type: "bytes32" },
    { name: "policyDataRoot", type: "bytes32" },
    { name: "keysRoot", type: "bytes32" },
    { name: "fieldsRoot", type: "bytes32" },
    { name: "requestIntentHash", type: "bytes32" },
    { name: "requesterSigHash", type: "bytes32" },
    { name: "decidedAtBlock", type: "uint64" },
    { name: "stateRoot", type: "bytes32" },
    { name: "stateProofRoot", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/**
 * keysRoot 와 fieldsRoot 를 **항상 리프에서 재계산**한다. 호출부가 이 값을 넘길
 * 경로가 없다. 넘길 수 있으면 필드는 A, 루트는 B 로 서명해 둘을 분리할 수 있다.
 */
function rejectionMessage(leaf: Leaf | LeafBody) {
  validateLeafStructure(leaf);
  return {
    schemaVersion: leaf.v,
    gateway: leaf.gateway as Address,
    policyHash: leaf.policy_hash as Hex,
    policyDataRoot: leaf.policy_data_root as Hex,
    keysRoot: hex32(keysRoot(leaf.keys)),
    fieldsRoot: hex32(fieldsRoot(leaf.field_hashes)),
    requestIntentHash: leaf.request_intent_hash as Hex,
    requesterSigHash: leaf.requester_sig_hash as Hex,
    decidedAtBlock: BigInt(leaf.decided_at_block),
    stateRoot: leaf.state_root as Hex,
    stateProofRoot: leaf.state_proof_root as Hex,
    issuedAt: BigInt(leaf.issued_at),
    nonce: leaf.nonce as Hex,
  };
}

/** 서명 대상 digest. 서명을 만들지는 않는다. */
export function rejectionDigest(leaf: Leaf | LeafBody, d: TypedDataDomain): Hex {
  return hashTypedData({
    domain: d,
    types: REJECTION_TYPES,
    primaryType: "RejectionRecord",
    message: rejectionMessage(leaf),
  });
}

export async function signLeaf(
  body: LeafBody,
  account: Account,
  d: TypedDataDomain,
): Promise<Leaf> {
  if (!account.signTypedData) {
    throw new SignatureError("서명할 수 없는 계정");
  }
  const signature = await account.signTypedData({
    domain: d,
    types: REJECTION_TYPES,
    primaryType: "RejectionRecord",
    message: rejectionMessage(body),
  });
  return { ...body, signature };
}

/** 서명자 주소를 복원한다. leaf.gateway 와의 비교는 호출부 몫이다. */
export async function recoverLeafSigner(leaf: Leaf, d: TypedDataDomain): Promise<Address> {
  return recoverTypedDataAddress({
    domain: d,
    types: REJECTION_TYPES,
    primaryType: "RejectionRecord",
    message: rejectionMessage(leaf),
    signature: leaf.signature as Hex,
  });
}

/** 복원 주소가 leaf.gateway 와 같은지. 레지스트리 등록 여부는 별도 단계다. */
export async function verifyLeafSignature(leaf: Leaf, d: TypedDataDomain): Promise<boolean> {
  let recovered: Address;
  try {
    recovered = await recoverLeafSigner(leaf, d);
  } catch {
    return false;
  }
  return recovered.toLowerCase() === leaf.gateway.toLowerCase();
}

// ---------- 3. LogAck — 로그 운영자 ----------

export const LOG_ACK_TYPES = {
  LogAck: [
    { name: "leafHash", type: "bytes32" },
    { name: "receivedAt", type: "uint64" },
    { name: "promisedBy", type: "uint64" },
    { name: "logOperator", type: "address" },
  ],
} as const;

/**
 * 로그의 접수 확인증.
 *
 * promised_by 가 서명된 편입 기한이다. 그 시각이 지나도 포함 증명이 없으면
 * 로그가 자기 서명을 어긴 것이다. 누락 탐지가 여기 걸려 있다.
 */
export interface LogAck {
  leaf_hash: Hex;
  received_at: number;
  /** 편입 기한. */
  promised_by: number;
  log_operator: Address;
  log_signature: Hex;
}

export type LogAckBody = Omit<LogAck, "log_signature">;

function ackMessage(a: LogAckBody) {
  if (a.promised_by < a.received_at) {
    throw new SignatureError("promised_by 가 received_at 보다 이르다");
  }
  return {
    leafHash: a.leaf_hash,
    receivedAt: BigInt(a.received_at),
    promisedBy: BigInt(a.promised_by),
    logOperator: a.log_operator,
  };
}

export async function signLogAck(
  body: LogAckBody,
  account: Account,
  d: TypedDataDomain,
): Promise<LogAck> {
  if (!account.signTypedData) {
    throw new SignatureError("서명할 수 없는 계정");
  }
  const log_signature = await account.signTypedData({
    domain: d,
    types: LOG_ACK_TYPES,
    primaryType: "LogAck",
    message: ackMessage(body),
  });
  return { ...body, log_signature };
}

/**
 * expectedOperator 는 컨트랙트의 logOperator 다. immutable 이라 과거 확인증의
 * 검증이 현재 상태에 흔들리지 않는다.
 */
export async function verifyLogAck(
  ack: LogAck,
  expectedOperator: Address,
  d: TypedDataDomain,
): Promise<boolean> {
  // 번들에서 온 값이라 모양을 믿을 수 없다. 예외가 새면 검증이 크래시한다.
  if (!ack || typeof ack.log_operator !== "string" || typeof ack.log_signature !== "string") {
    return false;
  }
  if (ack.log_operator.toLowerCase() !== expectedOperator.toLowerCase()) return false;
  let recovered: Address;
  try {
    recovered = await recoverTypedDataAddress({
      domain: d,
      types: LOG_ACK_TYPES,
      primaryType: "LogAck",
      message: ackMessage(ack),
      signature: ack.log_signature,
    });
  } catch {
    return false;
  }
  return recovered.toLowerCase() === expectedOperator.toLowerCase();
}

export { ZERO32 };
