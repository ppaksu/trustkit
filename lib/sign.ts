// EIP-712 구조화 서명. 명세 docs/DESIGN.md 4.3절.
//
// 도메인 상수는 이 파일에서만 관리한다. `name` 은 프로토콜 식별자이지
// 프로젝트 이름이 아니다. 이 값을 바꾸면 그 이전에 발급한 영수증의 서명이
// 전부 검증에 실패한다. EIP-712 명세가 "서로 다른 버전의 서명은 호환되지
// 않는다"고 규정하기 때문이다.
import {
  hashTypedData,
  recoverTypedDataAddress,
  type Address,
  type Hex,
  type TypedDataDomain,
} from "viem";
import type { Account } from "viem/accounts";
import { keysRoot, fieldsRoot, validateLeafStructure, type Leaf, type LeafBody } from "./record.ts";

/** 프로토콜 식별자. 프로젝트명과 분리한다. */
export const DOMAIN_NAME = "TRUST404 Rejection Log";
export const DOMAIN_VERSION = "1";

export class SignatureError extends Error {}

/**
 * 서명 도메인.
 *
 * `chainId` 와 `verifyingContract` 가 여기 들어가는 것이 교차 체인 재사용과
 * 동일 코드 배포본 간 재사용을 막는 장치다. 둘 중 하나라도 빼면 같은 서명이
 * 다른 체인이나 다른 배포본에서 그대로 유효해진다.
 */
export function domain(chainId: number, verifyingContract: Address): TypedDataDomain {
  return {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId,
    verifyingContract,
  };
}

export const REJECTION_TYPES = {
  RejectionRecord: [
    { name: "schemaVersion", type: "uint8" },
    { name: "gatekeeper", type: "address" },
    { name: "policyHash", type: "bytes32" },
    { name: "keysRoot", type: "bytes32" },
    { name: "fieldsRoot", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

export const LOG_ACK_TYPES = {
  LogAck: [
    { name: "leafHash", type: "bytes32" },
    { name: "receivedAt", type: "uint64" },
    { name: "promisedBy", type: "uint64" },
    { name: "logOperator", type: "address" },
  ],
} as const;

const hex32 = (b: Buffer): Hex => `0x${b.toString("hex")}`;

/**
 * 리프에서 서명 대상 메시지를 만든다.
 *
 * `keysRoot` 와 `fieldsRoot` 를 항상 리프에서 **재계산**한다. 호출부가 이 값을
 * 따로 넘길 수 있는 경로가 없다. 클라이언트가 제출한 루트를 그대로 쓰면
 * 서명이 실제 필드와 무관해진다.
 */
function rejectionMessage(leaf: Leaf | LeafBody) {
  validateLeafStructure(leaf);
  return {
    schemaVersion: leaf.v,
    gatekeeper: leaf.gatekeeper as Address,
    policyHash: leaf.policy_hash as Hex,
    keysRoot: hex32(keysRoot(leaf.keys)),
    fieldsRoot: hex32(fieldsRoot(leaf.field_hashes)),
    issuedAt: BigInt(leaf.issued_at),
    nonce: leaf.nonce as Hex,
  };
}

/** 서명 digest. 두 체인에서 서로 다른 값이 나오는 이유가 도메인 절반이다. */
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

/** 서명자 주소를 복구한다. 리프의 `gatekeeper` 와 비교하는 것은 호출부의 몫이다. */
export async function recoverLeafSigner(leaf: Leaf, d: TypedDataDomain): Promise<Address> {
  return recoverTypedDataAddress({
    domain: d,
    types: REJECTION_TYPES,
    primaryType: "RejectionRecord",
    message: rejectionMessage(leaf),
    signature: leaf.signature as Hex,
  });
}

/**
 * 검증 2단계. 서명이 유효하고 복구된 주소가 `leaf.gatekeeper` 와 일치하는가.
 * 게이트키퍼가 레지스트리에 등록되었는지는 3단계에서 따로 확인한다.
 */
export async function verifyLeafSignature(leaf: Leaf, d: TypedDataDomain): Promise<boolean> {
  let recovered: Address;
  try {
    recovered = await recoverLeafSigner(leaf, d);
  } catch {
    return false;
  }
  return recovered.toLowerCase() === leaf.gatekeeper.toLowerCase();
}

// ---------- LogAck ----------

export interface LogAck {
  leaf_hash: Hex;
  received_at: number;
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
 * 검증 4단계. 접수 확인의 서명자가 배포 시 고정된 로그 운영자와 일치하는가.
 *
 * `expectedOperator` 는 앵커 컨트랙트의 `logOperator` 다. 그 값이 `immutable`
 * 이므로 과거 접수 확인의 검증이 현재 상태에 의존하지 않는다.
 */
export async function verifyLogAck(
  ack: LogAck,
  expectedOperator: Address,
  d: TypedDataDomain,
): Promise<boolean> {
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
