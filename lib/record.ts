// 거절 기록의 리프 구조와 필드 커밋.
//
// 원문은 로그에 올리지 않는다. 필드마다 난수를 섞어 해시한 커밋만 올린다.
// 난수가 필드마다 달라야 한다. severity 는 값이 셋뿐이라 난수 없이 해시하면
// 바로 역산되고, 난수가 공통이면 값이 같은 레코드끼리 연결된다.
import { createHash, randomBytes } from "node:crypto";
import { canonicalize, canonicalBytes, type JsonValue } from "./jcs.ts";

const sha256 = (...parts: Buffer[]): Buffer =>
  createHash("sha256").update(Buffer.concat(parts)).digest();

const PREFIX_LEAF = Buffer.from([0x00]);

/** 필드 커밋의 도메인 분리자. 다른 해시 용도와 입력 공간을 나눈다. */
const FIELD_DOMAIN = "neglog/field/v1|";

export const SCHEMA_VERSION = 2;

export const ZERO32 = "0x" + "00".repeat(32);

/** decision 은 거절 판단, policy_update 는 참조 목록 갱신. 같은 로그에 쌓인다. */
export type LeafType = "decision" | "policy_update";

/** 사유를 기계가 검증할 수 있는 부류인지. 봉인하지 않는다. SEALED_KEYS 참고. */
export type Verifiability = "verifiable" | "external" | "discretionary";

/**
 * 거절의 심각도. 통과는 여기 없다.
 *
 * 이 로그가 다루는 것은 거절뿐이다. 통과한 요청은 아무 기록도 남기지 않는다.
 * 트랙이 요구하는 것이 "체인에 남지 않는 차단·거절 행위의 기록과 증명" 이고,
 * 통과는 체인에 트랜잭션으로 남으므로 이 로그가 채울 공백이 아니다.
 */
export type Severity = "block" | "hold" | "review";

export const VERIFIABILITY_VALUES: readonly Verifiability[] = [
  "verifiable",
  "external",
  "discretionary",
];
export const SEVERITY_VALUES: readonly Severity[] = ["block", "hold", "review"];

/**
 * 필수 키. 사전순 고정이고 이 순서가 그대로 field_hashes 의 순서다.
 * 목록 자체도 서명에 들어가므로 필드를 빼면 서명이 안 맞는다.
 */
export const REQUIRED_KEYS: Record<number, Record<LeafType, readonly string[]>> = {
  2: {
    decision: [
      "calldata_hash",
      "requester",
      "rule_id",
      "severity",
      "target",
      "value",
      "verifiability",
    ],
    // 참조 데이터 갱신은 필드 커밋을 갖지 않는다. 갱신 내용은 policy_data_root 다.
    policy_update: [],
  },
};

/**
 * 봉인 대상. 요청자가 열기 전까지 원문이 어디에도 없다.
 *
 * verifiability 가 빠져 있는 게 의도다. 공개돼야 기관이 검증 불가 사유 뒤에
 * 숨는 비율을 외부에서 셀 수 있다.
 */
export const SEALED_KEYS: ReadonlySet<string> = new Set([
  "requester",
  "rule_id",
  "target",
  "value",
]);

/** [난수, 키, 값]. 요청자만 보관한다. 로그에는 이걸 해시한 값만 올라간다. */
export type Disclosure = [saltHex: string, key: string, value: string];

export interface Leaf {
  v: number;
  type: LeafType;
  gateway: string;
  policy_hash: string;
  /** 참조 데이터의 정렬 머클 루트. 없으면 ZERO32. */
  policy_data_root: string;
  keys: string[];
  field_hashes: string[];
  /** 요청자 의도 구조체의 EIP-712 digest. 요청자 서명이 없으면 ZERO32. */
  request_intent_hash: string;
  requester_sig_hash: string;
  /** 판단 기준 블록. 동적 사유가 없으면 0. */
  decided_at_block: number;
  /** 그 블록 헤더의 stateRoot. 없으면 ZERO32. */
  state_root: string;
  /** 상태 증거 묶음의 커밋. 없으면 ZERO32. */
  state_proof_root: string;
  issued_at: number;
  nonce: string;
  signature: string;
}

/** 서명 전 리프. `signature` 만 빠져 있다. */
export type LeafBody = Omit<Leaf, "signature">;

export class RecordError extends Error {}

const hex = (b: Buffer) => "0x" + b.toString("hex");

function fromHex(s: string, what: string): Buffer {
  if (typeof s !== "string" || !/^0x[0-9a-f]*$/.test(s) || s.length % 2 !== 0) {
    throw new RecordError(`16진 문자열이 아님 (${what}): ${s}`);
  }
  return Buffer.from(s.slice(2), "hex");
}

function need32(s: string, what: string): void {
  if (fromHex(s, what).length !== 32) throw new RecordError(`${what} 는 32바이트여야 함: ${s}`);
}

/**
 * h = SHA256(FIELD_DOMAIN + JCS([salt, key, value]))
 *
 * 접두사는 도메인 분리자. 다른 용도로 만든 해시를 여기 끼워넣지 못하게 한다.
 */
export function fieldCommitment(d: Disclosure): Buffer {
  const [saltHex, key, value] = d;
  const salt = fromHex(saltHex, "salt");
  if (salt.length !== 32) {
    throw new RecordError(`salt 는 32바이트여야 함: ${salt.length}`);
  }
  const body = canonicalize([saltHex, key, value] as JsonValue);
  return sha256(Buffer.from(FIELD_DOMAIN + body, "utf8"));
}

/**
 * 키 집합 커밋. 서명에 들어가 필드 누락을 막는다.
 *
 * 이 값이 leaf type 도 분리한다. decision 은 키 7개, policy_update 는 0개라
 * 절대 겹치지 않는다. 서명 구조체에 type 이 없어도 혼동이 없는 이유다.
 */
export function keysRoot(keys: readonly string[]): Buffer {
  return sha256(canonicalBytes(keys as JsonValue));
}

/** 필드 커밋 묶음. 순서는 keys 와 같다. */
export function fieldsRoot(fieldHashes: readonly string[]): Buffer {
  return sha256(Buffer.concat(fieldHashes.map((h) => fromHex(h, "field_hash"))));
}

export interface BuildInput {
  gateway: string;
  policyHash: string;
  /** 필수 키 집합과 정확히 일치해야 한다. */
  fields: Record<string, string>;
  issuedAt: number;
  type?: LeafType;
  policyDataRoot?: string;
  requestIntentHash?: string;
  requesterSigHash?: string;
  decidedAtBlock?: number;
  stateRoot?: string;
  stateProofRoot?: string;
  schemaVersion?: number;
}

/**
 * 리프 본문과 disclosure 를 만든다. salt 는 필드마다 새로 뽑는다.
 * field_hashes[i] 가 keys[i] 의 커밋이 되도록 위치를 묶는다.
 */
export function buildLeafBody(
  input: BuildInput,
): { body: LeafBody; disclosures: Disclosure[] } {
  const v = input.schemaVersion ?? SCHEMA_VERSION;
  const type = input.type ?? "decision";
  const required = REQUIRED_KEYS[v]?.[type];
  if (!required) throw new RecordError(`알 수 없는 schemaVersion 또는 type: ${v}/${type}`);

  const given = Object.keys(input.fields).sort();
  if (given.length !== required.length || given.some((k, i) => k !== required[i])) {
    throw new RecordError(
      `필수 키 집합 불일치. 필요: [${required.join(", ")}] 받음: [${given.join(", ")}]`,
    );
  }
  if (type === "decision") {
    if (!VERIFIABILITY_VALUES.includes(input.fields.verifiability as Verifiability)) {
      throw new RecordError(`verifiability 값이 유효하지 않음: ${input.fields.verifiability}`);
    }
    if (!SEVERITY_VALUES.includes(input.fields.severity as Severity)) {
      throw new RecordError(`severity 값이 유효하지 않음: ${input.fields.severity}`);
    }
  }

  const disclosures: Disclosure[] = required.map((k) => [
    hex(randomBytes(32)),
    k,
    input.fields[k],
  ]);

  const body: LeafBody = {
    v,
    type,
    gateway: input.gateway,
    policy_hash: input.policyHash,
    policy_data_root: input.policyDataRoot ?? ZERO32,
    keys: [...required],
    field_hashes: disclosures.map((d) => hex(fieldCommitment(d))),
    request_intent_hash: input.requestIntentHash ?? ZERO32,
    requester_sig_hash: input.requesterSigHash ?? ZERO32,
    decided_at_block: input.decidedAtBlock ?? 0,
    state_root: input.stateRoot ?? ZERO32,
    state_proof_root: input.stateProofRoot ?? ZERO32,
    issued_at: input.issuedAt,
    nonce: hex(randomBytes(32)),
  };
  return { body, disclosures };
}

/** 리프 구조 검증. 서명 검증은 sign.ts 의 몫이다. */
export function validateLeafStructure(leaf: Leaf | LeafBody): void {
  const byType = REQUIRED_KEYS[leaf.v];
  if (!byType) throw new RecordError(`알 수 없는 schemaVersion: ${leaf.v}`);
  const required = byType[leaf.type];
  if (!required) throw new RecordError(`알 수 없는 leaf type: ${leaf.type}`);

  if (leaf.keys.length !== required.length) {
    throw new RecordError(`키 개수 불일치: ${leaf.keys.length} != ${required.length}`);
  }
  for (let i = 0; i < required.length; i++) {
    if (leaf.keys[i] !== required[i]) {
      throw new RecordError(
        `키 불일치 또는 정렬 위반. 위치 ${i}: ${leaf.keys[i]} != ${required[i]}`,
      );
    }
  }
  if (leaf.field_hashes.length !== leaf.keys.length) {
    throw new RecordError(
      `field_hashes 길이가 keys 와 다름: ${leaf.field_hashes.length} != ${leaf.keys.length}`,
    );
  }
  for (const h of leaf.field_hashes) need32(h, "field_hash");

  need32(leaf.policy_hash, "policy_hash");
  need32(leaf.policy_data_root, "policy_data_root");
  need32(leaf.request_intent_hash, "request_intent_hash");
  need32(leaf.requester_sig_hash, "requester_sig_hash");
  need32(leaf.state_root, "state_root");
  need32(leaf.state_proof_root, "state_proof_root");

  if (!Number.isSafeInteger(leaf.decided_at_block) || leaf.decided_at_block < 0) {
    throw new RecordError(`decided_at_block 이 유효하지 않음: ${leaf.decided_at_block}`);
  }
  // 상태 증거를 커밋했으면 어느 블록의 상태인지가 있어야 한다.
  if (leaf.state_proof_root !== ZERO32 && leaf.decided_at_block === 0) {
    throw new RecordError("state_proof_root 가 있는데 decided_at_block 이 0");
  }
  if (!Number.isSafeInteger(leaf.issued_at) || leaf.issued_at < 0) {
    throw new RecordError(`issued_at 이 유효하지 않음: ${leaf.issued_at}`);
  }
  need32(leaf.nonce, "nonce");
}

/** 트리에 들어갈 리프 해시. 서명까지 포함한 리프에 대해 계산한다. */
export function leafHash(leaf: Leaf): Buffer {
  return sha256(PREFIX_LEAF, canonicalBytes(leaf as unknown as JsonValue));
}

/**
 * 공개된 원문이 그 자리의 커밋과 맞는지.
 *
 * 집합 포함이 아니라 **위치 대조**다. 그래서 문제 필드 하나만 공개해도 드러난다.
 */
export function verifyDisclosure(leaf: Leaf | LeafBody, d: Disclosure): boolean {
  const [, key] = d;
  const i = leaf.keys.indexOf(key);
  if (i < 0) return false;
  const expected = leaf.field_hashes[i];
  if (expected === undefined) return false;
  return fieldCommitment(d).equals(fromHex(expected, "field_hash"));
}

/** 공개된 값을 키로 찾는다. 없으면 그 단계는 판정 불가가 된다. */
export function disclosedValue(
  disclosures: readonly Disclosure[],
  key: string,
): string | undefined {
  return disclosures.find((d) => d[1] === key)?.[2];
}

// ---------- 정책 문서 ----------
//
// 규칙 내용은 기관 것을 그대로 쓴다. 프로토콜이 정하는 건 형식 네 가지뿐이다.
// 문서 해시 방법, 규칙 인용 방법, 술어 형태, 검증 불가 표시 방법.

/**
 * 술어. 있으면 검증기가 판정까지 하고, 없으면 규칙 실재 확인까지만 한다.
 *
 * in_set / not_in_set 은 정렬 머클 증명이나 목록 전체가 필요하다.
 * gt 는 한도가 규칙 안에 있어 외부 데이터 없이 판정된다.
 * state_slot 은 EIP-1186 상태 증거가 필요하다.
 */
export type Predicate =
  | { kind: "in_set"; field: string; set: string }
  | { kind: "not_in_set"; field: string; set: string }
  | { kind: "gt"; field: string; limit: string }
  | { kind: "state_slot"; account: string; slot: string; op: "lt" | "gte"; operand: string };

export interface PolicyRule {
  rule_id: string;
  description: string;
  severity: Severity;
  verifiability: Verifiability;
  predicate?: Predicate;
}

/** 이 객체 전체의 해시가 리프의 policy_hash 이며 서명에 묶인다. */
export interface PolicyDocument {
  version: number;
  /** 순서도 정책의 일부다. 먼저 일치하는 규칙이 이긴다. */
  rules: PolicyRule[];
  /** 술어가 가리키는 참조 목록. 실제 커밋은 리프의 policy_data_root 가 한다. */
  data_sets?: Record<string, string[]>;
}

export function policyHash(p: PolicyDocument): string {
  return hex(sha256(canonicalBytes(p as unknown as JsonValue)));
}

/** 인용한 규칙이 커밋된 문서에 실재하는지. */
export function findRule(p: PolicyDocument, ruleId: string): PolicyRule | undefined {
  return p.rules.find((r) => r.rule_id === ruleId);
}
