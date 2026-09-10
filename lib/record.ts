// 거절 기록의 리프 구성과 필드 커밋. 명세 docs/DESIGN.md 4장.
import { createHash, randomBytes } from "node:crypto";
import { canonicalize, canonicalBytes, type JsonValue } from "./jcs.ts";

const sha256 = (...parts: Buffer[]): Buffer =>
  createHash("sha256").update(Buffer.concat(parts)).digest();

const PREFIX_LEAF = Buffer.from([0x00]);

/** 필드 커밋의 도메인 분리자. 다른 해시 용도와 입력 공간을 나눈다. */
const FIELD_DOMAIN = "TRUST404/field/v1|";

export const SCHEMA_VERSION = 1;

/**
 * schemaVersion 이 필수 키 집합을 고정한다. 사전순 정렬이며 이 순서가 곧
 * `field_hashes` 의 순서다. 게이트키퍼가 키를 빼면 검증 1단계에서 걸린다.
 */
export const REQUIRED_KEYS: Record<number, readonly string[]> = {
  1: ["calldata_hash", "requester", "rule_id", "severity", "target", "value"],
};

/** 요청자만 보관한다. 로그에는 이 값의 해시만 올라간다. */
export type Disclosure = [saltHex: string, key: string, value: string];

export interface Leaf {
  v: number;
  gatekeeper: string;
  policy_hash: string;
  keys: string[];
  field_hashes: string[];
  issued_at: number;
  nonce: string;
  signature: string;
}

/** 서명 전 리프. `signature` 만 빠져 있다. */
export type LeafBody = Omit<Leaf, "signature">;

export class RecordError extends Error {}

const hex = (b: Buffer) => "0x" + b.toString("hex");

function fromHex(s: string, what: string): Buffer {
  if (!/^0x[0-9a-f]*$/.test(s) || s.length % 2 !== 0) {
    throw new RecordError(`16진 문자열이 아님 (${what}): ${s}`);
  }
  return Buffer.from(s.slice(2), "hex");
}

/**
 * 필드 하나의 커밋.
 *
 *   h = SHA256("TRUST404/field/v1|" + canonical_json([saltHex, key, value]))
 *
 * salt 가 있으므로 값 공간이 작아도 사전 대입으로 복원되지 않는다.
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

/** 서명 대상에 들어가는 키 집합 커밋. 키 누락을 서명에 묶는다. */
export function keysRoot(keys: readonly string[]): Buffer {
  return sha256(canonicalBytes(keys as JsonValue));
}

/** 서명 대상에 들어가는 필드 커밋 묶음. 순서는 `keys` 와 같다. */
export function fieldsRoot(fieldHashes: readonly string[]): Buffer {
  return sha256(Buffer.concat(fieldHashes.map((h) => fromHex(h, "field_hash"))));
}

export interface BuildInput {
  gatekeeper: string;
  policyHash: string;
  /** 필수 키 집합과 정확히 일치해야 한다. */
  fields: Record<string, string>;
  issuedAt: number;
  schemaVersion?: number;
}

/**
 * 리프 본문과 disclosure 를 만든다. salt 는 필드마다 새로 뽑는다.
 * `field_hashes[i]` 가 `keys[i]` 의 커밋이 되도록 위치를 묶는다.
 */
export function buildLeafBody(
  input: BuildInput,
): { body: LeafBody; disclosures: Disclosure[] } {
  const v = input.schemaVersion ?? SCHEMA_VERSION;
  const required = REQUIRED_KEYS[v];
  if (!required) throw new RecordError(`알 수 없는 schemaVersion: ${v}`);

  const given = Object.keys(input.fields).sort();
  if (given.length !== required.length || given.some((k, i) => k !== required[i])) {
    throw new RecordError(
      `필수 키 집합 불일치. 필요: [${required.join(", ")}] 받음: [${given.join(", ")}]`,
    );
  }

  const disclosures: Disclosure[] = required.map((k) => [
    hex(randomBytes(32)),
    k,
    input.fields[k],
  ]);

  const body: LeafBody = {
    v,
    gatekeeper: input.gatekeeper,
    policy_hash: input.policyHash,
    keys: [...required],
    field_hashes: disclosures.map((d) => hex(fieldCommitment(d))),
    issued_at: input.issuedAt,
    nonce: hex(randomBytes(32)),
  };
  return { body, disclosures };
}

/**
 * 리프의 구조를 검증한다. 접수 검증 1번과 4번, 검증 1단계가 이 함수를 쓴다.
 * 서명 검증은 sign.ts 의 몫이다.
 */
export function validateLeafStructure(leaf: Leaf | LeafBody): void {
  const required = REQUIRED_KEYS[leaf.v];
  if (!required) throw new RecordError(`알 수 없는 schemaVersion: ${leaf.v}`);

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
  for (const h of leaf.field_hashes) {
    if (fromHex(h, "field_hash").length !== 32) {
      throw new RecordError(`필드 커밋이 32바이트가 아님: ${h}`);
    }
  }
  if (!Number.isSafeInteger(leaf.issued_at) || leaf.issued_at < 0) {
    throw new RecordError(`issued_at 이 유효하지 않음: ${leaf.issued_at}`);
  }
  if (fromHex(leaf.nonce, "nonce").length !== 32) {
    throw new RecordError("nonce 는 32바이트여야 함");
  }
}

/**
 * 리프 해시. 접두사 0x00 이 내부 노드와 입력 공간을 분리한다.
 * 서명까지 포함한 완성된 리프에 대해 계산한다.
 */
export function leafHash(leaf: Leaf): Buffer {
  return sha256(PREFIX_LEAF, canonicalBytes(leaf as unknown as JsonValue));
}

/**
 * 선택적 공개 검증. 검증 7단계.
 *
 * 집합 포함이 아니라 위치 대조라는 점이 핵심이다. 게이트키퍼가 어떤 키 자리에
 * 다른 값을 커밋했다면 그 자리의 해시가 안 맞는다. 요청자가 전체를 공개할
 * 필요 없이 문제 필드 하나만으로 드러난다.
 */
export function verifyDisclosure(leaf: Leaf | LeafBody, d: Disclosure): boolean {
  const [, key] = d;
  const i = leaf.keys.indexOf(key);
  if (i < 0) return false;
  const expected = leaf.field_hashes[i];
  if (expected === undefined) return false;
  return fieldCommitment(d).equals(fromHex(expected, "field_hash"));
}
