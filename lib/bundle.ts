// 번들 조립과 파싱.
//
// 자족성 원칙: 검증에 필요한 모든 것이 번들 안이거나 체인 위에 있어야 한다.
// 증명 수집은 거절 직후에 끝내고, 검증 시점에는 로그 서버가 꺼져 있어도 된다.
//
// 정책 문서를 동봉하는 이유. 해시가 서명에 묶여 체인에 고정돼 있으므로 문서는
// 어디서 받아도 된다. 커밋이 출처를 자유롭게 한다.
import type { Address, Hex } from "viem";
import {
  validateLeafStructure,
  leafHash,
  policyHash,
  ZERO32,
  type Disclosure,
  type Leaf,
  type PolicyDocument,
} from "./record.ts";
import type { LogAck, RequestIntent } from "./sign.ts";
import type { StateEvidence } from "./state-proof.ts";
import type { Receipt } from "./receipt.ts";
import type { ConsistencyProof, InclusionProof, PolicyUpdateProof, ProofSource } from "./verify.ts";

export type { PolicyUpdateProof };

export class BundleError extends Error {}

/** 검증자가 읽을 체인과 컨트랙트. 서명 도메인도 이 둘에서 나온다. */
export interface AnchorRef {
  chain_id: number;
  address: Address;
}

/** 로그가 내주는 증명 절반. 리프도 서명도 들어 있지 않다. */
export interface ProofHalf {
  inclusion_proof: InclusionProof;
  consistency_proof: ConsistencyProof | null;
}

/**
 * 헤더는 RLP 가 아니라 필드 객체로 담는다. RLP 는 거기서 다시 만들 수 있고,
 * 파생값을 같이 넣으면 진실이 둘이 된다.
 */
export type StateProofBlob = StateEvidence;

export interface Bundle {
  v: 2;
  leaf: Leaf;
  leaf_hash: Hex;
  request_intent: RequestIntent | null;
  request_sig: Hex | null;
  disclosures: Disclosure[];
  log_ack: LogAck;
  inclusion_proof: InclusionProof;
  consistency_proof: ConsistencyProof | null;
  policy_document: PolicyDocument | null;
  policy_update: PolicyUpdateProof | null;
  state_proof: StateProofBlob | null;
  anchor: AnchorRef;
}

export interface AssembleInput {
  receipt: Receipt;
  proofs: ProofHalf;
  anchor: AnchorRef;
  /** 정책 문서 원문. */
  policy?: PolicyDocument;
  policyUpdate?: PolicyUpdateProof;
  stateProof?: StateProofBlob;
  /** 생략하면 영수증의 disclosure 를 전부 넣는다. */
  discloseKeys?: readonly string[];
  /**
   * 의도 구조체에는 target·value·requester 가 원문으로 들어 있다. 그 셋을
   * 봉인해놓고 의도를 같이 넣으면 봉인이 무의미해진다. false 로 두면 봉인이
   * 유지되는 대신 검증 4단계가 판정 불가가 된다.
   */
  includeIntent?: boolean;
}

/** 의도 구조체가 원문으로 드러내는 필드. */
export const INTENT_REVEALS: readonly string[] = ["requester", "target", "value"];

/**
 * 번들을 만든다. 무엇을 열지는 요청자가 정한다.
 *
 * 조립 전에 불변식을 확인한다. 여기서 안 걸러내면 나중에 검증기에서 실패하는데,
 * 그때는 조립이 잘못된 건지 기록이 잘못된 건지 구분이 안 된다.
 */
export function assembleBundle(i: AssembleInput): Bundle {
  const { receipt } = i;
  if (!receipt.log_ack) {
    throw new BundleError("접수 확인이 없다. 게이트웨이가 로그에 제출하지 않았다");
  }
  validateLeafStructure(receipt.leaf);

  const computed = `0x${leafHash(receipt.leaf).toString("hex")}`;
  if (computed !== receipt.leaf_hash.toLowerCase()) {
    throw new BundleError(`leaf_hash 가 리프와 맞지 않는다: ${receipt.leaf_hash}`);
  }
  if (i.policy && policyHash(i.policy) !== receipt.leaf.policy_hash) {
    throw new BundleError("정책 문서 해시가 리프 커밋과 다르다");
  }

  const disclosures = i.discloseKeys
    ? receipt.disclosures.filter((d) => i.discloseKeys!.includes(d[1]))
    : [...receipt.disclosures];

  const withIntent = i.includeIntent ?? true;

  return {
    v: 2,
    leaf: receipt.leaf,
    leaf_hash: receipt.leaf_hash,
    request_intent: withIntent ? receipt.request_intent ?? null : null,
    request_sig: withIntent ? receipt.request_sig ?? null : null,
    disclosures,
    log_ack: receipt.log_ack,
    inclusion_proof: i.proofs.inclusion_proof,
    consistency_proof: i.proofs.consistency_proof,
    policy_document: i.policy ?? null,
    policy_update: i.policyUpdate ?? null,
    state_proof: i.stateProof ?? null,
    anchor: i.anchor,
  };
}

export function serializeBundle(b: Bundle): string {
  return JSON.stringify(b, null, 2);
}

/**
 * 형태만 검증한다. 참거짓은 verify.ts 가 정한다.
 *
 * 검증 도구가 낯선 파일을 먹으므로, 형태가 깨졌을 때 11단계 중간에서 죽지
 * 않도록 먼저 막는다.
 */
export function parseBundle(text: string): Bundle {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new BundleError(`JSON 파싱 실패: ${(e as Error).message}`);
  }
  const b = raw as Bundle;
  if (!b || typeof b !== "object") throw new BundleError("번들이 객체가 아니다");
  if (b.v !== 2) throw new BundleError(`알 수 없는 번들 버전: ${b.v}`);

  for (const k of ["leaf", "leaf_hash", "log_ack", "inclusion_proof", "anchor"] as const) {
    if (b[k] === undefined || b[k] === null) throw new BundleError(`${k} 가 없다`);
  }
  if (typeof b.leaf_hash !== "string") throw new BundleError("leaf_hash 가 문자열이 아니다");
  if (!Array.isArray(b.disclosures)) throw new BundleError("disclosures 가 배열이 아니다");
  for (const d of b.disclosures) {
    if (!Array.isArray(d) || d.length !== 3 || d.some((x) => typeof x !== "string")) {
      throw new BundleError("disclosure 는 [salt, key, value] 문자열 세 쌍이어야 한다");
    }
  }

  const ack = b.log_ack as Partial<LogAck> | undefined;
  if (
    typeof ack?.leaf_hash !== "string" ||
    typeof ack.log_operator !== "string" ||
    typeof ack.log_signature !== "string" ||
    !Number.isSafeInteger(ack.received_at) ||
    !Number.isSafeInteger(ack.promised_by)
  ) {
    throw new BundleError("log_ack 의 모양이 올바르지 않다");
  }

  try {
    validateLeafStructure(b.leaf);
  } catch (e) {
    throw new BundleError(`리프 구조가 깨졌다: ${(e as Error).message}`);
  }

  // leaf_hash 는 번들이 준 값을 믿지 않고 재계산한다. 믿으면 본문은 A 로 적고
  // 해시는 트리에 있는 B 로 적어, 포함 증명은 B 로 통과하는데 사람은 A 를 읽는다.
  const computed = `0x${leafHash(b.leaf).toString("hex")}` as Hex;
  if (computed !== b.leaf_hash.toLowerCase()) {
    throw new BundleError(`leaf_hash 가 리프와 맞지 않는다: ${b.leaf_hash} != ${computed}`);
  }

  // 선택 필드들도 모양을 본다. 여기서 안 막으면 11단계 중간에서 TypeError 로
  // 죽는다. 검증 도구는 낯선 파일을 먹으므로 전부 통과하거나 전부 거절해야 한다.
  const proofShape = (p: unknown): boolean =>
    !!p &&
    typeof p === "object" &&
    Number.isSafeInteger((p as InclusionProof).index) &&
    Number.isSafeInteger((p as InclusionProof).anchor?.tree_size) &&
    Array.isArray((p as InclusionProof).audit_path) &&
    (p as InclusionProof).audit_path.every((x) => typeof x === "string");

  if (b.consistency_proof !== null && b.consistency_proof !== undefined) {
    const c = b.consistency_proof as Partial<ConsistencyProof>;
    if (
      !Number.isSafeInteger(c.from_anchor?.tree_size) ||
      !Number.isSafeInteger(c.to_anchor?.tree_size) ||
      !Array.isArray(c.path) ||
      c.path.some((x) => typeof x !== "string")
    ) {
      throw new BundleError("consistency_proof 의 모양이 올바르지 않다");
    }
  } else {
    b.consistency_proof = null;
  }

  if (b.policy_update !== null && b.policy_update !== undefined) {
    const u = b.policy_update as Partial<PolicyUpdateProof>;
    if (typeof u.leaf_hash !== "string" || !u.leaf || !proofShape(u.inclusion_proof)) {
      throw new BundleError("policy_update 의 모양이 올바르지 않다");
    }
    try {
      validateLeafStructure(u.leaf);
    } catch (e) {
      throw new BundleError(`policy_update 리프 구조가 깨졌다: ${(e as Error).message}`);
    }
    if (typeof u.leaf.gateway !== "string") {
      throw new BundleError("policy_update 리프의 gateway 가 문자열이 아니다");
    }
  } else {
    b.policy_update = null;
  }

  if (!proofShape(b.inclusion_proof)) {
    throw new BundleError("inclusion_proof 의 모양이 올바르지 않다");
  }

  const a = b.anchor;
  if (!Number.isSafeInteger(a?.chain_id) || !/^0x[0-9a-fA-F]{40}$/.test(a?.address ?? "")) {
    throw new BundleError("anchor 의 chain_id 나 address 가 유효하지 않다");
  }
  return b;
}

/** 검증기가 먹는 영수증 부분만 꺼낸다. */
export function receiptOf(b: Bundle): Receipt {
  return {
    leaf: b.leaf,
    leaf_hash: b.leaf_hash,
    disclosures: b.disclosures,
    log_ack: b.log_ack,
    request_intent: b.request_intent ?? undefined,
    request_sig: b.request_sig ?? undefined,
  };
}

/** 번들 안의 증명만 쓴다. 네트워크 호출이 한 줄도 없다. */
export function bundleProofSource(b: Bundle): ProofSource {
  return {
    async inclusion(h) {
      if (h.toLowerCase() !== b.leaf_hash.toLowerCase()) {
        throw new BundleError("번들에 없는 리프의 포함 증명을 요구했다");
      }
      return b.inclusion_proof;
    },
    async consistency(from, to) {
      const c = b.consistency_proof;
      if (!c || c.from_anchor.tree_size !== from || c.to_anchor.tree_size !== to) {
        throw new BundleError(`번들에 ${from} → ${to} 일관성 증명이 없다`);
      }
      return c;
    },
    async laterAnchorThan(treeSize) {
      const c = b.consistency_proof;
      if (!c || c.to_anchor.tree_size <= treeSize) return null;
      return c.to_anchor.tree_size;
    },
  };
}

/** 검증 도구가 보고서 앞에 찍는 요약. 봉인 필드가 의도로 새면 경고를 붙인다. */
export function describeBundle(b: Bundle): string {
  const open = b.disclosures.map((d) => d[1]).sort();
  const sealed = b.leaf.keys.filter((k) => !open.includes(k));
  // 의도 구조체가 봉인했다고 믿는 필드를 원문으로 흘리고 있으면 알린다.
  const leaked = b.request_intent ? sealed.filter((k) => INTENT_REVEALS.includes(k)) : [];
  return [
    `  리프          ${b.leaf_hash}`,
    `  게이트웨이    ${b.leaf.gateway}`,
    `  앵커          chain ${b.anchor.chain_id} @ ${b.anchor.address}`,
    `  트리 크기     ${b.inclusion_proof.anchor.tree_size} (인덱스 ${b.inclusion_proof.index})`,
    `  공개 필드     ${open.length ? open.join(", ") : "없음"}`,
    `  봉인 필드     ${sealed.length ? sealed.join(", ") : "없음"}`,
    `  정책 문서     ${b.policy_document ? "동봉" : "없음"}`,
    `  목록 갱신     ${b.policy_update ? `리프 ${b.policy_update.inclusion_proof.index} 에 공표됨` : "없음"}`,
    `  상태 증거     ${b.state_proof ? `블록 ${b.state_proof.block_number}` : "없음"}`,
    `  요청자 서명   ${b.request_sig ? "있음" : "없음"}`,
    leaked.length
      ? `  주의          의도 구조체가 봉인 필드를 원문으로 드러냄: ${leaked.join(", ")}`
      : null,
    b.leaf.state_proof_root === ZERO32 ? null : `  상태 커밋     ${b.leaf.state_proof_root}`,
  ]
    .filter((x): x is string => x !== null)
    .join("\n");
}
