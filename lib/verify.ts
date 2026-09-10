// 검증 절차. 명세 docs/DESIGN.md 8장.
//
// 검증자는 게이트키퍼도 로그 서버도 신뢰하지 않는다. 서명은 공개키로 확인하고,
// 앵커는 체인에서 직접 읽는다. 로그 서버가 준 앵커는 참고값일 뿐이다.
import type { Address, Hex, TypedDataDomain } from "viem";
import { keysRoot, fieldsRoot, validateLeafStructure, leafHash, REQUIRED_KEYS } from "./record.ts";
import { verifyLeafSignature, verifyLogAck } from "./sign.ts";
import { rootFromInclusionProof, verifyConsistency } from "./merkle.ts";
import { assignFault, type Fault, type Receipt } from "./receipt.ts";

export interface StepResult {
  step: number;
  name: string;
  ok: boolean;
  detail: string;
}

/** 검증자가 체인에서 직접 읽는 것들. */
export interface VerifyChain {
  isRegistered(gatekeeper: Address): Promise<boolean>;
  rootByTreeSize(treeSize: number): Promise<Hex>;
  logOperator(): Promise<Address>;
}

export interface InclusionProof {
  anchor: { tree_size: number; root: Hex };
  index: number;
  audit_path: Hex[];
}

export interface ConsistencyProof {
  from_anchor: { tree_size: number; root: Hex };
  to_anchor: { tree_size: number; root: Hex };
  path: Hex[];
}

/** 증명 공급자. HTTP 클라이언트나 저장소 직접 접근 모두 끼울 수 있다. */
export interface ProofSource {
  inclusion(leafHash: Hex): Promise<InclusionProof>;
  consistency(from: number, to: number): Promise<ConsistencyProof>;
  /** 일관성 검증에 쓸 더 나중 앵커. 없으면 6단계를 건너뛴다. */
  laterAnchorThan?(treeSize: number): Promise<number | null>;
}

export interface VerifyOptions {
  receipt: Receipt;
  domain: TypedDataDomain;
  chain: VerifyChain;
  proofs: ProofSource;
  now?: () => number;
}

export interface VerifyReport {
  ok: boolean;
  steps: StepResult[];
  fault: Fault;
  /** 처음 실패한 단계. 공격 시연이 이 값을 가리킨다. */
  failedAt: number | null;
}

const ZERO32 = "0x" + "00".repeat(32);
const unhex = (s: string) => Buffer.from(s.replace(/^0x/, ""), "hex");

export async function verifyReceipt(o: VerifyOptions): Promise<VerifyReport> {
  const now = (o.now ?? (() => Math.floor(Date.now() / 1000)))();
  const { receipt, domain, chain, proofs } = o;
  const leaf = receipt.leaf;
  const steps: StepResult[] = [];
  let hasInclusion = false;

  const add = (step: number, name: string, ok: boolean, detail: string) => {
    steps.push({ step, name, ok, detail });
    return ok;
  };

  // 1. keys 집합 확인 + 두 루트 재계산
  try {
    validateLeafStructure(leaf);
    const required = REQUIRED_KEYS[leaf.v];
    const same = required.length === leaf.keys.length && required.every((k, i) => k === leaf.keys[i]);
    if (!same) throw new Error("필수 키 집합 불일치");
    keysRoot(leaf.keys);
    fieldsRoot(leaf.field_hashes);
    add(1, "필드 집합과 커밋 루트", true, `키 ${leaf.keys.length}개, 누락 없음`);
  } catch (e) {
    add(1, "필드 집합과 커밋 루트", false, `필드 누락 또는 버전 불일치: ${(e as Error).message}`);
    return finish(steps, receipt, false, now);
  }

  // 2. EIP-712 서명 복원
  const sigOk = await verifyLeafSignature(leaf, domain);
  if (!add(2, "게이트키퍼 서명", sigOk, sigOk ? `${leaf.gatekeeper} 로 복원됨` : "위조된 영수증")) {
    return finish(steps, receipt, false, now);
  }

  // 3. 온체인 레지스트리 등록
  const registered = await chain.isRegistered(leaf.gatekeeper as Address);
  if (!add(3, "레지스트리 등록", registered, registered ? "등록된 게이트키퍼" : "신뢰할 수 없는 발급자")) {
    return finish(steps, receipt, false, now);
  }

  // 4. LogAck 서명
  if (!receipt.log_ack) {
    add(4, "로그 접수 확인", false, "접수 확인이 없음. 게이트키퍼가 제출하지 않았다");
    return finish(steps, receipt, false, now);
  }
  const operator = await chain.logOperator();
  const ackOk = await verifyLogAck(receipt.log_ack, operator, domain);
  if (!add(4, "로그 접수 확인", ackOk, ackOk ? `운영자 ${operator}` : "접수 확인 서명이 유효하지 않음")) {
    return finish(steps, receipt, false, now);
  }

  // 5. 체인에서 루트를 직접 읽고 포함 증명과 대조
  let anchoredSize: number | null = null;
  try {
    const p = await proofs.inclusion(receipt.leaf_hash);
    const chainRoot = await chain.rootByTreeSize(p.anchor.tree_size);
    if (chainRoot === ZERO32) throw new Error(`tree_size ${p.anchor.tree_size} 가 체인에 앵커되지 않음`);

    const recomputed = rootFromInclusionProof(
      p.index,
      p.anchor.tree_size,
      leafHash(leaf),
      p.audit_path.map(unhex),
    );
    const match = recomputed !== null && `0x${recomputed.toString("hex")}` === chainRoot.toLowerCase();
    hasInclusion = match;
    anchoredSize = p.anchor.tree_size;
    if (!add(5, "포함 증명", match, match ? `체인 루트와 일치, tree_size=${p.anchor.tree_size}` : "체인 루트로 재계산되지 않음")) {
      return finish(steps, receipt, false, now);
    }
  } catch (e) {
    add(5, "포함 증명", false, `누락 또는 삭제 가능성: ${(e as Error).message}`);
    return finish(steps, receipt, false, now);
  }

  // 6. 두 앵커 사이 일관성
  const later = proofs.laterAnchorThan ? await proofs.laterAnchorThan(anchoredSize!) : null;
  if (later === null) {
    add(6, "일관성 증명", true, "비교할 나중 앵커가 없어 건너뜀");
  } else {
    try {
      const c = await proofs.consistency(anchoredSize!, later);
      const oldRoot = await chain.rootByTreeSize(c.from_anchor.tree_size);
      const newRoot = await chain.rootByTreeSize(c.to_anchor.tree_size);
      const consistent = verifyConsistency(
        c.from_anchor.tree_size,
        c.to_anchor.tree_size,
        unhex(oldRoot),
        unhex(newRoot),
        c.path.map(unhex),
      );
      if (!add(6, "일관성 증명", consistent, consistent ? `${c.from_anchor.tree_size} → ${c.to_anchor.tree_size} 순수 확장` : "역사 조작 또는 비순차 확장")) {
        return finish(steps, receipt, hasInclusion, now);
      }
    } catch (e) {
      add(6, "일관성 증명", false, `증명을 얻지 못함: ${(e as Error).message}`);
      return finish(steps, receipt, hasInclusion, now);
    }
  }

  // 7. 선택적 공개 (위치 대조)
  const { verifyDisclosure } = await import("./record.ts");
  const bad = receipt.disclosures.filter((d) => !verifyDisclosure(leaf, d));
  add(
    7,
    "선택적 공개",
    bad.length === 0,
    bad.length === 0
      ? `${receipt.disclosures.length}개 필드가 각자 자리와 일치`
      : `자리와 안 맞는 필드: ${bad.map((d) => d[1]).join(", ")}`,
  );

  return finish(steps, receipt, hasInclusion, now);
}

function finish(
  steps: StepResult[],
  receipt: Receipt,
  hasInclusion: boolean,
  now: number,
): VerifyReport {
  const failed = steps.find((s) => !s.ok);
  return {
    ok: !failed,
    steps,
    fault: assignFault(receipt, hasInclusion, now),
    failedAt: failed ? failed.step : null,
  };
}

/** 보고서를 사람이 읽는 형태로. 명령줄 데모가 이 함수를 쓴다. */
export function formatReport(r: VerifyReport): string {
  const lines = r.steps.map(
    (s) => `  ${s.ok ? "통과" : "실패"}  ${s.step}. ${s.name}\n         ${s.detail}`,
  );
  lines.push("");
  lines.push(`  판정: ${r.ok ? "검증 통과" : `${r.failedAt}단계에서 실패`}`);
  lines.push(`  책임: ${r.fault}`);
  return lines.join("\n");
}
