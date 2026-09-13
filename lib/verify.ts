// 검증 11단계. 번들 하나와 공개 RPC 하나로 끝난다. 기관 서버는 부르지 않는다.
//
// 결과가 세 값이다. 통과, 실패, **판정 불가**. 재량 사유를 실패로 처리하면
// 정직한 기관이 걸리고, 통과로 처리하면 아무 말이나 대는 기관이 빠져나간다.
import type { Address, Hex, TypedDataDomain } from "viem";
import {
  keysRoot,
  fieldsRoot,
  validateLeafStructure,
  leafHash,
  verifyDisclosure,
  disclosedValue,
  findRule,
  policyHash,
  REQUIRED_KEYS,
  ZERO32,
  type Disclosure,
  type Leaf,
  type PolicyDocument,
  type PolicyRule,
  type Verifiability,
} from "./record.ts";
import {
  verifyLeafSignature,
  verifyLogAck,
  verifyRequestIntent,
  requestIntentHash,
  requesterSigHash,
} from "./sign.ts";
import { rootFromInclusionProof, verifyConsistency } from "./merkle.ts";
import { assignFault, type Fault, type Receipt } from "./receipt.ts";

export type StepStatus = "pass" | "fail" | "unverifiable";

export interface StepResult {
  step: number;
  name: string;
  status: StepStatus;
  detail: string;
}

/** 체인에서 직접 읽는 것들. 테스트가 대역을 끼울 수 있게 인터페이스로 둔다. */
export interface VerifyChain {
  isRegistered(gateway: Address): Promise<boolean>;
  rootByTreeSize(treeSize: number): Promise<Hex>;
  logOperator(): Promise<Address>;
}

export interface InclusionProof {
  anchor: { tree_size: number; root: Hex };
  index: number;
  audit_path: Hex[];
}

/**
 * 참조 목록 갱신 레코드와 그 포함 증명.
 *
 * 거절 레코드의 policy_data_root 가 **판단보다 먼저 공표된 값**임을 보인다.
 * 없으면 게이트웨이가 판단 시점에 유리한 목록을 지어낼 수 있다.
 */
export interface PolicyUpdateProof {
  leaf: Leaf;
  leaf_hash: Hex;
  inclusion_proof: InclusionProof;
}

export interface ConsistencyProof {
  from_anchor: { tree_size: number; root: Hex };
  to_anchor: { tree_size: number; root: Hex };
  path: Hex[];
}

/** 증명 공급자. 실제 검증에서는 번들 안의 것을 꺼내 쓴다. 네트워크를 안 탄다. */
export interface ProofSource {
  inclusion(leafHash: Hex): Promise<InclusionProof>;
  consistency(from: number, to: number): Promise<ConsistencyProof>;
  /** 일관성 검증에 쓸 더 나중 앵커. 없으면 7단계를 건너뛴다. */
  laterAnchorThan?(treeSize: number): Promise<number | null>;
}

/** 10·11 단계 검사기의 반환값. */
export type Verdict =
  | { status: "pass"; detail: string }
  | { status: "fail"; detail: string }
  | { status: "unverifiable"; detail: string };

export interface PredicateContext {
  leaf: Leaf;
  disclosures: Disclosure[];
  rule: NonNullable<ReturnType<typeof findRule>>;
  policy: PolicyDocument;
}

export interface VerifyOptions {
  receipt: Receipt;
  domain: TypedDataDomain;
  chain: VerifyChain;
  proofs: ProofSource;
  /** 없으면 9단계가 판정 불가다. */
  policy?: PolicyDocument;
  /** 참조 목록이 판단보다 먼저 공표됐음을 보이는 증거. 없으면 9단계가 판정 불가다. */
  policyUpdate?: PolicyUpdateProof;
  /**
   * 9단계. 참조 데이터 갱신 레코드의 증거. `policy_data_root` 가 비어 있지
   * 않은데 이것이 없으면 그 부분을 확인할 수 없다.
   */
  policyDataProof?: (root: Hex, rule: PolicyRule, policy: PolicyDocument) => Promise<Verdict>;
  /** sorted-merkle.ts 의 sortedSetChecker(). 없으면 10단계가 판정 불가다. */
  staticCheck?: (ctx: PredicateContext) => Promise<Verdict>;
  /** state-proof.ts 의 stateSlotChecker(). 없으면 11단계가 판정 불가다. */
  stateCheck?: (ctx: PredicateContext) => Promise<Verdict>;
  now?: () => number;
}

export interface VerifyReport {
  /** 판정 불가가 있어도 true 다. 실패만 false 로 만든다. */
  ok: boolean;
  steps: StepResult[];
  /** 누락 시 책임 소재. */
  fault: Fault;
  /** 처음 실패한 단계. */
  failedAt: number | null;
  /** 판정 불가로 남은 단계. */
  unverifiable: number[];
}

const unhex = (s: string) => Buffer.from(s.replace(/^0x/, ""), "hex");
const lower = (s: string) => s.toLowerCase();

export async function verifyReceipt(o: VerifyOptions): Promise<VerifyReport> {
  const now = (o.now ?? (() => Math.floor(Date.now() / 1000)))();
  const { receipt, domain, chain, proofs } = o;
  const leaf = receipt.leaf;
  const steps: StepResult[] = [];
  let hasInclusion = false;

  const add = (step: number, name: string, status: StepStatus, detail: string): boolean => {
    steps.push({ step, name, status, detail });
    return status !== "fail";
  };
  const stop = () => finish(steps, receipt, hasInclusion, now);

  // 1. 필드 집합과 리프 구조
  try {
    validateLeafStructure(leaf);
    if (leaf.type !== "decision") throw new Error(`판단 레코드가 아님: type=${leaf.type}`);
    const required = REQUIRED_KEYS[leaf.v][leaf.type];
    const same =
      required.length === leaf.keys.length && required.every((k, i) => k === leaf.keys[i]);
    if (!same) throw new Error("필수 키 집합 불일치");
    keysRoot(leaf.keys);
    fieldsRoot(leaf.field_hashes);
    add(1, "필드 집합과 커밋 루트", "pass", `키 ${leaf.keys.length}개, 누락 없음`);
  } catch (e) {
    add(1, "필드 집합과 커밋 루트", "fail", `필드 누락 또는 버전 불일치: ${(e as Error).message}`);
    return stop();
  }

  // 2. 게이트웨이 서명
  const sigOk = await verifyLeafSignature(leaf, domain);
  if (!add(2, "게이트웨이 서명", sigOk ? "pass" : "fail", sigOk ? `${leaf.gateway} 로 복원됨` : "위조된 영수증")) {
    return stop();
  }

  // 3. 온체인 레지스트리 등록
  const registered = await chain.isRegistered(leaf.gateway as Address);
  if (!add(3, "레지스트리 등록", registered ? "pass" : "fail", registered ? "등록된 게이트웨이" : "신뢰할 수 없는 발급자")) {
    return stop();
  }

  // 4. 요청자 서명. 없으면 실패가 아니라 판정 불가다. 서명 없이 발급하는 것도
  //    가능한 구성이고, 대신 요청 사실의 부인을 막지 못한다.
  {
    const intent = receipt.request_intent;
    const sig = receipt.request_sig;
    if (!intent || !sig) {
      const claimed = leaf.request_intent_hash !== ZERO32;
      add(
        4,
        "요청자 서명",
        "unverifiable",
        claimed
          ? "리프가 요청자 서명을 주장하지만 번들에 의도 구조체가 없다"
          : "요청자 서명 없이 발급된 레코드",
      );
    } else {
      let detail = "";
      let ok = await verifyRequestIntent(intent, sig, domain);
      if (!ok) detail = "요청자 서명이 requester 로 복원되지 않음";
      if (ok && requestIntentHash(intent, domain) !== leaf.request_intent_hash) {
        ok = false;
        detail = "의도 해시가 리프 커밋과 다름";
      }
      if (ok && requesterSigHash(sig) !== leaf.requester_sig_hash) {
        ok = false;
        detail = "요청자 서명 해시가 리프 커밋과 다름";
      }
      if (ok && lower(intent.gateway) !== lower(leaf.gateway)) {
        ok = false;
        detail = "의도가 가리키는 게이트웨이가 리프와 다름";
      }
      if (!add(4, "요청자 서명", ok ? "pass" : "fail", ok ? `${intent.requester} 의 의도에 묶임` : detail)) {
        return stop();
      }
    }
  }

  // 5. 로그 접수 확인
  if (!receipt.log_ack) {
    add(5, "로그 접수 확인", "fail", "접수 확인이 없음. 게이트웨이가 제출하지 않았다");
    return stop();
  }
  const operator = await chain.logOperator();
  const ackOk = await verifyLogAck(receipt.log_ack, operator, domain);
  if (!add(5, "로그 접수 확인", ackOk ? "pass" : "fail", ackOk ? `운영자 ${operator}` : "접수 확인 서명이 유효하지 않음")) {
    return stop();
  }
  if (receipt.log_ack.leaf_hash.toLowerCase() !== receipt.leaf_hash.toLowerCase()) {
    steps[steps.length - 1] = {
      step: 5,
      name: "로그 접수 확인",
      status: "fail",
      detail: "접수 확인이 다른 리프를 가리킨다",
    };
    return stop();
  }

  // 6. 포함 증명. 결정적인 단계다.
  //    재계산한 루트를 로그가 준 값이 아니라 chain.rootByTreeSize 로 체인에서
  //    직접 읽은 값과 대조한다. 로그가 준 루트를 쓰면 아무것도 증명되지 않는다.
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
    if (!add(6, "포함 증명", match ? "pass" : "fail", match ? `체인 루트와 일치, tree_size=${p.anchor.tree_size}` : "체인 루트로 재계산되지 않음")) {
      return stop();
    }
  } catch (e) {
    add(6, "포함 증명", "fail", `누락 또는 삭제 가능성: ${(e as Error).message}`);
    return stop();
  }

  // 7. 일관성 증명. 비교할 나중 앵커가 없으면 판정 불가다.
  const later = proofs.laterAnchorThan ? await proofs.laterAnchorThan(anchoredSize!) : null;
  if (later === null) {
    add(7, "일관성 증명", "unverifiable", "비교할 나중 앵커가 아직 없다");
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
      if (!add(7, "일관성 증명", consistent ? "pass" : "fail", consistent ? `${c.from_anchor.tree_size} → ${c.to_anchor.tree_size} 순수 확장` : "역사 조작 또는 비순차 확장")) {
        return stop();
      }
    } catch (e) {
      add(7, "일관성 증명", "fail", `증명을 얻지 못함: ${(e as Error).message}`);
      return stop();
    }
  }

  // 8. 선택적 공개. 집합 포함이 아니라 위치 대조다.
  const bad = receipt.disclosures.filter((d) => !verifyDisclosure(leaf, d));
  if (!add(
    8,
    "선택적 공개",
    bad.length === 0 ? "pass" : "fail",
    bad.length === 0
      ? `${receipt.disclosures.length}개 필드가 각자 자리와 일치`
      : `자리와 안 맞는 필드: ${bad.map((d) => d[1]).join(", ")}`,
  )) {
    return stop();
  }

  // 9. 정책 커밋과 규칙 실재
  const ruleId = disclosedValue(receipt.disclosures, "rule_id");
  const declared = disclosedValue(receipt.disclosures, "verifiability") as Verifiability | undefined;
  let rule: PolicyRule | undefined;

  if (!o.policy) {
    add(9, "정책 커밋", "unverifiable", "번들에 정책 문서가 없다");
  } else if (policyHash(o.policy) !== leaf.policy_hash) {
    add(9, "정책 커밋", "fail", "정책 문서 해시가 리프 커밋과 다름");
    return stop();
  } else if (ruleId === undefined) {
    add(9, "정책 커밋", "unverifiable", "rule_id 가 공개되지 않아 규칙 실재를 확인할 수 없다");
  } else {
    rule = findRule(o.policy, ruleId);
    if (!rule) {
      add(9, "정책 커밋", "fail", `커밋된 문서에 없는 규칙을 인용함: ${ruleId}`);
      return stop();
    }
    if (declared !== undefined && declared !== rule.verifiability) {
      add(9, "정책 커밋", "fail", `verifiability 가 규칙 정의와 다름: ${declared} != ${rule.verifiability}`);
      return stop();
    }
    if (leaf.policy_data_root !== ZERO32) {
      // 갱신 레코드가 먼저다. 이게 통과해야 목록 대조가 의미를 갖는다.
      const pub = await checkPolicyUpdate(o, leaf, chain);
      if (pub.status !== "pass") {
        if (!add(9, "정책 커밋", pub.status, `규칙 ${ruleId} 실재 확인. ${pub.detail}`)) return stop();
      } else if (!o.policyDataProof) {
        add(9, "정책 커밋", "unverifiable", `규칙 ${ruleId} 실재 확인, 목록 공표 확인. 동봉 목록 대조는 검사기 없음`);
      } else {
        const v = await o.policyDataProof(leaf.policy_data_root as Hex, rule, o.policy);
        if (!add(9, "정책 커밋", v.status, `규칙 ${ruleId} 실재. ${pub.detail} ${v.detail}`)) return stop();
      }
    } else {
      add(9, "정책 커밋", "pass", `규칙 ${ruleId} 가 커밋된 문서에 실재`);
    }
  }

  const ctx = (): PredicateContext | null =>
    o.policy && rule ? { leaf, disclosures: receipt.disclosures, rule, policy: o.policy } : null;

  // 10. 정적 사유. 커밋된 목록과 모순되는가.
  {
    const v = await staticVerdict(o, ctx(), declared);
    if (!add(10, "정적 사유", v.status, v.detail)) return stop();
  }

  // 11. 동적 사유. 상태 증거와 모순되는가.
  {
    const v = await stateVerdict(o, ctx(), declared);
    if (!add(11, "동적 사유", v.status, v.detail)) return stop();
  }

  return stop();
}

/**
 * 참조 목록이 **판단보다 먼저** 공표됐는지.
 *
 * 이게 없으면 게이트웨이가 피해자별로 목록을 지어낼 수 있다. 앨리스를 막고 싶으면
 * 앨리스만 뺀 목록을 만들어 그 루트를 레코드에 커밋하면 그만이다. 목록도 루트도
 * 게이트웨이가 고르니 자기들끼리 앞뒤가 맞는다.
 *
 * 갱신 레코드를 같은 append-only 로그에 먼저 박게 하면 그 수법이 막힌다. 목록을
 * 고치려면 고쳤다는 사실이 모두가 보는 로그에 남아야 한다. 사적인 위조가 공개된
 * 행위로 바뀐다.
 */
async function checkPolicyUpdate(
  o: VerifyOptions,
  leaf: Leaf,
  chain: VerifyChain,
): Promise<Verdict> {
  const p = o.policyUpdate;
  if (!p) {
    return { status: "unverifiable", detail: "목록 갱신 레코드가 번들에 없어 사전 공표를 확인할 수 없다." };
  }
  if (p.leaf.type !== "policy_update") {
    return { status: "fail", detail: "갱신 레코드가 아니다." };
  }
  if (lower(p.leaf.gateway) !== lower(leaf.gateway)) {
    return { status: "fail", detail: "다른 게이트웨이의 갱신 레코드다." };
  }
  if (p.leaf.policy_data_root !== leaf.policy_data_root) {
    return { status: "fail", detail: "판단이 가리키는 루트가 공표된 루트와 다르다." };
  }
  // 공표가 판단보다 늦으면 사후에 끼워 맞춘 것이다.
  if (p.leaf.issued_at > leaf.issued_at) {
    return { status: "fail", detail: "목록 공표가 판단보다 나중이다." };
  }
  if (!(await verifyLeafSignature(p.leaf, o.domain))) {
    return { status: "fail", detail: "갱신 레코드 서명이 유효하지 않다." };
  }

  const computed = `0x${leafHash(p.leaf).toString("hex")}`;
  if (computed !== p.leaf_hash.toLowerCase()) {
    return { status: "fail", detail: "갱신 레코드 해시가 본문과 맞지 않는다." };
  }

  // 로그에 실제로 박혔는지. 여기도 체인에서 읽은 루트와 대조한다.
  const size = p.inclusion_proof.anchor.tree_size;
  let chainRoot: Hex;
  try {
    chainRoot = await chain.rootByTreeSize(size);
  } catch (e) {
    return { status: "unverifiable", detail: `앵커 조회 실패: ${(e as Error).message}` };
  }
  if (chainRoot === ZERO32) {
    return { status: "fail", detail: `갱신 레코드를 덮는 tree_size ${size} 가 앵커되지 않았다.` };
  }
  const root = rootFromInclusionProof(
    p.inclusion_proof.index,
    size,
    leafHash(p.leaf),
    p.inclusion_proof.audit_path.map(unhex),
  );
  if (root === null || `0x${root.toString("hex")}` !== chainRoot.toLowerCase()) {
    return { status: "fail", detail: "갱신 레코드가 앵커된 트리 안에 없다." };
  }

  return { status: "pass", detail: `목록이 판단보다 먼저 공표됨(리프 ${p.inclusion_proof.index}).` };
}

/** 10·11 공통 전처리. null 이면 계속 진행해도 된다는 뜻이다. */
function gate(
  ctx: PredicateContext | null,
  declared: Verifiability | undefined,
  kinds: readonly string[],
): Verdict | null {
  if (declared === "external") {
    return { status: "unverifiable", detail: "외부 데이터에 의존하는 사유. 판정 불가" };
  }
  if (declared === "discretionary") {
    return { status: "unverifiable", detail: "재량 사유. 판정 불가" };
  }
  if (!ctx) return { status: "unverifiable", detail: "정책 문서나 규칙이 없어 술어를 적용할 수 없다" };
  if (!ctx.rule.predicate) {
    return { status: "unverifiable", detail: "참조 수준 규칙. 술어가 없어 적용 여부는 판정하지 않는다" };
  }
  if (!kinds.includes(ctx.rule.predicate.kind)) return null; // 이 단계 소관이 아니다
  return null;
}

async function staticVerdict(
  o: VerifyOptions,
  ctx: PredicateContext | null,
  declared: Verifiability | undefined,
): Promise<Verdict> {
  const early = gate(ctx, declared, ["in_set", "not_in_set", "gt"]);
  if (early) return early;
  const p = ctx!.rule.predicate!;
  if (p.kind === "state_slot") {
    return { status: "pass", detail: "동적 사유라 11단계 소관" };
  }

  // `gt` 는 한도가 규칙 안에 있어 외부 데이터가 필요 없다. 바로 판정한다.
  if (p.kind === "gt") {
    const raw = disclosedValue(ctx!.disclosures, p.field);
    if (raw === undefined) {
      return { status: "unverifiable", detail: `${p.field} 가 공개되지 않았다` };
    }
    let holds: boolean;
    try {
      holds = BigInt(raw) > BigInt(p.limit);
    } catch {
      return { status: "fail", detail: `${p.field} 가 정수가 아님: ${raw}` };
    }
    return holds
      ? { status: "pass", detail: `${p.field}=${raw} 가 한도 ${p.limit} 을 초과. 사유가 참` }
      : { status: "fail", detail: `${p.field}=${raw} 는 한도 ${p.limit} 이하. 거짓 정적 사유` };
  }

  // 집합 소속은 정렬 머클 증명이 필요하다.
  if (!o.staticCheck) {
    return { status: "unverifiable", detail: `${p.kind} 술어는 정렬 머클 증명이 필요하다. 검사기 없음` };
  }
  return o.staticCheck(ctx!);
}

async function stateVerdict(
  o: VerifyOptions,
  ctx: PredicateContext | null,
  declared: Verifiability | undefined,
): Promise<Verdict> {
  const early = gate(ctx, declared, ["state_slot"]);
  if (early) return early;
  if (ctx!.rule.predicate!.kind !== "state_slot") {
    return { status: "pass", detail: "정적 사유라 10단계 소관" };
  }
  if (ctx!.leaf.state_proof_root === ZERO32) {
    return { status: "fail", detail: "동적 사유인데 상태 증거를 커밋하지 않았다" };
  }
  if (!o.stateCheck) {
    return { status: "unverifiable", detail: "EIP-1186 검사기 없음" };
  }
  return o.stateCheck(ctx!);
}


function finish(
  steps: StepResult[],
  receipt: Receipt,
  hasInclusion: boolean,
  now: number,
): VerifyReport {
  const failed = steps.find((s) => s.status === "fail");
  return {
    ok: !failed,
    steps,
    fault: assignFault(receipt, hasInclusion, now),
    failedAt: failed ? failed.step : null,
    unverifiable: steps.filter((s) => s.status === "unverifiable").map((s) => s.step),
  };
}

const LABEL: Record<StepStatus, string> = {
  pass: "통과",
  fail: "실패",
  unverifiable: "판정 불가",
};

/** 명령줄 출력용. */
export function formatReport(r: VerifyReport): string {
  const lines = r.steps.map(
    (s) => `  ${LABEL[s.status].padEnd(5)}  ${s.step}. ${s.name}\n            ${s.detail}`,
  );
  lines.push("");
  lines.push(`  판정: ${r.ok ? "검증 통과" : `${r.failedAt}단계에서 실패`}`);
  if (r.unverifiable.length) lines.push(`  판정 불가 단계: ${r.unverifiable.join(", ")}`);
  lines.push(`  책임: ${r.fault}`);
  return lines.join("\n");
}
