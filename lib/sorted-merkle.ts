// 정렬 머클 트리와 비포함 증명. 이 프로젝트의 유일한 신규 자료구조다.
//
// 목록을 정렬해두면 값이 들어갈 자리가 하나로 정해진다. 그 자리 양옆 항목의 포함
// 증명을 내고, 둘이 인접하며, 값이 그 사이라는 걸 보이면 "없다" 가 증명된다.
//
// 트리 계산은 merkle.ts 를 그대로 쓴다. 새로 만드는 건 정렬 불변식뿐이다.
import { createHash } from "node:crypto";
import { mth, inclusionPath, rootFromInclusionProof } from "./merkle.ts";

export class SortedMerkleError extends Error {}

/**
 * 주소는 대소문자가 섞여 들어온다. 정규화를 안 하면 같은 값이 두 번 들어가고
 * 정렬 순서가 흔들려 비포함 증명이 무의미해진다.
 */
export function normalize(value: string): string {
  return value.trim().toLowerCase();
}

/** 트리에 들어가는 바이트열. */
function leafData(value: string): Buffer {
  return Buffer.from(normalize(value), "utf8");
}

/** 바이트 순서 비교. 정렬과 대소 판정이 같은 기준을 써야 한다. 엇갈리면 뚫린다. */
export function compare(a: string, b: string): number {
  return Buffer.compare(leafData(a), leafData(b));
}

export interface SortedTree {
  /** 정규화·정렬·중복 제거를 마친 목록. */
  values: string[];
  data: Buffer[];
}

/**
 * 정렬·중복 제거. 중복을 남기면 인접한 두 항목이 같은 값이 되어 "그 사이에
 * 아무것도 없다" 는 주장이 공허해진다.
 */
export function buildSortedTree(values: readonly string[]): SortedTree {
  const seen = new Set<string>();
  const sorted: string[] = [];
  for (const v of [...values].map(normalize).sort((a, b) => compare(a, b))) {
    if (seen.has(v)) continue;
    seen.add(v);
    sorted.push(v);
  }
  return { values: sorted, data: sorted.map(leafData) };
}

export function sortedRoot(t: SortedTree): string {
  return `0x${mth(t.data).toString("hex")}`;
}

export function rootOfList(values: readonly string[]): string {
  return sortedRoot(buildSortedTree(values));
}

// ---------- 포함 증명 ----------

export interface MembershipProof {
  kind: "member";
  tree_size: number;
  index: number;
  value: string;
  audit_path: string[];
}

export function proveMembership(t: SortedTree, value: string): MembershipProof {
  const v = normalize(value);
  const index = t.values.indexOf(v);
  if (index < 0) throw new SortedMerkleError(`목록에 없는 값의 포함 증명: ${v}`);
  return {
    kind: "member",
    tree_size: t.values.length,
    index,
    value: v,
    audit_path: inclusionPath(index, t.data).map((b) => `0x${b.toString("hex")}`),
  };
}

// ---------- 비포함 증명 ----------

/**
 * 비포함 증명. 경계 항목의 포함 증명을 품는다. 안 품으면 없는 항목을 지어내
 * 아무 값이나 "사이에 있다" 고 우길 수 있다.
 */
export type NonMembershipProof =
  | { kind: "empty"; tree_size: 0 }
  | { kind: "before_first"; tree_size: number; right: MembershipProof }
  | { kind: "after_last"; tree_size: number; left: MembershipProof }
  | { kind: "between"; tree_size: number; left: MembershipProof; right: MembershipProof };

export function proveNonMembership(t: SortedTree, value: string): NonMembershipProof {
  const v = normalize(value);
  const n = t.values.length;
  if (n === 0) return { kind: "empty", tree_size: 0 };

  // 검증에서도 막히지만 여기서 먼저 막는다. 만들 수 있는 것처럼 보이는 API 를
  // 두면 누군가 결과를 확인 없이 쓴다.
  if (t.values.includes(v)) {
    throw new SortedMerkleError(`목록에 있는 값의 비포함 증명은 만들 수 없다: ${v}`);
  }

  if (compare(v, t.values[0]) < 0) {
    return { kind: "before_first", tree_size: n, right: proveMembership(t, t.values[0]) };
  }
  if (compare(v, t.values[n - 1]) > 0) {
    return { kind: "after_last", tree_size: n, left: proveMembership(t, t.values[n - 1]) };
  }

  // 삽입 지점. values[i-1] < v < values[i] 인 i.
  let lo = 0;
  let hi = n - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (compare(t.values[mid], v) < 0) lo = mid + 1;
    else hi = mid;
  }
  return {
    kind: "between",
    tree_size: n,
    left: proveMembership(t, t.values[lo - 1]),
    right: proveMembership(t, t.values[lo]),
  };
}

// ---------- 검증 ----------

const unhex = (s: string) => Buffer.from(s.replace(/^0x/, ""), "hex");

/** 포함 증명이 루트로 재계산되는지. */
export function verifyMembership(root: string, p: MembershipProof): boolean {
  if (p.kind !== "member") return false;
  if (!Number.isSafeInteger(p.index) || p.index < 0 || p.index >= p.tree_size) return false;
  const recomputed = rootFromInclusionProof(
    p.index,
    p.tree_size,
    // 리프 해시는 RFC 6962 규칙 그대로. 접두사 0x00.
    hashLeaf(p.value),
    p.audit_path.map(unhex),
  );
  return recomputed !== null && `0x${recomputed.toString("hex")}` === root.toLowerCase();
}

function hashLeaf(value: string): Buffer {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x00]), leafData(value)]))
    .digest();
}

/**
 * 비포함 증명 검증. 놓치면 뚫리는 것 셋. 아래 코드에 하나씩 대응한다.
 *
 * 1. 경계의 포함 증명이 루트로 재계산되어야 한다. 안 보면 없는 값 두 개를
 *    지어내 아무거나 그 사이에 끼울 수 있다.
 * 2. 두 경계가 인접해야 한다. [10,20,30] 에서 10 과 30 을 내밀며 "20 이 없다"
 *    고 하는 수법을 막는다.
 * 3. 부등호 둘 다 엄격해야 한다. `<=` 를 쓰면 경계 자신이 통과한다.
 */
export function verifyNonMembership(
  root: string,
  value: string,
  p: NonMembershipProof,
): boolean {
  const v = normalize(value);

  if (p.kind === "empty") {
    return p.tree_size === 0 && rootOfList([]) === root.toLowerCase();
  }

  if (p.kind === "before_first") {
    if (p.right.index !== 0 || p.right.tree_size !== p.tree_size) return false;
    if (!verifyMembership(root, p.right)) return false;
    return compare(v, p.right.value) < 0;
  }

  if (p.kind === "after_last") {
    if (p.left.index !== p.tree_size - 1 || p.left.tree_size !== p.tree_size) return false;
    if (!verifyMembership(root, p.left)) return false;
    return compare(v, p.left.value) > 0;
  }

  if (p.kind === "between") {
    const { left, right } = p;
    if (left.tree_size !== p.tree_size || right.tree_size !== p.tree_size) return false;
    if (left.index + 1 !== right.index) return false;         // 2. 바로 옆자리인가
    if (compare(left.value, right.value) >= 0) return false;  // 정렬이 맞는가
    if (!verifyMembership(root, left) || !verifyMembership(root, right)) return false; // 1.
    return compare(left.value, v) < 0 && compare(v, right.value) < 0;  // 3. 엄격 비교
  }

  return false;
}

// ---------- 검증기 붙임부 ----------

import { ZERO32, disclosedValue } from "./record.ts";
import type { PredicateContext, Verdict } from "./verify.ts";
import type { PolicyDocument, PolicyRule } from "./record.ts";

/**
 * 검증 10단계 검사기.
 *
 * 루트 대조를 먼저 하고 술어를 나중에 본다. 순서를 바꾸면 게이트웨이가 유리한
 * 목록을 지어내 붙일 수 있다.
 */
export function sortedSetChecker(): (ctx: PredicateContext) => Promise<Verdict> {
  return async (ctx) => {
    const p = ctx.rule.predicate;
    if (!p || (p.kind !== "in_set" && p.kind !== "not_in_set")) {
      return { status: "unverifiable", detail: "집합 술어가 아니다" };
    }

    const list = ctx.policy.data_sets?.[p.set];
    if (!list) {
      return { status: "unverifiable", detail: `참조 데이터 ${p.set} 가 번들에 없다` };
    }

    const tree = buildSortedTree(list);
    const root = sortedRoot(tree);
    if (ctx.leaf.policy_data_root === ZERO32) {
      return {
        status: "unverifiable",
        detail: "게이트웨이가 참조 데이터 루트를 커밋하지 않았다",
      };
    }
    if (root !== ctx.leaf.policy_data_root.toLowerCase()) {
      return {
        status: "fail",
        detail: `커밋한 참조 데이터 루트와 동봉된 목록이 다르다: ${ctx.leaf.policy_data_root.slice(0, 18)}… != ${root.slice(0, 18)}…`,
      };
    }

    const value = disclosedValue(ctx.disclosures, p.field);
    if (value === undefined) {
      return { status: "unverifiable", detail: `${p.field} 가 공개되지 않았다` };
    }

    const v = normalize(value);
    const member = tree.values.includes(v);

    if (p.kind === "not_in_set") {
      if (member) {
        // 반박은 포함 증명이다. 목록 안에 있다는 것을 루트에 대해 보인다.
        const proof = proveMembership(tree, v);
        return {
          status: "fail",
          detail: `거짓 정적 사유. ${p.set} 목록 인덱스 ${proof.index} 에 ${v} 가 실재한다`,
        };
      }
      const proof = proveNonMembership(tree, v);
      return {
        status: "pass",
        detail: `${p.set} 비포함 확인 (${proof.kind}). 사유가 참`,
      };
    }

    if (!member) {
      const proof = proveNonMembership(tree, v);
      return {
        status: "fail",
        detail: `거짓 정적 사유. ${v} 는 ${p.set} 에 없다 (${proof.kind})`,
      };
    }
    const proof = proveMembership(tree, v);
    return { status: "pass", detail: `${p.set} 인덱스 ${proof.index} 에 실재. 사유가 참` };
  };
}

/**
 * 검증 9단계 검사기. 동봉된 목록이 커밋된 그 목록인지까지만 본다.
 *
 * "판단 시점에 최신 목록이었나" 는 확인 못 한다. policy_update 레코드와 그
 * 포함 증명이 번들에 들어와야 한다.
 */
export function policyDataRootChecker(): (
  root: string,
  rule: PolicyRule,
  policy: PolicyDocument,
) => Promise<Verdict> {
  return async (root, rule, policy) => {
    const p = rule.predicate;
    if (!p || (p.kind !== "in_set" && p.kind !== "not_in_set")) {
      return {
        status: "unverifiable",
        detail: "집합을 참조하지 않는 규칙이라 참조 데이터 루트를 대조할 수 없다",
      };
    }
    const list = policy.data_sets?.[p.set];
    if (!list) {
      return { status: "unverifiable", detail: `참조 데이터 ${p.set} 가 번들에 없다` };
    }
    if (rootOfList(list) !== root.toLowerCase()) {
      return {
        status: "fail",
        detail: `커밋한 참조 데이터 루트가 동봉된 ${p.set} 목록과 다르다`,
      };
    }
    return {
      status: "pass",
      detail: `참조 데이터 ${p.set} ${list.length}건이 커밋된 루트와 일치`,
    };
  };
}
