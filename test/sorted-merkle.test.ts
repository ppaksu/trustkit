// 정렬 머클 비포함 증명 테스트.
//
// 신규 자료구조라 밀도를 머클 테스트와 맞춘다. 핵심은 음성 테스트다. 목록에
// 있는 값으로 비포함 증명을 만들 수도, 손으로 조립해 통과시킬 수도 없어야 한다.
import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSortedTree,
  sortedRoot,
  rootOfList,
  proveMembership,
  proveNonMembership,
  verifyMembership,
  verifyNonMembership,
  compare,
  normalize,
  SortedMerkleError,
  type MembershipProof,
  type NonMembershipProof,
} from "../lib/sorted-merkle.ts";

const addr = (n: number) => "0x" + n.toString(16).padStart(40, "0");

/** 0, 2, 4, … 짝수만 넣는다. 홀수는 전부 목록 밖이다. */
const evens = (count: number) => Array.from({ length: count }, (_, i) => addr(i * 2));

// ---------- 정규화와 정렬 ----------

test("정규화 — 대소문자와 공백이 같은 값으로 접힌다", () => {
  assert.equal(normalize("  0xAbCd "), "0xabcd");
  assert.equal(compare("0xAB", "0xab"), 0);
});

test("정렬 — 중복이 제거되고 바이트 순서로 늘어선다", () => {
  const t = buildSortedTree(["0xcc", "0xAA", "0xbb", "0xaa", "0xCC"]);
  assert.deepEqual(t.values, ["0xaa", "0xbb", "0xcc"]);
});

test("정렬 — 입력 순서가 달라도 같은 루트가 나온다", () => {
  const a = rootOfList(["0xcc", "0xaa", "0xbb"]);
  const b = rootOfList(["0xbb", "0xcc", "0xaa"]);
  assert.equal(a, b);
});

test("정렬 — 원소 하나가 바뀌면 루트가 바뀐다", () => {
  assert.notEqual(rootOfList(["0xaa", "0xbb"]), rootOfList(["0xaa", "0xbc"]));
});

// ---------- 포함 증명 ----------

test("포함 — 크기 1~33 의 모든 인덱스가 검증된다", () => {
  for (let n = 1; n <= 33; n++) {
    const t = buildSortedTree(evens(n));
    const root = sortedRoot(t);
    for (let i = 0; i < n; i++) {
      const p = proveMembership(t, t.values[i]);
      assert.equal(p.index, i);
      assert.ok(verifyMembership(root, p), `크기 ${n} 인덱스 ${i}`);
    }
  }
});

test("포함 — 목록에 없는 값은 증명을 만들 수 없다", () => {
  const t = buildSortedTree(evens(8));
  assert.throws(() => proveMembership(t, addr(3)), SortedMerkleError);
});

test("포함 — audit path 를 한 바이트 바꾸면 실패한다", () => {
  const t = buildSortedTree(evens(8));
  const root = sortedRoot(t);
  const p = proveMembership(t, t.values[3]);
  const bad: MembershipProof = { ...p, audit_path: [...p.audit_path] };
  bad.audit_path[0] = "0x" + "ff".repeat(32);
  assert.equal(verifyMembership(root, bad), false);
});

test("포함 — 인덱스를 위조하면 실패한다", () => {
  const t = buildSortedTree(evens(8));
  const root = sortedRoot(t);
  const p = proveMembership(t, t.values[3]);
  assert.equal(verifyMembership(root, { ...p, index: 4 }), false);
  assert.equal(verifyMembership(root, { ...p, index: -1 }), false);
  assert.equal(verifyMembership(root, { ...p, index: p.tree_size }), false);
});

test("포함 — 값을 바꾸면 실패한다", () => {
  const t = buildSortedTree(evens(8));
  const root = sortedRoot(t);
  const p = proveMembership(t, t.values[3]);
  assert.equal(verifyMembership(root, { ...p, value: addr(99) }), false);
});

// ---------- 비포함 증명 ----------

test("비포함 — 크기 1~33 에서 모든 사이 값이 검증된다", () => {
  for (let n = 1; n <= 33; n++) {
    const t = buildSortedTree(evens(n));
    const root = sortedRoot(t);
    for (let i = 0; i < n; i++) {
      const missing = addr(i * 2 + 1); // 짝수 사이의 홀수
      const p = proveNonMembership(t, missing);
      assert.ok(verifyNonMembership(root, missing, p), `크기 ${n} 값 ${missing}`);
    }
  }
});

test("비포함 — 첫 항목보다 작은 값", () => {
  const t = buildSortedTree(["0xbb", "0xcc"]);
  const root = sortedRoot(t);
  const p = proveNonMembership(t, "0xaa");
  assert.equal(p.kind, "before_first");
  assert.ok(verifyNonMembership(root, "0xaa", p));
});

test("비포함 — 마지막 항목보다 큰 값", () => {
  const t = buildSortedTree(["0xaa", "0xbb"]);
  const root = sortedRoot(t);
  const p = proveNonMembership(t, "0xcc");
  assert.equal(p.kind, "after_last");
  assert.ok(verifyNonMembership(root, "0xcc", p));
});

test("비포함 — 빈 목록", () => {
  const t = buildSortedTree([]);
  const root = sortedRoot(t);
  const p = proveNonMembership(t, "0xaa");
  assert.equal(p.kind, "empty");
  assert.ok(verifyNonMembership(root, "0xaa", p));
});

// ---------- 음성 테스트 ----------

test("비포함 — 목록에 있는 값으로는 증명을 만들 수 없다", () => {
  const t = buildSortedTree(evens(16));
  for (const v of t.values) {
    assert.throws(() => proveNonMembership(t, v), SortedMerkleError, `값 ${v}`);
  }
});

test("비포함 — 목록에 있는 값의 위조 증명은 반드시 실패한다", () => {
  // 공격자가 직접 조립한다. 인접한 두 항목을 정직하게 골라도 대상 값이 그
  // 경계와 같으면 엄격 비교에서 막힌다.
  const t = buildSortedTree(evens(16));
  const root = sortedRoot(t);

  for (let i = 0; i + 1 < t.values.length; i++) {
    const forged: NonMembershipProof = {
      kind: "between",
      tree_size: t.values.length,
      left: proveMembership(t, t.values[i]),
      right: proveMembership(t, t.values[i + 1]),
    };
    // 경계 자신을 "없다" 고 주장
    assert.equal(verifyNonMembership(root, t.values[i], forged), false, `왼쪽 경계 ${i}`);
    assert.equal(verifyNonMembership(root, t.values[i + 1], forged), false, `오른쪽 경계 ${i}`);
  }
});

test("비포함 — 인접하지 않은 두 리프를 제시하면 실패한다", () => {
  const t = buildSortedTree(evens(16));
  const root = sortedRoot(t);
  // 0 과 4 를 경계로 내세우고 그 사이의 2 가 "없다" 고 주장한다.
  const forged: NonMembershipProof = {
    kind: "between",
    tree_size: t.values.length,
    left: proveMembership(t, t.values[0]),
    right: proveMembership(t, t.values[2]),
  };
  assert.equal(verifyNonMembership(root, t.values[1], forged), false);
});

test("비포함 — 경계 순서를 뒤집으면 실패한다", () => {
  const t = buildSortedTree(evens(16));
  const root = sortedRoot(t);
  const forged: NonMembershipProof = {
    kind: "between",
    tree_size: t.values.length,
    left: proveMembership(t, t.values[5]),
    right: proveMembership(t, t.values[4]),
  };
  assert.equal(verifyNonMembership(root, addr(9), forged), false);
});

test("비포함 — 경계의 포함 증명이 깨지면 실패한다", () => {
  const t = buildSortedTree(evens(16));
  const root = sortedRoot(t);
  const p = proveNonMembership(t, addr(7)) as Extract<NonMembershipProof, { kind: "between" }>;
  const broken: NonMembershipProof = {
    ...p,
    left: { ...p.left, audit_path: [...p.left.audit_path.slice(1), "0x" + "ee".repeat(32)] },
  };
  assert.equal(verifyNonMembership(root, addr(7), broken), false);
});

test("비포함 — 다른 목록의 루트에 대해서는 실패한다", () => {
  const t = buildSortedTree(evens(16));
  const other = rootOfList(evens(15));
  const p = proveNonMembership(t, addr(7));
  assert.equal(verifyNonMembership(other, addr(7), p), false);
});

test("비포함 — before_first 로 위장해 첫 항목보다 큰 값을 통과시킬 수 없다", () => {
  const t = buildSortedTree(evens(8));
  const root = sortedRoot(t);
  const forged: NonMembershipProof = {
    kind: "before_first",
    tree_size: t.values.length,
    right: proveMembership(t, t.values[0]),
  };
  assert.equal(verifyNonMembership(root, addr(7), forged), false);
});

test("비포함 — after_last 로 위장해 마지막보다 작은 값을 통과시킬 수 없다", () => {
  const t = buildSortedTree(evens(8));
  const root = sortedRoot(t);
  const forged: NonMembershipProof = {
    kind: "after_last",
    tree_size: t.values.length,
    left: proveMembership(t, t.values[t.values.length - 1]),
  };
  assert.equal(verifyNonMembership(root, addr(3), forged), false);
});

test("비포함 — 빈 목록 증명을 비어 있지 않은 루트에 쓸 수 없다", () => {
  const root = rootOfList(evens(4));
  assert.equal(verifyNonMembership(root, addr(3), { kind: "empty", tree_size: 0 }), false);
});
