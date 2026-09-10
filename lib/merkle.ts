// RFC 6962 Merkle tree. 명세 docs/DESIGN.md 5장 그대로.
// 트리 정의는 RFC 9162 도 변경 없이 승계했다. 5.0절 참조.
import { createHash } from "node:crypto";

const PREFIX_LEAF = Buffer.from([0x00]);
const PREFIX_NODE = Buffer.from([0x01]);

const sha256 = (...parts: Buffer[]): Buffer =>
  createHash("sha256").update(Buffer.concat(parts)).digest();

/** n 보다 작은 최대 2의 거듭제곱. n >= 2 에서만 호출된다. */
function largestPow2Below(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** 리프 데이터 하나의 해시. 접두사 0x00 이 두 번째 원상 공격을 막는다. */
export function leafHash(data: Buffer): Buffer {
  return sha256(PREFIX_LEAF, data);
}

/** RFC 6962 §2.1 — Merkle Tree Hash */
export function mth(d: Buffer[]): Buffer {
  if (d.length === 0) return createHash("sha256").update(Buffer.alloc(0)).digest();
  if (d.length === 1) return sha256(PREFIX_LEAF, d[0]);
  const k = largestPow2Below(d.length);
  return sha256(PREFIX_NODE, mth(d.slice(0, k)), mth(d.slice(k)));
}

/** RFC 6962 §2.1.1 — 인덱스 m 의 audit path */
export function inclusionPath(m: number, d: Buffer[]): Buffer[] {
  if (d.length === 1) return [];
  const k = largestPow2Below(d.length);
  if (m < k) return [...inclusionPath(m, d.slice(0, k)), mth(d.slice(k))];
  return [...inclusionPath(m - k, d.slice(k)), mth(d.slice(0, k))];
}

/** RFC 6962 §2.1.2 — 크기 m 트리에서 크기 n 트리로의 consistency proof */
export function consistencyProof(m: number, d: Buffer[]): Buffer[] {
  return subproof(m, d, true);
}

function subproof(m: number, d: Buffer[], b: boolean): Buffer[] {
  if (m === d.length) return b ? [] : [mth(d)];
  const k = largestPow2Below(d.length);
  if (m <= k) return [...subproof(m, d.slice(0, k), b), mth(d.slice(k))];
  return [...subproof(m - k, d.slice(k), false), mth(d.slice(0, k))];
}

/**
 * audit path 로부터 루트를 재계산한다. 반복형이며 생성기와 독립이다.
 * 검증자는 이 결과를 온체인 앵커의 루트와 비교한다. 현재 루트가 아니다.
 * 실패하면 null.
 */
export function rootFromInclusionProof(
  leafIndex: number,
  treeSize: number,
  leaf: Buffer,
  proof: Buffer[],
): Buffer | null {
  if (leafIndex < 0 || treeSize < 0 || leafIndex >= treeSize) return null;
  let node = leafIndex;
  let lastNode = treeSize - 1;
  let i = 0;
  let res = leaf;
  while (lastNode > 0) {
    if (i === proof.length) return null;
    if (node % 2 === 1) {
      res = sha256(PREFIX_NODE, proof[i], res);
      i++;
    } else if (node < lastNode) {
      res = sha256(PREFIX_NODE, res, proof[i]);
      i++;
    }
    node = Math.floor(node / 2);
    lastNode = Math.floor(lastNode / 2);
  }
  if (i !== proof.length) return null;
  return res;
}

/**
 * 크기 n 트리가 크기 m 트리의 순수 확장인지 검증한다.
 *
 * 주의 — 형제가 없는 자리(node 가 짝수이고 lastNode 와 같은 레벨 끝)에서는
 * 증명 원소를 소비하면 안 된다. 소비하면 특정 (m, n) 조합에서만 실패해
 * 몇 개만 테스트하면 통과한다. test/merkle.test.ts 의 모든 m < n 검사가
 * 이 버그를 잡는 장치다.
 */
export function verifyConsistency(
  m: number,
  n: number,
  oldRoot: Buffer,
  newRoot: Buffer,
  proof: Buffer[],
): boolean {
  if (m < 0 || n < m) return false;
  if (m === n) return proof.length === 0 && oldRoot.equals(newRoot);
  if (m === 0) return proof.length === 0;
  if (proof.length === 0) return false;

  let node = m - 1;
  let lastNode = n - 1;
  let i = 0;
  while (node % 2 === 1) {
    node = Math.floor(node / 2);
    lastNode = Math.floor(lastNode / 2);
  }

  let n1: Buffer;
  let n2: Buffer;
  if (node > 0) {
    n1 = proof[i];
    n2 = proof[i];
    i++;
  } else {
    n1 = oldRoot;
    n2 = oldRoot;
  }

  while (node > 0) {
    if (node % 2 === 1) {
      if (i === proof.length) return false;
      n1 = sha256(PREFIX_NODE, proof[i], n1);
      n2 = sha256(PREFIX_NODE, proof[i], n2);
      i++;
    } else if (node < lastNode) {
      if (i === proof.length) return false;
      n2 = sha256(PREFIX_NODE, n2, proof[i]);
      i++;
    }
    node = Math.floor(node / 2);
    lastNode = Math.floor(lastNode / 2);
  }
  while (lastNode > 0) {
    if (i === proof.length) return false;
    n2 = sha256(PREFIX_NODE, n2, proof[i]);
    i++;
    lastNode = Math.floor(lastNode / 2);
  }

  return i === proof.length && n1.equals(oldRoot) && n2.equals(newRoot);
}
