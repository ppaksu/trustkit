// RFC 6962 머클 트리.
//
// RFC 9162 가 6962 를 대체했지만 트리 정의는 그대로 승계했다. 9162 의 변경점은
// CMS precertificate, TLS 확장 개명, 로그 OID, TransItem 인코딩으로 전부 인증서
// 생태계 배관이다.

import { createHash } from "node:crypto";

const PREFIX_LEAF = Buffer.from([0x00]);
const PREFIX_NODE = Buffer.from([0x01]);

const sha256 = (...parts: Buffer[]): Buffer =>
  createHash("sha256").update(Buffer.concat(parts)).digest();

/** RFC 가 정한 분할 지점. 다르게 가르면 같은 데이터에서 다른 루트가 나온다. */
function largestPow2Below(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** 접두사 0x00. 내부 노드(0x01)와 입력 공간을 나눠 제2역상 공격을 막는다. */
export function leafHash(data: Buffer): Buffer {
  return sha256(PREFIX_LEAF, data);
}

/** 리프 전체의 루트. */
export function mth(d: Buffer[]): Buffer {
  if (d.length === 0) return createHash("sha256").update(Buffer.alloc(0)).digest();
  if (d.length === 1) return sha256(PREFIX_LEAF, d[0]);
  const k = largestPow2Below(d.length);
  return sha256(PREFIX_NODE, mth(d.slice(0, k)), mth(d.slice(k)));
}

/** 리프 m 의 포함 증명. 루트까지 올라가며 만나는 형제 해시들. */
export function inclusionPath(m: number, d: Buffer[]): Buffer[] {
  if (d.length === 1) return [];
  const k = largestPow2Below(d.length);
  if (m < k) return [...inclusionPath(m, d.slice(0, k)), mth(d.slice(k))];
  return [...inclusionPath(m - k, d.slice(k)), mth(d.slice(0, k))];
}

/** 크기 m 에서 n 으로 덧붙이기만 했음을 보이는 증명. */
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
 * 포함 증명에서 루트를 재계산한다. 불가능한 입력이면 null.
 *
 * 결과는 **체인에 박힌 루트**와 비교해야 한다. 로그 서버가 알려준 루트와
 * 비교하면 아무것도 증명되지 않는다. 거짓 루트를 같이 불러주면 그만이다.
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
 * 일관성 증명 검증. 같은 증명으로 옛 루트와 새 루트를 동시에 재계산한다.
 *
 * 함정: 형제가 없는 자리(node 가 짝수이면서 그 레벨의 끝)에서 증명 해시를
 * 소비하면 안 된다. 소비하면 특정 (m, n) 조합에서만 실패해서 몇 개만 골라
 * 테스트하면 통과한다. 여기서 실제로 버그가 났었다.
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
