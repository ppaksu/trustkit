// 명세 docs/DESIGN.md 5.4절 필수 테스트 5종.
// 실행: node --test
import test from "node:test";
import assert from "node:assert/strict";
import {
  mth,
  leafHash,
  inclusionPath,
  consistencyProof,
  rootFromInclusionProof,
  verifyConsistency,
} from "../lib/merkle.ts";

const leaf = (i: number) => Buffer.from(`leaf-${i}`, "utf8");
const tree = (n: number) => Array.from({ length: n }, (_, i) => leaf(i));

test("알려진 값 — 빈 트리와 빈 리프", () => {
  assert.equal(
    mth([]).toString("hex"),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    'MTH({}) = SHA256("")',
  );
  assert.equal(
    leafHash(Buffer.alloc(0)).toString("hex"),
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "빈 리프 = SHA256(0x00)",
  );
});

test("1 — 크기 1~64, 모든 인덱스의 포함 증명이 통과한다", () => {
  for (let n = 1; n <= 64; n++) {
    const d = tree(n);
    const root = mth(d);
    for (let m = 0; m < n; m++) {
      const r = rootFromInclusionProof(m, n, leafHash(d[m]), inclusionPath(m, d));
      assert.ok(r !== null && r.equals(root), `inclusion n=${n} m=${m}`);
    }
  }
});

test("2 — 모든 m < n 쌍의 일관성 증명이 통과한다", () => {
  // 형제 없는 자리에서 증명 원소를 소비하는 버그를 잡는 검사다.
  // 몇 개만 돌리면 통과하므로 전수로 돌린다.
  for (let n = 2; n <= 64; n++) {
    const dn = tree(n);
    const rn = mth(dn);
    for (let m = 1; m < n; m++) {
      const ok = verifyConsistency(m, n, mth(tree(m)), rn, consistencyProof(m, dn));
      assert.ok(ok, `consistency m=${m} n=${n}`);
    }
  }
});

test("3 — m = n 인 동일 트리의 일관성 증명은 비어 있고 통과한다", () => {
  for (let n = 1; n <= 32; n++) {
    const d = tree(n);
    const r = mth(d);
    const p = consistencyProof(n, d);
    assert.equal(p.length, 0, `PROOF(n,n) 은 비어야 한다 n=${n}`);
    assert.ok(verifyConsistency(n, n, r, r, p), `consistency m=n=${n}`);
  }
});

test("4 — 음성: 리프를 고치면 일관성 증명이 반드시 실패한다", () => {
  for (let n = 4; n <= 32; n++) {
    for (let m = 1; m < n; m++) {
      const dn = tree(n);
      const victim = m > 1 ? m - 1 : 0; // 옛 트리 안쪽 리프
      dn[victim] = Buffer.from("TAMPERED", "utf8");
      const ok = verifyConsistency(m, n, mth(tree(m)), mth(dn), consistencyProof(m, dn));
      assert.equal(ok, false, `조작 미검출 m=${m} n=${n} victim=${victim}`);
    }
  }
});

test("5 — 음성: audit path 원소를 뒤집으면 포함 증명이 실패한다", () => {
  for (let n = 2; n <= 32; n++) {
    const d = tree(n);
    const root = mth(d);
    for (let m = 0; m < n; m++) {
      const p = inclusionPath(m, d);
      for (let j = 0; j < p.length; j++) {
        const q = p.map((x) => Buffer.from(x));
        q[j][0] ^= 0xff;
        const r = rootFromInclusionProof(m, n, leafHash(d[m]), q);
        assert.ok(r === null || !r.equals(root), `변조 미검출 n=${n} m=${m} j=${j}`);
      }
    }
  }
});

test("6 — 음성: 다른 인덱스로 주장하면 포함 증명이 실패한다", () => {
  for (let n = 2; n <= 32; n++) {
    const d = tree(n);
    const root = mth(d);
    for (let m = 0; m < n; m++) {
      const wrong = (m + 1) % n;
      const r = rootFromInclusionProof(wrong, n, leafHash(d[m]), inclusionPath(m, d));
      assert.ok(r === null || !r.equals(root), `인덱스 위조 미검출 n=${n} m=${m}`);
    }
  }
});
