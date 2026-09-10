// 서명 계층 테스트. 명세 docs/DESIGN.md 4.3절.
import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import { hashTypedData, type Address } from "viem";
import { buildLeafBody, leafHash, type Leaf } from "../lib/record.ts";
import {
  domain,
  rejectionDigest,
  signLeaf,
  recoverLeafSigner,
  verifyLeafSignature,
  signLogAck,
  verifyLogAck,
  SignatureError,
  REJECTION_TYPES,
} from "../lib/sign.ts";

const KEY_GK = ("0x" + "11".repeat(32)) as `0x${string}`;
const KEY_OP = ("0x" + "22".repeat(32)) as `0x${string}`;
const KEY_EVIL = ("0x" + "33".repeat(32)) as `0x${string}`;

const gk = privateKeyToAccount(KEY_GK);
const op = privateKeyToAccount(KEY_OP);
const evil = privateKeyToAccount(KEY_EVIL);

const ANCHOR = "0x5555555555555555555555555555555555555555" as Address;
const D = domain(84532, ANCHOR); // Base Sepolia

const build = (gatekeeper: Address = gk.address) =>
  buildLeafBody({
    gatekeeper,
    policyHash: "0x" + "9a".repeat(32),
    fields: {
      requester: "0xabc0000000000000000000000000000000000001",
      target: "0xdef0000000000000000000000000000000000002",
      value: "1000000000000000000",
      calldata_hash: "0x" + "cd".repeat(32),
      rule_id: "DENYLIST_SANCTIONED",
      severity: "block",
    },
    issuedAt: 1757203200,
  }).body;

// ---------- 왕복 ----------

test("서명 — 왕복 검증이 통과한다", async () => {
  const leaf = await signLeaf(build(), gk, D);
  assert.equal((await recoverLeafSigner(leaf, D)).toLowerCase(), gk.address.toLowerCase());
  assert.ok(await verifyLeafSignature(leaf, D));
  assert.equal(leaf.signature.length, 132, "65바이트 hex");
});

test("서명 — 다른 키로 서명하면 gatekeeper 와 안 맞는다 (D1 부인 시연의 반대편)", async () => {
  const body = build(gk.address); // 리프는 gk 를 주장
  const leaf = await signLeaf(body, evil, D); // 실제 서명은 evil
  assert.equal(await verifyLeafSignature(leaf, D), false);
});

// ---------- 도메인 분리 ----------

test("도메인 — chainId 가 다르면 digest 가 달라진다", () => {
  const body = build();
  const a = rejectionDigest(body, domain(84532, ANCHOR));
  const b = rejectionDigest(body, domain(1, ANCHOR));
  assert.notEqual(a, b);
});

test("도메인 — verifyingContract 가 다르면 digest 가 달라진다", () => {
  const body = build();
  const other = "0x6666666666666666666666666666666666666666" as Address;
  assert.notEqual(rejectionDigest(body, domain(84532, ANCHOR)), rejectionDigest(body, domain(84532, other)));
});

test("도메인 — 다른 체인에서 만든 서명은 재사용되지 않는다", async () => {
  const leaf = await signLeaf(build(), gk, domain(1, ANCHOR));
  assert.ok(await verifyLeafSignature(leaf, domain(1, ANCHOR)), "원래 체인에서는 유효");
  assert.equal(await verifyLeafSignature(leaf, domain(84532, ANCHOR)), false, "다른 체인에서는 무효");
});

// ---------- 서명이 덮는 범위 ----------

test("서명 — 필드 커밋을 바꾸면 검증이 실패한다", async () => {
  const leaf = await signLeaf(build(), gk, D);
  const tampered: Leaf = {
    ...leaf,
    field_hashes: [...leaf.field_hashes.slice(0, 5), "0x" + "ff".repeat(32)],
  };
  assert.equal(await verifyLeafSignature(tampered, D), false);
});

test("서명 — 알 수 없는 스키마 버전은 서명 이전에 거부된다", () => {
  const body = build();
  assert.throws(() => rejectionDigest({ ...body, v: 2 } as never, D));
});

test("서명 — schemaVersion 이 digest 에 반영된다 (교차 버전 재사용 차단)", () => {
  // 구조 검증을 우회해 타입 정의만 확인한다. 버전이 서명 대상 필드이므로
  // 값이 다르면 digest 가 달라야 한다.
  const body = build();
  const msg = {
    schemaVersion: 1,
    gatekeeper: body.gatekeeper as `0x${string}`,
    policyHash: body.policy_hash as `0x${string}`,
    keysRoot: ("0x" + "11".repeat(32)) as `0x${string}`,
    fieldsRoot: ("0x" + "22".repeat(32)) as `0x${string}`,
    issuedAt: 1n,
    nonce: ("0x" + "33".repeat(32)) as `0x${string}`,
  };
  const one = hashTypedData({ domain: D, types: REJECTION_TYPES, primaryType: "RejectionRecord", message: msg });
  const two = hashTypedData({
    domain: D,
    types: REJECTION_TYPES,
    primaryType: "RejectionRecord",
    message: { ...msg, schemaVersion: 2 },
  });
  assert.notEqual(one, two);
});

test("서명 — 정책 해시, 발급 시각, nonce 가 전부 서명에 덮인다", async () => {
  const body = build();
  const base = rejectionDigest(body, D);
  assert.notEqual(base, rejectionDigest({ ...body, policy_hash: "0x" + "01".repeat(32) }, D));
  assert.notEqual(base, rejectionDigest({ ...body, issued_at: body.issued_at + 1 }, D));
  assert.notEqual(base, rejectionDigest({ ...body, nonce: "0x" + "07".repeat(32) }, D));
});

test("서명 — 루트는 항상 리프에서 재계산되므로 위조 루트를 넘길 경로가 없다", async () => {
  // field_hashes 를 바꾸면 fieldsRoot 도 반드시 따라 바뀐다.
  const body = build();
  const swapped = { ...body, field_hashes: [...body.field_hashes].reverse() };
  assert.notEqual(rejectionDigest(body, D), rejectionDigest(swapped, D));
});

test("서명 — 구조가 깨진 리프는 서명 단계 이전에 거부된다", async () => {
  const body = build();
  const broken = { ...body, keys: body.keys.slice(0, 5) };
  assert.throws(() => rejectionDigest(broken, D));
});

// ---------- LogAck ----------

test("접수 확인 — 왕복 검증이 통과한다", async () => {
  const leaf = await signLeaf(build(), gk, D);
  const h = ("0x" + leafHash(leaf).toString("hex")) as `0x${string}`;
  const ack = await signLogAck(
    { leaf_hash: h, received_at: 1757203201, promised_by: 1757206801, log_operator: op.address },
    op,
    D,
  );
  assert.ok(await verifyLogAck(ack, op.address, D));
});

test("접수 확인 — 다른 운영자가 서명하면 실패한다", async () => {
  const ack = await signLogAck(
    {
      leaf_hash: ("0x" + "ab".repeat(32)) as `0x${string}`,
      received_at: 1,
      promised_by: 2,
      log_operator: op.address,
    },
    evil,
    D,
  );
  assert.equal(await verifyLogAck(ack, op.address, D), false);
});

test("접수 확인 — 약속 시각이 접수 시각보다 이르면 만들 수 없다", async () => {
  await assert.rejects(
    signLogAck(
      {
        leaf_hash: ("0x" + "ab".repeat(32)) as `0x${string}`,
        received_at: 100,
        promised_by: 50,
        log_operator: op.address,
      },
      op,
      D,
    ),
    SignatureError,
  );
});

test("접수 확인 — 리프 해시를 바꾸면 검증이 실패한다", async () => {
  const ack = await signLogAck(
    {
      leaf_hash: ("0x" + "ab".repeat(32)) as `0x${string}`,
      received_at: 1,
      promised_by: 2,
      log_operator: op.address,
    },
    op,
    D,
  );
  const tampered = { ...ack, leaf_hash: ("0x" + "cd".repeat(32)) as `0x${string}` };
  assert.equal(await verifyLogAck(tampered, op.address, D), false);
});

test("접수 확인 — 두 서명 타입이 서로 섞이지 않는다", async () => {
  // RejectionRecord 서명을 LogAck 으로 제시해도 통과하면 안 된다.
  const leaf = await signLeaf(build(), gk, D);
  const fake = {
    leaf_hash: ("0x" + "ab".repeat(32)) as `0x${string}`,
    received_at: 1,
    promised_by: 2,
    log_operator: gk.address,
    log_signature: leaf.signature as `0x${string}`,
  };
  assert.equal(await verifyLogAck(fake, gk.address, D), false);
});
