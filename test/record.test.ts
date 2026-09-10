// 레코드 계층 테스트. 명세 docs/DESIGN.md 4장.
// 실행: node --test "test/**/*.test.ts"
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { canonicalize, canonicalBytes, CanonicalizationError } from "../lib/jcs.ts";
import {
  buildLeafBody,
  fieldCommitment,
  keysRoot,
  fieldsRoot,
  leafHash,
  validateLeafStructure,
  verifyDisclosure,
  REQUIRED_KEYS,
  RecordError,
  type Leaf,
  type Disclosure,
} from "../lib/record.ts";

const SALT_A = "0x" + "11".repeat(32);
const SALT_B = "0x" + "22".repeat(32);

const sampleFields = () => ({
  requester: "0xabc0000000000000000000000000000000000001",
  target: "0xdef0000000000000000000000000000000000002",
  value: "1000000000000000000",
  calldata_hash: "0x" + "cd".repeat(32),
  rule_id: "DENYLIST_SANCTIONED",
  severity: "block",
});

const build = () =>
  buildLeafBody({
    gatekeeper: "0x1111111111111111111111111111111111111111",
    policyHash: "0x" + "9a".repeat(32),
    fields: sampleFields(),
    issuedAt: 1757203200,
  });

const sign = (body: ReturnType<typeof build>["body"]): Leaf => ({
  ...body,
  signature: "0x" + "ab".repeat(65),
});

// ---------- JCS ----------

test("JCS — 키를 UTF-16 코드 유닛 순서로 정렬한다", () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalize({ "é": 1, a: 2, Z: 3 }), '{"Z":3,"a":2,"é":1}');
  assert.equal(canonicalize({ b: { d: 1, c: 2 }, a: 3 }), '{"a":3,"b":{"c":2,"d":1}}');
});

test("JCS — 공백이 없고 배열 순서는 유지된다", () => {
  assert.equal(canonicalize([3, 1, 2]), "[3,1,2]");
  assert.equal(canonicalize({ a: [1, { c: 1, b: 2 }] }), '{"a":[1,{"b":2,"c":1}]}');
});

test("JCS — 숫자는 ECMAScript 표현을 따른다", () => {
  // JCS 가 요구하는 표현이 Number::toString 이고 JSON.stringify 가 그것이다.
  assert.equal(canonicalize(1.0), "1");
  assert.equal(canonicalize(-0), "0");
  assert.equal(canonicalize(1e21), "1e+21");
  assert.equal(canonicalize(0.1), "0.1");
  assert.equal(canonicalize(1e-7), "1e-7");
});

test("JCS — 비유한 숫자를 거부한다 (JSON.stringify 는 조용히 null 로 바꾼다)", () => {
  assert.equal(JSON.stringify(NaN), "null", "전제 확인");
  assert.throws(() => canonicalize(NaN), CanonicalizationError);
  assert.throws(() => canonicalize(Infinity), CanonicalizationError);
  assert.throws(() => canonicalize(-Infinity), CanonicalizationError);
});

test("JCS — 같은 객체를 다른 순서로 써도 같은 바이트열이 나온다", () => {
  const x = { z: [1, 2], a: "é", m: { q: true, b: null } };
  const y = { m: { b: null, q: true }, a: "é", z: [1, 2] };
  assert.equal(canonicalize(x), canonicalize(y));
});

// ---------- 필드 커밋 ----------

test("커밋 — salt 가 다르면 같은 값도 다른 해시가 된다", () => {
  const a = fieldCommitment([SALT_A, "severity", "block"]);
  const b = fieldCommitment([SALT_B, "severity", "block"]);
  assert.ok(!a.equals(b));
  assert.equal(a.length, 32);
});

test("커밋 — 키가 다르면 해시가 다르다", () => {
  const a = fieldCommitment([SALT_A, "target", "0xdead"]);
  const b = fieldCommitment([SALT_A, "requester", "0xdead"]);
  assert.ok(!a.equals(b));
});

test("커밋 — 32바이트가 아닌 salt 를 거부한다", () => {
  assert.throws(() => fieldCommitment(["0x1234", "severity", "block"]), RecordError);
});

// ---------- 리프 구성 ----------

test("리프 — keys 는 필수 집합과 같고 사전순이다", () => {
  const { body } = build();
  assert.deepEqual(body.keys, REQUIRED_KEYS[1]);
  assert.deepEqual([...body.keys].sort(), body.keys);
});

test("리프 — field_hashes[i] 가 keys[i] 의 커밋이다 (위치 결합)", () => {
  const { body, disclosures } = build();
  assert.equal(disclosures.length, body.keys.length);
  for (let i = 0; i < body.keys.length; i++) {
    assert.equal(disclosures[i][1], body.keys[i], `위치 ${i} 의 키`);
    assert.equal(
      "0x" + fieldCommitment(disclosures[i]).toString("hex"),
      body.field_hashes[i],
      `위치 ${i} 의 커밋`,
    );
  }
});

test("리프 — 필드가 빠지거나 남으면 구성이 거부된다", () => {
  const missing = sampleFields();
  delete (missing as Record<string, string>).target;
  assert.throws(
    () => buildLeafBody({ gatekeeper: "0x11", policyHash: "0x22", fields: missing, issuedAt: 1 }),
    RecordError,
  );

  const extra = { ...sampleFields(), memo: "hi" };
  assert.throws(
    () => buildLeafBody({ gatekeeper: "0x11", policyHash: "0x22", fields: extra, issuedAt: 1 }),
    RecordError,
  );
});

test("리프 — nonce 와 salt 가 호출마다 달라진다", () => {
  const a = build();
  const b = build();
  assert.notEqual(a.body.nonce, b.body.nonce);
  assert.notEqual(a.disclosures[0][0], b.disclosures[0][0]);
});

// ---------- 구조 검증 ----------

test("구조 검증 — 정상 리프를 통과시킨다", () => {
  const { body } = build();
  validateLeafStructure(body);
});

test("구조 검증 — 키를 하나 지우면 거부한다", () => {
  const { body } = build();
  const bad = { ...body, keys: body.keys.slice(0, 5), field_hashes: body.field_hashes.slice(0, 5) };
  assert.throws(() => validateLeafStructure(bad), RecordError);
});

test("구조 검증 — 키 순서를 뒤집으면 거부한다", () => {
  const { body } = build();
  const bad = { ...body, keys: [...body.keys].reverse() };
  assert.throws(() => validateLeafStructure(bad), RecordError);
});

test("구조 검증 — keys 와 field_hashes 길이가 어긋나면 거부한다", () => {
  const { body } = build();
  const bad = { ...body, field_hashes: body.field_hashes.slice(0, 5) };
  assert.throws(() => validateLeafStructure(bad), RecordError);
});

// ---------- 선택적 공개 ----------

test("공개 — 정상 disclosure 가 위치 대조를 통과한다", () => {
  const { body, disclosures } = build();
  for (const d of disclosures) {
    assert.ok(verifyDisclosure(body, d), `${d[1]} 공개 검증`);
  }
});

test("공개 — 값을 바꾼 disclosure 는 실패한다", () => {
  const { body, disclosures } = build();
  const forged: Disclosure = [disclosures[0][0], disclosures[0][1], "TAMPERED"];
  assert.equal(verifyDisclosure(body, forged), false);
});

test("공개 — 게이트키퍼가 한 키를 두 번 커밋하면 누락된 키에서 드러난다", () => {
  // target 자리에 rule_id 커밋을 넣어 target 을 사실상 빠뜨린 리프.
  const { body, disclosures } = build();
  const iTarget = body.keys.indexOf("target");
  const iRule = body.keys.indexOf("rule_id");
  const forgedLeaf = { ...body, field_hashes: [...body.field_hashes] };
  forgedLeaf.field_hashes[iTarget] = body.field_hashes[iRule];

  // 구조 검증은 통과한다. 길이와 키 집합은 멀쩡하기 때문이다.
  validateLeafStructure(forgedLeaf);

  // 그러나 target 을 공개하는 순간 그 자리의 해시가 안 맞는다.
  const dTarget = disclosures[iTarget];
  assert.equal(verifyDisclosure(forgedLeaf, dTarget), false, "누락된 target 이 드러나야 한다");
});

// ---------- 루트와 리프 해시 ----------

test("루트 — keysRoot 와 fieldsRoot 는 32바이트다", () => {
  const { body } = build();
  assert.equal(keysRoot(body.keys).length, 32);
  assert.equal(fieldsRoot(body.field_hashes).length, 32);
});

test("루트 — 키를 하나 바꾸면 keysRoot 가 바뀐다", () => {
  const { body } = build();
  const before = keysRoot(body.keys);
  const after = keysRoot([...body.keys.slice(0, 5), "memo"]);
  assert.ok(!before.equals(after));
});

test("리프 해시 — 필드 순서를 바꿔도 같은 해시가 나온다 (JCS 덕분)", () => {
  const { body } = build();
  const leaf = sign(body);
  const shuffled = {
    signature: leaf.signature,
    nonce: leaf.nonce,
    issued_at: leaf.issued_at,
    field_hashes: leaf.field_hashes,
    keys: leaf.keys,
    policy_hash: leaf.policy_hash,
    gatekeeper: leaf.gatekeeper,
    v: leaf.v,
  } as Leaf;
  assert.ok(leafHash(leaf).equals(leafHash(shuffled)));
});

test("리프 해시 — 값을 하나 바꾸면 해시가 바뀐다", () => {
  const { body } = build();
  const leaf = sign(body);
  const changed: Leaf = { ...leaf, issued_at: leaf.issued_at + 1 };
  assert.ok(!leafHash(leaf).equals(leafHash(changed)));
});

test("리프 해시 — 접두사 0x00 이 들어간다", () => {
  const leaf = sign(build().body);
  const expected = createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x00]), canonicalBytes(leaf)]))
    .digest();
  assert.ok(leafHash(leaf).equals(expected));
});
