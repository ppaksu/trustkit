// 실제로 생성된 거절 기록 하나를 명세 4장과 대조한다.
//
// 실행: npm run inspect
//
// 각 항목을 라이브러리 함수를 다시 부르지 않고 node:crypto 로 손수 재계산해서
// 비교한다. 구현이 자기 자신과 일치하는지가 아니라, 문서에 적힌 정의와
// 일치하는지를 본다.
import { createHash } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import { recoverTypedDataAddress, hashTypedData, type Address, type Hex } from "viem";
import { Gatekeeper, policyHash, type Policy } from "../sdk/gatekeeper.ts";
import { domain, DOMAIN_NAME, DOMAIN_VERSION, REJECTION_TYPES } from "../lib/sign.ts";
import { REQUIRED_KEYS } from "../lib/record.ts";
import type { Receipt } from "../lib/receipt.ts";

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest();
const hx = (b: Buffer) => "0x" + b.toString("hex");
const unhex = (s: string) => Buffer.from(s.replace(/^0x/, ""), "hex");

let pass = 0;
let fail = 0;
function check(label: string, actual: unknown, expected: unknown, note = ""): void {
  const okay = JSON.stringify(actual) === JSON.stringify(expected);
  okay ? pass++ : fail++;
  const mark = okay ? "  OK  " : " FAIL ";
  console.log(`${mark} ${label}${note ? `   ${note}` : ""}`);
  if (!okay) {
    console.log(`        기대: ${JSON.stringify(expected)}`);
    console.log(`        실제: ${JSON.stringify(actual)}`);
  }
}
function assertTrue(label: string, cond: boolean, note = ""): void {
  check(label, cond, true, note);
}
function section(title: string): void {
  console.log(`\n${title}`);
}

/** 명세 4.4절의 canonical JSON 을 독립적으로 다시 구현한다 (RFC 8785). */
function jcs(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("비유한 숫자");
    return JSON.stringify(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const o = v as Record<string, unknown>;
  return (
    "{" +
    Object.keys(o)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + jcs(o[k]))
      .join(",") +
    "}"
  );
}

//policy는 아직 작성 안된건가?
const POLICY: Policy = {
  version: 1,
  denylist: ["0x000000000000000000000000000000000000dead"],
  maxValueWei: "1000000000000000000",
  allowedTargets: ["0x000000000000000000000000000000000000beef"],
};

const ANCHOR = "0x5555555555555555555555555555555555555555" as Address;
const CHAIN_ID = 84532;

async function main() {
  const gk = privateKeyToAccount(("0x" + "11".repeat(32)) as Hex);
  const D = domain(CHAIN_ID, ANCHOR);
  const g = new Gatekeeper({ account: gk, domain: D, policy: POLICY });

  const calldata = "0xa9059cbb000000000000000000000000000000000000000000000000000000000000dead" as Hex;
  const result = await g.handle({
    requester: "0xabc0000000000000000000000000000000000001" as Address,
    target: "0x000000000000000000000000000000000000dead" as Address,
    value: 5_000_000_000_000_000n,
    calldata,
  });

  if (result.decision.allow) throw new Error("거절이 나와야 한다");
  const receipt = result.receipt as Receipt;
  const leaf = receipt.leaf;

  console.log("\n생성된 리프\n");
  console.log(JSON.stringify(leaf, null, 2).split("\n").map((l) => "  " + l).join("\n"));

  // ---------------- 4.1 필드 커밋 ----------------
  section("4.1  필드 커밋");

  check("필수 키 집합이 schemaVersion 1 의 정의와 같다", leaf.keys, [...REQUIRED_KEYS[1]]);
  assertTrue("disclosure 가 키마다 하나씩 있다", receipt.disclosures.length === leaf.keys.length);

  let saltsOk = true;
  let commitsOk = true;
  for (let i = 0; i < leaf.keys.length; i++) {
    const [saltHex, key, value] = receipt.disclosures[i];
    if (unhex(saltHex).length !== 32) saltsOk = false;
    // h_i = SHA256("TRUST404/field/v1|" + canonical_json([salt, key, value]))
    const recomputed = hx(
      sha256(Buffer.from("TRUST404/field/v1|" + jcs([saltHex, key, value]), "utf8")),
    );
    if (recomputed !== leaf.field_hashes[i]) commitsOk = false;
  }
  assertTrue("salt 가 모두 32바이트다", saltsOk);
  assertTrue("각 커밋이 명세 공식으로 재계산된다", commitsOk, "SHA256(도메인 + JCS([salt,key,value]))");

  const uniqueSalts = new Set(receipt.disclosures.map((d) => d[0]));
  assertTrue("salt 가 필드마다 다르다", uniqueSalts.size === receipt.disclosures.length);

  // ---------------- 4.2 Leaf ----------------
  section("4.2  Leaf");

  check("keys 가 사전순 정렬이다", leaf.keys, [...leaf.keys].sort());
  assertTrue("keys 에 중복이 없다", new Set(leaf.keys).size === leaf.keys.length);
  assertTrue("field_hashes 길이가 keys 와 같다", leaf.field_hashes.length === leaf.keys.length);
  assertTrue(
    "field_hashes 가 모두 32바이트다",
    leaf.field_hashes.every((h) => unhex(h).length === 32),
  );

  // 위치 결합. field_hashes[i] 가 keys[i] 의 커밋인가.
  let positionBound = true;
  for (let i = 0; i < leaf.keys.length; i++) {
    if (receipt.disclosures[i][1] !== leaf.keys[i]) positionBound = false;
  }
  assertTrue("field_hashes[i] 가 keys[i] 의 커밋이다", positionBound, "위치 결합");

  check("policy_hash 가 정책 문서의 SHA256 이다", leaf.policy_hash, policyHash(POLICY));
  check("policy_hash 를 손으로 재계산해도 같다", leaf.policy_hash, hx(sha256(Buffer.from(jcs(POLICY), "utf8"))));
  assertTrue("nonce 가 32바이트다", unhex(leaf.nonce).length === 32);
  assertTrue("issued_at 이 평문 정수다", Number.isSafeInteger(leaf.issued_at));
  check("v 가 schemaVersion 1 이다", leaf.v, 1);

  // ---------------- 4.3 서명 ----------------
  section("4.3  EIP-712 서명");

  assertTrue("서명이 65바이트다", unhex(leaf.signature).length === 65);

  const keysRootManual = hx(sha256(Buffer.from(jcs(leaf.keys), "utf8")));
  const fieldsRootManual = hx(sha256(Buffer.concat(leaf.field_hashes.map(unhex))));

  const message = {
    schemaVersion: leaf.v,
    gatekeeper: leaf.gatekeeper as Address,
    policyHash: leaf.policy_hash as Hex,
    keysRoot: keysRootManual as Hex,
    fieldsRoot: fieldsRootManual as Hex,
    issuedAt: BigInt(leaf.issued_at),
    nonce: leaf.nonce as Hex,
  };
  const recovered = await recoverTypedDataAddress({
    domain: D,
    types: REJECTION_TYPES,
    primaryType: "RejectionRecord",
    message,
    signature: leaf.signature as Hex,
  });
  check(
    "손으로 만든 루트로 서명이 gatekeeper 로 복원된다",
    recovered.toLowerCase(),
    leaf.gatekeeper.toLowerCase(),
    "keysRoot·fieldsRoot 재계산 포함",
  );

  check("도메인 이름이 프로토콜 식별자다", D.name, DOMAIN_NAME);
  check("도메인 버전", D.version, DOMAIN_VERSION);
  check("도메인에 chainId 가 있다", D.chainId, CHAIN_ID);
  check("도메인에 verifyingContract 가 있다", D.verifyingContract, ANCHOR);

  const digestHere = hashTypedData({ domain: D, types: REJECTION_TYPES, primaryType: "RejectionRecord", message });
  const digestOtherChain = hashTypedData({
    domain: domain(1, ANCHOR),
    types: REJECTION_TYPES,
    primaryType: "RejectionRecord",
    message,
  });
  assertTrue("다른 체인에서는 digest 가 달라진다", digestHere !== digestOtherChain, "교차 체인 재사용 차단");

  // ---------------- 4.4 Leaf Hash ----------------
  section("4.4  Leaf Hash");

  const canonical = jcs(leaf);
  assertTrue("정규화 결과에 공백이 없다", !/[\s]/.test(canonical.replace(/"[^"]*"/g, "")));
  const leafHashManual = hx(sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonical, "utf8")])));
  check("leaf_hash = SHA256(0x00 || JCS(leaf))", receipt.leaf_hash, leafHashManual);

  const noPrefix = hx(sha256(Buffer.from(canonical, "utf8")));
  assertTrue("접두사 없는 해시와 다르다", receipt.leaf_hash !== noPrefix, "두 번째 원상 공격 방지");

  // ---------------- 4.5 Receipt ----------------
  section("4.5  Receipt");

  assertTrue("leaf 를 담고 있다", !!receipt.leaf);
  assertTrue("leaf_hash 를 담고 있다", !!receipt.leaf_hash);
  assertTrue("disclosures 를 담고 있다", receipt.disclosures.length > 0);
  check("로그에 제출하지 않았으므로 log_ack 가 없다", receipt.log_ack, null);
  assertTrue(
    "리프에는 원문이 하나도 없다",
    !JSON.stringify(leaf).includes("DENYLIST_SANCTIONED"),
    "값은 커밋으로만 남는다",
  );

  // ---------------- 4.6 선택적 공개 ----------------
  section("4.6  선택적 공개");

  const ruleIdx = leaf.keys.indexOf("rule_id");
  const [salt, key, value] = receipt.disclosures[ruleIdx];
  const openOne = hx(sha256(Buffer.from("TRUST404/field/v1|" + jcs([salt, key, value]), "utf8")));
  check("공개한 필드가 그 자리의 커밋과 맞는다", openOne, leaf.field_hashes[ruleIdx], `키=${key}`);
  console.log(`       공개된 값: ${value}`);

  const forged = hx(sha256(Buffer.from("TRUST404/field/v1|" + jcs([salt, key, "SOMETHING_ELSE"]), "utf8")));
  assertTrue("값을 바꾸면 자리와 안 맞는다", forged !== leaf.field_hashes[ruleIdx]);

  const otherIdx = leaf.keys.indexOf("target");
  assertTrue(
    "공개하지 않은 필드는 해시만 남는다",
    unhex(leaf.field_hashes[otherIdx]).length === 32 && !JSON.stringify(leaf).includes("dead0"),
  );

  console.log(`\n대조 결과: ${pass}건 일치, ${fail}건 불일치\n`);
  if (fail > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error("\n대조 실패:", e instanceof Error ? e.message : e, "\n");
  process.exitCode = 1;
});
