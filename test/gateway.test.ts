// 게이트웨이 SDK 테스트.
import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { privateKeyToAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import { domain, verifyLeafSignature, verifyLogAck } from "../lib/sign.ts";
import { leafHash, verifyDisclosure } from "../lib/record.ts";
import { LogStore } from "../lib/log-store.ts";
import { createLogServer } from "../lib/log-server.ts";
import { assignFault, disclosureFor } from "../lib/receipt.ts";
import { Gateway, evaluate, policyHash, type PolicyDocument, type TxRequest } from "../sdk/gateway.ts";

const gk = privateKeyToAccount(("0x" + "11".repeat(32)) as `0x${string}`);
const op = privateKeyToAccount(("0x" + "22".repeat(32)) as `0x${string}`);
const D = domain(84532, "0x5555555555555555555555555555555555555555" as Address);
const NOW = 1757203200;

const SANCTIONED = "0x000000000000000000000000000000000000dead" as Address;
const NORMAL = "0x000000000000000000000000000000000000beef" as Address;
const STRANGER = "0x000000000000000000000000000000000000cafe" as Address;

const POLICY: PolicyDocument = {
  version: 2,
  rules: [
    {
      rule_id: "DENYLIST_SANCTIONED",
      description: "수신자가 제재 목록에 있음",
      severity: "block",
      verifiability: "verifiable",
      predicate: { kind: "in_set", field: "target", set: "denylist" },
    },
    {
      rule_id: "AMOUNT_CAP_EXCEEDED",
      description: "금액이 한도를 초과함",
      severity: "hold",
      verifiability: "verifiable",
      predicate: { kind: "gt", field: "value", limit: "1000000000000000000" },
    },
    {
      rule_id: "WHITELIST_MISS",
      description: "수신자가 허용 목록 밖임",
      severity: "review",
      verifiability: "verifiable",
      predicate: { kind: "not_in_set", field: "target", set: "allowedTargets" },
    },
    {
      rule_id: "MANUAL_REVIEW_HOLD",
      description: "담당자 수동 검토 보류",
      severity: "hold",
      verifiability: "discretionary",
    },
  ],
  data_sets: { denylist: [SANCTIONED], allowedTargets: [NORMAL] },
};

const req = (over: Partial<TxRequest> = {}): TxRequest => ({
  requester: "0xabc0000000000000000000000000000000000001" as Address,
  target: NORMAL,
  value: 1n,
  calldata: "0xa9059cbb" as Hex,
  ...over,
});

// ---------- 정책 ----------

test("정책 — 통과 요청은 아무 기록도 남기지 않는다", async () => {
  const g = new Gateway({ account: gk, domain: D, policy: POLICY, now: () => NOW });
  const r = await g.handle({ request: req() });
  assert.equal(r.decision.allow, true);
  assert.equal(r.receipt, undefined, "이 로그가 다루는 것은 거절뿐이다");
});

test("정책 — 먼저 일치하는 규칙이 이긴다", () => {
  // 제재 대상이면서 한도도 넘는 요청. 순서상 제재가 먼저다.
  const d = evaluate(POLICY, req({ target: SANCTIONED, value: 10n ** 19n }));
  assert.equal(d.allow, false);
  assert.equal(d.allow === false && d.rule.rule_id, "DENYLIST_SANCTIONED");
  assert.equal(d.allow === false && d.rule.severity, "block");
});

test("정책 — 세 규칙이 각각 다른 심각도를 낸다", () => {
  const a = evaluate(POLICY, req({ target: SANCTIONED }));
  const b = evaluate(POLICY, req({ value: 10n ** 19n }));
  const c = evaluate(POLICY, req({ target: STRANGER }));
  assert.equal(a.allow === false && a.rule.severity, "block");
  assert.equal(b.allow === false && b.rule.severity, "hold");
  assert.equal(c.allow === false && c.rule.severity, "review");
});

test("정책 — 규칙 순서를 바꾸면 policy_hash 가 달라진다", () => {
  const swapped: PolicyDocument = { ...POLICY, rules: [...POLICY.rules].reverse() };
  assert.notEqual(policyHash(POLICY), policyHash(swapped));
  // 같은 내용이면 같은 해시. JCS 덕분에 키 순서는 영향이 없다.
  assert.equal(policyHash(POLICY), policyHash({ ...POLICY }));
});

// ---------- 영수증 ----------

test("영수증 — 거절이면 서명된 영수증이 나온다", async () => {
  const g = new Gateway({ account: gk, domain: D, policy: POLICY, now: () => NOW });
  const r = await g.handle({ request: req({ target: SANCTIONED }) });
  assert.equal(r.decision.allow, false);
  const receipt = r.receipt!;
  assert.ok(await verifyLeafSignature(receipt.leaf, D));
  assert.equal(receipt.leaf_hash, "0x" + leafHash(receipt.leaf).toString("hex"));
  assert.equal(receipt.leaf.policy_hash, g.policyHash);
  assert.equal(receipt.log_ack, null, "제출 전에는 접수 확인이 없다");
});

test("영수증 — 판정 사유가 커밋되고 선택적으로 공개된다", async () => {
  const g = new Gateway({ account: gk, domain: D, policy: POLICY, now: () => NOW });
  const receipt = (await g.handle({ request: req({ target: SANCTIONED }) })).receipt!;

  const rule = disclosureFor(receipt, "rule_id")!;
  assert.equal(rule[2], "DENYLIST_SANCTIONED");
  assert.ok(verifyDisclosure(receipt.leaf, rule));

  // 사유만 공개해도 수신자는 해시로만 남는다
  const target = disclosureFor(receipt, "target")!;
  assert.equal(target[2], SANCTIONED.toLowerCase());
  assert.ok(verifyDisclosure(receipt.leaf, target));
});

test("영수증 — calldata 해시가 원문 calldata 에서 계산된다", async () => {
  const { createHash } = await import("node:crypto");
  const g = new Gateway({ account: gk, domain: D, policy: POLICY, now: () => NOW });
  const calldata = "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000001" as Hex;
  const receipt = (await g.handle({ request: req({ target: SANCTIONED, calldata }) })).receipt!;
  const d = disclosureFor(receipt, "calldata_hash")!;
  const expected =
    "0x" +
    createHash("sha256").update(Buffer.from(calldata.slice(2), "hex")).digest("hex");
  assert.equal(d[2], expected);
});

// ---------- 로그 제출 ----------

test("제출 — 로그에 올라가면 접수 확인이 영수증에 붙는다", async () => {
  const store = new LogStore({
    path: ":memory:",
    domain: D,
    operator: op,
    isRegistered: async () => true,
    now: () => NOW,
  });
  const server = createLogServer(store);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const g = new Gateway({
    account: gk,
    domain: D,
    policy: POLICY,
    logUrl: base,
    now: () => NOW,
  });
  const r = await g.handle({ request: req({ target: SANCTIONED }) });
  assert.equal(r.submitError, undefined);
  assert.ok(r.receipt!.log_ack);
  assert.ok(await verifyLogAck(r.receipt!.log_ack!, op.address, D));
  assert.equal(store.size(), 1);

  await new Promise<void>((r2) => server.close(() => r2()));
  store.close();
});

test("제출 — 로그가 죽어도 영수증은 유효하다", async () => {
  const g = new Gateway({
    account: gk,
    domain: D,
    policy: POLICY,
    logUrl: "http://127.0.0.1:1", // 닫힌 포트
    now: () => NOW,
  });
  const r = await g.handle({ request: req({ target: SANCTIONED }) });
  assert.ok(r.submitError, "제출은 실패해야 한다");
  assert.ok(await verifyLeafSignature(r.receipt!.leaf, D), "영수증 서명은 그대로 유효하다");
  assert.equal(r.receipt!.log_ack, null);
});

// ---------- 책임 분리 ----------

test("책임 — 영수증과 접수 확인의 유무로 과실이 갈린다", async () => {
  const g = new Gateway({ account: gk, domain: D, policy: POLICY, now: () => NOW });
  const receipt = (await g.handle({ request: req({ target: SANCTIONED }) })).receipt!;

  assert.equal(assignFault(null, false, NOW), "증명 불가");
  assert.equal(assignFault(receipt, false, NOW), "게이트웨이가 제출 안 함");

  const acked = {
    ...receipt,
    log_ack: { ...({} as never), promised_by: NOW + 3600, received_at: NOW } as never,
  };
  assert.equal(assignFault(acked, true, NOW), "정상");
  assert.equal(assignFault(acked, false, NOW + 100), "정상", "약속 시각 전에는 아직 아니다");
  assert.equal(assignFault(acked, false, NOW + 4000), "로그 운영자 과실");
});
