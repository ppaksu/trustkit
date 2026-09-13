// 데모용 정책 문서. 실제 기관의 정책이 아니고 실존 기관·제재 대상과 무관하다.
//
// DEMO_POLICY 전체가 policy_hash 의 대상이다. 규칙을 고치거나 순서를 바꾸면
// 해시가 달라지므로 모든 스크립트가 이 하나를 공유해야 한다.
import { policyHash, type PolicyDocument } from "../lib/record.ts";

export const GATEWAY_LABEL = "Demo Custody Gateway";

/** 데모용 차단 주소. */
export const SANCTIONED = "0x000000000000000000000000000000000000dead";
/** 데모용 허용 수신자. */
export const KNOWN_TARGET = "0x000000000000000000000000000000000000beef";
/** ERC-4337 EntryPoint 예치금 슬롯. 동적 사유 데모에 쓴다. */
export const ENTRYPOINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";
export const DEPOSIT_SLOT = "0x" + "00".repeat(31) + "01";

/**
 * 검증 가능 넷, 외부 데이터 의존 하나, 재량 하나. 뒤의 둘을 일부러 넣었다.
 * 재량 사유를 없애는 게 아니라 드러나게 만드는 것이 목표다.
 */
export const DEMO_POLICY: PolicyDocument = {
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
      rule_id: "DEPOSIT_INSUFFICIENT",
      description: "판단 시점 EntryPoint 예치금이 요청액 미만",
      severity: "block",
      verifiability: "verifiable",
      predicate: {
        kind: "state_slot",
        account: ENTRYPOINT,
        slot: DEPOSIT_SLOT,
        op: "lt",
        operand: "value",
      },
    },
    {
      rule_id: "SANCTIONS_SCREENING_HIT",
      description: "외부 제재 스크리닝 결과 적중",
      severity: "block",
      // 외부 데이터 의존. 입력을 커밋할 수 없어 검증기가 판정 불가로 보고한다.
      verifiability: "external",
    },
    {
      rule_id: "MANUAL_REVIEW_HOLD",
      description: "담당자 수동 검토 보류",
      severity: "hold",
      // 술어로 표현 불가. 재량 사유임을 레코드에 드러낸다.
      verifiability: "discretionary",
    },
  ],
  data_sets: {
    denylist: [SANCTIONED],
    allowedTargets: [KNOWN_TARGET],
  },
};

export const DEMO_POLICY_HASH = policyHash(DEMO_POLICY);

/** 데모 화면 출력용. */
export const RULE_DESCRIPTIONS: Record<string, string> = Object.fromEntries(
  DEMO_POLICY.rules.map((r) => [r.rule_id, `${r.description} (${r.severity})`]),
);
