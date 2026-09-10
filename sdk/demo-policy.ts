// 데모용 정책 문서. 이 파일의 내용 전체가 `policy_hash` 의 대상이다.
//
// 실제 기관의 정책이 아니다. 게이트키퍼 이름도 데모용이며 어떤 실존 기관도
// 사칭하지 않는다. 명세 docs/DESIGN.md 4.2절의 policy_hash 항목.
//
// 규칙을 고치거나 순서를 바꾸면 해시가 달라진다. 그래야 사후에 "어떤 규칙집합
// 하에서 내린 판단인가" 가 고정된다. 모든 스크립트가 이 하나를 공유해야
// 같은 policy_hash 가 나온다.
import type { Policy } from "./gatekeeper.ts";
import { policyHash } from "./gatekeeper.ts";

export const GATEKEEPER_LABEL = "Demo Custody Gatekeeper";

/** 제재 목록에 올린 데모 주소. 실제 제재 대상과 무관하다. */
export const SANCTIONED = "0x000000000000000000000000000000000000dead";
/** 허용 목록에 있는 데모 수신자. */
export const KNOWN_TARGET = "0x000000000000000000000000000000000000beef";

export const DEMO_POLICY: Policy = {
  version: 1,
  denylist: [SANCTIONED],
  maxValueWei: "1000000000000000000", // 1 ether
  allowedTargets: [KNOWN_TARGET],
};

/** 규칙 설명. 발표와 데모 화면에서 그대로 쓴다. */
export const RULE_DESCRIPTIONS: Record<string, string> = {
  DENYLIST_SANCTIONED: "수신자가 제재 목록에 있음 (차단)",
  AMOUNT_CAP_EXCEEDED: "금액이 한도를 초과함 (보류)",
  UNKNOWN_CONTRACT: "수신자가 허용 목록 밖임 (검토)",
};

export const DEMO_POLICY_HASH = policyHash(DEMO_POLICY);
