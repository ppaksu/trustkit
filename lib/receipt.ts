// 요청자가 보관하는 영수증.
//
// 게이트웨이 서명과 로그 접수 확인증이 분리돼 있다. 기록이 트리에 없을 때
// 확인증이 없으면 게이트웨이가 제출을 안 한 것이고, 있으면 로그가 버린 것이다.
import type { Hex } from "viem";
import type { Leaf, Disclosure } from "./record.ts";
import type { LogAck, RequestIntent } from "./sign.ts";

export interface Receipt {
  leaf: Leaf;
  leaf_hash: Hex;
  /** 원문. 로그에는 해시만 올라간다. */
  disclosures: Disclosure[];
  /** 없으면 게이트웨이가 제출하지 않은 것이다. */
  log_ack: LogAck | null;
  /** 없으면 검증 4단계가 판정 불가가 된다. */
  request_intent?: RequestIntent;
  request_sig?: Hex;
}

export type Fault = "정상" | "로그 운영자 과실" | "게이트웨이가 제출 안 함" | "증명 불가";

/**
 * 기록이 트리에 없을 때의 책임 판정. 기한 전에는 정상이다. 편입은 원래 비동기다.
 *
 * 운영 책임성 신호이지 수학적 부재 증명이 아니다. 게이트웨이가 아무것도 발급하지
 * 않은 경우는 요청자 손에 증거가 없어 여기서 다루지 못한다.
 */
export function assignFault(
  receipt: Receipt | null,
  hasInclusionProof: boolean,
  now: number,
): Fault {
  if (!receipt) return "증명 불가";
  if (!receipt.log_ack) return "게이트웨이가 제출 안 함";
  if (hasInclusionProof) return "정상";
  if (now <= receipt.log_ack.promised_by) return "정상"; // 아직 편입 기한 전이다
  return "로그 운영자 과실";
}

/** 선택적 공개에 쓴다. */
export function disclosureFor(receipt: Receipt, key: string): Disclosure | undefined {
  return receipt.disclosures.find((d) => d[1] === key);
}
