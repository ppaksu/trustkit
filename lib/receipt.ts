// 요청자가 보관하는 영수증. 명세 docs/DESIGN.md 4.5절.
//
// 게이트키퍼 서명(Receipt)과 로그 접수 서명(LogAck)이 한 객체에 담긴다.
// 이 둘이 분리되어 있어서 기록이 없을 때 누구 잘못인지가 갈린다.
import type { Hex } from "viem";
import type { Leaf, Disclosure } from "./record.ts";
import type { LogAck } from "./sign.ts";

export interface Receipt {
  leaf: Leaf;
  leaf_hash: Hex;
  /** 원문. 요청자만 보관한다. 로그에는 이 값의 해시만 올라간다. */
  disclosures: Disclosure[];
  /** 로그가 접수했다는 서명된 약속. 없으면 게이트키퍼가 제출하지 않은 것이다. */
  log_ack: LogAck | null;
}

export type Fault = "정상" | "로그 운영자 과실" | "게이트키퍼가 제출 안 함" | "증명 불가";

/**
 * 명세 4.5절의 책임 분리 표를 코드로 옮긴 것.
 *
 * 판정은 요청자가 무엇을 들고 있는지와, 약속 시각이 지난 뒤 포함 증명이
 * 나왔는지로 갈린다. 이것은 운영 책임성 신호이지 수학적 부재 증명이 아니다.
 */
export function assignFault(
  receipt: Receipt | null,
  hasInclusionProof: boolean,
  now: number,
): Fault {
  if (!receipt) return "증명 불가";
  if (!receipt.log_ack) return "게이트키퍼가 제출 안 함";
  if (hasInclusionProof) return "정상";
  if (now <= receipt.log_ack.promised_by) return "정상"; // 아직 약속 시각 전이다
  return "로그 운영자 과실";
}

/** 특정 키의 disclosure 를 꺼낸다. 선택적 공개에 쓴다. */
export function disclosureFor(receipt: Receipt, key: string): Disclosure | undefined {
  return receipt.disclosures.find((d) => d[1] === key);
}
