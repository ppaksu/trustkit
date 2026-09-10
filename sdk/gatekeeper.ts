// 게이트키퍼 SDK. 명세 docs/DESIGN.md 3.1절.
//
// 거절이 발생하는 지점이다. 정책을 평가하고, 막았으면 서명된 영수증을 만들어
// 요청자에게 주고 로그에 제출한다. 통과시킨 요청은 아무 기록도 남기지 않는다.
// 이 로그가 다루는 것은 거절뿐이다.
import { createHash } from "node:crypto";
import type { Account } from "viem/accounts";
import type { Address, Hex, TypedDataDomain } from "viem";
import { canonicalBytes, type JsonValue } from "../lib/jcs.ts";
import { buildLeafBody, leafHash } from "../lib/record.ts";
import { signLeaf, type LogAck } from "../lib/sign.ts";
import type { Receipt } from "../lib/receipt.ts";

const sha256 = (b: Buffer): Buffer => createHash("sha256").update(b).digest();
const hex = (b: Buffer): Hex => `0x${b.toString("hex")}`;

export type Severity = "block" | "hold" | "review";

/**
 * 데모 정책. 실제 게이트키퍼의 규칙집합 자리에 들어간다.
 * 이 문서 전체의 해시가 리프의 `policy_hash` 이며 서명 대상에 포함된다.
 * 어떤 규칙집합 하에서 내린 판단인지가 사후에 고정된다.
 */
export interface Policy {
  version: number;
  /** 제재 대상 수신자. 소문자 주소. */
  denylist: string[];
  /** wei 문자열. 초과하면 보류한다. */
  maxValueWei: string;
  /** 설정하면 이 목록 밖의 수신자는 검토 대상이 된다. */
  allowedTargets?: string[];
}

export interface TxRequest {
  requester: Address;
  target: Address;
  /** wei */
  value: bigint;
  calldata: Hex;
}

export type Decision =
  | { allow: true }
  | { allow: false; rule_id: string; severity: Severity };

/** 정책 문서의 해시. 규칙 순서까지 포함해 고정된다. */
export function policyHash(p: Policy): Hex {
  return hex(sha256(canonicalBytes(p as unknown as JsonValue)));
}

/**
 * 규칙 평가. **먼저 일치하는 규칙이 이긴다.** 순서가 정책의 일부이므로
 * 바꾸면 `policy_hash` 도 달라져야 한다.
 */
export function evaluate(policy: Policy, req: TxRequest): Decision {
  const target = req.target.toLowerCase();

  if (policy.denylist.some((d) => d.toLowerCase() === target)) {
    return { allow: false, rule_id: "DENYLIST_SANCTIONED", severity: "block" };
  }
  if (req.value > BigInt(policy.maxValueWei)) {
    return { allow: false, rule_id: "AMOUNT_CAP_EXCEEDED", severity: "hold" };
  }
  if (policy.allowedTargets && !policy.allowedTargets.some((t) => t.toLowerCase() === target)) {
    return { allow: false, rule_id: "UNKNOWN_CONTRACT", severity: "review" };
  }
  return { allow: true };
}

export interface GatekeeperOptions {
  account: Account;
  domain: TypedDataDomain;
  policy: Policy;
  /** 로그 서버 주소. 생략하면 영수증만 만들고 제출하지 않는다. */
  logUrl?: string;
  now?: () => number;
  fetchImpl?: typeof fetch;
}

export interface HandleResult {
  decision: Decision;
  /** 거절일 때만 있다. 통과한 요청은 기록을 남기지 않는다. */
  receipt?: Receipt;
  /** 로그 제출이 실패한 경우 이유. 영수증 자체는 유효하다. */
  submitError?: string;
}

export class Gatekeeper {
  private o: Required<Pick<GatekeeperOptions, "now" | "fetchImpl">> & GatekeeperOptions;
  readonly policyHash: Hex;

  constructor(options: GatekeeperOptions) {
    this.o = {
      now: () => Math.floor(Date.now() / 1000),
      fetchImpl: fetch,
      ...options,
    };
    this.policyHash = policyHash(options.policy);
  }

  get address(): Address {
    return this.o.account.address;
  }

  /**
   * 요청 하나를 처리한다.
   *
   * 거절이면 영수증에 서명해 **요청자에게 먼저 준다.** 로그 제출이 실패해도
   * 영수증은 이미 유효하다. 제출 실패는 나중에 책임 분리로 드러난다.
   * 명세 4.5절의 "Receipt 만 있고 log_ack 없음" 이 그 상태다.
   */
  async handle(req: TxRequest): Promise<HandleResult> {
    const decision = evaluate(this.o.policy, req);
    if (decision.allow) return { decision };

    const { body, disclosures } = buildLeafBody({
      gatekeeper: this.address,
      policyHash: this.policyHash,
      fields: {
        requester: req.requester.toLowerCase(),
        target: req.target.toLowerCase(),
        value: req.value.toString(),
        calldata_hash: hex(sha256(Buffer.from(req.calldata.slice(2), "hex"))),
        rule_id: decision.rule_id,
        severity: decision.severity,
      },
      issuedAt: this.o.now(),
    });

    const leaf = await signLeaf(body, this.o.account, this.o.domain);
    const receipt: Receipt = {
      leaf,
      leaf_hash: hex(leafHash(leaf)),
      disclosures,
      log_ack: null,
    };

    if (!this.o.logUrl) return { decision, receipt };

    try {
      const res = await this.o.fetchImpl(`${this.o.logUrl}/api/log/submit`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ leaf }),
      });
      if (!res.ok) {
        return { decision, receipt, submitError: `${res.status} ${await res.text()}` };
      }
      const out = (await res.json()) as { leaf_hash: Hex; log_ack: LogAck };
      if (out.leaf_hash !== receipt.leaf_hash) {
        return { decision, receipt, submitError: "로그가 다른 leaf_hash 를 돌려줬다" };
      }
      receipt.log_ack = out.log_ack;
      return { decision, receipt };
    } catch (e) {
      return { decision, receipt, submitError: (e as Error).message };
    }
  }
}
