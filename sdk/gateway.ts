// 게이트웨이 SDK. 거절이 발생하는 지점이다.
//
// 레코드를 요청자에게 **먼저** 주고 로그에 제출한다. 순서를 뒤집으면 제출 실패
// 시 요청자에게 아무것도 안 남는다.
import { createHash } from "node:crypto";
import type { Account } from "viem/accounts";
import type { Address, Hex, TypedDataDomain } from "viem";
import {
  buildLeafBody,
  leafHash,
  policyHash,
  ZERO32,
  type PolicyDocument,
  type PolicyRule,
  type Severity,
  type Verifiability,
} from "../lib/record.ts";
import {
  signLeaf,
  requestIntentHash,
  requesterSigHash,
  type LogAck,
  type RequestIntent,
} from "../lib/sign.ts";
import type { Receipt } from "../lib/receipt.ts";
import { rootOfList } from "../lib/sorted-merkle.ts";
import { stateProofRoot, type StateEvidence } from "../lib/state-proof.ts";

export type { StateEvidence };
export { stateProofRoot };

const sha256 = (b: Buffer): Buffer => createHash("sha256").update(b).digest();
const hex = (b: Buffer): Hex => `0x${b.toString("hex")}`;

export type { PolicyDocument, PolicyRule, Severity, Verifiability };

export interface TxRequest {
  requester: Address;
  target: Address;
  /** wei */
  value: bigint;
  calldata: Hex;
}

export type Decision =
  | { allow: true }
  | { allow: false; rule: PolicyRule };

/**
 * 먼저 일치하는 규칙이 이긴다. 순서가 정책의 일부다.
 * 술어 없는 규칙은 여기서 평가되지 않는다. handle 의 forceRule 로 넘긴다.
 */
export function evaluate(policy: PolicyDocument, req: TxRequest): Decision {
  const sets = policy.data_sets ?? {};
  const value = (field: string): string =>
    field === "target" ? req.target.toLowerCase()
    : field === "requester" ? req.requester.toLowerCase()
    : field === "value" ? req.value.toString()
    : "";

  for (const rule of policy.rules) {
    const p = rule.predicate;
    if (!p) continue;
    if (p.kind === "in_set" && (sets[p.set] ?? []).some((x) => x.toLowerCase() === value(p.field))) {
      return { allow: false, rule };
    }
    if (p.kind === "not_in_set" && !(sets[p.set] ?? []).some((x) => x.toLowerCase() === value(p.field))) {
      return { allow: false, rule };
    }
    if (p.kind === "gt" && BigInt(value(p.field) || "0") > BigInt(p.limit)) {
      return { allow: false, rule };
    }
    // state_slot 은 체인 상태를 읽어야 한다. 호출부가 forceRule 로 넘긴다.
  }
  return { allow: true };
}

export interface GatewayOptions {
  account: Account;
  domain: TypedDataDomain;
  policy: PolicyDocument;
  /** 참조 목록의 정렬 머클 루트. 사후에 유리한 목록을 지어내 붙이는 걸 막는다. */
  policyDataRoot?: Hex;
  /**
   * 목록 이름 => 루트. 정책에 목록이 둘 이상일 때 쓴다. 공표는 별도 프로세스에서
   * 이미 끝났고 이 프로세스는 판단만 하는 경우가 있어 값만 받는 경로가 필요하다.
   */
  policyDataRoots?: Record<string, Hex>;
  /** 생략하면 레코드만 만들고 제출하지 않는다. */
  logUrl?: string;
  now?: () => number;
  fetchImpl?: typeof fetch;
}

export interface HandleInput {
  request: TxRequest;
  /** 없으면 검증 4단계가 판정 불가가 된다. */
  intent?: RequestIntent;
  intentSig?: Hex;
  /** evaluate 를 건너뛴다. 기존 엔진이 판단한 경우와 거짓 사유 데모에 쓴다. */
  forceRule?: PolicyRule;
  /** 동적 사유일 때의 상태 증거. */
  state?: StateEvidence;
}

export interface HandleResult {
  decision: Decision;
  /** 거절 기록. 통과한 요청이면 없다. */
  receipt?: Receipt;
  /** 로그 제출이 실패했으면 그 이유. 기록 자체는 그래도 유효하다. */
  submitError?: string;
}

export class Gateway {
  private o: Required<Pick<GatewayOptions, "now" | "fetchImpl">> & GatewayOptions;
  /** 참조 목록 이름 => 공표한 루트. 정책에 목록이 둘 이상일 때 필요하다. */
  private roots = new Map<string, Hex>();
  readonly policyHash: Hex;

  constructor(options: GatewayOptions) {
    this.o = {
      now: () => Math.floor(Date.now() / 1000),
      fetchImpl: fetch,
      ...options,
    };
    this.policyHash = policyHash(options.policy) as Hex;
    for (const [k, v] of Object.entries(options.policyDataRoots ?? {})) this.roots.set(k, v);
  }

  get address(): Address {
    return this.o.account.address;
  }

  /**
   * 참조 목록을 공표한다. 갱신 레코드를 로그에 올리고 새 루트를 기억한다.
   *
   * 거절보다 **먼저** 불려야 한다. 이걸 안 하면 게이트웨이가 판단 시점에 목록을
   * 지어낼 수 있고, 그러면 정적 사유 검증이 자기들끼리 앞뒤만 맞는 공허한 확인이
   * 된다. 로그에 먼저 박아야 피해자별 위조가 공개된 행위로 바뀐다.
   */
  async publishPolicyData(values: readonly string[], setName?: string): Promise<Receipt> {
    const root = rootOfList(values) as Hex;
    const { body } = buildLeafBody({
      type: "policy_update",
      gateway: this.address,
      policyHash: this.policyHash,
      policyDataRoot: root,
      fields: {},
      issuedAt: this.o.now(),
    });
    const leaf = await signLeaf(body, this.o.account, this.o.domain);
    const receipt: Receipt = {
      leaf,
      leaf_hash: hex(leafHash(leaf)),
      disclosures: [],
      log_ack: null,
    };
    if (setName) this.roots.set(setName, root);
    this.o.policyDataRoot = root;

    if (!this.o.logUrl) return receipt;
    const res = await this.o.fetchImpl(`${this.o.logUrl}/api/log/submit`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ leaf }),
    });
    if (!res.ok) throw new Error(`갱신 레코드 제출 실패: ${res.status} ${await res.text()}`);
    const out = (await res.json()) as { leaf_hash: Hex; log_ack: LogAck };
    receipt.log_ack = out.log_ack;
    return receipt;
  }

  /**
   * 통과한 요청은 아무 기록도 남기지 않는다. 통과는 체인에 트랜잭션으로 남는다.
   * 로그 제출이 실패해도 예외를 던지지 않는다. 레코드는 이미 유효하다.
   */
  async handle(input: HandleInput): Promise<HandleResult> {
    const req = input.request;
    const decision: Decision = input.forceRule
      ? { allow: false, rule: input.forceRule }
      : evaluate(this.o.policy, req);
    if (decision.allow) return { decision };

    const rule = decision.rule;
    const state = input.state;

    // 레코드가 커밋하는 루트는 **그 거절 사유가 의존하는 목록**의 루트다. 정책에
    // 목록이 둘 이상이면 아무거나 박아서는 안 된다. 검증 9단계가 인용된 규칙의
    // 목록과 커밋된 루트를 대조하므로 다른 목록의 루트를 박으면 거기서 걸린다.
    const p = rule.predicate;
    const setName = p && (p.kind === "in_set" || p.kind === "not_in_set") ? p.set : undefined;
    const dataRoot = (setName && this.roots.get(setName)) || this.o.policyDataRoot;

    const { body, disclosures } = buildLeafBody({
      gateway: this.address,
      policyHash: this.policyHash,
      policyDataRoot: dataRoot,
      fields: {
        requester: req.requester.toLowerCase(),
        target: req.target.toLowerCase(),
        value: req.value.toString(),
        calldata_hash: hex(sha256(Buffer.from(req.calldata.slice(2), "hex"))),
        rule_id: rule.rule_id,
        severity: rule.severity,
        verifiability: rule.verifiability,
      },
      issuedAt: this.o.now(),
      requestIntentHash: input.intent
        ? requestIntentHash(input.intent, this.o.domain)
        : undefined,
      requesterSigHash: input.intentSig ? requesterSigHash(input.intentSig) : undefined,
      decidedAtBlock: state?.block_number,
      stateRoot: state?.header.stateRoot,
      stateProofRoot: state ? stateProofRoot(state) : undefined,
    });

    const leaf = await signLeaf(body, this.o.account, this.o.domain);
    const receipt: Receipt = {
      leaf,
      leaf_hash: hex(leafHash(leaf)),
      disclosures,
      log_ack: null,
      request_intent: input.intent,
      request_sig: input.intentSig,
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

export { policyHash, ZERO32 };
