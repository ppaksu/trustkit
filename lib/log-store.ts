// append-only 거절 로그 저장소. 접수 검증, 트리 관리, 증명 발급만 한다.
// HTTP 는 log-server.ts, 온체인 앵커링은 anchor-job.ts 가 맡는다.
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import type { Account } from "viem/accounts";
import type { Address, Hex, TypedDataDomain } from "viem";
import { canonicalBytes } from "./jcs.ts";
import { validateLeafStructure, leafHash, type Leaf } from "./record.ts";
import { verifyLeafSignature, signLogAck, type LogAck } from "./sign.ts";
import { mth, inclusionPath, consistencyProof } from "./merkle.ts";

export class LogError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const hex = (b: Buffer | Uint8Array): Hex => `0x${Buffer.from(b).toString("hex")}`;
const unhex = (s: string): Buffer => Buffer.from(s.replace(/^0x/, ""), "hex");

export interface Anchor {
  tree_size: number;
  root: Hex;
  tx_hash: string | null;
  anchored_at: number;
}

export interface LogStoreOptions {
  /** ":memory:" 또는 파일 경로 */
  path: string;
  domain: TypedDataDomain;
  /** LogAck 에 서명한다. 앵커 컨트랙트의 logOperator 와 같은 키여야 한다. */
  operator: Account;
  /** 발급자가 등록된 게이트웨이인지. 온체인 레지스트리 조회를 주입받는다. */
  isRegistered: (gateway: Address) => Promise<boolean>;
  /** 편입 약속 시한. Certificate Transparency 의 MMD 에 해당한다. */
  maxMergeDelaySec?: number;
  /** issued_at 허용 오차 */
  clockSkewSec?: number;
  now?: () => number;
}

export class LogStore {
  private db: DatabaseSync;
  private opts: Required<Pick<LogStoreOptions, "maxMergeDelaySec" | "clockSkewSec" | "now">> &
    LogStoreOptions;

  constructor(options: LogStoreOptions) {
    this.opts = {
      maxMergeDelaySec: 3600,
      clockSkewSec: 300,
      now: () => Math.floor(Date.now() / 1000),
      ...options,
    };
    this.db = new DatabaseSync(options.path);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS leaves (
        idx        INTEGER PRIMARY KEY,
        leaf_hash  BLOB NOT NULL UNIQUE,
        leaf_bytes BLOB NOT NULL,
        gateway TEXT NOT NULL,
        nonce      BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        UNIQUE(gateway, nonce)
      );
      CREATE TABLE IF NOT EXISTS anchors (
        tree_size   INTEGER PRIMARY KEY,
        root        BLOB NOT NULL,
        tx_hash     TEXT,
        anchored_at INTEGER NOT NULL
      );
    `);
  }

  close(): void {
    this.db.close();
  }

  // ---------- 접수 ----------

  /**
   * 접수 검증 7항목. 1~6 은 로컬만 보고 원격 조회인 7 을 마지막에 둔다.
   * 위조 요청이 쏟아질 때 노드 호출을 아끼기 위해서다.
   */
  async submit(leaf: Leaf): Promise<{ leaf_hash: Hex; log_ack: LogAck }> {
    // 1. 구조
    try {
      validateLeafStructure(leaf);
    } catch (e) {
      throw new LogError(`구조 검증 실패: ${(e as Error).message}`, 400);
    }

    // 2~3. keysRoot·fieldsRoot 를 리프에서 재계산해 서명 복원
    if (!(await verifyLeafSignature(leaf, this.opts.domain))) {
      throw new LogError("서명이 gateway 로 복원되지 않음", 400);
    }

    // 4. 저장 바이트와 리프 해시 확정
    const bytes = canonicalBytes(leaf as never);
    const h = leafHash(leaf);

    // 5. nonce 재사용. 같은 리프의 재전송은 idempotent, 다른 리프면 거부.
    const nonce = unhex(leaf.nonce);
    const gw = leaf.gateway.toLowerCase();
    const dup = this.db
      .prepare("SELECT leaf_hash FROM leaves WHERE gateway = ? AND nonce = ?")
      .get(gw, nonce) as { leaf_hash: Uint8Array } | undefined;
    if (dup) {
      // 같은 leaf 의 재전송은 idempotent, 다른 leaf 면 거부
      if (Buffer.from(dup.leaf_hash).equals(h)) {
        return { leaf_hash: hex(h), log_ack: await this.ack(h) };
      }
      throw new LogError("같은 nonce 로 다른 leaf 를 제출했다", 409);
    }

    // 6. issued_at 허용 오차
    const now = this.opts.now();
    if (Math.abs(now - leaf.issued_at) > this.opts.clockSkewSec) {
      throw new LogError(
        `issued_at 이 허용 오차 밖 (now=${now}, issued_at=${leaf.issued_at})`,
        400,
      );
    }

    // 7. 온체인 레지스트리 등록 — 유일한 원격 호출
    if (!(await this.opts.isRegistered(leaf.gateway as Address))) {
      throw new LogError("등록되지 않은 게이트웨이", 403);
    }

    const idx = this.size();
    this.db
      .prepare(
        "INSERT INTO leaves(idx, leaf_hash, leaf_bytes, gateway, nonce, created_at) VALUES(?,?,?,?,?,?)",
      )
      .run(idx, h, bytes, gw, nonce, now);

    return { leaf_hash: hex(h), log_ack: await this.ack(h) };
  }

  private async ack(h: Buffer): Promise<LogAck> {
    const receivedAt = this.opts.now();
    return signLogAck(
      {
        leaf_hash: hex(h),
        received_at: receivedAt,
        promised_by: receivedAt + this.opts.maxMergeDelaySec,
        log_operator: this.opts.operator.address,
      },
      this.opts.operator,
      this.opts.domain,
    );
  }

  // ---------- 트리 ----------

  size(): number {
    const r = this.db.prepare("SELECT COUNT(*) AS n FROM leaves").get() as { n: number };
    return r.n;
  }

  /** 트리는 매 호출마다 여기서 재계산한다. */
  private data(upto?: number): Buffer[] {
    const rows = (
      upto === undefined
        ? this.db.prepare("SELECT leaf_bytes FROM leaves ORDER BY idx").all()
        : this.db.prepare("SELECT leaf_bytes FROM leaves WHERE idx < ? ORDER BY idx").all(upto)
    ) as { leaf_bytes: Uint8Array }[];
    return rows.map((r) => Buffer.from(r.leaf_bytes));
    // ponytail: 전체 재계산 O(n). 리프 1만 건 넘어가면 캐시된 부분 트리로 교체.
  }

  /** 앵커 사이에 계속 변하는 오프체인 머리. 서명하지 않는다. */
  head(): { root: Hex; tree_size: number } {
    const n = this.size();
    return { root: hex(mth(this.data())), tree_size: n };
  }

  /** 앵커 작업이 이 값을 온체인에 올린다. */
  rootAt(treeSize: number): Hex {
    if (treeSize < 1 || treeSize > this.size()) {
      throw new LogError(`트리 크기 범위 밖: ${treeSize}`, 400);
    }
    return hex(mth(this.data(treeSize)));
  }

  // ---------- 앵커 ----------

  /** 온체인 submitRoot 성공 후 호출한다. 로컬 트리와 다르면 거부한다. */
  recordAnchor(treeSize: number, root: Hex, txHash: string | null = null): void {
    const expected = this.rootAt(treeSize);
    if (expected !== root) {
      throw new LogError(`앵커하려는 루트가 로컬 트리와 다름: ${root} != ${expected}`, 409);
    }
    this.db
      .prepare("INSERT OR REPLACE INTO anchors(tree_size, root, tx_hash, anchored_at) VALUES(?,?,?,?)")
      .run(treeSize, unhex(root), txHash, this.opts.now());
  }

  anchors(from?: number, to?: number): Anchor[] {
    const rows = this.db
      .prepare(
        "SELECT tree_size, root, tx_hash, anchored_at FROM anchors WHERE tree_size >= ? AND tree_size <= ? ORDER BY tree_size",
      )
      .all(from ?? 0, to ?? Number.MAX_SAFE_INTEGER) as {
      tree_size: number;
      root: Uint8Array;
      tx_hash: string | null;
      anchored_at: number;
    }[];
    return rows.map((r) => ({
      tree_size: r.tree_size,
      root: hex(r.root),
      tx_hash: r.tx_hash,
      anchored_at: r.anchored_at,
    }));
  }

  anchorAt(treeSize: number): Anchor | null {
    return this.anchors(treeSize, treeSize)[0] ?? null;
  }

  latestAnchor(): Anchor | null {
    const all = this.anchors();
    return all.length ? all[all.length - 1] : null;
  }

  // ---------- 증명 ----------

  /**
   * 포함 증명. treeSize 를 생략하면 그 리프를 덮는 가장 이른 앵커를 서버가 고른다.
   * 앵커는 주기적이라 인덱스 57 을 처음 덮는 앵커가 64 일 수 있고 클라이언트는
   * 그 값을 알 방법이 없다.
   */
  inclusionProof(
    leafHashHex: string,
    treeSize?: number,
  ): { anchor: Anchor; index: number; audit_path: Hex[] } {
    const row = this.db
      .prepare("SELECT idx FROM leaves WHERE leaf_hash = ?")
      .get(unhex(leafHashHex)) as { idx: number } | undefined;
    if (!row) throw new LogError("해당 leaf 를 찾을 수 없음", 404);

    let anchor: Anchor | null;
    if (treeSize === undefined) {
      anchor = this.anchors(row.idx + 1).find((a) => a.tree_size > row.idx) ?? null;
      if (!anchor) {
        throw new LogError("이 leaf 를 덮는 앵커가 아직 없음", 409);
      }
    } else {
      if (treeSize <= row.idx) {
        throw new LogError(`tree_size ${treeSize} 는 이 leaf 를 덮지 않음`, 400);
      }
      anchor = this.anchorAt(treeSize);
      if (!anchor) throw new LogError(`tree_size ${treeSize} 는 앵커되지 않음`, 409);
    }

    const path = inclusionPath(row.idx, this.data(anchor.tree_size));
    return { anchor, index: row.idx, audit_path: path.map(hex) };
  }

  /** 번들에 넣을 증명 절반. 리프도 서명도 내주지 않는다. */
  proofHalf(leafHashHex: string): {
    inclusion_proof: ReturnType<LogStore["inclusionProof"]>;
    consistency_proof: ReturnType<LogStore["consistencyProof"]> | null;
  } {
    const inclusion = this.inclusionProof(leafHashHex);
    const latest = this.latestAnchor();
    const consistency =
      latest && latest.tree_size > inclusion.anchor.tree_size
        ? this.consistencyProof(inclusion.anchor.tree_size, latest.tree_size)
        : null;
    return { inclusion_proof: inclusion, consistency_proof: consistency };
  }

  /** 일관성 증명. 앵커된 두 크기 사이에만 발급한다. */
  consistencyProof(from: number, to: number): {
    from_anchor: Anchor;
    to_anchor: Anchor;
    path: Hex[];
  } {
    const a = this.anchorAt(from);
    const b = this.anchorAt(to);
    if (!a) throw new LogError(`tree_size ${from} 는 앵커되지 않음`, 409);
    if (!b) throw new LogError(`tree_size ${to} 는 앵커되지 않음`, 409);
    if (from > to) throw new LogError("from 이 to 보다 큼", 400);
    return {
      from_anchor: a,
      to_anchor: b,
      path: consistencyProof(from, this.data(to)).map(hex),
    };
  }

  /** 로컬 도구용. HTTP 로는 노출하지 않는다. */
  entries(start = 0, end?: number): { idx: number; leaf: Leaf }[] {
    const rows = this.db
      .prepare("SELECT idx, leaf_bytes FROM leaves WHERE idx >= ? AND idx <= ? ORDER BY idx")
      .all(start, end ?? Number.MAX_SAFE_INTEGER) as { idx: number; leaf_bytes: Uint8Array }[];
    return rows.map((r) => ({
      idx: r.idx,
      leaf: JSON.parse(Buffer.from(r.leaf_bytes).toString("utf8")) as Leaf,
    }));
  }
}

/** 트리 크기 n 의 루트를 리프 데이터에서 계산한다. 앵커링 작업이 쓴다. */
export function rootOf(leafData: Buffer[]): Hex {
  return hex(mth(leafData));
}

/** 리프 데이터에서 리프 해시를 얻는다. 저장소 밖에서 대조할 때 쓴다. */
export function hashOfLeafBytes(bytes: Buffer): Hex {
  return hex(createHash("sha256").update(Buffer.concat([Buffer.from([0]), bytes])).digest());
}
