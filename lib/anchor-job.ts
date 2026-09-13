// 앵커링 작업. 오프체인 트리 머리를 주기적으로 체인에 고정한다.
//
// 이 작업이 거절 판정 경로에 있으면 안 된다. 게이트웨이는 로그 서버의 응답만
// 기다리고, 루트는 나중에 따로 올라간다. 체인 장애가 차단을 막지 않는다.
// 주기적 앵커링. 차단 경로 밖에서 돈다. 체인이 멈춰도 판단은 계속된다.
import type { Hex } from "viem";
import type { AnchorChain } from "./chain.ts";
import type { LogStore } from "./log-store.ts";

export interface AnchorJobOptions {
  store: LogStore;
  chain: AnchorChain;
  /** 새 리프가 이 수 미만이면 앵커하지 않는다. 가스는 앵커 1회당이다. */
  minBatch?: number;
  intervalMs?: number;
  onError?: (e: unknown) => void;
}

export interface AnchorResult {
  anchored: boolean;
  reason?: string;
  treeSize?: number;
  root?: Hex;
  txHash?: string;
}

/**
 * 한 번 앵커한다.
 *
 * 순서가 중요하다. 체인에 먼저 올리고 로컬에 기록한다. 반대로 하면 로컬은
 * 앵커됐다고 믿는데 체인에 없는 상태가 생기고, 그 상태로 발급한 포함 증명은
 * 검증자가 체인에서 확인할 수 없다. 반대 방향의 어긋남(체인에는 있고 로컬에
 * 없음)은 reconcile 로 복구된다.
 */
export async function anchorOnce(o: AnchorJobOptions): Promise<AnchorResult> {
  const { store, chain } = o;
  const minBatch = o.minBatch ?? 1;

  const head = store.head();
  if (head.tree_size === 0) return { anchored: false, reason: "리프가 없음" };

  const onchain = await chain.lastTreeSize();
  if (head.tree_size <= onchain) {
    return { anchored: false, reason: `이미 앵커됨 (체인 ${onchain} >= 머리 ${head.tree_size})` };
  }
  if (head.tree_size - onchain < minBatch) {
    return {
      anchored: false,
      reason: `새 리프가 ${head.tree_size - onchain} 개로 minBatch ${minBatch} 미만`,
    };
  }

  const root = store.rootAt(head.tree_size);
  const txHash = await chain.submitRoot(root, head.tree_size);
  store.recordAnchor(head.tree_size, root, txHash);
  return { anchored: true, treeSize: head.tree_size, root, txHash };
}

/**
 * 체인이 알고 로컬이 모르는 앵커를 메운다.
 *
 * 프로세스가 submitRoot 직후에 죽으면 이 상태가 된다. 체인의 lastTreeSize 를
 * 읽고 그 크기의 루트가 로컬 트리와 같으면 기록한다. 다르면 로그 이력이
 * 온체인 기준점과 어긋났다는 뜻이므로 예외를 던진다.
 */
export async function reconcile(o: Pick<AnchorJobOptions, "store" | "chain">): Promise<AnchorResult> {
  const { store, chain } = o;
  const onchain = await chain.lastTreeSize();
  if (onchain === 0) return { anchored: false, reason: "체인에 앵커가 없음" };
  if (store.anchorAt(onchain)) {
    return { anchored: false, reason: "이미 기록됨" };
  }
  if (onchain > store.size()) {
    throw new Error(
      `체인이 로컬보다 앞서 있다 (체인 ${onchain} > 로컬 ${store.size()}). 로그 데이터가 유실됐을 수 있다`,
    );
  }
  const chainRoot = await chain.rootByTreeSize(onchain);
  const localRoot = store.rootAt(onchain);
  if (chainRoot.toLowerCase() !== localRoot.toLowerCase()) {
    throw new Error(
      `크기 ${onchain} 에서 체인 루트와 로컬 루트가 다르다. 로그 이력이 어긋났다`,
    );
  }
  store.recordAnchor(onchain, localRoot, null);
  return { anchored: true, treeSize: onchain, root: localRoot };
}

/** 주기 실행. 반환된 stop 을 호출하면 멈춘다. */
export function startAnchorJob(o: AnchorJobOptions): { stop(): void } {
  const intervalMs = o.intervalMs ?? 30_000;
  let running = false;
  const tick = async () => {
    if (running) return; // 앞 회차가 아직 안 끝났으면 건너뛴다
    running = true;
    try {
      await anchorOnce(o);
    } catch (e) {
      (o.onError ?? ((err) => process.emitWarning(`앵커링 실패: ${err}`)))(e);
    } finally {
      running = false;
    }
  };
  const timer = setInterval(tick, intervalMs);
  timer.unref?.();
  void tick();
  return {
    stop() {
      clearInterval(timer);
    },
  };
}
