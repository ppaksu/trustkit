// 앵커링 작업 테스트. 체인은 대역으로 끼운다. Anvil 이 필요한 통합 확인은 scripts/e2e.ts.
import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import { buildLeafBody, type Leaf } from "../lib/record.ts";
import { domain, signLeaf } from "../lib/sign.ts";
import { LogStore } from "../lib/log-store.ts";
import { anchorOnce, reconcile } from "../lib/anchor-job.ts";
import type { AnchorChain } from "../lib/chain.ts";

const gk = privateKeyToAccount(("0x" + "11".repeat(32)) as `0x${string}`);
const op = privateKeyToAccount(("0x" + "22".repeat(32)) as `0x${string}`);
const D = domain(84532, "0x5555555555555555555555555555555555555555" as Address);
const NOW = 1757203200;

/** 컨트랙트의 단조성 강제까지 흉내 내는 대역. */
class FakeChain implements AnchorChain {
  roots = new Map<number, Hex>();
  last = 0;
  calls = 0;
  failNext = false;

  async lastTreeSize() {
    return this.last;
  }
  async rootByTreeSize(n: number) {
    return this.roots.get(n) ?? (("0x" + "00".repeat(32)) as Hex);
  }
  async submitRoot(root: Hex, treeSize: number) {
    this.calls++;
    if (this.failNext) {
      this.failNext = false;
      throw new Error("체인 오류");
    }
    if (treeSize <= this.last) throw new Error("TreeSizeNotIncreasing");
    this.roots.set(treeSize, root);
    this.last = treeSize;
    return "0x" + treeSize.toString(16).padStart(64, "0");
  }
}

let counter = 0;
async function makeLeaf(): Promise<Leaf> {
  counter++;
  const { body } = buildLeafBody({
    gatekeeper: gk.address,
    policyHash: "0x" + "9a".repeat(32),
    fields: {
      requester: "0xabc0000000000000000000000000000000000001",
      target: "0xdef0000000000000000000000000000000000002",
      value: String(counter),
      calldata_hash: "0x" + "cd".repeat(32),
      rule_id: "DENYLIST_SANCTIONED",
      severity: "block",
    },
    issuedAt: NOW,
  });
  return signLeaf(body, gk, D);
}

function newStore() {
  return new LogStore({
    path: ":memory:",
    domain: D,
    operator: op,
    isRegistered: async () => true,
    now: () => NOW,
  });
}

test("앵커 — 리프가 없으면 아무것도 안 한다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  const r = await anchorOnce({ store, chain });
  assert.equal(r.anchored, false);
  assert.equal(chain.calls, 0);
  store.close();
});

test("앵커 — 머리를 체인에 올리고 로컬에 기록한다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  for (let i = 0; i < 3; i++) await store.submit(await makeLeaf());

  const r = await anchorOnce({ store, chain });
  assert.equal(r.anchored, true);
  assert.equal(r.treeSize, 3);
  assert.equal(chain.last, 3);
  assert.equal(store.anchorAt(3)?.root, r.root);
  assert.equal(store.anchorAt(3)?.tx_hash, r.txHash);
  store.close();
});

test("앵커 — 체인 루트와 로컬 루트가 같다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  for (let i = 0; i < 5; i++) await store.submit(await makeLeaf());
  await anchorOnce({ store, chain });
  assert.equal(await chain.rootByTreeSize(5), store.rootAt(5));
  store.close();
});

test("앵커 — 새 리프가 없으면 두 번 올리지 않는다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  await store.submit(await makeLeaf());
  await anchorOnce({ store, chain });
  const second = await anchorOnce({ store, chain });
  assert.equal(second.anchored, false);
  assert.equal(chain.calls, 1);
  store.close();
});

test("앵커 — minBatch 미만이면 미룬다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  for (let i = 0; i < 2; i++) await store.submit(await makeLeaf());
  assert.equal((await anchorOnce({ store, chain, minBatch: 5 })).anchored, false);
  assert.equal(chain.calls, 0, "가스는 앵커 1회당이므로 모아서 올린다");

  for (let i = 0; i < 3; i++) await store.submit(await makeLeaf());
  assert.equal((await anchorOnce({ store, chain, minBatch: 5 })).anchored, true);
  store.close();
});

test("앵커 — 체인 전송이 실패하면 로컬에도 기록되지 않는다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  await store.submit(await makeLeaf());
  chain.failNext = true;
  await assert.rejects(anchorOnce({ store, chain }));
  assert.equal(store.anchorAt(1), null, "체인에 없는 앵커를 로컬이 믿으면 안 된다");
  store.close();
});

test("복구 — 체인에만 있는 앵커를 로컬에 메운다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  for (let i = 0; i < 4; i++) await store.submit(await makeLeaf());

  // submitRoot 직후 프로세스가 죽은 상황
  await chain.submitRoot(store.rootAt(4), 4);
  assert.equal(store.anchorAt(4), null);

  const r = await reconcile({ store, chain });
  assert.equal(r.anchored, true);
  assert.equal(store.anchorAt(4)?.root, store.rootAt(4));
  store.close();
});

test("복구 — 체인 루트와 로컬 루트가 다르면 예외를 던진다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  for (let i = 0; i < 3; i++) await store.submit(await makeLeaf());
  await chain.submitRoot(("0x" + "ff".repeat(32)) as Hex, 3);
  await assert.rejects(reconcile({ store, chain }), /어긋났다/);
  store.close();
});

test("복구 — 체인이 로컬보다 앞서면 예외를 던진다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  await store.submit(await makeLeaf());
  await chain.submitRoot(("0x" + "ab".repeat(32)) as Hex, 9);
  await assert.rejects(reconcile({ store, chain }), /유실/);
  store.close();
});

test("앵커 — 연속 앵커가 단조 증가한다", async () => {
  const store = newStore();
  const chain = new FakeChain();
  for (let i = 0; i < 2; i++) await store.submit(await makeLeaf());
  await anchorOnce({ store, chain });
  for (let i = 0; i < 3; i++) await store.submit(await makeLeaf());
  await anchorOnce({ store, chain });

  assert.deepEqual(
    store.anchors().map((a) => a.tree_size),
    [2, 5],
  );
  store.close();
});
