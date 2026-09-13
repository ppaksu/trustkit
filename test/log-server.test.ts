// 로그 서버 HTTP 계층 테스트. 라우팅과 상태 코드만 확인한다.
import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { privateKeyToAccount } from "viem/accounts";
import type { Address } from "viem";
import { buildLeafBody, leafHash, type Leaf } from "../lib/record.ts";
import { domain, signLeaf } from "../lib/sign.ts";
import { LogStore } from "../lib/log-store.ts";
import { createLogServer } from "../lib/log-server.ts";

const gk = privateKeyToAccount(("0x" + "11".repeat(32)) as `0x${string}`);
const op = privateKeyToAccount(("0x" + "22".repeat(32)) as `0x${string}`);
const D = domain(84532, "0x5555555555555555555555555555555555555555" as Address);
const NOW = 1757203200;

let counter = 0;
async function makeLeaf(): Promise<Leaf> {
  counter++;
  const { body } = buildLeafBody({
    gateway: gk.address,
    policyHash: "0x" + "9a".repeat(32),
    fields: {
      requester: "0xabc0000000000000000000000000000000000001",
      target: "0xdef0000000000000000000000000000000000002",
      value: String(counter),
      calldata_hash: "0x" + "cd".repeat(32),
      rule_id: "DENYLIST_SANCTIONED",
      severity: "block",
      verifiability: "verifiable",
    },
    issuedAt: NOW,
  });
  return signLeaf(body, gk, D);
}

async function withServer(fn: (base: string, store: LogStore) => Promise<void>): Promise<void> {
  const store = new LogStore({
    path: ":memory:",
    domain: D,
    operator: op,
    isRegistered: async () => true,
    now: () => NOW,
  });
  const server = createLogServer(store);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`, store);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    store.close();
  }
}

const postLeaf = (base: string, leaf: Leaf) =>
  fetch(`${base}/api/log/submit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ leaf }),
  });

test("서버 — 정상 경로가 끝까지 통과한다", async () => {
  await withServer(async (base, store) => {
    const leaf = await makeLeaf();

    const submitted = await postLeaf(base, leaf);
    assert.equal(submitted.status, 200);
    const { leaf_hash, log_ack } = (await submitted.json()) as {
      leaf_hash: string;
      log_ack: { promised_by: number };
    };
    assert.equal(leaf_hash, "0x" + leafHash(leaf).toString("hex"));
    assert.ok(log_ack.promised_by > NOW);

    const head = await (await fetch(`${base}/api/log/head`)).json();
    assert.equal((head as { tree_size: number }).tree_size, 1);

    // 앵커 전에는 포함 증명을 못 준다
    const early = await fetch(`${base}/api/log/proof/inclusion?leaf_hash=${leaf_hash}`);
    assert.equal(early.status, 409);

    store.recordAnchor(1, store.rootAt(1), "0xdeadbeef");

    const proof = await fetch(`${base}/api/log/proof/inclusion?leaf_hash=${leaf_hash}`);
    assert.equal(proof.status, 200);
    const p = (await proof.json()) as { index: number; anchor: { tree_size: number } };
    assert.equal(p.index, 0);
    assert.equal(p.anchor.tree_size, 1);

    const latest = await (await fetch(`${base}/api/log/anchors/latest`)).json();
    assert.equal((latest as { tx_hash: string }).tx_hash, "0xdeadbeef");
  });
});

test("서버 — 트리 머리와 최신 앵커가 다른 경로다", async () => {
  await withServer(async (base, store) => {
    for (let i = 0; i < 3; i++) await store.submit(await makeLeaf());
    store.recordAnchor(2, store.rootAt(2));

    const head = (await (await fetch(`${base}/api/log/head`)).json()) as { tree_size: number };
    const anchor = (await (await fetch(`${base}/api/log/anchors/latest`)).json()) as {
      tree_size: number;
    };
    assert.equal(head.tree_size, 3, "오프체인 머리");
    assert.equal(anchor.tree_size, 2, "체인에 고정된 기준점");
  });
});

test("서버 — 오류가 상태 코드로 구분된다", async () => {
  await withServer(async (base) => {
    assert.equal((await fetch(`${base}/api/log/nope`)).status, 404);
    assert.equal((await fetch(`${base}/api/log/anchors/latest`)).status, 404);
    assert.equal((await fetch(`${base}/api/log/proof/inclusion`)).status, 400);
    assert.equal(
      (await fetch(`${base}/api/log/proof/inclusion?leaf_hash=0x${"ab".repeat(32)}`)).status,
      404,
    );
    assert.equal((await fetch(`${base}/api/log/proof/consistency?from=1`)).status, 400);
    assert.equal((await fetch(`${base}/api/log/head`, { method: "DELETE" })).status, 405);

    const bad = await fetch(`${base}/api/log/submit`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{ not json",
    });
    assert.equal(bad.status, 400);

    const noLeaf = await fetch(`${base}/api/log/submit`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(noLeaf.status, 400);
  });
});

test("서버 — 위조 서명은 400 이고 트리에 안 들어간다", async () => {
  await withServer(async (base, store) => {
    const leaf = await makeLeaf();
    const forged = { ...leaf, issued_at: leaf.issued_at + 1 }; // 서명 범위 밖으로 벗어남
    assert.equal((await postLeaf(base, forged)).status, 400);
    assert.equal(store.size(), 0);
  });
});

test("서버 — 일관성 증명 경로가 두 앵커를 돌려준다", async () => {
  await withServer(async (base, store) => {
    for (let i = 0; i < 5; i++) await store.submit(await makeLeaf());
    store.recordAnchor(2, store.rootAt(2));
    store.recordAnchor(5, store.rootAt(5));

    const r = await fetch(`${base}/api/log/proof/consistency?from=2&to=5`);
    assert.equal(r.status, 200);
    const p = (await r.json()) as {
      from_anchor: { tree_size: number };
      to_anchor: { tree_size: number };
      path: string[];
    };
    assert.equal(p.from_anchor.tree_size, 2);
    assert.equal(p.to_anchor.tree_size, 5);
    assert.ok(p.path.length > 0);
  });
});
