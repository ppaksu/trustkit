// 로그 서버 HTTP 계층. 명세 docs/DESIGN.md 6장.
// 라우팅과 상태 코드만 담당한다. 검증과 트리는 log-store.ts 가 한다.
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { LogError, type LogStore } from "./log-store.ts";
import type { Leaf } from "./record.ts";

const MAX_BODY = 64 * 1024;

function send(res: ServerResponse, status: number, body: unknown): void {
  const s = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(s);
}

function fail(res: ServerResponse, e: unknown): void {
  if (e instanceof LogError) {
    send(res, e.status, { error: e.message });
    return;
  }
  // 내부 오류의 상세를 밖으로 내보내지 않는다.
  process.emitWarning(`로그 서버 내부 오류: ${(e as Error)?.stack ?? e}`);
  send(res, 500, { error: "internal error" });
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new LogError("본문이 너무 큼", 413);
    chunks.push(c as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new LogError("JSON 파싱 실패", 400);
  }
}

function intParam(v: string | null, what: string): number | undefined {
  if (v === null) return undefined;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0) throw new LogError(`${what} 가 정수가 아님`, 400);
  return n;
}

export function createLogServer(store: LogStore): Server {
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const path = url.pathname;
      const q = url.searchParams;

      if (req.method === "POST" && path === "/api/log/submit") {
        const body = (await readJson(req)) as { leaf?: Leaf };
        if (!body || typeof body !== "object" || !body.leaf) {
          throw new LogError("leaf 필드가 없음", 400);
        }
        return send(res, 200, await store.submit(body.leaf));
      }

      if (req.method !== "GET") {
        return send(res, 405, { error: "method not allowed" });
      }

      // 오프체인 트리 머리. 앵커 사이에 계속 변하며 서명하지 않는다.
      if (path === "/api/log/head") {
        return send(res, 200, store.head());
      }

      // 체인에 고정된 최신 기준점. 위와 다른 값이므로 경로를 나눠 둔다.
      if (path === "/api/log/anchors/latest") {
        const a = store.latestAnchor();
        if (!a) throw new LogError("앵커가 아직 없음", 404);
        return send(res, 200, a);
      }

      if (path === "/api/log/anchors") {
        return send(res, 200, {
          anchors: store.anchors(intParam(q.get("from"), "from"), intParam(q.get("to"), "to")),
        });
      }

      const m = path.match(/^\/api\/log\/anchors\/(\d+)$/);
      if (m) {
        const a = store.anchorAt(Number(m[1]));
        if (!a) throw new LogError("해당 크기의 앵커가 없음", 404);
        return send(res, 200, a);
      }

      if (path === "/api/log/proof/inclusion") {
        const leafHash = q.get("leaf_hash");
        if (!leafHash) throw new LogError("leaf_hash 가 없음", 400);
        return send(res, 200, store.inclusionProof(leafHash, intParam(q.get("tree_size"), "tree_size")));
      }

      if (path === "/api/log/proof/consistency") {
        const from = intParam(q.get("from"), "from");
        const to = intParam(q.get("to"), "to");
        if (from === undefined || to === undefined) {
          throw new LogError("from 과 to 가 필요함", 400);
        }
        return send(res, 200, store.consistencyProof(from, to));
      }

      // 감사자용. 운영 환경에서는 접근 제어가 필요하다.
      if (path === "/api/log/entries") {
        return send(res, 200, {
          leaves: store.entries(intParam(q.get("start"), "start") ?? 0, intParam(q.get("end"), "end")),
        });
      }

      send(res, 404, { error: "not found" });
    } catch (e) {
      fail(res, e);
    }
  });
}
