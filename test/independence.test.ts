// 검증기 자족성 테스트.
//
// 이 프로젝트의 유일한 주장이 "기관에 접촉하지 않고 검증한다" 이다. 그 주장은
// 검증기가 기관 쪽 코드를 로드하지 않는다는 사실 위에 서 있다.
//
// 그런데 그건 관례로만 유지된다. 누가 편의로 log-store.ts 를 import 해도 테스트는
// 전부 통과하고 데모도 돌아간다. 아무도 모르는 채로 주장만 거짓이 된다.
//
// 그래서 import 폐포를 직접 계산해 서버 쪽 모듈이 섞였는지 본다.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, normalize, relative } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;

/** 진입점에서 시작해 상대 경로 import 를 따라가며 전부 모은다. */
function closure(entry: string): { local: Set<string>; external: Set<string> } {
  const local = new Set<string>();
  const external = new Set<string>();
  const walk = (file: string): void => {
    if (local.has(file)) return;
    local.add(file);
    const src = readFileSync(join(ROOT, file), "utf8");
    for (const m of src.matchAll(/\bfrom\s+"([^"]+)"/g)) {
      const spec = m[1];
      if (spec.startsWith(".")) {
        walk(relative(ROOT, normalize(join(ROOT, dirname(file), spec))));
      } else {
        external.add(spec);
      }
    }
  };
  walk(entry);
  return { local, external };
}

/** 기관이 돌리는 것들. 검증기에 들어오면 안 된다. */
const INSTITUTION_SIDE = [
  "lib/log-store.ts",
  "lib/log-server.ts",
  "lib/anchor-job.ts",
  "sdk/gateway.ts",
  "sdk/demo-policy.ts",
];

test("자족성 — 검증 도구가 기관 쪽 코드를 로드하지 않는다", () => {
  const { local } = closure("cli/verify-rejection.ts");
  const leaked = INSTITUTION_SIDE.filter((m) => local.has(m));
  assert.deepEqual(
    leaked,
    [],
    `검증기가 기관 코드를 끌어온다: ${leaked.join(", ")}. ` +
      "이게 들어오면 기관 무접촉 주장이 깨진다.",
  );
});

test("자족성 — 검증 계층도 기관 쪽 코드를 로드하지 않는다", () => {
  // CLI 뿐 아니라 검증 계층 자체가 깨끗해야 한다. 다른 진입점이 생겨도 유지된다.
  for (const entry of ["lib/verify.ts", "lib/bundle.ts"]) {
    const { local } = closure(entry);
    const leaked = INSTITUTION_SIDE.filter((m) => local.has(m));
    assert.deepEqual(leaked, [], `${entry} 가 ${leaked.join(", ")} 를 끌어온다`);
  }
});

test("자족성 — 검증기의 외부 의존성이 예상 밖으로 늘지 않았다", () => {
  // 새 패키지가 조용히 들어오면 공급망 표면이 늘어난다. 늘릴 거면 의식적으로 늘린다.
  const { external } = closure("cli/verify-rejection.ts");
  const allowed = new Set([
    "node:fs", "node:crypto",
    "viem", "viem/accounts",
    "@ethereumjs/mpt", "@ethereumjs/util",
  ]);
  const unexpected = [...external].filter((p) => !allowed.has(p));
  assert.deepEqual(unexpected, [], `허용되지 않은 의존성: ${unexpected.join(", ")}`);
});

test("자족성 — 검증 경로에 HTTP 호출이 없다", () => {
  // 증명은 번들 안에 있다. 가져오는 게 아니라 펴는 것이다.
  const { local } = closure("cli/verify-rejection.ts");
  for (const f of local) {
    if (f.startsWith("cli/")) continue; // CLI 는 RPC 를 부른다
    const src = readFileSync(join(ROOT, f), "utf8");
    const code = src.replace(/\/\/[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    assert.ok(!/\bfetch\s*\(/.test(code), `${f} 에 fetch 호출이 있다`);
  }
});
