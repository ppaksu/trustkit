// 데모 1 — 기관 무접촉 검증. 필수 제출물.
//
// 평가 축 둘을 친다. 독립 검증 가능성과 부인 방지.
//
// 이 데모의 전부는 한 장면이다. **로그 서버를 죽인 채 검증이 끝난다.**
// 검증자가 닿는 곳은 공개 RPC 하나뿐이고 기관 서버는 한 번도 부르지 않는다.
//
// 그리고 덤이 하나 더 있다. 번들러가 댄 "예치금 부족" 이 거짓임이 MPT 증거로
// 로컬에서 판정된다.
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Address, Hex } from "viem";
import { withStack, step, heading, resetSteps, type Stack } from "./harness.ts";
import { serializeBundle, describeBundle } from "../lib/bundle.ts";
import { blockHashOf } from "../lib/state-proof.ts";
import { DEMO_POLICY, ENTRYPOINT, DEPOSIT_SLOT } from "../sdk/demo-policy.ts";

const DEPOSIT_RULE = DEMO_POLICY.rules.find((r) => r.rule_id === "DEPOSIT_INSUFFICIENT")!;

/** 실제 예치금은 넉넉하다. 번들러의 사유가 거짓이 되는 지점이다. */
const ACTUAL_DEPOSIT = 5n * 10n ** 18n;
/** 요청액은 그보다 작다. */
const REQUESTED = 1n * 10n ** 18n;

async function run(s: Stack, dir: string): Promise<void> {
  heading("1부 — 체인에 아무것도 남지 않는 거절");

  // 참조 목록을 먼저 공표한다. 이 데모의 사유는 목록을 쓰지 않지만, 게이트웨이는
  // 자기 참조 데이터를 판단과 무관하게 공표해둔다.
  await s.publishList(DEMO_POLICY.data_sets!.allowedTargets);

  const evidence = await s.stateEvidenceFor(ENTRYPOINT as Address, DEPOSIT_SLOT as Hex, ACTUAL_DEPOSIT);
  step("EntryPoint 예치금 심기", `블록 ${evidence.block_number}, 슬롯 값 ${ACTUAL_DEPOSIT}`);

  const receipt = await s.reject(
    {
      requester: s.requester.address,
      target: ENTRYPOINT as Address,
      value: REQUESTED,
      calldata: "0xb61d27f6" as Hex,
    },
    DEPOSIT_RULE,
    evidence,
  );
  step("번들러가 UserOperation 드랍", `사유 ${DEPOSIT_RULE.rule_id}`);
  step("체인에 남은 것", "없음 — 브로드캐스트 전에 막혔다");
  step("요청자가 받은 것", `거절 레코드 ${receipt.leaf_hash.slice(0, 18)}…`);

  const n = s.store.size();
  const root = s.store.rootAt(n);
  await s.chain.submitRoot(root, n);
  s.store.recordAnchor(n, root);
  step("로그 루트 앵커", `size=${n}`);

  // 뒤에 앵커가 하나 더 있어야 일관성 증명까지 번들에 담긴다.
  await s.reject({
    requester: s.requester.address,
    target: "0x000000000000000000000000000000000000cafe" as Address,
    value: 1n,
    calldata: "0x" as Hex,
  });
  const n2 = s.store.size();
  const root2 = s.store.rootAt(n2);
  await s.chain.submitRoot(root2, n2);
  s.store.recordAnchor(n2, root2);
  step("이후 앵커", `size=${n2}`);

  heading("2부 — 자족적 번들로 굳힌다");

  // 무엇을 열지는 요청자가 정한다. 검증에 필요한 것만 연다. 수신자와 요청자
  // 주소, calldata 는 봉인한 채로 둔다. 그래도 11단계까지 다 돌아간다.
  const OPEN = ["rule_id", "severity", "value", "verifiability"] as const;
  const bundle = await s.bundleFor(receipt, OPEN, evidence);
  const file = join(dir, "rejection_bundle.json");
  writeFileSync(file, serializeBundle(bundle));
  step("번들 파일", `${file} (${serializeBundle(bundle).length.toLocaleString()} 바이트)`);
  console.log();
  console.log(describeBundle(bundle));
  console.log();

  step("선택적 공개", `${OPEN.length}개만 열고 3개는 커밋만 남김`);
  step(
    "교환 관계",
    "의도 구조체는 수신자와 요청자를 원문으로 담는다. 부인 방지를 포기하면 그것도 뺄 수 있다",
  );
  step("헤더에서 계산한 블록 해시", blockHashOf(bundle.state_proof!.header).slice(0, 18) + "…");

  heading("3부 — 로그 서버를 죽이고 검증한다");

  await s.closeLog();
  step("로그 서버 종료", "이제 기관 쪽에서 가져올 수 있는 것이 없다");

  const dead = await fetch(`${s.base}/api/log/head`).then(
    () => "!!! 아직 살아 있음",
    (e) => `연결 거부 — ${(e as Error).message.split("\n")[0]}`,
  );
  step("로그 서버 확인", dead);

  console.log();
  console.log(`  $ node cli/verify-rejection.ts ${file} --rpc ${s.rpc}`);

  let out = "";
  let code = 0;
  try {
    out = execFileSync("node", ["cli/verify-rejection.ts", file, "--rpc", s.rpc], {
      encoding: "utf8",
    });
  } catch (e) {
    const err = e as { stdout?: string; status?: number };
    out = err.stdout ?? "";
    code = err.status ?? 1;
  }
  console.log(out);
  step("검증 도구 종료 코드", String(code));

  console.log();
  console.log("  검증 과정에서 기관 서버를 부른 횟수: 0");
  console.log("  공개 RPC 호출: 체인 ID, 앵커 루트, 레지스트리, 운영자, 블록 해시.");
  console.log("  전부 누구나 접근 가능한 온체인 데이터다. 노드를 직접 돌려도 된다.");
  console.log();
  console.log("  그리고 11단계가 말한다. 번들러가 댄 예치금 부족은 거짓이다.");
}

const dir = mkdtempSync(join(tmpdir(), "ocdl-demo1-"));
try {
  await withStack(async (s) => {
    console.log("\n데모 1 — 기관 무접촉 검증 (독립 검증 가능성 · 부인 방지)");
    resetSteps();
    await run(s, dir);
    console.log();
  });
} finally {
  rmSync(dir, { recursive: true, force: true });
}
