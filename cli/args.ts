// CLI 공통. 인자 읽기와 종료 처리.
//
// 최상위 await 에서 던진 예외는 기본적으로 Node 스택 트레이스로 찍힌다. 운영자가
// 보는 건 "포트가 이미 쓰이고 있다" 같은 한 줄이어야 한다.

/** `--key value` 또는 환경변수 `OCDL_KEY`. 기본값 없이 빠지면 던진다. */
export const arg = (k: string, d?: string): string => {
  const i = process.argv.indexOf(`--${k}`);
  const v = i >= 0 ? process.argv[i + 1] : process.env[`OCDL_${k.toUpperCase().replace(/-/g, "_")}`];
  if (v === undefined && d === undefined) throw new Error(`--${k} 가 필요하다`);
  return v ?? d!;
};

export function installErrorHandler(): void {
  const die = (e: unknown): never => {
    const m = e instanceof Error ? e.message : String(e);
    console.error(`오류: ${m.split("\n")[0]}`);
    process.exit(1);
  };
  process.on("uncaughtException", die);
  process.on("unhandledRejection", die);
}
