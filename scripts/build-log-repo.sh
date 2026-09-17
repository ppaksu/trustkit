#!/usr/bin/env bash
# 공개용 거절 로그 데이터를 만든다. 정상본과 조작본 둘, 셋을 같이 낸다.
#
#   ./scripts/build-log-repo.sh ../ocdl-public-log
#
# 체인 상태도 같이 뜬다. 로컬 anvil 위에서 만든 로그라 앵커된 루트가 그 체인에만
# 있고, 상태 덤프가 없으면 어느 판본이 정상인지 대조할 기준이 사라진다.
set -euo pipefail

OUT="${1:-../ocdl-public-log}"
COUNT="${COUNT:-20000}"
PORT="${PORT:-8545}"
LOG_PORT="${LOG_PORT:-8788}"
WORK="$(mktemp -d)"

OWNER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
OP_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
OP_ADDR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
GW_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
GW_ADDR=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
RPC="http://127.0.0.1:$PORT"

cd "$(dirname "$0")/.."
mkdir -p "$OUT/chain"

cleanup() {
  pkill -f "cli/log-server.ts --db $WORK" 2>/dev/null || true
  [ -n "${ANVIL:-}" ] && kill "$ANVIL" 2>/dev/null || true
}
trap cleanup EXIT

echo "체인 기동"
anvil --port "$PORT" --silent --dump-state "$WORK/anvil-state.json" &
ANVIL=$!
sleep 3

ANCHOR=$(cd contracts && LOG_OPERATOR=$OP_ADDR forge script script/Deploy.s.sol \
  --rpc-url "$RPC" --broadcast --private-key "$OWNER_KEY" 2>&1 \
  | grep "LogAnchor deployed:" | awk '{print $NF}')
echo "  앵커 $ANCHOR"

cast send "$ANCHOR" "setGateway(address,bool)" "$GW_ADDR" true \
  --rpc-url "$RPC" --private-key "$OWNER_KEY" >/dev/null
echo "  게이트웨이 등록"

node cli/log-server.ts --db "$WORK/log.db" --port "$LOG_PORT" \
  --anchor "$ANCHOR" --rpc "$RPC" --operator-key "$OP_KEY" >"$WORK/server.log" 2>&1 &
sleep 3

echo "거절 $COUNT 건 적재"
node cli/seed.ts --count "$COUNT" --mix --anchor "$ANCHOR" --rpc "$RPC" \
  --gateway-key "$GW_KEY" --log "http://127.0.0.1:$LOG_PORT" \
  --policy-update-out "$WORK/policy-update.json" | tail -1

node cli/anchor.ts --db "$WORK/log.db" --anchor "$ANCHOR" --rpc "$RPC" \
  --operator-key "$OP_KEY" | tail -1

# 앵커를 두 번 올린다. 기준점이 둘이어야 어느 구간이 어긋났는지가 갈린다.
node cli/seed.ts --count 500 --mix --anchor "$ANCHOR" --rpc "$RPC" \
  --gateway-key "$GW_KEY" --log "http://127.0.0.1:$LOG_PORT" \
  --policy-update-out "$WORK/ignore.json" | tail -1
node cli/anchor.ts --db "$WORK/log.db" --anchor "$ANCHOR" --rpc "$RPC" \
  --operator-key "$OP_KEY" | tail -1

echo "정상본 내보내기"
node cli/export-log.ts --db "$WORK/log.db" --out "$OUT/log-normal" | sed 's/^/  /'

cleanup
kill -INT "$ANVIL" 2>/dev/null || true
wait "$ANVIL" 2>/dev/null || true
cp "$WORK/anvil-state.json" "$OUT/chain/anvil-state.json"

# 조작본 둘. 운영자가 DB 를 직접 만졌을 때 나오는 두 가지 상태다. 같은 세 건을
# 골라 한쪽은 고치고 한쪽은 지운다. 둘이 다르게 잡힌다.
echo "조작본 만들기"
rm -rf "$OUT/log-tampered" "$OUT/log-deleted"
cp -r "$OUT/log-normal" "$OUT/log-tampered"
cp -r "$OUT/log-normal" "$OUT/log-deleted"

python3 - "$OUT" <<'PY'
import json, sys, pathlib

out = pathlib.Path(sys.argv[1])
src = (out / "log-normal" / "leaves.jsonl").read_text().rstrip("\n").split("\n")
targets = [len(src) // 4, len(src) // 2, (len(src) * 3) // 4]

# 수정본: 발급 시각을 하루 앞당긴다. 서명과 루트가 같이 깨진다.
lines = list(src)
for i in targets:
    d = json.loads(lines[i])
    d["issued_at"] -= 86400
    lines[i] = json.dumps(d, separators=(",", ":"), sort_keys=True)
(out / "log-tampered" / "leaves.jsonl").write_text("\n".join(lines) + "\n")

# 삭제본: 같은 세 줄을 뺀다. 남은 리프의 서명은 전부 멀쩡하다.
kept = [l for i, l in enumerate(src) if i not in targets]
(out / "log-deleted" / "leaves.jsonl").write_text("\n".join(kept) + "\n")

print(f"  대상 인덱스 {targets}")
print(f"  수정본 {len(src)}줄, 삭제본 {len(kept)}줄")
PY

cat >"$OUT/README.md" <<EOF
# 거절 로그

오프체인 게이트웨이가 막은 거절 기록이다. 같은 로그의 세 판본이 들어 있다.

| 디렉터리 | 내용 |
|---|---|
| \`log-normal/\` | 정상본. 로그 서버가 만든 그대로다 |
| \`log-tampered/\` | 세 건의 발급 시각을 하루씩 앞당긴 것 |
| \`log-deleted/\` | 그 세 건을 통째로 지운 것 |

각 디렉터리에 파일이 둘 있다.

\`leaves.jsonl\` 은 한 줄에 리프 하나다. 줄 번호가 곧 머클 트리의 인덱스다.
\`anchors.json\` 은 앵커 이력이다. 트리 크기, 루트, 트랜잭션 해시, 체인 시각이
들어 있다.

리프에는 원문이 없다. 필드마다 다른 난수를 붙여 해시한 커밋만 들어 있다. 누가
요청했고 어디로 얼마를 보내려 했고 무슨 사유였는지는 로그에 없다. 남는 것은 어느
게이트웨이가 어느 정책 해시 아래서 언제 거절했는지다.

\`chain/anvil-state.json\` 은 앵커 컨트랙트가 올라간 체인의 상태다. 루트가 여기
박혀 있어서 세 판본 중 어느 것이 정상인지 갈린다.

    anvil --load-state chain/anvil-state.json --port 8545

앵커 컨트랙트 \`$ANCHOR\`, 체인 ID 31337, 로그 운영자 \`$OP_ADDR\`,
게이트웨이 \`$GW_ADDR\`.

데모 데이터다. 실존 기관·제재 대상과 무관하고 주소는 전부 로컬 테스트 키다.
EOF

echo
echo "완료  $OUT"
du -sh "$OUT"/*
rm -rf "$WORK"
