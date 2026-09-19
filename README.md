# OCDL

체인에 남지 않는 거절을 증명한다. Off-Chain Decision Log.

커스터디나 번들러가 트랜잭션을 **브로드캐스트하기 전에** 막으면 체인에는 아무것도 안
남는다. 기관은 요청을 받은 적 없다고 할 수 있고, 사유와 시각을 나중에 고칠 수 있고,
불리한 기록을 지울 수 있다. OCDL 은 그 거절에 증거를 붙인다. 제3자는 기관 서버에 한
번도 접촉하지 않고 판단의 진위, 기록의 불변성, 거절 사유의 참거짓까지 확인한다.

TRUST404 트랙 3 — Off-chain Decision Provenance 제출작.

## 설치

```bash
npm install
```

Node 24 이상. `node:sqlite`와 네이티브 TypeScript 실행을 쓴다. 앵커 컨트랙트를
띄우려면 anvil과 forge도 필요하다. `curl -L https://foundry.paradigm.xyz | bash`

## 쓰는 법

주체가 넷이다. 체인, 로그, 게이트웨이, 검증자. 각자 다른 프로세스다.

### 체인

```bash
anvil --port 8545

cd contracts && LOG_OPERATOR=$OP_ADDR forge script script/Deploy.s.sol \
  --rpc-url http://127.0.0.1:8545 --broadcast --private-key $OWNER_KEY

cast send $ANCHOR "setGateway(address,bool)" $GW_ADDR true \
  --rpc-url http://127.0.0.1:8545 --private-key $OWNER_KEY
```

Sepolia 에 배포해 둔 것을 그대로 써도 된다. 아래 두 값을 넣고 `--rpc` 만 바꾸면
나머지 명령은 그대로다.

```bash
export ANCHOR=0xD289Aa81F321bed57388d3e9770B728d2660c5f1
export RPC=https://ethereum-sepolia-rpc.publicnode.com
```

[sepolia.etherscan.io](https://sepolia.etherscan.io/address/0xD289Aa81F321bed57388d3e9770B728d2660c5f1)
· 체인 ID `11155111` · 로그 운영자 `0x98bC48DCB9CD9Cf9696b9bAc5253442B0F72965F`

이 앵커에 레코드를 올리려면 게이트웨이 등록이 필요하다. 읽기만 하는 검증·감사는
등록 없이 누구나 돌릴 수 있다.

### 로그와 앵커

```bash
node cli/log-server.ts --db ./log.db --port 8788 \
  --anchor $ANCHOR --rpc http://127.0.0.1:8545 --operator-key $OP_KEY

node cli/anchor.ts --db ./log.db --anchor $ANCHOR \
  --rpc http://127.0.0.1:8545 --operator-key $OP_KEY --watch 15
```

### 게이트웨이

참조 목록을 판단보다 먼저 공표한다.

```bash
node cli/gateway.ts publish-list --anchor $ANCHOR --rpc http://127.0.0.1:8545 \
  --log http://127.0.0.1:8788 --gateway-key $GW_KEY --out policy-update.json
```

거절이 나면 영수증을, 앵커가 그 리프를 덮으면 번들을 낸다. `--wait` 가 그때까지 기다린다.

```bash
node cli/gateway.ts reject --target 0x…cafe --value 5000000000000000000 \
  --anchor $ANCHOR --rpc http://127.0.0.1:8545 --log http://127.0.0.1:8788 \
  --gateway-key $GW_KEY --requester-key $RQ_KEY --out receipt.json

node cli/gateway.ts bundle --receipt receipt.json --out bundle.json --wait 90 \
  --anchor $ANCHOR --rpc http://127.0.0.1:8545 --log http://127.0.0.1:8788 \
  --gateway-key $GW_KEY
```

### 검증자

번들 파일 하나와 RPC 주소면 된다. 종료 코드는 통과 0, 실패 1, 번들이나 RPC 오류 2.
`--json` 으로 기계가 읽는 보고서를 낸다.

```bash
node cli/verify-rejection.ts bundle.json --rpc http://127.0.0.1:8545
```

```
  통과     1. 필드 집합과 커밋 루트
  통과     2. 게이트웨이 서명
  통과     3. 레지스트리 등록
  통과     4. 요청자 서명
  통과     5. 로그 접수 확인
  통과     6. 포함 증명
  통과     7. 일관성 증명
  통과     8. 선택적 공개
  통과     9. 정책 커밋
  통과     10. 정적 사유
  실패     11. 동적 사유
            거짓 동적 사유. 블록 3 슬롯 값 5000000000000000000 < 1000000000000000000 가 거짓

  판정: 11단계에서 실패
  책임: 정상
```

### 로그 공개와 감사

`export-log` 는 운영 키를 받지 않는다. sqlite 를 읽기만 한다.

```bash
node cli/export-log.ts --db ./log.db --out ./public-log

node cli/audit-log.ts --dir ./public-log --anchor $ANCHOR --rpc http://127.0.0.1:8545
```

```
  통과  모든 리프가 JCS 정규형
  통과  리프 67건 전부 등록된 게이트웨이의 서명
  통과  크기 61 루트가 체인과 일치

  6건이 아직 앵커되지 않았다. 이 구간은 판정하지 않는다.
```

`--dir` 대신 `--leaves` 와 `--anchors` 로 파일을 따로 줄 수 있다. 대량 적재는
`node cli/seed.ts --count 20000 …`.

데모 로그: **[ppaksu/ocdl-rejection-log](https://github.com/ppaksu/ocdl-rejection-log)**
거절 2만 건의 정상본, 세 건을 고친 수정본, 그 세 건을 지운 삭제본, 체인 상태.

## 거절 레코드 스키마

원문은 로그에 올라가지 않는다. 필드마다 다른 난수를 붙여 해시한 값만 올린다.

```
h_i        = SHA256("ocdl/field/v1|" + JCS([salt_i, key, value]))
keysRoot   = SHA256(JCS(keys))
fieldsRoot = SHA256(h_0 ‖ … ‖ h_6)
leaf_hash  = SHA256(0x00 ‖ JCS(leaf))
```

난수는 필드마다 다르다. 서명 대상은 EIP-712 `RejectionRecord` 13필드다.

필수 키 일곱 개. 사전순이며 이 순서가 곧 `field_hashes` 순서다.

| key | 봉인 |
|---|---|
| `calldata_hash` | 아니오 |
| `requester` | 예 |
| `rule_id` | 예 |
| `severity` | 아니오 |
| `target` | 예 |
| `value` | 예 |
| `verifiability` | 아니오 |

봉인한 필드는 커밋만 공개하고 원문은 요청자 번들에만 둔다. 무엇을 열지는 요청자가
정한다. 7개 중 4개만 열어도 검증 11단계가 전부 돈다.

## 검증 11단계

| 단계 | 확인 |
|---|---|
| 1 | 필드 집합, 두 루트 재계산, `leaf_hash` 가 리프 본문과 결속 |
| 2 | 게이트웨이 서명 복원 |
| 3 | 게이트웨이가 온체인 레지스트리에 등록됨 |
| 4 | 요청자 서명 복원, 해시가 리프 커밋과 일치 |
| 5 | 로그 접수 확인 서명, 발급 ≤ 접수 |
| 6 | 포함 증명이 **체인에서 읽은** 루트와 일치, 발급 ≤ 앵커 |
| 7 | **요청한 구간**의 일관성 증명, 두 구간 모두 앵커됨 |
| 8 | 공개된 값이 그 자리의 커밋과 일치 |
| 9 | 정책 해시, `rule_id` 실재, 목록이 판단보다 **먼저 공표**됨 |
| 10 | 정적 사유가 커밋된 목록과 모순되는가 |
| 11 | 동적 사유가 상태 증거와 모순되는가 |

결과는 통과, 실패, **판정 불가** 셋이다. 10·11 중 하나도 판정되지 않으면 보고서가
"검증 통과" 대신 "조작 흔적 없음, 다만 사유는 검증되지 않았다" 로 쓴다.

## 레포 구조

```
.
├── lib/                    검증에 필요한 전부. 신뢰 경계 안쪽
│   ├── jcs.ts              RFC 8785 정규화. 모든 해시 입력이 여기를 거친다
│   ├── merkle.ts           RFC 6962 트리. 포함 증명, 일관성 증명
│   ├── sorted-merkle.ts    정렬 트리. 비포함 증명
│   ├── state-proof.ts      EIP-1186 상태 증거. 헤더 RLP, MPT 검증
│   ├── record.ts           리프 구성, 필드 커밋, 정책 문서
│   ├── sign.ts             EIP-712 서명 세 개
│   ├── receipt.ts          요청자 영수증, 책임 판정
│   ├── bundle.ts           자족적 번들 조립과 파싱
│   ├── verify.ts           검증 11단계
│   ├── log-store.ts        접수 검증, 트리 관리, 증명 발급
│   ├── log-server.ts       HTTP 계층
│   ├── chain.ts            앵커 컨트랙트 바인딩
│   └── anchor-job.ts       주기 앵커링
├── sdk/
│   ├── gateway.ts          정책 평가, 상태 증거 수집, 레코드 서명
│   └── demo-policy.ts      데모용 정책 문서. 규칙 6종
├── cli/
│   ├── verify-rejection.ts 독립 검증 도구
│   ├── audit-log.ts        공개된 로그 전체 감사
│   ├── log-server.ts       로그 서버
│   ├── gateway.ts          목록 공표, 거절, 번들 조립
│   ├── anchor.ts           앵커링
│   ├── export-log.ts       로그 전체 내보내기
│   ├── seed.ts             대량 적재
│   └── args.ts             인자 파싱, 종료 처리
├── contracts/
│   ├── src/LogAnchor.sol   루트 앵커 + 게이트웨이 레지스트리
│   ├── script/Deploy.s.sol
│   └── test/LogAnchor.t.sol
├── scripts/                시나리오 검증
└── test/                   단위 테스트 12개 파일
```

앵커 컨트랙트는 루트 고정과 게이트웨이 레지스트리만 한다.

```solidity
function submitRoot(bytes32 root, uint64 treeSize) external {
    if (msg.sender != logOperator) revert NotAuthorized();
    if (root == bytes32(0) || treeSize == 0) revert InvalidRoot();
    if (treeSize <= lastTreeSize) revert TreeSizeNotIncreasing();
    rootByTreeSize[treeSize] = root;
    anchoredAt[treeSize] = uint64(block.timestamp);
    lastTreeSize = treeSize;
    emit RootAnchored(treeSize, root, uint64(block.timestamp));
}
```

`treeSize <= lastTreeSize`를 막는 한 줄이 롤백과 같은 크기 재앵커를 동시에 막는다.
`anchoredAt`이 발급 시각의 상한을 준다. 검증 6단계의 시각 검사가 여기에 걸려 있다.

앵커 1회에 슬롯 세 개를 쓴다. 레코드 건수와 무관하다. 2만 건을 한 루트로 묶어도 같다.
forge 측정 73,115, Sepolia 실측 73,475. 1 gwei 면 앵커 1회에 0.0000735 ETH 다.

## 테스트

```bash
npm test               # 183
npm run test:contracts #   9

npm run lifecycle      # 정상 / 수정 / 삭제 순으로 로그를 흔든다
npm run evil           # 규칙을 전부 무시한 기관 구현 8종
npm run regress        # 감사에서 찾은 우회 경로가 여전히 막히는지
```

`test/state-proof.test.ts` 는 anvil 을 띄워 실제 `eth_getProof` 응답으로 왕복한다.

## 상태

해커톤 제출용 프로토타입이다. 로컬 anvil 과 Sepolia 양쪽에서 돌렸다. Sepolia 에서는
리프 42건에 앵커 2회를 올려 검증 11단계가 전부 통과했다. 일관성 증명(7단계)도 두 앵커
사이에서 실제로 돌았다.

단일 로그 운영자 구성이며 운영 환경에서는 내구성 저장소와 키 관리가 따로 필요하다.

Node 26에서 개발하고 테스트했다. `node:sqlite`와 네이티브 TypeScript 실행을 쓰므로
24 미만에서는 돌지 않는다. 런타임 의존성은 viem과 `@ethereumjs/mpt`, `@ethereumjs/util` 셋뿐이다.
