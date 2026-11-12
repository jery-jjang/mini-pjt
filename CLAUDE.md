# 프로젝트 규칙

무엇을 왜 만드는지는 `SERVICE.md`에 있습니다. 이 문서는 어떻게 만드는지만 다룹니다.
산출물 규약의 원문은 `reference/`의 "mini PJT" 자료(4. 산출물 규약)입니다. 폴더 구조, API 형식, 인-아웃 세트 스키마는 그 규약을 따릅니다.
상세 인수 기준은 `.ouroboros/seed_bfee3756e9e9.yaml`에 있습니다(커밋되지 않는 로컬 파일). 그 파일과 경로, 파일 이름, 응답 형식이 다르면 이 문서가 우선합니다. 예: 명세의 `miniprj/eval_set.json`은 `evaluation/test_queries.csv`, `miniprj/run_eval.py`는 `evaluation/run_eval.py`, `miniprj/tests/`는 `tests/`입니다.

## PoC 범위

- 만든다: 등록, 해당 여부 조회, 현황 조회, 취약점 설명문 검색, 거절, 주기 검색과 알림(파일 저장).
- 만들지 않는다: 오탐 교정(3차), 실시간 NVD/OSV 조회, 실제 메일 발송, 로그인 화면. 계정은 고정 토큰 3개(팀 A 팀원, 팀 B 팀원, 보안 담당자)로 대신한다.

## 기술 스택

- Python 3.14.8, 로컬 venv. Docker는 쓰지 않는다. (의존성이 3.14에 설치되지 않으면 사용자에게 알리고 멈춘다)
- LangChain 1.4.7, LangGraph 1.2.19, langchain-aws 1.9.1, FastAPI 0.162.0 (실습 환경과 같은 버전)
- 모델은 Amazon Bedrock Claude Sonnet 4.5: `global.anthropic.claude-sonnet-4-5-20250929-v1:0`, 리전 `us-east-1`, `langchain-aws`의 `ChatBedrockConverse`
- Agent 생성은 `langchain.agents`의 `create_agent`를 쓴다
- API 서버는 FastAPI, 저장소는 SQLite, 테스트는 pytest
- 문서 검색은 `rank-bm25` 키워드 검색을 쓴다(외부 호출 없음)
- LangSmith 추적은 끈다. `.env`에 값이 있어도 앱 시작 시 코드에서 `LANGSMITH_TRACING=false`로 강제한다
- 추적(트레이스)은 응답의 `trace`와 로컬 기록 파일 `var/traces.jsonl`로 남긴다

## 실행 방법

```
python -m venv .venv                      가상환경 만들기 (처음 한 번)
.venv\Scripts\python -m pip install -r requirements.txt   의존성 설치
.venv\Scripts\python -m uvicorn app:app   서버 실행
.venv\Scripts\python -m pytest tests -q   배선 테스트 (실제 LLM 호출 없음)
.venv\Scripts\python evaluation/run_eval.py --round 1    25건 평가 (실제 Bedrock 호출)
.venv\Scripts\python evaluation/run_ragas.py --round 1   RAGAS 지표 (run_eval 뒤에 실행. 설치 방법은 requirements.txt 아래쪽)
.venv\Scripts\python -m src.scheduler --snapshot T2      검색 1회 실행 (시연용)
```

## 폴더 구조 (제출 규약. 바꾸지 않는다)

```
SERVICE.md            무엇을 왜 만드는가
CLAUDE.md             이 문서
README.md             산출물 규약의 README 틀을 따른다 (활용 패턴, 아키텍처, 실행 방법, 평가 결과, 통과율, 회고, 핵심 코드 위치)
requirements.txt      의존성
.gitignore            .venv/, var/, outbox/, .env, .claude, .ouroboros 제외
app.py                POST /query 진입점 (FastAPI)
src/agent.py          메인 에이전트 그래프
src/tools.py          도메인 도구 (등록, 조회, 문서 검색, 감시)
src/retriever.py      RAG 파이프라인 (취약점 설명문 검색)
src/matching.py       취약점 해당 여부 판정과 알림 대상 판정 (일반 코드, LLM 호출 없음)
src/notifier.py       알림 메일 작성과 저장, 발송 이력
src/scheduler.py      주기 검색과 '지금 1회 실행'
src/sources.py        취약점 정보원 (오프라인 스냅샷)
src/auth.py           로그인, 토큰, 팀·역할 확인
src/storage.py        SQLite 접근
src/config.py         설정값 (환경 변수에서 읽고 기본값을 둔다)
data/                 취약점 스냅샷(1차·2차 시점), 초기 시드 데이터
evaluation/           test_queries.csv, 채점 스크립트 run_eval.py, RAGAS 스크립트 run_ragas.py, round1_report.md, round2_report.md
tests/                pytest (가짜 모델 주입, 실제 LLM 호출 없음)
var/                  실행 중 만들어지는 SQLite 파일과 traces.jsonl (커밋하지 않는다)
outbox/               저장된 알림 메일 파일 (커밋하지 않는다)
```

## 주고받는 형식 (제출 규약)

- `POST /query`로 받고 본문의 `question` 필드를 읽는다. `question`만 필수다.
- 로그인 토큰은 선택이다(`Authorization` 헤더). 토큰이 없으면 기본 평가 계정(팀 A 팀원)으로 처리한다.
- 답은 아래 여섯 키로 돌려주며 항상 모두 채운다.

| 키 | 내용 |
|---|---|
| `answer` | 사용자에게 보여 줄 답변 문장 |
| `contexts` | 답의 근거로 쓴 취약점 레코드 목록. 각 항목은 `{"doc_id": "CVE-...", "text": "..."}` (없으면 빈 목록) |
| `trace` | 실행 단계 기록. 각 항목은 `{"step": "도구 이름 등", "input": "...", "output": "..."}`, 호출 순서대로 |
| `label` | `answer` / `no_answer` / `guardrail` 중 하나 |
| `cve_ids` | 답에 포함된 CVE ID 목록(CVE가 없으면 원래 ID) |
| `tools_called` | 호출한 도구 이름 목록(중복 없이, 채점용) |

- 등록은 두 번의 요청으로 이뤄진다. 첫 요청에서 후보 1~3개를 제시하고 계정별 '대기 중인 후보'를 SQLite에 저장한다. 같은 계정의 다음 요청("1번으로 확정")이 그 후보를 확정한다. 요청 형식은 바꾸지 않는다.
- 프로젝트와 프로젝트별 알림 수신 주소는 `data/`의 초기 시드에 넣어 둔다. 대화로 프로젝트를 새로 만드는 기능은 만들지 않는다.
- UI용 설정 API: `GET /settings`(누구나)는 `scan_interval_hours`, `scheduler_enabled`, `last_run_at`, `next_run_at`을 돌려준다. `PUT /settings/scan-interval`(보안 담당자만, 본문 `{"hours": 숫자}`)은 검색 주기를 바꾸고 같은 형식으로 돌려준다. 팀원·토큰 없음은 403, 모르는 토큰은 401, 0 이하나 숫자가 아닌 값은 422.

## 인-아웃 세트 형식 (제출 규약)

- 파일은 `evaluation/test_queries.csv`, 25건. 열은 아래 7개이며 더하거나 빼지 않는다.

| 열 | 필수 | 내용 |
|---|---|---|
| `id` | 필수 | 1부터 시작하는 번호, 중복 금지 |
| `category` | 필수 | `positive` / `negative` / `edge` / `guardrail` |
| `input` | 필수 | 사용자 질의. `POST /query`의 `question`으로 보낸다 |
| `expected_traits` | 필수 | 답변에 반드시 들어가야 할 항목. 세미콜론으로 구분 |
| `forbidden` | 선택 | 답변에 나오면 안 되는 항목. 세미콜론으로 구분 |
| `expected_tools` | 선택 | 호출되어야 할 도구 이름. 세미콜론으로 구분 |
| `note` | 선택 | 의도 메모. `requester=...`, `label=...`, `kind=...`, `ids=exact` 같은 채점용 표시도 여기에 세미콜론으로 구분해 적는다 |

- 건수: `positive` 10(등록 3, 해당 여부 4, 현황 3), `negative` 4(근거 없음), `edge` 6(등록 2, 해당 여부 2, 현황 2), `guardrail` 5. 합치면 등록 5, 해당 여부 6, 현황 5, 근거 없음 4, 거절 5이다.
- 기대 라벨: `positive`는 `answer`, `negative`는 `no_answer`, `guardrail`은 `guardrail`. `edge`는 `note`의 `label=` 값을 따른다.
- 요청자: `note`에 `requester=team_b_member` 또는 `requester=security_admin`이 있으면 그 계정의 토큰으로 보낸다. 없으면 `team_a_member`.
- guardrail은 네 유형(다른 팀 데이터, 공격 방법, 지시 조작, 무관한 질문)을 각각 1건 이상 넣는다.
- 자동 채점: 라벨 일치, `expected_traits` 중 `CVE-` 또는 `GHSA-`로 시작하는 ID가 모두 답에 있을 것, `expected_tools`를 불렀을 것, `forbidden` 문자열이 답에 없을 것.
- 정확 일치: `note`에 `ids=exact`가 있는 문항은 답에 나온 CVE·GHSA ID가 기대 목록과 정확히 같아야 한다(GHSA 별칭은 CVE ID로 바꿔 센다). 해당하지 않는 취약점을 보태는 답을 잡기 위한 것으로, 해당 여부와 조건 조회 문항 8건에 건다. 표시가 없는 문항은 추가 ID를 허용한다.
- ID가 아닌 `expected_traits`는 LLM 채점(LLM-as-Judge)으로 판정하고, 답변과 나란히 리포트에 남겨 사람이 확인한다.
- 평가 실행 전에 SQLite를 `data/`의 초기 시드로 되돌린다. 문항 하나가 예외를 던져도 멈추지 않고 그 문항만 `error`로 기록한다. 분류별 통과율과 전체 통과율을 출력하고 `evaluation/roundN_report.md`로 저장한다.

## 작업 순서

1. 인-아웃 세트(`evaluation/test_queries.csv`)와 고정 데이터(`data/`)를 코드보다 먼저 쓴다.
2. 한 번에 한 가지 기능만 붙이고, 붙일 때마다 실행해서 결과를 보여 준다.
3. 계획을 먼저 보여 주고 승인을 받은 뒤 파일을 고친다.

## 코드 규칙

- 파일 하나에 한 가지 역할만 둔다.
- 함수와 도구에는 한국어 docstring을 쓰고, 주석도 한국어로 쓴다.
- 비밀 값은 `.env`에서 읽고 코드에 적지 않는다. `.env`는 커밋하지 않는다.
- 모델은 모듈 최상단에서 만들지 않는다. 함수 안에서 만들고 `llm=None` 인자로 가짜 모델을 주입할 수 있게 한다.
- `tests/`의 테스트는 실제 LLM과 외부 API를 호출하지 않는다. SQLite와 메일 파일은 임시 경로에 만든다.
- 더미 데이터 파일에는 "교육용 더미 데이터입니다"를 명시한다.

## 반드시 지킬 동작 규칙

- 취약점 해당 여부 판정과 알림 발송 결정은 `src/matching.py`의 일반 코드가 한다. LLM에 맡기지 않는다.
- 다른 팀 데이터 차단은 토큰(또는 기본 계정) 기준으로 코드가 처리한다. LLM 판단에 맡기지 않는다.
- LLM과 NVD/OSV로는 제품명과 버전만 보낸다. 질문 속 팀명과 프로젝트명은 LLM에 보내기 전에 가린다.
- 도구로 조회한 결과만 근거로 답한다. 근거가 없으면 `no_answer` 라벨로 "확인할 수 없음"이라고 답하고, "안전함"이나 "해당 없음"이라고 하지 않는다.
- 알림 조건은 CVSS 9.0 이상 또는 KEV 등재. 프로젝트+CVE당 1회, 점수 상승이나 KEV 신규 등재 시 1회 더.
- 점수는 NVD 우선, 없으면 CNA/OSV, 둘 다 없으면 '점수 미정'. GHSA 별칭은 연결된 CVE ID로 통일한다.
- 알림은 기본으로 메일 내용을 파일에 저장한다. 요약에는 CVE ID, 점수 또는 KEV 여부, 제품과 버전을 넣는다.
- `data/`의 오프라인 스냅샷만 쓴다. 실시간 NVD/OSV 조회와 실제 메일 발송은 이번 PoC에서 만들지 않는다. 설정 항목(`live_lookup`, `send_real_mail`)은 자리만 있고, 실시간 조회를 켜면 만들지 않았다는 오류를 낸다.
- 스케줄러 주기(기본 6시간), 연속 실패 통지 횟수(기본 2회), 알림 기준 점수(기본 9.0)는 `src/config.py`의 설정값으로 둔다.
- 검색 주기는 서버 재시작 없이 바꿀 수 있어야 한다. 바꾼 값은 SQLite에 저장해 재시작 뒤에도 쓰고, `.env` 값은 저장값이 없을 때만 쓴다. 다음 검색은 바꾼 시각 + 새 주기다. 0 이하는 `config.validate_interval`로 막는다(`.env`에 있으면 서버가 뜨지 않는다).

## 하지 말 것

- 폴더 구조에 없는 파일은 요청 없이 새로 만들지 않는다.
- 기존 파일을 통째로 다시 쓰지 않는다. 바뀐 부분만 고친다.
- 폴더 구조와 주고받는 형식을 바꾸지 않는다.
- 통과한 평가 문항을 지우거나, 통과시키려고 문항의 기대값을 고치지 않는다.
- 사용자가 요청하기 전에는 커밋하지 않는다.
