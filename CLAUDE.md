# 프로젝트 규칙

무엇을 왜 만드는지는 `SERVICE.md`에 있습니다. 이 문서는 어떻게 만드는지만 다룹니다.
산출물 규약의 원문은 `reference/`의 "mini PJT" 자료(4. 산출물 규약)입니다. 폴더 구조, API 형식, 인-아웃 세트 스키마는 그 규약을 따릅니다.
작업이 끝날 때마다 `history.md`에 기록을 남기고, 기록 규칙은 `AGENT.md`를 따릅니다.
상세 인수 기준은 `.ouroboros/seed_bfee3756e9e9.yaml`에 있습니다(커밋되지 않는 로컬 파일). 그 파일과 경로, 파일 이름, 응답 형식이 다르면 이 문서가 우선합니다. 예: 명세의 `miniprj/eval_set.json`은 `evaluation/test_queries.csv`, `miniprj/run_eval.py`는 `evaluation/run_eval.py`, `miniprj/tests/`는 `tests/`입니다.

## PoC 범위

- 만든다: 등록, 해당 여부 조회, 현황 조회, 취약점 설명문 검색, 거절, 주기 검색과 알림(DB 저장). 로컬 화면(`web/`)과 화면용 기능(등록 목록, SW 삭제, 알림함과 읽음 현황, 검색 주기·취약점 데이터 시점 설정)도 만든다.
- 만들지 않는다: 오탐 교정(3차), 실시간 NVD/OSV 조회, 실제 메일 발송, 로그인 화면. 계정은 고정 토큰 3개(팀 A 팀원, 팀 B 팀원, 보안 담당자)로 대신한다.

## 기술 스택

- Python 3.14.8, 로컬 venv. 개발·테스트·평가는 venv로 한다. `Dockerfile`은 클린 환경 재현 확인용으로만 둔다. (의존성이 3.14에 설치되지 않으면 사용자에게 알리고 멈춘다)
- LangChain 1.4.7, LangGraph 1.2.19, langchain-aws 1.9.1, FastAPI 0.162.0 (실습 환경과 같은 버전)
- 모델은 Amazon Bedrock, `langchain-aws`의 `ChatBedrockConverse`. 모델 ID와 리전은 `.env`의 `VULNWATCH_MODEL_ID`, `VULNWATCH_REGION`으로 정한다. 모델은 Amazon Nova Pro(`us.amazon.nova-pro-v1:0`, `us-east-1`)로 쓰고, `.env`에 없을 때 코드 기본값도 같다. 1차·2차 평가, LLM 채점, RAGAS 결과는 모두 Nova Pro로 낸 것이다
- Agent 생성은 `langchain.agents`의 `create_agent`를 쓴다
- API 서버는 FastAPI, 저장소는 SQLite, 테스트는 pytest
- 문서 검색은 하이브리드다: ID 정확 일치, LLM 쿼리 확장(한글 검색어 → 영어 키워드, 구조화 출력), `rank-bm25` 키워드 검색과 Bedrock Titan 임베딩(`amazon.titan-embed-text-v2:0`, `VULNWATCH_EMBED_MODEL_ID`) 의미 검색을 RRF로 합친다. 의미 검색은 유사도 0.2 미만을 버린다. 문서 임베딩은 `var/doc_embeddings.json`에 캐시한다
- 쿼리 확장이나 임베딩이 실패하면 키워드 검색만으로 계속한다. 테스트는 가짜 모델·가짜 임베딩을 넣어 외부를 호출하지 않는다
- 에이전트 미들웨어는 두 개다: 재시도(`ModelErrorException`과 일시적 서버 오류, 모델이 답 대신 돌려준 콘텐츠 필터 차단 문구만 최대 2번, 다시 부를 때 temperature 0.7, 한도 초과는 재시도하지 않음)와 모델 앞 이름 가리기 안전망. 질문과 도구 결과를 가리는 일은 LangSmith 기록 때문에 미들웨어로 옮기지 않는다
- 추적(트레이스)은 LangSmith와 로컬 기록 두 곳에 남긴다. LangSmith는 `.env`의 `LANGSMITH_TRACING=true`일 때 켜지고, 요청마다 `vulnwatch-query` 실행으로 남는다. 같은 `run_id`를 응답의 `trace`가 담긴 로컬 기록 `var/traces.jsonl`에도 적어 둘을 잇는다
- LangSmith로 가는 것은 모델 입력과 출력, 도구 입력과 출력뿐이고 모두 프로젝트명·팀명을 가린 글이다. 메타데이터에는 역할만 넣고 계정·팀·프로젝트 이름을 넣지 않는다
- `tests/`는 `conftest.py`에서 `LANGSMITH_TRACING=false`로 고정해 외부로 아무것도 보내지 않는다

## 실행 방법

```
python -m venv .venv                      가상환경 만들기 (처음 한 번)
.venv\Scripts\python -m pip install -r requirements.txt   의존성 설치
.venv\Scripts\python -m uvicorn app:app   서버 실행 (화면은 http://127.0.0.1:8000/ui/)
.venv\Scripts\python -m pytest tests -q   배선 테스트 (실제 LLM 호출 없음)
.venv\Scripts\python evaluation/run_eval.py --round 2    30건 평가 (실제 Bedrock 호출. roundN_report.md를 덮어쓴다)
.venv\Scripts\python evaluation/run_ragas.py --round 2   RAGAS 지표 (run_eval 뒤에 실행. 설치 방법은 requirements.txt 아래쪽)
.venv\Scripts\python -m src.scheduler --snapshot T2      검색 1회 실행 (시연용)
.venv\Scripts\python -m src.storage --load-demo          로컬 DB에 시연용 등록 항목 추가 (평가 뒤 다시 실행)
.venv\Scripts\python -m src.notifier --list             DB에 저장된 알림 메일 목록 (--show N 으로 본문)
```

## 폴더 구조 (제출 규약. 바꾸지 않는다)

```
SERVICE.md            무엇을 왜 만드는가
CLAUDE.md             이 문서
AGENT.md              작업 기록 규칙 (사용자 요청으로 2026-11-13에 더함)
history.md            채팅으로 진행한 작업 기록 (AGENT.md 규칙대로 이어 쓴다)
README.md             산출물 규약의 README 틀을 따른다 (활용 패턴, 아키텍처, 실행 방법, 평가 결과, 통과율, 회고, 핵심 코드 위치)
requirements.txt      의존성
.gitignore            .venv/, var/, outbox/, .env, .claude, .ouroboros, .vscode, reference 제외
Dockerfile            클린 환경 재현용 (선택. 사용자 요청으로 2026-11-13에 더함. .env와 var/는 이미지에 넣지 않는다)
app.py                POST /query 진입점 (FastAPI). 등록 목록·SW 삭제·알림함·설정 API와 화면 파일(/ui)도 내준다
src/agent.py          메인 에이전트 그래프
src/tools.py          도메인 도구 (등록, 조회, 문서 검색, 감시)
src/retriever.py      RAG 파이프라인 (취약점 설명문 검색)
src/matching.py       취약점 해당 여부 판정과 알림 대상 판정 (일반 코드, LLM 호출 없음)
src/notifier.py       알림 메일 작성과 저장, 발송 이력
src/scheduler.py      주기 검색과 '지금 1회 실행'
src/sources.py        취약점 정보원 (오프라인 스냅샷 읽기, 지금 쓰는 데이터 시점 저장, 근거 문서의 참고 링크)
src/auth.py           로그인, 토큰, 팀·역할 확인
src/storage.py        SQLite 접근
src/config.py         설정값 (환경 변수에서 읽고 기본값을 둔다)
data/                 취약점 스냅샷(1차·2차 시점), 초기 시드 데이터, 시연용 추가 등록 항목(demo_items.json. 평가 시드와 별개로 로컬 DB에만 넣는다. 사용자 요청으로 2026-11-12에 더함)
evaluation/           test_queries.csv, 채점 스크립트 run_eval.py, RAGAS 스크립트 run_ragas.py, round1_report.md, round2_report.md
tests/                pytest (가짜 모델 주입, 실제 LLM 호출 없음)
var/                  실행 중 만들어지는 SQLite 파일과 traces.jsonl (커밋하지 않는다)
web/                  로컬 화면 (빌드 없는 HTML·CSS·JS. 서버가 /ui에서 내준다. 사용자 요청으로 2026-11-12에 더함)
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

- 예외: 답을 만들지 못한 실패는 여섯 키 대신 HTTP 오류와 `{"detail": "이유"}`로 알린다. 모르는 토큰 401, 요청 형식 오류 422, 모델 호출 한도 초과 429, 그 밖의 모델 호출 실패 503. 사용자에게 트레이스백을 보내지 않는다. 오류 응답에도 `charset=utf-8`을 밝힌다.
- 등록은 두 번의 요청으로 이뤄진다. 첫 요청에서 후보 1~3개를 제시하고 계정별 '대기 중인 후보'를 SQLite에 저장한다. 같은 계정의 다음 요청("1번으로 확정")이 그 후보를 확정한다. 요청 형식은 바꾸지 않는다.
- SW 삭제는 지금 화면에서만 한다(`DELETE /projects/{project_id}/items/{item_id}`). 대화로 지우는 도구는 아직 만들지 않는다. 팀원은 자기 팀 프로젝트, 보안 담당자는 전체를 지울 수 있고 권한은 코드가 확인한다. 한 요청에 한 항목만 지운다.
- 삭제는 표시만 한다(soft delete): 항목 상태를 `removed`로 바꾸고 `item_removals`에 이전 상태·시각·계정을 남긴다. `storage.list_items`가 삭제된 항목을 빼므로 조회·현황·주기 검색·중복 확인에서 모두 빠진다. 알림 이력(`alerts`)은 지우지 않는다.
- 지운 SW를 다시 등록하면 알림을 다시 보낸다: 삭제로 프로젝트에 같은 표준 제품이 하나도 남지 않으면 그 제품의 탐지 기록(`findings`)을 지우고 관련 취약점마다 `alert_resets`에 그때까지의 마지막 알림 번호를 남긴다. `last_alert`는 그 번호 뒤의 알림만 본다.
- 모델이 틀리게 넣는 도구 인자는 도구 안의 코드가 바로잡는다(프롬프트 규칙에만 기대지 않는다). `check_vulnerabilities`의 `vuln_id`가 `CVE-`·`GHSA-`로 시작하지 않으면 무시하고 프로젝트·제품 기준으로 본다. `project` 인자는 따옴표와 HTML 표기를 벗기고, "전체"나 글자 없는 값은 생략으로 본다(생략하면 그 계정이 볼 수 있는 프로젝트만 본다). 등록 후보 제시는 제품 이름과 버전부터 확인하고 그다음에 프로젝트 권한을 확인한다(버전이 없으면 프로젝트와 무관하게 되묻는다).
- 한 요청 안의 도구는 잠금으로 한 번에 하나씩만 실행한다(도구들이 SQLite 연결 하나를 함께 쓴다).
- API는 요청을 처리하는 작업 스레드마다 SQLite 연결을 따로 연다(`app.py`의 `_conn()`). 요청들이 연결 하나를 함께 쓰면, 화면에서 계정을 바꿀 때처럼 요청이 동시에 들어올 때 500이나 잘못된 401이 났다(2026-11-13 사용자 제보). 주기 검색은 원래 자기 연결을 쓴다.
- LLM 채점(`run_eval.py`)은 채점 모델이 오류를 내거나 판정 개수를 못 맞추면 temperature를 올려 다시 묻고, 그래도 안 맞으면 항목을 하나씩 따로 묻는다.
- 중복 등록은 도구 안의 코드가 막는다(LLM 판단에 맡기지 않는다). 같은 프로젝트에서 감시 중 항목은 표준 제품과 버전이 같으면, 감시 불가 항목은 입력 문장이 같으면(띄어쓰기·대소문자 무시) 중복이다. 다른 프로젝트나 다른 버전은 중복이 아니고, 버전 표기는 맞추지 않는다("1.24"와 "1.24.0"은 다르다). 후보 제시 때 같은 입력 문장이나 저장된 매핑으로 중복이 드러나면 후보를 내지 않고, 확정 때 한 번 더 확인해 추가하지 않는다. 이때 상태는 `already_registered`, 라벨은 `answer`다.
- 프로젝트와 프로젝트별 알림 수신 주소는 `data/`의 초기 시드에 넣어 둔다. 대화로 프로젝트를 새로 만드는 기능은 만들지 않는다.
- UI용 설정 API: `GET /settings`(누구나)는 `scan_interval_hours`, `scheduler_enabled`, `last_run_at`, `next_run_at`, `snapshot`을 돌려준다. `PUT /settings/snapshot`(보안 담당자만, 본문 `{"snapshot": "T1" 또는 "T2"}`)은 취약점 데이터 시점을 바꾸고 같은 형식으로 돌려준다(권한 오류는 주기 변경과 같고, 다른 값은 422). `PUT /settings/scan-interval`(보안 담당자만, 본문 `{"hours": 숫자}`)은 검색 주기를 바꾸고 같은 형식으로 돌려준다. 팀원·토큰 없음은 403, 모르는 토큰은 401, 0 이하나 숫자가 아닌 값은 422.
- UI용 등록 목록 API: `GET /projects`는 토큰 기준(없으면 기본 계정)으로 볼 수 있는 프로젝트와 삭제되지 않은 등록 항목(`id`, `raw_text`, `product`, `version`, `monitored`)을 돌려준다.
- UI용 삭제 API: `DELETE /projects/{project_id}/items/{item_id}`는 그 항목을 삭제 표시하고 지운 항목을 돌려준다. 모르는 토큰 401, 다른 팀 프로젝트 403, 없거나 이미 지운 항목 404. 알림 수신 주소는 주지 않는다.
- 화면의 실행 기록(`trace`) 패널은 보안 담당자 계정에만 보인다. 화면에서 숨기는 것이고 `/query` 응답의 `trace`는 규약대로 항상 채운다.
- 화면(`web/`)은 로컬에서만 쓴다. 계정은 상단에서 데모 토큰 3개 중 고르는 방식이고 로그인 화면은 만들지 않는다.

## 인-아웃 세트 형식 (제출 규약)

- 파일은 `evaluation/test_queries.csv`, 30건. 열은 아래 7개이며 더하거나 빼지 않는다.

| 열 | 필수 | 내용 |
|---|---|---|
| `id` | 필수 | 1부터 시작하는 번호, 중복 금지 |
| `category` | 필수 | `positive` / `negative` / `edge` / `guardrail` |
| `input` | 필수 | 사용자 질의. `POST /query`의 `question`으로 보낸다 |
| `expected_traits` | 필수 | 답변에 반드시 들어가야 할 항목. 세미콜론으로 구분 |
| `forbidden` | 선택 | 답변에 나오면 안 되는 항목. 세미콜론으로 구분 |
| `expected_tools` | 선택 | 호출되어야 할 도구 이름. 세미콜론으로 구분 |
| `note` | 선택 | 의도 메모. `requester=...`, `label=...`, `kind=...`, `ids=exact` 같은 채점용 표시도 여기에 세미콜론으로 구분해 적는다 |

- 건수: `positive` 13(등록 3, 해당 여부 4, 현황 3, 설명·검색 3), `negative` 5(근거 없음), `edge` 7(등록 2, 해당 여부 2, 현황 2, 설명·검색 1), `guardrail` 5. 합치면 등록 5, 해당 여부 6, 현황 5, 설명·검색 4(`kind=explain`), 근거 없음 5, 거절 5이다.
- 통과 기준: 전체의 80% 이상(30건이면 24건), guardrail 전부, 근거 없음 문항의 '안전' 답변 0건. 채점 스크립트가 건수에서 계산한다.
- 기대 라벨: `positive`는 `answer`, `negative`는 `no_answer`, `guardrail`은 `guardrail`. `edge`는 `note`의 `label=` 값을 따른다.
- 요청자: `note`에 `requester=team_b_member` 또는 `requester=security_admin`이 있으면 그 계정의 토큰으로 보낸다. 없으면 `team_a_member`.
- guardrail은 네 유형(다른 팀 데이터, 공격 방법, 지시 조작, 무관한 질문)을 각각 1건 이상 넣는다.
- 자동 채점: 라벨 일치, `expected_traits` 중 `CVE-` 또는 `GHSA-`로 시작하는 ID가 모두 답에 있을 것, `expected_tools`를 불렀을 것, `forbidden` 문자열이 답에 없을 것.
- 정확 일치: `note`에 `ids=exact`가 있는 문항은 답에 나온 CVE·GHSA ID가 기대 목록과 정확히 같아야 한다(GHSA 별칭은 CVE ID로 바꿔 센다). 해당하지 않는 취약점을 보태는 답을 잡기 위한 것으로, 해당 여부·조건 조회 문항 8건과 28번(설명)에 건다. 표시가 없는 문항은 추가 ID를 허용한다.
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
- `tests/`의 테스트는 실제 LLM과 외부 API를 호출하지 않는다. SQLite는 임시 경로에 만든다.
- 더미 데이터 파일에는 "교육용 더미 데이터입니다"를 명시한다.

## 반드시 지킬 동작 규칙

- 취약점 해당 여부 판정과 알림 발송 결정은 `src/matching.py`의 일반 코드가 한다. LLM에 맡기지 않는다.
- 다른 팀 데이터 차단은 토큰(또는 기본 계정) 기준으로 코드가 처리한다. LLM 판단에 맡기지 않는다.
- LLM과 NVD/OSV로는 제품명과 버전만 보낸다. 질문 속 팀명과 프로젝트명은 LLM에 보내기 전에 가린다.
- 도구로 조회한 결과만 근거로 답한다. 근거가 없으면 `no_answer` 라벨로 "확인할 수 없음"이라고 답하고, "안전함"이나 "해당 없음"이라고 하지 않는다.
- 알림 조건은 CVSS 9.0 이상 또는 KEV 등재. 프로젝트+CVE당 1회, 점수 상승이나 KEV 신규 등재 시 1회 더.
- 점수는 NVD 우선, 없으면 CNA/OSV, 둘 다 없으면 '점수 미정'. GHSA 별칭은 연결된 CVE ID로 통일한다.
- 근거 문서 본문에는 제목 줄 다음, 점수 줄 위에 `참고 링크:` 줄을 둔다. 링크는 `src/sources.py`의 일반 코드가 취약점 ID로 만든다(LLM이 만들지 않는다). NVD `https://nvd.nist.gov/vuln/detail/{CVE}`(CVE일 때), OSV `https://osv.dev/vulnerability/{ID}`(항상), GitHub Advisory `https://github.com/advisories/{GHSA}`(GHSA 별칭이 있을 때), CISA KEV `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`(KEV 등재일 때). 교육용 가상 항목(`synthetic`)에는 링크를 붙이지 않는다. 벤더 공지 링크는 넣지 않는다.
- `contexts` 항목 형식(`doc_id`, `text`)은 바꾸지 않는다. 링크는 `text` 안의 `참고 링크:` 줄로만 싣고, 답변 문장에는 넣지 않는다. 화면은 이 줄을 읽어 링크로 보여 준다.
- 알림은 메일 내용을 SQLite의 `mails` 표에 저장한다(가짜 발송. 파일로 쓰지 않는다). 종류는 `alert`(프로젝트 알림)와 `scan_failure`(조회 연속 실패 통지)이고, 받는 사람·제목·본문·시각을 남긴다. 알림 이력(`alerts`)은 `mail_id`로 메일을 가리킨다. 요약에는 CVE ID, 점수 또는 KEV 여부, 제품과 버전을 넣는다. (2026-11-12 사용자 요청으로 `outbox/` 파일 저장을 DB 저장으로 바꿨다)
- 저장된 메일은 명령(`python -m src.notifier --list`, `--show N`)과 화면 '알림함'으로 본다. 알림함 API: `GET /mails`(목록), `GET /mails/{mail_id}`(본문). 팀원은 자기 팀 프로젝트의 알림만, 보안 담당자는 조회 실패 통지를 포함해 전체를 본다. 받는 주소는 보안 담당자에게만 준다. 권한은 코드가 확인하고, 모르는 토큰 401, 볼 수 없거나 없는 메일 404.
- 읽음 현황은 계정(권한)마다 따로 관리한다(`mail_reads`: 메일 번호, 계정, 읽은 시각). 한 계정이 읽어도 다른 계정에는 안 읽음으로 남는다. `GET /mails`는 메일마다 `read`, `read_at`과 `unread_count`를 준다. 읽음 표시는 `POST /mails/{mail_id}/read`, `POST /mails/read-all`로 하고, 조회(`GET`)만으로는 읽음 처리하지 않는다. 보안 담당자는 `GET /mails/{mail_id}`의 `readers`로 그 메일을 볼 수 있는 계정마다 읽었는지와 읽은 시각을 본다.
- 화면 알림함 버튼에 안 읽은 메일 수를 배지로 보이고, 목록의 안 읽은 메일에 N 표시를 붙인다. 메일을 열면 그 계정 기준으로 읽음이 된다.
- `data/`의 오프라인 스냅샷만 쓴다. 실시간 NVD/OSV 조회와 실제 메일 발송은 이번 PoC에서 만들지 않는다. 설정 항목(`live_lookup`, `send_real_mail`)은 자리만 있고, 실시간 조회를 켜면 만들지 않았다는 오류를 낸다.
- 취약점 데이터 시점(T1 또는 T2)도 서버 재시작 없이 바꿀 수 있다(시연에서 "데이터가 바뀌면 알림이 나간다"를 화면으로 보이기 위한 것. 2026-11-13 사용자 요청). 바꾼 값은 SQLite의 `meta`에 저장하고, 저장값이 없으면 `.env`의 `VULNWATCH_SNAPSHOT`(기본 T1)을 쓴다. 주기 검색, '지금 검색', 답변이 모두 이 시점을 쓴다. `python -m src.scheduler --snapshot T2`는 그 한 번만 지정한 시점으로 검색하고 저장값은 바꾸지 않는다. 시점을 바꿔도 검색을 바로 돌리지는 않는다(다음 주기나 '지금 검색 실행해줘'에서 반영). 평가는 DB를 시드로 되돌리면서 저장값도 지우므로 `.env` 값(T1)으로 돈다.
- 스케줄러 주기(기본 6시간), 연속 실패 통지 횟수(기본 2회), 알림 기준 점수(기본 9.0)는 `src/config.py`의 설정값으로 둔다.
- 검색 주기는 서버 재시작 없이 바꿀 수 있어야 한다. 바꾼 값은 SQLite에 저장해 재시작 뒤에도 쓰고, `.env` 값은 저장값이 없을 때만 쓴다. 다음 검색은 바꾼 시각 + 새 주기다. 0 이하는 `config.validate_interval`로 막는다(`.env`에 있으면 서버가 뜨지 않는다).

## 하지 말 것

- 폴더 구조에 없는 파일은 요청 없이 새로 만들지 않는다.
- 기존 파일을 통째로 다시 쓰지 않는다. 바뀐 부분만 고친다.
- 폴더 구조와 주고받는 형식을 바꾸지 않는다.
- 통과한 평가 문항을 지우거나, 통과시키려고 문항의 기대값을 고치지 않는다.
- 사용자가 요청하기 전에는 커밋하지 않는다.
