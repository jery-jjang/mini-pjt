# 프로젝트 규칙

무엇을 왜 만드는지는 `SERVICE.md`에 있습니다. 이 문서는 어떻게 만드는지만 다룹니다.
상세 인수 기준은 `.ouroboros/seed_bfee3756e9e9.yaml`에 있으며, 그 파일의 `miniprj/` 경로는 이 저장소 루트로 읽습니다.

## 기술 스택

- Python 3.14.8, 로컬 venv. Docker는 쓰지 않는다. (의존성이 3.14에 설치되지 않으면 사용자에게 알리고 멈춘다)
- LangChain, LangGraph
- 모델은 Amazon Bedrock Claude Sonnet 4.5: `us.anthropic.claude-sonnet-4-5-20250929-v1:0`, 리전 `us-east-1`, `langchain-aws`의 `ChatBedrockConverse`
- Agent 생성은 `langchain.agents`의 `create_agent`를 쓴다
- API 서버는 FastAPI, 저장소는 SQLite, 테스트는 pytest
- LangSmith 추적은 끈다

## 폴더 구조 (제출 규약. 바꾸지 않는다)

```
SERVICE.md            무엇을 왜 만드는가
CLAUDE.md             이 문서
README.md             주제, 설계, 핵심 의사결정 2가지
app.py                POST /query 진입점 (FastAPI)
src/agent.py          메인 에이전트 그래프
src/tools.py          도메인 도구 (등록, 조회, 교정, 감시)
src/matching.py       취약점 해당 여부 판정과 알림 대상 판정 (일반 코드, LLM 호출 없음)
src/notifier.py       알림 메일 작성과 저장, 발송 이력
src/scheduler.py      주기 검색과 '지금 1회 실행'
src/sources.py        취약점 정보원 (오프라인 스냅샷, 실시간 NVD/OSV)
src/auth.py           로그인, 토큰, 팀·역할 확인
src/storage.py        SQLite 접근
data/                 취약점 스냅샷(1차·2차 시점), 초기 시드 데이터
evaluation/           test_queries.json, 채점 스크립트 run_eval.py, 평가 리포트
tests/                pytest (가짜 모델 주입, 실제 LLM 호출 없음)
```

- RAG는 쓰지 않으므로 `src/retriever.py`는 만들지 않는다.

## 주고받는 형식 (제출 규약)

- `POST /query`로 받고 본문의 `question` 필드를 읽는다. `question`만 필수다.
- 로그인 토큰은 선택이다(`Authorization` 헤더). 토큰이 없으면 기본 평가 계정(팀 A 팀원)으로 처리한다.
- 답은 아래 키로 돌려준다. 앞의 세 키는 제출 규약이고, 나머지는 자체 채점용이며 항상 채운다.

| 키 | 내용 |
|---|---|
| `answer` | 사용자에게 보여 줄 답변 문장 |
| `contexts` | 답의 근거로 쓴 취약점 레코드 목록(없으면 빈 목록) |
| `trace` | 실행 단계 기록(호출한 도구와 인자) |
| `label` | `answer` / `no_answer` / `guardrail` 중 하나 |
| `cve_ids` | 답에 포함된 CVE ID 목록(CVE가 없으면 원래 ID) |
| `tools_called` | 호출한 도구 이름 목록 |

## 평가셋 형식

- 파일은 `evaluation/test_queries.json`, 25건.
- 필수 칸: `id`, `question`, `type`. `id`는 중복 금지.
- `type` 값과 건수: `register` 5, `applicability` 6, `status` 5, `no_answer` 4, `guardrail` 5.
- 선택 칸: `requester`(`team_a_member` / `team_b_member` / `security_admin`, 비어 있으면 `team_a_member`), `expected_label`, `expected_cve_ids`, `expected_tools`, `forbidden`.
- guardrail은 네 유형(다른 팀 데이터, 공격 방법, 지시 조작, 무관한 질문)을 각각 1건 이상 넣는다.
- 채점: 라벨 일치, 기대 CVE ID 전부 포함(추가 허용), 필수 도구 호출 여부, `forbidden` 문자열이 답에 없을 것.
- 평가 실행 전에 SQLite를 `data/`의 초기 시드로 되돌린다. 문항 하나가 예외를 던져도 멈추지 않고 그 문항만 `error`로 기록한다. 유형별 통과율과 전체 통과율을 출력한다.

## 작업 순서

1. 평가셋(`evaluation/test_queries.json`)과 고정 데이터(`data/`)를 코드보다 먼저 쓴다.
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
- 기본 모드는 `data/`의 오프라인 스냅샷만 쓴다. 실시간 NVD/OSV 조회는 설정으로 켠다.
- 스케줄러 주기(기본 6시간), 연속 실패 통지 횟수(기본 2회), 실제 발송 여부는 설정값으로 둔다.

## 하지 말 것

- 요청하지 않은 파일을 새로 만들지 않는다.
- 기존 파일을 통째로 다시 쓰지 않는다. 바뀐 부분만 고친다.
- 폴더 구조와 주고받는 형식을 바꾸지 않는다.
- 통과한 평가 문항을 지우거나, 통과시키려고 문항의 기대값을 고치지 않는다.
- 사용자가 요청하기 전에는 커밋하지 않는다.
