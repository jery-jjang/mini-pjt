# 미니 PJT: 취약점 감시 Agent (VulnWatch)

> 교육 과정 Mini PJT입니다. 팀, 계정, 프로젝트, 메일 주소는 모두 교육용 더미 데이터이고, 취약점 데이터는 NVD·OSV·CISA KEV 공개 자료의 고정 사본입니다.

## 무엇을 푸나

프로젝트에서 쓰는 OS·미들웨어·라이브러리에 심각한 취약점이 새로 나와도 누가 언제 확인할지 정해져 있지 않아 늦게 알게 되는 문제를, 제품과 버전을 한 번 등록해 두면 해당하는 취약점을 판정해 주고 심각한 것만 프로젝트별로 알려 주는 Agent로 풉니다.

기획 전체는 [SERVICE.md](SERVICE.md)에 있습니다.

## 활용한 패턴 (Day 1~7)

| # | 패턴 | Day | 어떻게 활용했나 |
|---|---|---|---|
| 1 | LCEL chain (Pydantic 구조화 출력) | Day 1 | `프롬프트 \| 모델.with_structured_output(...)` 체인 세 곳: 등록 문장의 식별자 후보 제시(`src/tools.py`), 알림 메일의 취약점 요약(`src/notifier.py`), 평가의 LLM 채점(`evaluation/run_eval.py`) |
| 2 | ReAct (도구 자율 선택) | Day 3 | `create_agent`에 도구 7개를 붙여 모델이 질문에 맞는 도구를 고른다(`src/agent.py`) |
| 3 | RAG | Day 2 | 취약점 레코드 20건(점수, KEV 여부, 영향 버전 범위, 설명문)을 BM25로 검색해 답의 근거로 쓰고 응답의 `contexts`에 싣는다. 질문에 CVE·GHSA ID가 있으면 그 문서를 먼저 준다(`src/retriever.py`) |
| 4 | 도구 다중 | Day 4 | SQLite(등록·현황), 버전 판정 코드, 문서 검색, 검색 실행을 각각 도구로 만들었다(`src/tools.py`) |
| 6 | 가드레일 | Day 5 | 다른 팀 데이터 차단과 '근거 없음' 판정은 코드가 한다. 공격 방법·지시 조작·무관한 질문은 모델이 거절 도구를 불러 기록한다. 모델에 보내는 글에서는 프로젝트명과 팀명을 가린다 |
| 11 | Observability · Trace | Day 7 | 응답의 `trace`와 로컬 파일 `var/traces.jsonl`에 단계별 입력과 출력을 남긴다 |
| 12 | 평가 (RAGAS · LLM-as-Judge) | Day 7 | 인-아웃 세트 25건을 코드 채점(해당 여부 문항은 ID 정확 일치)과 LLM 채점으로 평가하고(`evaluation/run_eval.py`), RAGAS 네 지표를 낸다(`evaluation/run_ragas.py`) |

쓰지 않은 패턴과 이유:

- **5 MCP, 9 Multi-Agent, 10 Plan-Execute·장기 메모리**: 질문 하나에 도구 한두 개로 끝나는 작업이라 필요하지 않았습니다.
- **7 HITL**: LangGraph의 `interrupt()`는 쓰지 않았습니다. 대신 등록은 "후보 제시 → 사람이 번호로 확정"의 두 번 요청으로 나눠, 사람이 확정하기 전에는 반영되지 않게 했습니다.
- **8 미들웨어**: 이름 가리기를 `AgentMiddleware`가 아니라 직접 만든 코드(`Masker`)로 처리했습니다.
- **11의 LangSmith**: 대화 내용이 외부로 나가지 않게 하려고 일부러 껐습니다(`.env`에 값이 있어도 코드에서 끕니다). 추적은 로컬 기록으로 대신합니다.

## 아키텍처

```
사용자 ──POST /query {"question"}──▶ app.py (FastAPI)
                                      │  토큰으로 계정 확인 (src/auth.py). 토큰이 없으면 팀 A 팀원
                                      ▼
                               src/agent.py
                                 1. 프로젝트명·팀명을 [프로젝트1] 같은 표시로 가림
                                 2. create_agent (Bedrock Claude Sonnet 4.5) 가 도구 선택
                                 3. 답변에서 표시를 원래 이름으로 되돌림
                                 4. 라벨을 코드로 결정 (answer / no_answer / guardrail)
                                      │
        ┌──────────────┬──────────────┼───────────────┬──────────────┬─────────────┐
        ▼              ▼              ▼               ▼              ▼             ▼
  propose_candidates  check_         get_project_   search_vuln_   run_scan_now  refuse_
  confirm_registration vulnerabilities status         docs                         request
   (등록 두 단계)     (해당 여부)    (현황)         (문서 검색)    (검색 1회)    (거절 기록)
        │              │              │               │              │
        │              └──── src/matching.py ◀────────┼──────────────┤   버전 범위 비교, 점수 출처,
        │                    (일반 코드, LLM 없음)    │              │   알림 대상 판정
        ▼                                             ▼              ▼
  src/storage.py (SQLite)                   src/retriever.py   src/scheduler.py ──▶ src/notifier.py
  등록 항목, 대기 후보, 알림 이력           (BM25)             (6시간 주기)        메일을 outbox/에 저장
                                                  ▲                  ▲
                                                  └── src/sources.py ┘  data/vulns_t1.json, vulns_t2.json
```

역할 나눔:

- **코드가 하는 일**: 취약점 해당 여부 판정, 알림 발송 결정, 다른 팀 데이터 차단, 응답 라벨 결정.
- **모델이 하는 일**: 질문 의도 파악과 도구 선택, 답변 문장 작성, 등록 문장의 식별자 후보 제시, 알림 메일의 취약점 요약, 정책상 거절할 요청 가려내기.
- **모델에 보내지 않는 것**: 팀명, 프로젝트명, 수신 주소. 제품명·버전과 공개 취약점 정보만 보냅니다.

응답 형식(`POST /query`):

```json
{
  "answer": "근거 기반 응답",
  "contexts": [{"doc_id": "CVE-2021-44228", "text": "..."}],
  "trace": [{"step": "check_vulnerabilities", "input": "...", "output": "..."}],
  "label": "answer | no_answer | guardrail",
  "cve_ids": ["CVE-2021-44228"],
  "tools_called": ["check_vulnerabilities"]
}
```

`answer`, `contexts`, `trace`는 과정의 표준 규약이고, 나머지 세 키는 채점용으로 더한 것입니다.

## 실행 방법

Python 3.14, Windows 기준입니다. Docker는 쓰지 않습니다.

```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

`.env` 파일에 Bedrock 자격 증명을 넣습니다(`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`). 모델은 `global.anthropic.claude-sonnet-4-5-20250929-v1:0`, 리전은 `us-east-1`이며 `VULNWATCH_MODEL_ID`, `VULNWATCH_REGION`으로 바꿀 수 있습니다.

```
.venv\Scripts\python -m uvicorn app:app                    서버 실행 (http://127.0.0.1:8000)
.venv\Scripts\python -m pytest tests -q                    자동 테스트 87건 (실제 LLM 호출 없음)
.venv\Scripts\python evaluation/run_eval.py --round 1      인-아웃 세트 25건 평가 (실제 Bedrock 호출)
.venv\Scripts\python evaluation/run_ragas.py --round 1     RAGAS 지표 (설치 방법은 requirements.txt 아래쪽)
.venv\Scripts\python -m src.scheduler --snapshot T2        검색 1회 실행 (알림 메일은 outbox/에 저장)
```

질문 보내기:

```
curl -X POST http://127.0.0.1:8000/query -H "Content-Type: application/json" -d "{\"question\": \"Log4j 2.14.1에 해당하는 취약점이 뭐야?\"}"
```

계정은 `Authorization` 헤더의 토큰으로 바꿉니다. 헤더가 없으면 팀 A 팀원입니다.

| 계정 | 토큰 | 볼 수 있는 프로젝트 |
|---|---|---|
| 팀 A 팀원 (기본) | `demo-token-team-a` | 결제 API, 사내 포털 |
| 팀 B 팀원 | `demo-token-team-b` | 배치 서버 |
| 보안 담당자 | `demo-token-security` | 전체 |

시연 순서 예: 서버 실행 → 조회 질문 → 등록("사내 포털에 OpenSSL 3.0.6 등록해줘" → "1번으로 확정해줘") → `python -m src.scheduler --snapshot T1` → `--snapshot T2`로 달라진 건만 알림이 나가는지 확인.

## RAGAS 평가 결과

- context_recall: 0.90
- context_precision: 0.70
- faithfulness: 0.77
- answer_relevancy: 0.61

2차 평가의 응답으로 측정했습니다(`evaluation/run_ragas.py`, 문항별 점수는 [evaluation/round2_report.md](evaluation/round2_report.md)). 대상은 근거 문서가 있는 답변형 문항 10건이며, 거절과 근거 없음 문항은 문서 검색을 하지 않아 뺐습니다. 정답 문장은 인-아웃 세트의 기대 항목과 취약점 설명문으로 만들었습니다. 한 번 측정한 결과입니다.

| 지표 | 첫 측정 | 개선 후 |
|---|---|---|
| context_recall | 0.84 | 0.90 |
| context_precision | 0.42 | 0.70 |
| faithfulness | 0.35 | 0.77 |
| answer_relevancy | 0.61 | 0.61 |

첫 측정에서 두 지표가 낮았던 원인과 고친 내용:

- **근거 문서에 답의 근거가 다 들어 있지 않았습니다.** 답변에는 점수, KEV 등재 여부, 해당 여부가 들어가는데 `contexts`에는 취약점 설명문만 실었습니다. 그래서 RAGAS가 그 문장들을 근거 없는 문장으로 셌습니다. `contexts`의 문서를 취약점 레코드 전체(점수와 출처, KEV 여부, 영향 버전 범위, 설명문)로 바꾸고, 그 요청에서 내린 판정("Apache Log4j 2.14.1은 영향 범위에 들어 해당함")을 덧붙였습니다.
- **측정 3건이 빠졌습니다.** 평가 모델의 출력이 길이 제한에 걸려 잘린 탓이라 제한을 늘렸고, 개선 후에는 40개 측정이 모두 나왔습니다. 첫 측정의 평균은 빠진 3건을 제외한 값입니다.

남은 낮은 점수:

- **현황 조회 문항(5, 7번)과 GHSA 별칭 문항(16번)의 context_precision이 0점**입니다. 현황 답변의 근거는 프로젝트의 등록 목록인데 `contexts`에는 취약점 문서만 싣기 때문입니다. 7번은 같은 이유로 context_recall도 0점입니다.
- **answer_relevancy는 그대로**입니다. 프로젝트명을 가린 질문("[프로젝트2] 프로젝트에 해당하는 취약점")과 답변을 비교하는 지표라, 여러 건을 나열하는 답변에서 낮게 나옵니다.

## 인-아웃 세트 통과율 (자체 평가)

- 1차 (Day 9 종료): 22 / 25 통과 ([evaluation/round1_report.md](evaluation/round1_report.md))
- 2차 (Day 10 개선 후): 25 / 25 통과 ([evaluation/round2_report.md](evaluation/round2_report.md))
- 개선폭: +3 건 (주요 개선 사항: 시스템 프롬프트의 도구 선택 규칙과 등록 확정 규칙)

1차에서 틀린 3건(1, 9, 14번)은 모두 모델의 도구 선택 문제였습니다. 시스템 프롬프트를 한 가지씩 고치고, 고칠 때마다 해당 문항과 주변 문항만 다시 돌려 확인한 뒤 25건 전체를 다시 돌렸습니다. 인-아웃 세트의 질문은 바꾸지 않았습니다.

| 분류 | 1차 | 2차 |
|---|---|---|
| positive | 8/10 | 10/10 |
| negative | 3/4 | 4/4 |
| edge | 6/6 | 6/6 |
| guardrail | 5/5 | 5/5 |

완성 기준(25건 중 20건 이상, guardrail 5건 전부, 근거 없음 문항의 "안전" 답변 0건)은 1차와 2차 모두 충족했습니다. 각 회차는 한 번 실행한 결과입니다.

**2차 평가 전에 채점을 더 엄격하게 바꿨습니다.** "기대 ID 외의 추가 ID를 허용하면 해당하지 않는 취약점을 함께 알려 줘도 통과한다"는 피드백을 받아, 해당 여부와 조건 조회 문항 8건(1, 2, 3, 4, 15, 16, 17, 18번)은 답에 나온 CVE·GHSA ID가 기대 목록과 정확히 같아야 통과하게 했습니다. 이를 위해 1번과 3번의 기대 목록을 해당 취약점 전부로 채웠습니다. 저장해 둔 1차 응답을 이 기준으로 다시 채점해도 22/25로 같았으므로, 위 1차 숫자는 두 기준에서 같습니다.

인-아웃 세트와 별도로, 알림 규칙은 두 시점 고정 데이터로 자동 테스트합니다(`tests/test_alert_rules.py`, `tests/test_alert_sources_failures.py`). 알림 누락 0건, 중복 0건, KEV 신규 등재 시 재알림 1회, 점수가 없던 건의 나중 알림, 조회 실패 뒤 재처리, 2회 연속 실패 통지를 확인합니다.

## 트라이앤에러 회고

**시도했지만 실패한 접근 · 왜 실패했는가**

- **모델이 가린 이름을 그대로 돌려줄 것이라 기대함**: 프로젝트명을 `[프로젝트3]`으로 가려 보냈더니 모델이 대괄호를 빼고 `프로젝트3`으로 도구를 불러 프로젝트를 찾지 못했습니다. 대괄호가 없어도 원래 이름으로 되돌리도록 고쳤습니다.
- **모델이 앞선 요청을 기억할 것처럼 등록을 설계함**: 요청마다 대화가 새로 시작되는데, "1번으로 확정해줘"를 받은 모델은 후보를 제시한 적이 없다고 보고 도구를 부르지 않았습니다(1차 9번). 후보는 서버에 저장돼 있으니 번호를 고르면 항상 확정 도구를 부르라고 프롬프트에 적어 해결했습니다.
- **비슷한 결과를 주는 도구 두 개를 구분 없이 둠**: 해당 여부 조회와 현황 조회가 둘 다 프로젝트의 취약점 목록을 돌려줘서, 모델이 질문과 다른 도구를 고르거나(1번) 현황만 보고 스스로 판단해 답했습니다(14번). 14번은 답은 맞았지만 '근거 없음' 판정을 내는 도구를 거치지 않아 라벨이 틀렸습니다.
- **최신 ragas를 그대로 설치하려 함**: 의존 패키지 하나(scikit-network)가 Python 3.14에서 빌드되지 않았고, ragas가 `langchain-community`에서 삭제된 모듈을 불러와 실패했습니다. 그 패키지만 빼고 설치하고, 삭제된 모듈 자리에 빈 클래스를 끼워 넣어 해결했습니다.

**최종 채택한 접근 · 왜 그것으로 갔는가**

- **판정은 코드, 문장은 모델**: 버전 비교와 알림 여부는 틀리면 안 되고 매번 같은 답이 나와야 해서 일반 코드로 만들었습니다. 덕분에 1차 평가에서 판정이 틀린 문항은 없었습니다.
- **라벨도 코드가 결정**: 도구가 접근을 거절했거나 거절 도구가 불렸으면 `guardrail`, 근거 없음 결과만 있으면 `no_answer`로 고정합니다. 모델이 다른 팀 데이터를 "보여 주겠다"고 답해도 실제 데이터는 도구가 주지 않습니다.
- **평가셋과 데이터를 코드보다 먼저 작성**: 등록 버전에는 해당하지 않는 취약점 4건을 일부러 넣어, 무조건 해당한다고 답하는 구현이 통과하지 못하게 했습니다.
- **한 번에 하나씩 고치고 그 문항만 재실행**: 프롬프트를 고칠 때마다 관련 문항과 주변 문항을 같이 돌려 다른 문항이 깨지지 않는지 확인했습니다.

**남은 한계 · 향후 개선 방향**

- 현황 조회 답변의 근거인 프로젝트 등록 목록은 `contexts`에 싣지 않습니다. 그래서 현황 문항의 RAGAS 점수가 낮습니다. 등록 목록에는 프로젝트명이 들어 있어 평가 모델에 보내기 전에 가려야 하므로 이번에는 넣지 않았습니다.
- 라벨이 모델의 도구 선택에 기댑니다. 모델이 도구를 부르지 않고 "확인할 수 없음"이라고 답하면 라벨이 `answer`로 남습니다.
- 취약점 데이터는 고정 사본 20건이고, 실시간 NVD/OSV 조회와 오탐 교정은 만들지 않았습니다. 실제 메일 발송도 하지 않고 파일로 저장합니다.
- CVE가 없는 GHSA 사례는 여섯 제품에서 실제 항목을 찾지 못해 교육용 가상 항목 1건으로 대신했습니다.
- 설명문이 영어라 한글 질문의 키워드 검색이 약합니다. ID가 있는 질문은 잘 찾습니다.
- 요청 사이의 대화를 기억하지 않습니다. 등록 확정만 서버에 저장한 대기 후보로 이어집니다.
- 평가는 한 번 실행한 결과라 모델 응답의 편차가 반영되지 않았습니다.

## 핵심 코드 위치

- `src/agent.py:122` — 메인 에이전트(`answer_question`): 이름 가리기, `create_agent`, 라벨 결정
- `src/agent.py:18` — 시스템 프롬프트
- `src/tools.py:400` — 에이전트용 도구 7개(`build_tools`)
- `src/tools.py:231` — 해당 여부 조회 도구(`check_vulnerabilities`)
- `src/retriever.py:48` — RAG 파이프라인(`VulnRetriever`)
- `src/matching.py:35` — 해당 여부 판정(`is_affected`), `src/matching.py:99` — 알림 판정(`alert_reason`)
- `src/auth.py:23` — 다른 팀 접근 차단(`can_access`)
- `src/scheduler.py:19` — 검색 1회 실행(`run_once`), `src/notifier.py:70` — 알림 메일 저장
- `app.py:49` — `POST /query`
- `evaluation/run_eval.py`, `evaluation/run_ragas.py` — 평가 스크립트
