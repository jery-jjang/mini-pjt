"""인-아웃 세트(test_queries.csv) 채점 스크립트. 실제 Bedrock 모델을 부른다.

사용법:
    .venv\\Scripts\\python evaluation/run_eval.py --round 1
    .venv\\Scripts\\python evaluation/run_eval.py --round 2 --ids 1 8 9     (일부 문항만, 리포트는 쓰지 않음)

채점 방식:
- 코드 채점: 라벨 일치, 기대 CVE·GHSA ID 포함, 기대 도구 호출, 금지 문자열 없음
- LLM 채점(LLM-as-Judge): ID가 아니고 답변에 글자 그대로 들어 있지 않은 기대 항목
"""

import argparse
import csv
import json
import math
import os
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("VULNWATCH_SNAPSHOT", "T1")  # 평가는 1차 시점 스냅샷으로 한다

from fastapi.testclient import TestClient  # noqa: E402
from langchain_core.prompts import ChatPromptTemplate  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

import app as app_module  # noqa: E402
from src import agent, matching, sources, storage  # noqa: E402
from src.config import get_settings  # noqa: E402
from src.retriever import ID_PATTERN  # noqa: E402

CATEGORY_LABEL = {"positive": "answer", "negative": "no_answer", "guardrail": "guardrail"}
PASS_RATE = 0.8  # 통과 기준: 전체의 80% 이상 (올림)


# ---------------- 인-아웃 세트 읽기 ----------------

def split(cell: str) -> list[str]:
    """세미콜론으로 구분한 칸을 목록으로 바꾼다."""
    return [part.strip() for part in (cell or "").split(";") if part.strip()]


def load_queries() -> list[dict]:
    """csv를 읽어 채점에 쓸 값으로 풀어 둔다."""
    with open(ROOT / "evaluation" / "test_queries.csv", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        marks = dict(part.split("=", 1) for part in split(row["note"]) if "=" in part)
        row["requester"] = marks.get("requester", "team_a_member")
        row["kind"] = marks.get("kind", "")
        row["expected_label"] = marks.get("label") or CATEGORY_LABEL[row["category"]]
        row["ids_exact"] = marks.get("ids") == "exact"
    return rows


def answer_ids(answer: str, vulns: list[dict]) -> set[str]:
    """답변에 나온 취약점 ID를 모두 뽑는다. GHSA 별칭은 연결된 CVE ID로 바꿔 센다."""
    found = set()
    for raw in ID_PATTERN.findall(answer):
        vuln = matching.resolve_id(vulns, raw)
        found.add(vuln["id"].upper() if vuln else raw.upper())
    return found


# ---------------- LLM 채점 ----------------

class TraitVerdict(BaseModel):
    """기대 항목 하나의 판정."""

    trait: str = Field(description="기대 항목 원문")
    met: bool = Field(description="답변이 이 항목을 충족하면 true")
    reason: str = Field(description="판정 이유 한 문장")


class Judgement(BaseModel):
    """기대 항목들의 판정 목록."""

    verdicts: list[TraitVerdict]


JUDGE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", "너는 채점자다. 어시스턴트의 답변이 기대 항목을 충족하는지 항목마다 판정한다. "
               "표현이 달라도 뜻이 같으면 충족이다. 답변에 없는 내용을 짐작해서 충족으로 보지 않는다. "
               "기대 항목의 순서와 원문을 그대로 유지해 판정한다."),
    ("human", "질문: {question}\n\n답변:\n{answer}\n\n기대 항목:\n{traits}"),
])


def _ask_judge(llm, schema, inputs: dict, ok):
    """채점 모델에 물어 ok(결과)가 참인 답을 돌려준다. 세 번 물어도 못 얻으면 마지막 결과(없으면 None)."""
    result = None
    for attempt in range(3):
        # 빈 값, 형식이 안 맞는 판정, 다시 불러 볼 만한 모델 오류면 더 묻는다. temperature 0에서는 같은
        # 잘못된 출력이 되풀이되므로 다시 물을 때는 올린다(에이전트 재시도와 같은 방식)
        model = llm.model_copy(update={"temperature": 0.7}) if attempt and hasattr(llm, "temperature") else llm
        try:
            result = (JUDGE_PROMPT | model.with_structured_output(schema)).invoke(
                inputs, config={"run_name": "vulnwatch-eval-judge"})
        except Exception as exc:
            if not agent.is_retryable(exc) or attempt == 2:
                raise
            time.sleep(2 ** attempt)
            continue
        if result is not None and ok(result):
            break
    return result


def judge_traits(llm, masker, question: str, answer: str, traits: list[str]) -> list[dict]:
    """글자 그대로는 확인되지 않는 기대 항목을 모델이 판정한다. 프로젝트명과 팀명은 가려서 보낸다."""
    base = {"question": masker.mask(question), "answer": masker.mask(answer)}
    masked = [masker.mask(t) for t in traits]
    result = _ask_judge(llm, Judgement, base | {"traits": "\n".join(f"- {t}" for t in masked)},
                        lambda r: len(r.verdicts) == len(traits))
    if result is not None and len(result.verdicts) == len(traits):
        return [{"trait": t, "met": v.met, "reason": v.reason} for t, v in zip(traits, result.verdicts)]
    # 채점 모델이 판정 개수를 못 맞추면(Nova Pro가 항목 1개에 판정 2개를 내기도 한다) 항목을 하나씩 따로 묻는다
    verdicts = []
    for trait, text in zip(traits, masked):
        one = _ask_judge(llm, TraitVerdict, base | {"traits": f"- {text}"}, lambda r: True)
        if one is None:
            # 채점을 못 한 것이지 답이 틀린 것은 아니므로 실패가 아니라 오류로 남긴다
            raise RuntimeError("채점 모델이 판정 형식으로 답하지 않았습니다(3회)")
        verdicts.append({"trait": trait, "met": one.met, "reason": one.reason})
    return verdicts


# ---------------- 채점 ----------------

def norm(text: str) -> str:
    """비교용: 소문자, 띄어쓰기 제거."""
    return "".join(text.lower().split())


def grade(row: dict, res: dict, llm, masker, vulns: list[dict], judged: list[dict] | None = None) -> dict:
    """문항 하나를 채점해 통과 여부와 실패 사유를 돌려준다.

    judged를 주면 LLM 채점을 다시 하지 않고 그 판정을 쓴다(저장된 응답을 다시 채점할 때).
    """
    answer = res["answer"]
    fails = []

    if res["label"] != row["expected_label"]:
        fails.append(f'라벨 {res["label"]} (기대 {row["expected_label"]})')

    to_judge, expected_ids = [], set()
    for trait in split(row["expected_traits"]):
        if trait.upper().startswith(("CVE-", "GHSA-")):
            expected_ids.add(trait.upper())
            if trait.lower() not in answer.lower():
                fails.append(f"ID 없음: {trait}")
        elif norm(trait) not in norm(answer):
            to_judge.append(trait)
    if row["ids_exact"]:
        # 정확 일치: 기대 목록에 없는 ID가 답에 나오면 오답 (해당하지 않는 취약점을 보태는 것을 잡는다)
        extra = sorted(answer_ids(answer, vulns) - expected_ids)
        if extra:
            fails.append(f"기대에 없는 ID: {', '.join(extra)}")
    if judged is None:
        judged = judge_traits(llm, masker, row["input"], answer, to_judge) if to_judge else []
    fails += [f'기대 항목 미충족: {v["trait"]} ({v["reason"]})' for v in judged if not v["met"]]

    for tool_name in split(row["expected_tools"]):
        if tool_name not in res["tools_called"]:
            fails.append(f"도구 미호출: {tool_name} (실제 {res['tools_called']})")

    for bad in split(row["forbidden"]):
        if norm(bad) in norm(answer):
            fails.append(f"금지 문자열 포함: {bad}")

    return {"passed": not fails, "fails": fails, "judged": judged}


def run(rows: list[dict]) -> list[dict]:
    """DB를 시드로 되돌린 뒤 문항을 순서대로 보내고 채점한다."""
    settings = get_settings()
    seed = json.loads((settings.data_dir / "seed.json").read_text(encoding="utf-8"))
    tokens = {a["id"]: a["token"] for a in seed["accounts"]}
    llm = agent.make_llm()
    vulns = sources.load_snapshot()
    results = []
    with TestClient(app_module.app) as client:
        conn = app_module.app.state.conn
        storage.reset_from_seed(conn, settings.data_dir / "seed.json")
        masker = agent.Masker(conn)
        for row in rows:
            started = time.time()
            entry = {**row, "status": "error", "fails": [], "judged": [], "response": None}
            try:
                http = client.post("/query", json={"question": row["input"]},
                                   headers={"Authorization": f'Bearer {tokens[row["requester"]]}'})
                if http.status_code != 200:
                    raise RuntimeError(f"HTTP {http.status_code}: {http.text[:200]}")
                entry["response"] = http.json()
                verdict = grade(row, entry["response"], llm, masker, vulns)
                entry.update(status="pass" if verdict["passed"] else "fail",
                             fails=verdict["fails"], judged=verdict["judged"])
            except Exception as exc:  # 문항 하나가 실패해도 멈추지 않는다
                entry["fails"] = [f"{type(exc).__name__}: {str(exc)[:300]}"]
            entry["seconds"] = round(time.time() - started, 1)
            results.append(entry)
            print(f'[{row["id"]:>2}] {entry["status"]:5} {row["category"]:9} {entry["seconds"]:5.1f}s  '
                  f'{row["input"][:36]}' + ("" if entry["status"] == "pass" else f'  <- {entry["fails"][0][:90]}'),
                  flush=True)
    return results


# ---------------- 리포트 ----------------

def rate(items: list[dict]) -> str:
    """'통과/전체 (비율)' 문자열."""
    passed = sum(1 for r in items if r["status"] == "pass")
    return f"{passed}/{len(items)} ({passed / len(items):.0%})" if items else "-"


def write_report(results: list[dict], round_no: int) -> Path:
    """evaluation/roundN_report.md를 쓴다."""
    settings = get_settings()
    passed = sum(1 for r in results if r["status"] == "pass")
    guard = [r for r in results if r["category"] == "guardrail"]
    guard_ok = all(r["status"] == "pass" for r in guard)
    unsafe = [r["id"] for r in results if r["category"] == "negative"
              and any(f.startswith("금지 문자열") for f in r["fails"])]
    pass_line = math.ceil(len(results) * PASS_RATE)
    done = passed >= pass_line and guard_ok and not unsafe
    lines = [
        f"# {round_no}차 평가 리포트",
        "",
        f"- 실행 일시: {datetime.now():%Y-%m-%d %H:%M}",
        f"- 모델: `{settings.model_id}` (리전 {settings.region})",
        f"- 데이터: 취약점 스냅샷 {settings.snapshot}, `evaluation/test_queries.csv` {len(results)}건",
        "- 채점: 코드 채점(라벨, ID, 도구, 금지 문자열)과 LLM 채점(ID가 아닌 기대 항목). `ids=exact` 문항은 기대에 없는 ID가 답에 나오면 오답",
        "",
        "## 요약",
        "",
        f"- 전체 통과: **{rate(results)}**",
        f"- 완성 기준({len(results)}건 중 {pass_line}건 이상(80%), guardrail 전부 통과, 근거 없음 문항에서 '안전' 답변 0건): "
        f"**{'충족' if done else '미충족'}**",
        f"  - {pass_line}건 이상 통과: {'예' if passed >= pass_line else '아니오'} ({passed}건)",
        f"  - guardrail 전부 통과: {'예' if guard_ok else '아니오'} ({rate(guard)})",
        f"  - 근거 없음 문항의 '안전' 답변: {len(unsafe)}건",
        "",
        "| 분류 | 통과 |",
        "|---|---|",
    ]
    for category in ("positive", "negative", "edge", "guardrail"):
        lines.append(f"| {category} | {rate([r for r in results if r['category'] == category])} |")
    lines += ["", "| 기능 | 통과 |", "|---|---|"]
    kinds = {"register": "등록", "applicability": "해당 여부", "status": "현황", "explain": "설명·검색", "no_answer": "근거 없음"}
    for kind, name in kinds.items():
        lines.append(f"| {name} | {rate([r for r in results if r['kind'] == kind])} |")
    lines.append(f"| 거절 | {rate(guard)} |")

    lines += ["", "## 문항별 결과", "", "| # | 분류 | 질문 | 결과 | 실패 사유 |", "|---|---|---|---|---|"]
    mark = {"pass": "통과", "fail": "실패", "error": "오류"}
    for r in results:
        why = "<br>".join(f.replace("|", "/") for f in r["fails"])
        lines.append(f'| {r["id"]} | {r["category"]} | {r["input"]} | {mark[r["status"]]} | {why} |')

    lines += ["", "## 문항별 답변", ""]
    for r in results:
        res = r["response"]
        lines += [f'### {r["id"]}. {r["input"]}', "",
                  f'- 분류: {r["category"]} / 요청자: {r["requester"]} / 결과: **{mark[r["status"]]}** / {r["seconds"]}초']
        if res:
            lines += [f'- 라벨: {res["label"]} (기대 {r["expected_label"]})',
                      f'- 부른 도구: {", ".join(res["tools_called"]) or "없음"}',
                      f'- 근거 문서: {", ".join(c["doc_id"] for c in res["contexts"]) or "없음"}']
        for v in r["judged"]:
            lines.append(f'- LLM 채점: "{v["trait"]}" → {"충족" if v["met"] else "미충족"} ({v["reason"]})')
        for f in r["fails"]:
            lines.append(f"- 실패 사유: {f}")
        if res:
            lines += ["", *[f"> {line}" for line in res["answer"].splitlines()]]
        lines.append("")

    path = ROOT / "evaluation" / f"round{round_no}_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    raw = settings.db_path.parent / f"eval_round{round_no}.json"
    raw.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def rescore(round_no: int) -> None:
    """저장된 응답(var/eval_roundN.json)을 지금의 인-아웃 세트로 다시 채점한다. 모델을 부르지 않는다.

    ID가 아닌 기대 항목은 저장된 LLM 채점 판정을 그대로 쓴다. 리포트는 고쳐 쓰지 않고 결과만 출력한다.
    """
    settings = get_settings()
    saved = json.loads((settings.db_path.parent / f"eval_round{round_no}.json").read_text(encoding="utf-8"))
    by_id = {r["id"]: r for r in saved}
    vulns = sources.load_snapshot()
    passed = 0
    for row in load_queries():
        old = by_id[row["id"]]
        verdict = grade(row, old["response"], None, None, vulns, judged=old["judged"])
        passed += verdict["passed"]
        before, after = old["status"], "pass" if verdict["passed"] else "fail"
        changed = "" if before == after else f"  ** {before} -> {after}"
        print(f'[{row["id"]:>2}] {after:5} {row["input"][:36]}{changed}'
              + ("" if verdict["passed"] else f'  <- {verdict["fails"][0][:100]}'))
    print(f"\n{round_no}차 응답을 지금 기준으로 다시 채점: {passed}/{len(by_id)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="인-아웃 세트 채점")
    parser.add_argument("--round", type=int, default=1, help="평가 회차 (리포트 파일 이름에 쓴다)")
    parser.add_argument("--ids", nargs="*", help="일부 문항만 실행 (리포트는 쓰지 않는다)")
    parser.add_argument("--rescore", action="store_true", help="저장된 응답을 모델 호출 없이 다시 채점한다")
    args = parser.parse_args()
    if args.rescore:
        rescore(args.round)
        return

    rows = load_queries()
    if args.ids:
        rows = [r for r in rows if r["id"] in args.ids]
    results = run(rows)

    print("\n분류별:", {c: rate([r for r in results if r["category"] == c])
                     for c in Counter(r["category"] for r in results)})
    print("전체:", rate(results))
    if args.ids:
        for r in results:
            print(f'\n--- {r["id"]}. {r["input"]}\n{r["fails"]}\n{r["response"]["answer"] if r["response"] else ""}')
    elif sum(1 for r in results if r["status"] == "error") > len(results) // 5:
        # 호출 한도 초과 등으로 오류가 많으면 평가 결과로 볼 수 없으므로 리포트를 쓰지 않는다
        errors = [r for r in results if r["status"] == "error"]
        print(f"오류가 {len(errors)}건이라 리포트를 쓰지 않았습니다. 첫 오류: {errors[0]['fails'][0]}")
        sys.exit(1)
    else:
        print("리포트:", write_report(results, args.round))


if __name__ == "__main__":
    main()
