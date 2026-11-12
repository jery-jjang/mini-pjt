"""RAGAS 평가 스크립트. run_eval.py가 저장한 응답(var/eval_roundN.json)으로 네 지표를 낸다.

사용법:
    .venv\\Scripts\\python evaluation/run_ragas.py --round 2            (실제 Bedrock 호출)
    .venv\\Scripts\\python evaluation/run_ragas.py --round 2 --dry-run  (모델을 부르지 않고 평가 대상만 확인)

- 대상: 근거 문서(contexts)가 있는 답변형 문항. 거절과 근거 없음 문항은 문서 검색을 하지 않으므로 뺀다.
- 정답(reference)은 인-아웃 세트의 기대 항목과 취약점 스냅샷의 설명문으로 코드가 만든다.
- 평가 모델에 보내는 질문과 답변에서도 프로젝트명과 팀명을 가린다.
- 결과는 evaluation/roundN_report.md의 'RAGAS 평가' 절에 쓴다.
"""

import argparse
import json
import math
import os
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("VULNWATCH_SNAPSHOT", "T1")

from src import agent, matching, sources, storage  # noqa: E402
from src.config import get_settings  # noqa: E402

METRICS = ["context_recall", "context_precision", "faithfulness", "answer_relevancy"]
SECTION = "## RAGAS 평가"


def split(cell: str) -> list[str]:
    """세미콜론으로 구분한 칸을 목록으로 바꾼다."""
    return [part.strip() for part in (cell or "").split(";") if part.strip()]


def build_reference(row: dict, vulns: list[dict]) -> str:
    """정답 문장을 만든다: ID가 아닌 기대 항목 + 기대 취약점의 ID와 설명문."""
    lines = []
    for trait in split(row["expected_traits"]):
        vuln = matching.resolve_id(vulns, trait) if trait.upper().startswith(("CVE-", "GHSA-")) else None
        lines.append(f'{vuln["id"]}: {vuln["description"]}' if vuln else trait)
    return "\n".join(lines)


def build_samples(round_no: int) -> list[dict]:
    """저장된 응답에서 RAGAS 평가 대상을 고르고, 이름을 가린 표본을 만든다."""
    settings = get_settings()
    path = settings.db_path.parent / f"eval_round{round_no}.json"
    if not path.exists():
        sys.exit(f"{path.name}이 없습니다. 먼저 evaluation/run_eval.py --round {round_no} 를 실행하세요.")
    results = json.loads(path.read_text(encoding="utf-8"))
    vulns = sources.load_snapshot()
    conn = storage.connect(settings.db_path)
    if not storage.list_projects(conn):
        storage.reset_from_seed(conn, settings.data_dir / "seed.json")
    masker = agent.Masker(conn)

    samples = []
    for row in results:
        res = row["response"]
        if not res or res["label"] != "answer" or row["expected_label"] != "answer" or not res["contexts"]:
            continue
        samples.append({
            "id": row["id"],
            "user_input": masker.mask(row["input"]),
            "response": masker.mask(res["answer"]),
            "retrieved_contexts": [c["text"] for c in res["contexts"]],
            "reference": masker.mask(build_reference(row, vulns)),
        })
    return samples


def load_ragas():
    """ragas를 불러온다.

    ragas 0.4.3은 langchain-community에서 삭제된 Vertex AI 모듈을 종류 확인용으로 불러온다.
    우리는 Bedrock만 쓰므로 그 자리에 빈 클래스를 끼워 넣는다.
    """
    name = "langchain_community.chat_models.vertexai"
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            shim = types.ModuleType(name)
            shim.ChatVertexAI = type("ChatVertexAI", (), {})
            sys.modules[name] = shim
    import ragas
    from ragas.embeddings import LangchainEmbeddingsWrapper
    from ragas.llms import LangchainLLMWrapper
    from ragas.metrics import Faithfulness, LLMContextPrecisionWithReference, LLMContextRecall, ResponseRelevancy
    from ragas.run_config import RunConfig

    return ragas, {
        "llm_wrapper": LangchainLLMWrapper, "embed_wrapper": LangchainEmbeddingsWrapper, "run_config": RunConfig,
        "context_recall": LLMContextRecall, "context_precision": LLMContextPrecisionWithReference,
        "faithfulness": Faithfulness, "answer_relevancy": ResponseRelevancy,
    }


def make_embeddings():
    """답변 관련도(answer_relevancy)에 쓰는 임베딩 모델. 쓸 수 없으면 None."""
    model_id = get_settings().embed_model_id
    try:
        embeddings = agent.make_embedder()  # 문서 검색과 같은 임베딩 모델
        embeddings.embed_query("test")
        return embeddings, model_id
    except Exception as exc:
        print(f"임베딩 모델({model_id})을 쓸 수 없어 answer_relevancy는 건너뜁니다: {type(exc).__name__}")
        return None, model_id


def evaluate(samples: list[dict]) -> tuple[dict, list[dict], str]:
    """네 지표를 계산한다. (평균, 문항별 점수, 임베딩 모델 이름)을 돌려준다."""
    ragas, parts = load_ragas()
    # 문항 하나의 판정 목록이 길어 기본 길이 제한(2000)에서는 출력이 잘린다
    llm = parts["llm_wrapper"](agent.make_llm(max_tokens=8000))
    embeddings, embed_model = make_embeddings()
    names = [m for m in METRICS if m != "answer_relevancy" or embeddings is not None]
    metrics = [parts[m]() for m in names]
    dataset = ragas.EvaluationDataset.from_list([{k: v for k, v in s.items() if k != "id"} for s in samples])
    result = ragas.evaluate(
        dataset, metrics=metrics, llm=llm,
        embeddings=parts["embed_wrapper"](embeddings) if embeddings is not None else None,
        run_config=parts["run_config"](max_workers=2, timeout=180), show_progress=False,
    )
    frame = result.to_pandas()
    columns = {m: next((c for c in frame.columns if m.replace("answer_relevancy", "relevancy") in c
                        or c.replace("llm_", "").startswith(m)), None) for m in names}
    rows, means = [], {}
    for i, sample in enumerate(samples):
        rows.append({"id": sample["id"], **{m: _num(frame[c].iloc[i]) for m, c in columns.items() if c}})
    for m in METRICS:
        values = [r[m] for r in rows if r.get(m) is not None]
        means[m] = round(sum(values) / len(values), 2) if values else None
    return means, rows, embed_model if embeddings is not None else "사용 불가"


def _num(value):
    """NaN은 None으로, 숫자는 소수 둘째 자리로."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(number) else round(number, 2)


def write_section(round_no: int, samples: list[dict], means: dict, rows: list[dict], embed_model: str) -> Path:
    """리포트의 'RAGAS 평가' 절을 새로 쓴다(있으면 바꾼다)."""
    settings = get_settings()
    show = lambda v: "측정 못함" if v is None else f"{v:.2f}"
    lines = [
        SECTION, "",
        f"- 대상: 근거 문서가 있는 답변형 문항 {len(samples)}건 (문항 번호: {', '.join(s['id'] for s in samples)})",
        f"- 평가 모델: `{settings.model_id}`, 임베딩: `{embed_model}`, 라이브러리: ragas",
        "- 정답 문장은 인-아웃 세트의 기대 항목과 취약점 스냅샷의 설명문으로 만들었다.",
        "",
        *[f"- {m}: {show(means[m])}" for m in METRICS],
        "",
        "| # | " + " | ".join(METRICS) + " |",
        "|---|" + "---|" * len(METRICS),
        *[f'| {r["id"]} | ' + " | ".join(show(r.get(m)) for m in METRICS) + " |" for r in rows],
        "",
    ]
    path = ROOT / "evaluation" / f"round{round_no}_report.md"
    text = path.read_text(encoding="utf-8")
    text = re.sub(rf"\n{re.escape(SECTION)}\n.*?(?=\n## |\Z)", "", text, flags=re.DOTALL)
    marker = "\n## 문항별 결과"
    block = "\n" + "\n".join(lines)
    text = text.replace(marker, block + marker, 1) if marker in text else text + block
    path.write_text(text, encoding="utf-8")
    (settings.db_path.parent / f"ragas_round{round_no}.json").write_text(
        json.dumps({"means": means, "rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="RAGAS 평가")
    parser.add_argument("--round", type=int, default=1, help="평가 회차")
    parser.add_argument("--dry-run", action="store_true", help="모델을 부르지 않고 평가 대상만 보여 준다")
    args = parser.parse_args()

    samples = build_samples(args.round)
    print(f"평가 대상 {len(samples)}건: {[s['id'] for s in samples]}")
    if args.dry_run:
        first = samples[0]
        print(f"\n[{first['id']}] 질문: {first['user_input']}\n근거 문서 {len(first['retrieved_contexts'])}건"
              f"\n정답 문장(앞부분): {first['reference'][:300]}")
        load_ragas()
        print("\nragas 불러오기 정상")
        return
    means, rows, embed_model = evaluate(samples)
    for metric in METRICS:
        print(f"{metric}: {means[metric]}")
    print("리포트:", write_section(args.round, samples, means, rows, embed_model))


if __name__ == "__main__":
    main()
