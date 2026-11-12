"""RAG 파이프라인. 취약점 설명문을 하이브리드로 검색한다.

1. ID 정확 일치: 질문에 CVE·GHSA ID가 있으면 그 문서를 맨 앞에 둔다.
2. 쿼리 확장: 한글 검색어는 모델이 영어 키워드로 넓힌다(설명문이 영어라서). 실패하면 원래 검색어만 쓴다.
3. 키워드 검색(BM25)과 의미 검색(임베딩 벡터)을 각각 하고, 두 순위를 RRF(순위 역수 합)로 합친다.

모델과 임베딩은 주입받는다. 둘 다 없으면 키워드 검색만 한다(테스트, 오프라인).
외부로 보내는 것은 검색어(프로젝트명·팀명은 이미 가린 글)와 공개 취약점 설명문뿐이다.
"""

import hashlib
import json
import math
import re
from pathlib import Path

from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from rank_bm25 import BM25Okapi

from src import matching

ID_PATTERN = re.compile(r"(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})", re.IGNORECASE)
HANGUL = re.compile(r"[가-힣]")
RRF_K = 60  # RRF 순위 합산 상수 (흔히 쓰는 값)
MIN_SIMILARITY = 0.2  # 의미 검색 결과로 인정할 최소 코사인 유사도 (무관한 질문을 걸러낸다)


def _tokenize(text: str) -> list[str]:
    """소문자로 바꾸고 영문·숫자 덩어리와 한글 덩어리로 나눈다."""
    return re.findall(r"[a-z0-9]+|[가-힣]+", text.lower())


def _index_text(vuln: dict) -> str:
    """검색 색인용 본문: ID, 별칭, 제품, 설명문. 모든 문서에 공통인 한글 항목 이름은 빼 잡음을 줄인다."""
    products = " ".join(t["product"] for t in vuln["affects"])
    return f'{vuln["id"]} {" ".join(vuln["aliases"])} {products} {vuln["description"]}'


# ---------------- 쿼리 확장 ----------------

class Expansion(BaseModel):
    """검색어를 넓힌 영어 키워드."""

    keywords: list[str] = Field(description="영어 보안 용어 키워드 3~8개. 제품명, 취약점 종류, 동작 방식, 영향")


EXPAND_PROMPT = ChatPromptTemplate.from_messages([
    ("system", "너는 취약점 설명문(영어) 검색을 돕는다. 사용자의 검색어를 영어 설명문에 나올 법한 영어 키워드 3~8개로 바꾼다. "
               "제품명, 취약점 종류(예: remote code execution, denial of service, privilege escalation), "
               "동작 방식과 구성 요소를 영어로 적는다. 검색어에 없는 CVE ID를 지어내지 않는다. "
               "[프로젝트1] 같은 표시는 키워드에 넣지 않는다."),
    ("human", "검색어: {query}"),
])


def make_expander(llm):
    """모델로 한글 검색어를 영어 키워드로 넓히는 함수를 만든다(Pydantic 구조화 출력)."""
    chain = EXPAND_PROMPT | llm.with_structured_output(Expansion)

    def expand(query: str) -> list[str]:
        result = chain.invoke({"query": query}, config={"run_name": "vulnwatch-query-expansion"})
        return [k.strip() for k in result.keywords if k.strip()][:8]
    return expand


# ---------------- 의미 검색 (임베딩) ----------------

_EMBED_CACHE: dict[str, list[float]] = {}  # 문서 임베딩: 프로세스 안에서 한 번만 계산한다


def _cosine(a: list[float], b: list[float]) -> float:
    """두 벡터의 코사인 유사도."""
    dot = sum(x * y for x, y in zip(a, b))
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return dot / norm if norm else 0.0


def _embed_key(model: str, text: str) -> str:
    return model + ":" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def embed_documents(embedder, texts: list[str], cache_path=None) -> list[list[float]]:
    """문서 임베딩. 같은 모델·같은 본문은 다시 계산하지 않는다(메모리와 파일 캐시)."""
    model = str(getattr(embedder, "model_id", type(embedder).__name__))
    path = Path(cache_path) if cache_path else None
    if path and path.exists() and not _EMBED_CACHE:
        try:
            _EMBED_CACHE.update(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    keys = [_embed_key(model, t) for t in texts]
    missing = [(k, t) for k, t in zip(keys, texts) if k not in _EMBED_CACHE]
    if missing:
        vectors = embedder.embed_documents([t for _, t in missing])
        _EMBED_CACHE.update({k: v for (k, _), v in zip(missing, vectors)})
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(_EMBED_CACHE), encoding="utf-8")
    return [_EMBED_CACHE[k] for k in keys]


def _range_text(rng: dict) -> str:
    """영향 버전 범위를 글로 적는다."""
    start = f'{rng["introduced"]} 이상'
    if "fixed" in rng:
        return f'{start} {rng["fixed"]} 미만'
    if "last_affected" in rng:
        return f'{start} {rng["last_affected"]} 이하'
    return start


def _doc_text(vuln: dict) -> str:
    """문서 본문: 취약점 레코드 전체(ID, 별칭, 점수와 출처, KEV 여부, 영향 제품과 버전, 설명문).

    답에 쓰이는 점수·KEV·영향 범위가 근거 문서에도 들어 있어야 답과 근거를 대조할 수 있다.
    """
    score, source = matching.effective_score(vuln)
    score_text = f"{score} ({source})" if score is not None else "점수 미정"
    targets = []
    for target in vuln["affects"]:
        spec = ", ".join(target["versions"]) if "versions" in target else ", ".join(
            _range_text(r) for r in target["ranges"])
        targets.append(f'{target["product"]} {spec}')
    title = vuln["id"] + (f' (별칭: {", ".join(vuln["aliases"])})' if vuln["aliases"] else "")
    return "\n".join([
        title,
        f'점수: {score_text} / CISA KEV: {"등재" if vuln["kev"] else "미등재"}',
        f'영향 제품과 버전: {"; ".join(targets)}',
        f'설명: {vuln["description"]}',
    ])


class VulnRetriever:
    """취약점 스냅샷에서 관련 문서를 찾아 {doc_id, text} 목록으로 돌려준다.

    expander: 검색어 -> 영어 키워드 목록을 돌려주는 함수(없으면 확장하지 않음).
    embedder: embed_documents/embed_query를 가진 임베딩 모델(없으면 의미 검색을 하지 않음).
    """

    def __init__(self, vulns: list[dict], expander=None, embedder=None, cache_path=None,
                 min_similarity: float = MIN_SIMILARITY):
        self.vulns = vulns
        self.docs = [{"doc_id": v["id"], "text": _doc_text(v)} for v in vulns]
        self._index_texts = [_index_text(v) for v in vulns]
        self.index = BM25Okapi([_tokenize(t) for t in self._index_texts])
        self.expander = expander
        self.embedder = embedder
        self.cache_path = cache_path
        self.min_similarity = min_similarity
        self.last_search: dict = {}  # 마지막 검색의 과정 기록 (trace에 남긴다)

    def expand(self, query: str) -> list[str]:
        """한글이 든 검색어만 영어 키워드로 넓힌다. 실패하면 빈 목록."""
        if self.expander is None or not HANGUL.search(query):
            return []
        try:
            return self.expander(query)
        except Exception:  # 확장 실패로 검색이 멈추면 안 된다
            return []

    def _keyword_ranking(self, text: str) -> list[int]:
        """BM25 점수가 0보다 큰 문서를 점수 순으로."""
        scores = self.index.get_scores(_tokenize(text))
        return [i for i in sorted(range(len(self.docs)), key=lambda i: scores[i], reverse=True) if scores[i] > 0]

    def _vector_ranking(self, text: str) -> tuple[list[int], dict[int, float]]:
        """최소 유사도를 넘는 문서를 유사도 순으로. 임베딩을 못 쓰면 빈 결과."""
        if self.embedder is None:
            return [], {}
        try:
            doc_vectors = embed_documents(self.embedder, self._index_texts, self.cache_path)
            query_vector = self.embedder.embed_query(text)
        except Exception:  # 임베딩 실패 시 키워드 검색만으로 계속한다
            return [], {}
        sims = {i: _cosine(query_vector, v) for i, v in enumerate(doc_vectors)}
        ranked = [i for i in sorted(sims, key=sims.get, reverse=True) if sims[i] >= self.min_similarity]
        return ranked, sims

    def search(self, query: str, k: int = 3) -> list[dict]:
        """질문과 관련 있는 문서를 최대 k건 돌려준다. 관련 문서가 없으면 빈 목록."""
        picked: list[dict] = []
        for found in ID_PATTERN.findall(query):
            vuln = matching.resolve_id(self.vulns, found)
            if vuln:
                self._add(picked, vuln["id"])

        keywords = self.expand(query)
        text = " ".join([query, *keywords])
        keyword_ranked = self._keyword_ranking(text)
        vector_ranked, sims = self._vector_ranking(text)

        # RRF: 두 순위에서 위에 있을수록 점수가 크다. 한쪽에만 있어도 후보가 된다.
        fused: dict[int, float] = {}
        for ranking in (keyword_ranked, vector_ranked):
            for rank, i in enumerate(ranking):
                fused[i] = fused.get(i, 0.0) + 1.0 / (RRF_K + rank + 1)
        for i in sorted(fused, key=fused.get, reverse=True):
            if len(picked) >= k:
                break
            self._add(picked, self.docs[i]["doc_id"])

        self.last_search = {
            "expanded_keywords": keywords,
            "keyword_hits": [self.docs[i]["doc_id"] for i in keyword_ranked[:5]],
            "vector_hits": [f'{self.docs[i]["doc_id"]}({sims[i]:.2f})' for i in vector_ranked[:5]],
            "method": "hybrid" if self.embedder is not None else "keyword",
        }
        return picked[:k]

    def get(self, doc_id: str) -> dict | None:
        """문서 ID로 한 건을 꺼낸다."""
        for doc in self.docs:
            if doc["doc_id"] == doc_id:
                return dict(doc)
        return None

    def _add(self, picked: list[dict], doc_id: str) -> None:
        """중복 없이 결과에 담는다."""
        if all(d["doc_id"] != doc_id for d in picked):
            picked.append(self.get(doc_id))
