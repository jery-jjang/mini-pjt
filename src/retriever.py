"""RAG 파이프라인. 취약점 설명문을 키워드(BM25)로 검색한다. 외부 호출은 없다."""

import re

from rank_bm25 import BM25Okapi

from src import matching

ID_PATTERN = re.compile(r"(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})", re.IGNORECASE)


def _tokenize(text: str) -> list[str]:
    """소문자로 바꾸고 영문·숫자 덩어리와 한글 덩어리로 나눈다."""
    return re.findall(r"[a-z0-9]+|[가-힣]+", text.lower())


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
    """취약점 스냅샷에서 관련 설명문을 찾아 {doc_id, text} 목록으로 돌려준다."""

    def __init__(self, vulns: list[dict]):
        self.vulns = vulns
        self.docs = [{"doc_id": v["id"], "text": _doc_text(v)} for v in vulns]
        self.index = BM25Okapi([_tokenize(d["text"]) for d in self.docs])

    def search(self, query: str, k: int = 3) -> list[dict]:
        """질문과 관련 있는 문서를 최대 k건 돌려준다.

        질문에 CVE·GHSA ID가 있으면 그 문서를 맨 앞에 둔다. 관련 문서가 없으면 빈 목록.
        """
        picked: list[dict] = []
        for found in ID_PATTERN.findall(query):
            vuln = matching.resolve_id(self.vulns, found)
            if vuln:
                self._add(picked, vuln["id"])
        scores = self.index.get_scores(_tokenize(query))
        ranked = sorted(range(len(self.docs)), key=lambda i: scores[i], reverse=True)
        for i in ranked:
            if len(picked) >= k:
                break
            if scores[i] > 0:
                self._add(picked, self.docs[i]["doc_id"])
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
