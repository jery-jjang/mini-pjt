"""RAG 파이프라인. 취약점 설명문을 키워드(BM25)로 검색한다. 외부 호출은 없다."""

import re

from rank_bm25 import BM25Okapi

from src import matching

ID_PATTERN = re.compile(r"(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})", re.IGNORECASE)


def _tokenize(text: str) -> list[str]:
    """소문자로 바꾸고 영문·숫자 덩어리와 한글 덩어리로 나눈다."""
    return re.findall(r"[a-z0-9]+|[가-힣]+", text.lower())


def _doc_text(vuln: dict) -> str:
    """검색 대상 문서 본문: ID, 별칭, 제품, 설명문."""
    products = ", ".join(t["product"] for t in vuln["affects"])
    aliases = " ".join(vuln["aliases"])
    return f'{vuln["id"]} {aliases} [{products}] {vuln["description"]}'.replace("  ", " ")


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
