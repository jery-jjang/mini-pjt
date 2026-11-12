"""하이브리드 문서 검색 테스트: ID 일치, 쿼리 확장, 키워드·의미 검색 합치기, 무관한 질문 거르기.

실제 임베딩·모델 대신 가짜를 쓴다. 가짜 임베딩은 정해 둔 개념 단어가 몇 번 나오는지로 벡터를 만든다.
"""

import pytest
from langchain_core.runnables import RunnableLambda

from src import retriever as R
from src import storage, tools
from src.retriever import VulnRetriever

# 개념 -> 그 개념을 뜻하는 말(영어 설명문과 한글 질문 모두)
CONCEPTS = {
    "denial": ["denial", "마비", "서비스 거부"],
    "http2": ["http/2", "stream", "스트림"],
    "mp4": ["mp4"],
    "logging": ["log4j", "jndi", "로그"],
    "ssh": ["ssh", "sshd"],
    "certificate": ["certificate", "x.509", "인증서"],
}


class FakeEmbedder:
    """개념 단어 빈도로 벡터를 만드는 가짜 임베딩. 호출 횟수를 센다."""

    model_id = "fake-embedder"

    def __init__(self):
        self.doc_calls = 0
        self.query_calls = 0

    def _vec(self, text):
        text = text.lower()
        return [float(sum(text.count(w) for w in words)) for words in CONCEPTS.values()]

    def embed_documents(self, texts):
        self.doc_calls += 1
        return [self._vec(t) for t in texts]

    def embed_query(self, text):
        self.query_calls += 1
        return self._vec(text)


@pytest.fixture(autouse=True)
def clear_cache():
    """테스트마다 문서 임베딩 캐시를 비운다."""
    R._EMBED_CACHE.clear()
    yield
    R._EMBED_CACHE.clear()


def ids(docs):
    return [d["doc_id"] for d in docs]


# ---------------- 하이브리드 ----------------

def test_키워드로_못_찾는_한글_질문을_의미_검색이_찾는다(vulns_t1):
    keyword_only = VulnRetriever(vulns_t1)
    hybrid = VulnRetriever(vulns_t1, embedder=FakeEmbedder())
    query = "스트림을 취소해서 서버를 마비시키는 취약점"
    assert keyword_only.search(query) == []               # 설명문이 영어라 한글 키워드가 안 맞는다
    assert ids(hybrid.search(query))[0] == "CVE-2023-44487"
    assert hybrid.last_search["method"] == "hybrid"
    assert hybrid.last_search["keyword_hits"] == [] and hybrid.last_search["vector_hits"]


def test_두_검색에서_모두_위에_있는_문서가_먼저_온다(vulns_t1):
    r = VulnRetriever(vulns_t1, embedder=FakeEmbedder())
    top = ids(r.search("mp4 module memory"))
    assert set(top[:2]) == {"CVE-2024-7347", "CVE-2022-41741"}


def test_무관한_질문은_의미_검색에서도_걸러진다(vulns_t1):
    r = VulnRetriever(vulns_t1, embedder=FakeEmbedder())
    assert r.search("오늘 서울 날씨 어때?") == []


def test_ID가_있으면_그_문서가_맨_앞(vulns_t1):
    r = VulnRetriever(vulns_t1, embedder=FakeEmbedder())
    assert ids(r.search("CVE-2022-3602 스트림 마비"))[0] == "CVE-2022-3602"


def test_문서_임베딩은_한_번만_계산한다(vulns_t1, tmp_path):
    embedder = FakeEmbedder()
    for _ in range(3):
        VulnRetriever(vulns_t1, embedder=embedder, cache_path=tmp_path / "e.json").search("마비")
    assert embedder.doc_calls == 1 and embedder.query_calls == 3
    R._EMBED_CACHE.clear()                                 # 프로세스를 다시 띄운 것처럼 메모리 캐시를 비워도
    VulnRetriever(vulns_t1, embedder=embedder, cache_path=tmp_path / "e.json").search("마비")
    assert embedder.doc_calls == 1                         # 파일 캐시로 다시 계산하지 않는다


def test_임베딩이_실패하면_키워드_검색만으로_계속한다(vulns_t1):
    class Broken(FakeEmbedder):
        def embed_query(self, text):
            raise RuntimeError("임베딩 실패")

    r = VulnRetriever(vulns_t1, embedder=Broken())
    assert "CVE-2023-44487" in ids(r.search("HTTP/2 request cancellation reset streams"))


# ---------------- 쿼리 확장 ----------------

def test_한글_검색어는_영어_키워드로_넓혀_찾는다(vulns_t1):
    seen = []

    def expander(query):
        seen.append(query)
        return ["HTTP/2", "rapid reset", "stream cancellation", "denial of service"]

    r = VulnRetriever(vulns_t1, expander=expander)        # 의미 검색 없이 키워드 검색만으로도
    assert ids(r.search("요청을 빠르게 취소해서 서버를 멈추게 하는 취약점"))[0] == "CVE-2023-44487"
    assert r.last_search["expanded_keywords"][0] == "HTTP/2"
    assert seen == ["요청을 빠르게 취소해서 서버를 멈추게 하는 취약점"]


def test_영어_검색어는_확장하지_않는다(vulns_t1):
    calls = []
    r = VulnRetriever(vulns_t1, expander=lambda q: calls.append(q) or ["x"])
    r.search("JNDI LDAP lookup")
    assert calls == [] and r.last_search["expanded_keywords"] == []


def test_확장이_실패하면_원래_검색어로_찾는다(vulns_t1):
    def broken(query):
        raise RuntimeError("모델 호출 실패")

    r = VulnRetriever(vulns_t1, expander=broken, embedder=FakeEmbedder())
    assert ids(r.search("스트림 마비"))[0] == "CVE-2023-44487"
    assert r.last_search["expanded_keywords"] == []


def test_쿼리_확장은_구조화_출력으로_키워드를_받는다():
    sent = []

    class FakeLLM:
        def with_structured_output(self, schema):
            def run(prompt_value):
                sent.append(prompt_value.to_string())
                return schema(keywords=["OpenSSH", " sshd ", "", "race condition"])
            return RunnableLambda(run)

    expand = R.make_expander(FakeLLM())
    assert expand("[프로젝트1]의 SSH 서버 취약점") == ["OpenSSH", "sshd", "race condition"]
    assert "[프로젝트1]의 SSH 서버 취약점" in sent[0]   # 가린 검색어 그대로 보낸다


# ---------------- 검색 도구 ----------------

@pytest.fixture
def session(conn, vulns_t1):
    return tools.Session(conn=conn, account=storage.get_account(conn, "team_a_member"), vulns=vulns_t1,
                         embedder=FakeEmbedder())


def test_없는_ID로_검색하면_비슷한_문서를_내놓지_않고_확인할_수_없음(session):
    result = tools.search_vuln_docs(session, "CVE-2099-99999는 어떤 취약점이야?")
    assert result["status"] == "unknown_vuln" and session.no_data and session.contexts == []


def test_ID_일부만_있으면_있는_것으로_찾는다(session):
    result = tools.search_vuln_docs(session, "CVE-2099-99999와 CVE-2021-44228 비교")
    assert result["status"] == "ok" and result["docs"][0]["doc_id"] == "CVE-2021-44228"


def test_찾은_문서가_없으면_확인할_수_없음(session):
    result = tools.search_vuln_docs(session, "오늘 날씨")
    assert result["status"] == "no_docs" and session.no_data


def test_검색_과정이_도구_결과에_남는다(session):
    result = tools.search_vuln_docs(session, "스트림 마비")
    assert result["search"]["method"] == "hybrid"
    assert result["docs"][0]["doc_id"] == "CVE-2023-44487" and "CVE-2023-44487" in session.searched
