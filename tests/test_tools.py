"""도구와 문서 검색 테스트. 후보 제시 모델은 가짜로 대신한다."""

import json

import pytest
from langchain_core.runnables import RunnableLambda

from src import storage, tools
from src.retriever import VulnRetriever


class FakeLLM:
    """정해 둔 후보 key를 돌려주는 가짜 모델. 받은 입력을 기록한다."""

    def __init__(self, keys):
        self.keys = keys
        self.seen = []

    def with_structured_output(self, schema):
        def run(prompt_value):
            self.seen.append(prompt_value.to_string())
            return schema(keys=self.keys)
        return RunnableLambda(run)


@pytest.fixture
def session_for(conn, vulns_t1):
    """계정 ID를 받아 그 계정의 세션을 만든다."""
    def make(account_id="team_a_member", llm=None):
        return tools.Session(conn=conn, account=storage.get_account(conn, account_id), vulns=vulns_t1, llm=llm)
    return make


def ids(result):
    return {m["id"] for m in result["matches"]}


# ---------------- 등록 ----------------

def test_등록은_후보_제시_뒤_확정해야_반영된다(session_for, conn):
    llm = FakeLLM(["openssl", "nginx", "없는키"])
    s = session_for(llm=llm)
    result = tools.propose_candidates(s, "사내 포털", "오픈에스에스엘 암호 라이브러리 3.0.6")  # 확정한 매핑이 없는 이름
    assert result["status"] == "candidates" and result["source"] == "모델 제안"
    assert [c["product"] for c in result["candidates"]] == ["openssl", "nginx"]  # 목록에 없는 key는 버린다
    assert len(storage.list_items(conn, "portal")) == 2  # 아직 등록 전

    done = tools.confirm_registration(session_for(), 1)
    assert done["status"] == "registered" and done["item"] == "OpenSSL 3.0.6"
    assert storage.list_items(conn, "portal")[-1]["product"] == "openssl"
    assert storage.get_pending(conn, "team_a_member") is None


def test_후보_제시_모델에는_제품_이름만_간다(session_for):
    llm = FakeLLM(["nginx"])
    tools.propose_candidates(session_for(llm=llm), "결제 API", "엔진엑스 웹서버 1.24.0")
    sent = llm.seen[0]
    assert "엔진엑스 웹서버" in sent
    assert "결제" not in sent and "팀 A" not in sent and "1.24.0" not in sent.split("제품 이름:")[1]


def test_확정했던_매핑은_모델_없이_다시_쓴다(session_for):
    result = tools.propose_candidates(session_for(), "사내 포털", "tomcat 10.1.5")
    assert result["source"] == "이전에 확정한 매핑"
    assert [c["product"] for c in result["candidates"]] == ["tomcat"]


def test_버전이_없으면_되묻는다(session_for, conn):
    result = tools.propose_candidates(session_for(), "결제 API", "톰캣")
    assert result["status"] == "need_version"
    assert storage.get_pending(conn, "team_a_member") is None


def test_후보가_없으면_감시_불가로_등록한다(session_for, conn):
    result = tools.propose_candidates(session_for(llm=FakeLLM([])), "결제 API", "자체 결제 모듈 1.0")
    assert result["status"] == "registered_unmonitored"
    assert storage.list_items(conn, "pay-api")[-1]["status"] == "unconfirmed"


def test_대기_후보가_없으면_확정할_수_없다(session_for):
    assert tools.confirm_registration(session_for("team_b_member"), 2)["status"] == "no_pending"


def test_없는_번호는_확정할_수_없다(session_for):
    tools.propose_candidates(session_for(), "사내 포털", "nginx 1.25.0")
    assert tools.confirm_registration(session_for(), 3)["status"] == "invalid_choice"


def test_다른_팀_프로젝트에는_등록할_수_없다(session_for, conn):
    s = session_for()
    assert tools.propose_candidates(s, "배치 서버", "nginx 1.24.0")["status"] == "denied"
    assert s.denied and storage.get_pending(conn, "team_a_member") is None


# ---------------- 조회 ----------------

def test_프로젝트_단위_조회(session_for):
    s = session_for()
    result = tools.check_vulnerabilities(s, project="결제 API")
    assert result["status"] == "ok" and len(ids(result)) == 10
    assert {"CVE-2021-44228", "CVE-2022-22965", "CVE-2024-50379", "CVE-2023-44487"} <= ids(result)
    assert not {"CVE-2022-22950", "CVE-2023-41080"} & ids(result)
    assert result["matches"][0]["kev"] is True  # KEV 등재가 먼저 온다
    assert {c["doc_id"] for c in s.contexts} == ids(result)


def test_제품과_버전_단위_조회(session_for):
    result = tools.check_vulnerabilities(session_for(), product="Log4j 2.14.1")
    assert ids(result) == {"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"}
    result = tools.check_vulnerabilities(session_for(), product="nginx", version="1.24.0")
    assert "CVE-2022-41741" not in ids(result) and "CVE-2024-7347" in ids(result)


def test_특정_취약점_해당_여부(session_for):
    result = tools.check_vulnerabilities(session_for(), product="OpenSSL 3.0.6", vuln_id="CVE-2022-3602")
    assert ids(result) == {"CVE-2022-3602"}


def test_영향_없음은_범위_근거와_함께_답한다(session_for):
    s = session_for()
    result = tools.check_vulnerabilities(s, product="Spring Framework 5.3.17", vuln_id="CVE-2022-22950")
    assert result["status"] == "not_affected" and not s.no_data
    assert {"introduced": "5.3.0", "fixed": "5.3.17"} in result["affected_ranges"][0]["ranges"]
    assert s.contexts[0]["doc_id"] == "CVE-2022-22950"


def test_GHSA_별칭은_CVE로_통일한다(session_for):
    result = tools.check_vulnerabilities(session_for(), project="결제 API", vuln_id="GHSA-jfh8-c2jp-5v3q")
    assert ids(result) == {"CVE-2021-44228"}


@pytest.mark.parametrize("kwargs, status", [
    ({"vuln_id": "CVE-2099-12345"}, "unknown_vuln"),
    ({"product": "Redis 7.2"}, "unknown_product"),
    ({"product": "사내 공통 로깅 모듈 2.1"}, "unmonitored_item"),
    ({"project": "결제 API", "product": "PostgreSQL"}, "unknown_product"),
    ({"product": "Tomcat 9.0.80", "vuln_id": "CVE-2022-3602"}, "not_listed_product"),
])
def test_근거가_없으면_확인할_수_없음으로_표시한다(session_for, kwargs, status):
    s = session_for()
    assert tools.check_vulnerabilities(s, **kwargs)["status"] == status
    assert s.no_data and not s.contexts


def test_고쳐진_버전은_없음이지만_안전하다고_하지_않는다(session_for):
    s = session_for()
    result = tools.check_vulnerabilities(s, product="Log4j 2.17.1")
    assert result["status"] == "none_found" and "안전" not in result["message"]


def test_다른_팀_프로젝트_조회는_거절하고_데이터를_주지_않는다(session_for):
    for account, project in [("team_a_member", "배치 서버"), ("team_b_member", "결제 API")]:
        s = session_for(account)
        for result in (tools.check_vulnerabilities(s, project=project), tools.get_project_status(s, project=project)):
            assert result["status"] == "denied" and set(result) == {"status", "message"}
        assert s.denied and not s.contexts


# ---------------- 현황 ----------------

def test_현황에는_등록_목록과_감시_불가가_나온다(session_for):
    result = tools.get_project_status(session_for(), "사내 포털")
    portal = result["projects"][0]
    assert {"item": "NGINX 1.24.0", "status": "감시 중"} in portal["items"]
    assert portal["unmonitored"] == ["사내 공통 로깅 모듈 2.1"]


def test_현황에서_점수_미정이_보인다(session_for):
    pay = tools.get_project_status(session_for(), "결제 API")["projects"][0]
    unscored = [v["id"] for v in pay["vulnerabilities"] if v["score"] == "점수 미정"]
    assert unscored == ["CVE-2025-24813"]


def test_전체_현황은_볼_수_있는_프로젝트만(session_for):
    names = lambda account: {p["project"] for p in tools.get_project_status(session_for(account))["projects"]}
    assert names("team_a_member") == {"결제 API", "사내 포털"}
    assert names("team_b_member") == {"배치 서버"}
    assert names("security_admin") == {"결제 API", "사내 포털", "배치 서버"}


# ---------------- 문서 검색 ----------------

def test_ID가_있으면_그_문서가_맨_앞(vulns_t1):
    r = VulnRetriever(vulns_t1)
    assert r.search("ghsa-jfh8-c2jp-5v3q 설명해줘")[0]["doc_id"] == "CVE-2021-44228"
    assert r.search("CVE-2022-3602 buffer overrun")[0]["doc_id"] == "CVE-2022-3602"


def test_근거_문서에는_점수와_KEV와_영향_범위가_들어간다(vulns_t1):
    r = VulnRetriever(vulns_t1)
    text = r.get("CVE-2021-44228")["text"]
    assert "별칭: GHSA-jfh8-c2jp-5v3q" in text
    assert "점수: 10.0 (NVD) / CISA KEV: 등재" in text
    assert "log4j 2.0.1 이상 2.3.1 미만" in text and "2.13.0 이상 2.15.0 미만" in text
    assert "점수: 9.8 (CISA-ADP) / CISA KEV: 미등재" in r.get("CVE-2024-50379")["text"]
    assert "점수: 점수 미정" in r.get("CVE-2025-24813")["text"]
    assert "ubuntu 22.04, 23.04" in r.get("CVE-2023-4911")["text"]


def test_근거_문서에_이번_판정이_덧붙는다(session_for):
    s = session_for()
    tools.check_vulnerabilities(s, product="Log4j 2.14.1")
    assert all("판정: Apache Log4j 2.14.1은 영향 범위에 들어 해당함" in c["text"] for c in s.contexts)
    s = session_for()
    tools.check_vulnerabilities(s, product="Spring Framework 5.3.17", vuln_id="CVE-2022-22950")
    assert "판정: Spring Framework 5.3.17은 영향 범위 밖이라 해당하지 않음" in s.contexts[0]["text"]
    assert "판정:" not in s.retriever.get("CVE-2022-22950")["text"]  # 원본 문서는 바뀌지 않는다


def test_키워드로_관련_문서를_찾는다(vulns_t1):
    r = VulnRetriever(vulns_t1)
    assert "CVE-2023-44487" in [d["doc_id"] for d in r.search("HTTP/2 request cancellation reset streams")]
    assert set(r.search("JNDI LDAP lookup")[0]) == {"doc_id", "text"}
    assert r.search("오늘 날씨") == []


# ---------------- 에이전트용 도구 ----------------

def test_도구_호출은_trace에_남고_프로젝트명은_가려서_돌려준다(session_for):
    s = session_for()
    s.mask = lambda text: text.replace("결제 API", "[프로젝트1]")
    s.unmask = lambda text: text.replace("[프로젝트1]", "결제 API")
    by_name = {t.name: t for t in tools.build_tools(s)}
    assert set(by_name) == {"propose_candidates", "confirm_registration", "check_vulnerabilities",
                            "get_project_status", "search_vuln_docs", "run_scan_now", "refuse_request"}
    out = by_name["check_vulnerabilities"].invoke({"project": "[프로젝트1]"})
    assert "결제 API" not in out and "[프로젝트1]" in out
    assert json.loads(out)["status"] == "ok"
    assert s.trace[0]["step"] == "check_vulnerabilities" and "결제 API" in s.trace[0]["input"]
    assert set(s.trace[0]) == {"step", "input", "output"}
    assert s.tools_called == ["check_vulnerabilities"]
