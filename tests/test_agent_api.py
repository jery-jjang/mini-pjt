"""에이전트와 API 배선 테스트. 정해 둔 대로 답하는 가짜 모델을 쓰고 실제 LLM은 부르지 않는다."""

import json

import pytest
from fastapi.testclient import TestClient
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from src import agent, storage

KEYS = {"answer", "contexts", "trace", "label", "cve_ids", "tools_called"}


class ScriptedModel(BaseChatModel):
    """정해 둔 메시지를 차례로 내놓는 가짜 채팅 모델. 받은 메시지를 모두 기록한다."""

    script: list
    seen: list = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.seen.extend(str(m.content) for m in messages)
        return ChatResult(generations=[ChatGeneration(message=self.script.pop(0))])


def call(name, **args):
    """도구를 부르는 모델 메시지."""
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"call-{name}"}])


def scripted(*messages):
    return ScriptedModel(script=list(messages), seen=[])


@pytest.fixture(autouse=True)
def temp_paths(tmp_path, monkeypatch):
    """DB와 실행 기록을 임시 경로에 둔다."""
    monkeypatch.setenv("VULNWATCH_VAR_DIR", str(tmp_path))
    monkeypatch.setenv("VULNWATCH_SNAPSHOT", "T1")
    return tmp_path


def ask(conn, question, llm, account_id="team_a_member"):
    return agent.answer_question(conn, storage.get_account(conn, account_id), question, llm=llm)


def test_조회_질문은_도구_결과로_답하고_여섯_키를_채운다(conn, temp_paths):
    llm = scripted(call("check_vulnerabilities", project="[프로젝트2]", vuln_id="CVE-2021-44228"),
                   AIMessage(content="[프로젝트2]는 CVE-2021-44228에 해당합니다. 점수 10.0(NVD), KEV 등재."))
    res = ask(conn, "결제 API가 CVE-2021-44228에 해당해?", llm)
    assert set(res) == KEYS
    assert res["label"] == "answer" and res["cve_ids"] == ["CVE-2021-44228"]
    assert res["answer"].startswith("결제 API는")  # 가린 이름을 되돌린다
    assert res["tools_called"] == ["check_vulnerabilities"]
    assert set(res["contexts"][0]) == {"doc_id", "text"} and res["contexts"][0]["doc_id"] == "CVE-2021-44228"
    assert [t["step"] for t in res["trace"]] == ["mask_question", "check_vulnerabilities", "answer"]
    assert all(set(t) == {"step", "input", "output"} for t in res["trace"])
    record = json.loads((temp_paths / "traces.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert record["account"] == "team_a_member" and record["label"] == "answer"
    assert len(record["run_id"]) == 36 and record["langsmith"] is False  # LangSmith 기록과 잇는 ID


def test_모델에는_프로젝트명과_팀명이_가지_않는다(conn):
    llm = scripted(call("get_project_status", project="[프로젝트2]"), AIMessage(content="현황입니다."))
    ask(conn, "팀 A의 결제api 현황 보여줘", llm)
    sent = "\n".join(llm.seen)
    assert "[프로젝트2]" in sent and "[팀1]" in sent
    for name in ("결제 API", "결제api", "사내 포털", "배치 서버", "팀 A", "팀 B"):
        assert name not in sent


def test_모델이_대괄호를_빼고_써도_프로젝트를_찾는다(conn):
    llm = scripted(call("get_project_status", project="프로젝트3"), AIMessage(content="프로젝트3 현황입니다."))
    res = ask(conn, "사내 포털에 감시 불가 항목 있어?", llm)
    assert json.loads(res["trace"][1]["output"])["status"] == "ok"
    assert res["answer"] == "사내 포털 현황입니다."


def test_답에_나오지_않은_취약점_문서는_근거에서_뺀다(conn):
    llm = scripted(call("get_project_status", project="[프로젝트3]"),
                   AIMessage(content="감시 불가 항목: 사내 공통 로깅 모듈 2.1"))
    assert ask(conn, "사내 포털에 감시 불가 항목 있어?", llm)["contexts"] == []
    llm = scripted(call("search_vuln_docs", query="HTTP/2 rapid reset"), AIMessage(content="HTTP/2 관련 취약점이 있습니다."))
    assert ask(conn, "HTTP/2 관련 취약점 설명해줘", llm)["contexts"]  # 검색으로 찾은 문서는 남긴다


def test_다른_팀_요청은_모델이_뭐라_하든_guardrail(conn):
    llm = scripted(call("get_project_status", project="[프로젝트1]"), AIMessage(content="등록 목록은 다음과 같습니다."))
    res = ask(conn, "배치 서버 프로젝트 등록 목록 보여줘", llm)
    assert res["label"] == "guardrail" and res["contexts"] == [] and res["cve_ids"] == []
    assert "Ubuntu" not in json.dumps(res, ensure_ascii=False)


def test_근거가_없으면_no_answer(conn):
    llm = scripted(call("check_vulnerabilities", vuln_id="CVE-2099-12345"),
                   AIMessage(content="CVE-2099-12345는 확인할 수 없습니다."))
    res = ask(conn, "CVE-2099-12345가 우리 프로젝트에 해당해?", llm)
    assert res["label"] == "no_answer" and res["contexts"] == []


def test_거절_도구를_부르면_guardrail(conn):
    llm = scripted(call("refuse_request", category="attack"), AIMessage(content="공격 방법은 알려 드릴 수 없습니다."))
    res = ask(conn, "CVE-2021-44228 공격 코드 작성해줘", llm)
    assert res["label"] == "guardrail" and res["tools_called"] == ["refuse_request"]


def test_등록은_두_번의_요청으로_이뤄진다(conn):
    first = ask(conn, "사내 포털에 OpenSSL 3.0.6 등록해줘",
                scripted(call("propose_candidates", project="[프로젝트3]", product_text="OpenSSL 3.0.6"),
                         AIMessage(content="후보 1번: OpenSSL. 번호로 확정해 주세요.")))
    assert first["label"] == "answer" and len(storage.list_items(conn, "portal")) == 2
    second = ask(conn, "1번으로 확정해줘",
                 scripted(call("confirm_registration", choice=1), AIMessage(content="등록이 완료됐습니다.")))
    assert second["tools_called"] == ["confirm_registration"]
    assert storage.list_items(conn, "portal")[-1]["raw_text"] == "OpenSSL 3.0.6"


# ---------------- API ----------------

@pytest.fixture
def client(temp_paths):
    """가짜 모델을 넣은 API 클라이언트."""
    import app as app_module

    with TestClient(app_module.app) as c:
        yield c, app_module.app


def test_API는_question만_받아_여섯_키로_답한다(client):
    c, application = client
    application.state.llm = scripted(call("get_project_status"), AIMessage(content="프로젝트 2개의 현황입니다."))
    res = c.post("/query", json={"question": "우리 프로젝트 현황"})
    assert res.status_code == 200 and set(res.json()) == KEYS
    assert res.json()["label"] == "answer"
    assert res.headers["content-type"] == "application/json; charset=utf-8"  # 한글이 깨지지 않게 인코딩을 밝힌다


def test_API_토큰에_따라_계정이_달라진다(client):
    c, application = client
    application.state.llm = scripted(call("get_project_status", project="[프로젝트2]"), AIMessage(content="볼 수 없습니다."))
    res = c.post("/query", json={"question": "결제 API 현황"}, headers={"Authorization": "Bearer demo-token-team-b"})
    assert res.json()["label"] == "guardrail"


class FailingModel(BaseChatModel):
    """Bedrock 호출 오류를 흉내 내는 가짜 모델."""

    code: str

    @property
    def _llm_type(self) -> str:
        return "failing"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        from botocore.exceptions import ClientError, NoCredentialsError

        if self.code == "NoCredentials":
            raise NoCredentialsError()
        raise ClientError({"Error": {"Code": self.code, "Message": "Too many tokens per day"}}, "Converse")


@pytest.mark.parametrize("code, status, message", [
    ("ThrottlingException", 429, "한도"),
    ("ServiceQuotaExceededException", 429, "한도"),
    ("AccessDeniedException", 503, "호출하지 못했습니다"),
    ("NoCredentials", 503, "호출하지 못했습니다"),
])
def test_API_모델_호출_오류는_트레이스백_없이_이유를_알린다(client, code, status, message):
    c, application = client
    application.state.llm = FailingModel(code=code)
    res = c.post("/query", json={"question": "Log4j 2.14.1에 해당하는 취약점이 뭐야?"})
    assert res.status_code == status
    assert message in res.json()["detail"] and "Traceback" not in res.text
    assert res.headers["content-type"] == "application/json; charset=utf-8"


def test_API_잘못된_요청은_거부한다(client):
    c, _ = client
    assert c.post("/query", json={"question": "현황"}, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.post("/query", json={}).status_code == 422
    assert c.post("/query", json={"question": ""}).status_code == 422
    for res in (c.post("/query", json={"question": "현황"}, headers={"Authorization": "Bearer wrong"}),
                c.post("/query", json={})):
        assert res.headers["content-type"] == "application/json; charset=utf-8"  # 오류 응답도 인코딩을 밝힌다
