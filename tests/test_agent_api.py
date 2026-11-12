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


def test_도구가_가리기를_빠뜨려도_미들웨어가_모델에는_가린_글만_보낸다(conn, monkeypatch):
    from src import tools

    # 도구 결과를 가리지 않고 그대로 돌려주는 실수를 흉내 낸다
    outputs = []

    def leaky_record(session, name, args, result):
        outputs.append(json.dumps(result, ensure_ascii=False))
        return outputs[-1]

    monkeypatch.setattr(tools, "_record", leaky_record)
    llm = scripted(call("get_project_status", project="[프로젝트2]"), AIMessage(content="현황입니다."))
    ask(conn, "결제 API 현황 보여줘", llm)
    assert "결제 API" in outputs[0]  # 도구 결과에는 실제 이름이 있었지만
    sent = "\n".join(llm.seen)
    assert "[프로젝트2]" in sent and "결제 API" not in sent  # 모델에는 가린 글만 갔다


class FlakyModel(BaseChatModel):
    """처음 몇 번은 Bedrock 오류를 내고 그다음에는 정해 둔 답을 내는 가짜 모델."""

    code: str
    failures: int
    log: list  # 호출 기록. 재시도 때 모델을 복사해도 같은 목록을 함께 쓴다
    temperature: float | None = None

    @property
    def calls(self) -> int:
        return len(self.log)

    @property
    def _llm_type(self) -> str:
        return "flaky"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        from botocore.exceptions import ClientError

        self.log.append(self.temperature)
        if self.calls <= self.failures:
            raise ClientError({"Error": {"Code": self.code, "Message": "invalid sequence as part of ToolUse"}}, "Converse")
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="CVE-2099-12345는 확인할 수 없습니다."))])


@pytest.fixture
def no_wait(monkeypatch):
    """재시도 사이의 대기를 없앤다."""
    monkeypatch.setattr(agent.time, "sleep", lambda _s: None)


def test_모델_형식_오류는_temperature를_올려_다시_불러_답한다(conn, no_wait):
    llm = FlakyModel(code="ModelErrorException", failures=2, log=[], temperature=0.0)
    res = ask(conn, "CVE-2099-12345가 우리 프로젝트에 해당해?", llm)
    assert "확인할 수 없습니다" in res["answer"]
    assert llm.log == [0.0, 0.7, 0.7]  # 처음은 0, 다시 부를 때만 올린다


@pytest.mark.parametrize("code, failures, calls", [
    ("ModelErrorException", 3, 3),   # 두 번 다시 불러도 실패하면 오류를 그대로 낸다(API는 503)
    ("ThrottlingException", 1, 1),   # 한도 초과는 다시 부르지 않는다(API는 429)
])
def test_재시도_한도와_대상(conn, no_wait, code, failures, calls):
    from botocore.exceptions import ClientError

    llm = FlakyModel(code=code, failures=failures, log=[])
    with pytest.raises(ClientError):
        ask(conn, "CVE-2099-12345가 우리 프로젝트에 해당해?", llm)
    assert llm.calls == calls


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


@pytest.mark.parametrize("token, names", [
    (None, ["결제 API", "사내 포털"]),  # 토큰이 없으면 기본 계정(팀 A 팀원)
    ("demo-token-team-b", ["배치 서버"]),
    ("demo-token-security", ["결제 API", "사내 포털", "배치 서버"]),
])
def test_API_등록_목록은_계정이_볼_수_있는_프로젝트만_준다(client, token, names):
    c, _ = client
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    res = c.get("/projects", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert sorted(p["name"] for p in body["projects"]) == sorted(names)
    assert "alert_email" not in res.text and "@" not in res.text  # 알림 수신 주소는 내주지 않는다
    items = [i for p in body["projects"] for i in p["items"]]
    assert items and all(set(i) == {"id", "raw_text", "product", "version", "monitored"} for i in items)


def test_API_등록_목록은_감시_불가_항목을_표시하고_모르는_토큰은_401(client):
    c, _ = client
    portal = next(p for p in c.get("/projects").json()["projects"] if p["name"] == "사내 포털")
    assert any(not i["monitored"] for i in portal["items"])
    assert c.get("/projects", headers={"Authorization": "Bearer wrong"}).status_code == 401


def _portal_items(c, headers=None):
    return next(p for p in c.get("/projects", headers=headers or {}).json()["projects"] if p["name"] == "사내 포털")["items"]


def test_API_팀원은_자기_팀_SW를_지울_수_있다(client):
    c, _ = client
    nginx = next(i for i in _portal_items(c) if i["product"] == "NGINX")
    res = c.delete(f"/projects/portal/items/{nginx['id']}")  # 토큰 없음 = 팀 A 팀원
    assert res.status_code == 200 and res.json()["removed"]["id"] == nginx["id"] and res.json()["project"] == "사내 포털"
    assert all(i["id"] != nginx["id"] for i in _portal_items(c))  # 목록에서 빠진다
    again = c.delete(f"/projects/portal/items/{nginx['id']}")
    assert again.status_code == 404 and "이미" in again.json()["detail"]


def test_API_다른_팀_SW는_지울_수_없고_보안_담당자는_전체를_지운다(client):
    c, _ = client
    nginx = next(i for i in _portal_items(c) if i["product"] == "NGINX")
    team_b = {"Authorization": "Bearer demo-token-team-b"}
    res = c.delete(f"/projects/portal/items/{nginx['id']}", headers=team_b)
    assert res.status_code == 403 and "다른 팀" in res.json()["detail"]
    assert any(i["id"] == nginx["id"] for i in _portal_items(c))  # 지워지지 않았다
    assert c.delete(f"/projects/portal/items/{nginx['id']}", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.delete("/projects/portal/items/99999").status_code == 404
    assert c.delete(f"/projects/nowhere/items/{nginx['id']}").status_code == 404
    admin = {"Authorization": "Bearer demo-token-security"}
    assert c.delete(f"/projects/portal/items/{nginx['id']}", headers=admin).status_code == 200


def test_화면은_ui에서_열린다(client):
    c, _ = client
    page = c.get("/ui/")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    assert "VulnWatch" in page.text
    assert c.get("/ui/app.js").status_code == 200
    first = c.get("/", follow_redirects=False)
    assert first.status_code in (302, 307) and first.headers["location"] == "/ui/"


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


# ---------------- 알림함 ----------------

def _send_mails(conn):
    """팀 A 프로젝트 알림, 팀 B 프로젝트 알림, 조회 실패 통지를 한 통씩 DB에 저장한다."""
    from src import notifier

    item = {"id": "CVE-2021-44228", "name": "Apache Log4j", "version": "2.14.1", "score": 10.0,
            "score_source": "NVD", "kev": True, "reason": "new", "description": "JNDI lookup issue."}
    projects = {p["id"]: p for p in storage.list_projects(conn)}
    a = notifier.save_alert_mail(conn, projects["pay-api"], [item])
    b = notifier.save_alert_mail(conn, projects["batch"], [item | {"name": "Ubuntu Linux", "version": "22.04"}])
    f = notifier.save_failure_notice(conn, 2, "timeout")
    return a, b, f


def test_API_알림함은_팀원에게_자기_팀_알림만_보여_준다(client):
    c, application = client
    a, b, f = _send_mails(application.state.conn)
    mine = c.get("/mails").json()["mails"]  # 팀 A 팀원
    assert [m["id"] for m in mine] == [a]
    assert mine[0]["project"] == "결제 API" and mine[0]["vuln_ids"] == ["CVE-2021-44228"]
    assert mine[0]["recipient"] is None and mine[0]["body"] is None  # 받는 주소는 주지 않고, 목록에는 본문이 없다
    one = c.get(f"/mails/{a}").json()
    assert "CVE-2021-44228" in one["body"] and "DB에 저장한 알림" in one["body"]
    assert c.get(f"/mails/{b}").status_code == 404  # 다른 팀 알림
    assert c.get(f"/mails/{f}").status_code == 404  # 조회 실패 통지는 보안 담당자만
    assert c.get("/mails", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_API_보안_담당자는_조회_실패_통지까지_모두_본다(client):
    c, application = client
    a, b, f = _send_mails(application.state.conn)
    admin = {"Authorization": "Bearer demo-token-security"}
    mails = c.get("/mails", headers=admin).json()["mails"]
    assert [m["id"] for m in mails] == [f, b, a]  # 최근 것부터
    failure = next(m for m in mails if m["id"] == f)
    assert failure["kind"] == "scan_failure" and failure["project"] is None and "@" in failure["recipient"]
    assert c.get("/mails/9999", headers=admin).status_code == 404


def test_예전_DB에는_알림_이력의_메일_번호_열을_더한다(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, vuln_id TEXT NOT NULL,"
                " reason TEXT NOT NULL, score REAL, kev INTEGER NOT NULL, sent_at TEXT NOT NULL, file TEXT NOT NULL)")
    old.commit()
    old.close()
    conn = storage.connect(path)
    assert "mail_id" in {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}
    storage.add_alert(conn, "pay-api", "CVE-2021-44228", "new", 10.0, True, "2026-11-12T00:00:00", 1)
    assert conn.execute("SELECT mail_id FROM alerts").fetchone()[0] == 1


def test_API_읽음_현황은_계정마다_따로다(client):
    c, application = client
    a, b, f = _send_mails(application.state.conn)
    team_a = {}  # 토큰 없음 = 팀 A 팀원
    admin = {"Authorization": "Bearer demo-token-security"}
    assert c.get("/mails").json()["unread_count"] == 1
    assert c.get("/mails", headers=admin).json()["unread_count"] == 3
    assert c.get(f"/mails/{a}").json()["read"] is False  # 열람(GET)만으로는 읽음이 되지 않는다

    read = c.post(f"/mails/{a}/read", headers=team_a).json()
    assert read["read"] is True and read["read_at"]
    first_time = read["read_at"]
    assert c.post(f"/mails/{a}/read").json()["read_at"] == first_time  # 다시 읽어도 처음 시각 유지
    assert c.get("/mails").json()["unread_count"] == 0
    assert c.get("/mails", headers=admin).json()["unread_count"] == 3  # 팀원이 읽어도 보안 담당자에게는 안 읽음
    assert c.post(f"/mails/{b}/read").status_code == 404  # 다른 팀 메일은 읽음 표시도 못 한다


def test_API_보안_담당자는_메일별로_누가_읽었는지_본다(client):
    c, application = client
    a, b, f = _send_mails(application.state.conn)
    admin = {"Authorization": "Bearer demo-token-security"}
    c.post(f"/mails/{a}/read")  # 팀 A 팀원이 읽음
    readers = {r["account"]: r["read_at"] for r in c.get(f"/mails/{a}", headers=admin).json()["readers"]}
    assert set(readers) == {"team_a_member", "security_admin"}  # 이 메일을 볼 수 있는 계정만
    assert readers["team_a_member"] and readers["security_admin"] is None
    assert [r["account"] for r in c.get(f"/mails/{f}", headers=admin).json()["readers"]] == ["security_admin"]
    assert c.get(f"/mails/{a}").json()["readers"] is None  # 팀원에게는 읽음 현황 목록을 주지 않는다

    done = c.post("/mails/read-all", headers=admin).json()
    assert done["unread_count"] == 0 and all(m["read"] for m in done["mails"])
    assert c.get("/mails", headers={"Authorization": "Bearer demo-token-team-b"}).json()["unread_count"] == 1
