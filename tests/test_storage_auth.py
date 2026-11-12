"""저장소 초기화와 접근 통제 테스트."""

import pytest

from src import auth, config, sources, storage
from tests.conftest import ROOT


def test_시드로_초기화하면_프로젝트와_항목이_들어간다(conn):
    assert [p["id"] for p in storage.list_projects(conn)] == ["batch", "pay-api", "portal"]
    assert len(storage.list_items(conn, "pay-api")) == 3
    unconfirmed = [i for i in storage.list_items(conn, "portal") if i["status"] == "unconfirmed"]
    assert [i["raw_text"] for i in unconfirmed] == ["사내 공통 로깅 모듈 2.1"]


def test_다시_초기화하면_추가한_항목이_사라진다(conn):
    storage.add_item(conn, "pay-api", "Nginx 1.24.0", "nginx", "1.24.0", "confirmed")
    assert len(storage.list_items(conn, "pay-api")) == 4
    storage.reset_from_seed(conn, ROOT / "data" / "seed.json")
    assert len(storage.list_items(conn, "pay-api")) == 3


def test_프로젝트는_이름이나_ID로_찾는다(conn):
    assert storage.find_project(conn, "결제 API")["id"] == "pay-api"
    assert storage.find_project(conn, "결제api")["id"] == "pay-api"
    assert storage.find_project(conn, "없는 프로젝트") is None


def test_확정한_매핑은_버전이_달라도_다시_쓴다(conn):
    assert storage.get_mapping(conn, "tomcat 10.1.5") == "tomcat"
    assert storage.get_mapping(conn, "Redis 7.2") is None


def test_대기_후보는_계정마다_하나(conn):
    storage.save_pending(conn, "team_a_member", "portal", "OpenSSL 3.0.6", "3.0.6", [{"product": "openssl"}])
    assert storage.get_pending(conn, "team_a_member")["candidates"] == [{"product": "openssl"}]
    assert storage.get_pending(conn, "team_b_member") is None
    storage.clear_pending(conn, "team_a_member")
    assert storage.get_pending(conn, "team_a_member") is None


def test_토큰이_없으면_기본_계정은_팀A_팀원(conn):
    assert auth.resolve_account(conn, None)["id"] == "team_a_member"
    assert auth.resolve_account(conn, "Bearer demo-token-team-b")["id"] == "team_b_member"
    assert auth.resolve_account(conn, "demo-token-security")["role"] == "security_admin"


def test_모르는_토큰은_거부한다(conn):
    with pytest.raises(auth.AuthError):
        auth.resolve_account(conn, "Bearer wrong")


def test_팀원은_자기_팀만_보안_담당자는_전체(conn):
    team_a = storage.get_account(conn, "team_a_member")
    team_b = storage.get_account(conn, "team_b_member")
    admin = storage.get_account(conn, "security_admin")
    batch = storage.find_project(conn, "배치 서버")
    assert not auth.can_access(team_a, batch)
    assert auth.can_access(team_b, batch)
    assert auth.can_access(admin, batch)
    assert {p["id"] for p in auth.accessible_projects(conn, team_a)} == {"pay-api", "portal"}
    assert {p["id"] for p in auth.accessible_projects(conn, team_b)} == {"batch"}
    assert len(auth.accessible_projects(conn, admin)) == 3


def test_스냅샷은_두_시점_모두_20건(vulns_t1, vulns_t2):
    assert len(vulns_t1) == len(vulns_t2) == 20


def test_없는_스냅샷은_조회_실패로_알린다(tmp_path):
    with pytest.raises(sources.SourceError):
        sources.load_snapshot("T1", tmp_path)


def test_LangSmith_추적은_항상_꺼진다():
    import os
    config.get_settings()
    assert os.environ["LANGSMITH_TRACING"] == "false"
