"""검색 주기 설정 테스트: 0 이하 거부, 서버 재시작 없이 즉시 반영, 저장, 설정 API와 권한."""

import threading
import time

import pytest
from fastapi.testclient import TestClient

from src import config, scheduler, storage

ADMIN = {"Authorization": "Bearer demo-token-security"}
TEAM_A = {"Authorization": "Bearer demo-token-team-a"}


class FakeClock:
    """테스트용 시계. advance()로 시간을 앞당긴다."""

    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def advance(self, hours):
        self.now += hours * 3600


# ---------------- 0 이하 예외 처리 ----------------

@pytest.mark.parametrize("bad", [0, -1, "0", "-0.5", "abc", "", None, float("nan"), float("inf")])
def test_0_이하나_숫자가_아닌_주기는_거부한다(bad):
    with pytest.raises(ValueError):
        config.validate_interval(bad)


def test_소수_주기는_받는다():
    assert config.validate_interval("0.5") == 0.5
    assert config.validate_interval(6) == 6.0


@pytest.mark.parametrize("bad", ["0", "-3", "abc"])
def test_env에_잘못된_주기가_있으면_설정_이름을_밝혀_멈춘다(monkeypatch, bad):
    monkeypatch.setenv("VULNWATCH_SCAN_INTERVAL_HOURS", bad)
    with pytest.raises(ValueError, match="VULNWATCH_SCAN_INTERVAL_HOURS"):
        config.get_settings()


# ---------------- 스케줄러 ----------------

def test_한_주기가_지나야_검색하고_다음_시각은_검색_시각_더하기_주기(conn):
    clock, runs = FakeClock(), []
    s = scheduler.Scheduler(6, clock=clock, runner=lambda c: runs.append(clock()))
    clock.advance(5.9)
    assert not s.tick(conn) and runs == []
    clock.advance(0.1)
    assert s.tick(conn) and len(runs) == 1
    assert s.next_run_at == clock() + 6 * 3600


def test_주기를_바꾸면_바꾼_시점부터_새_주기로_계산한다(conn):
    clock, runs = FakeClock(), []
    s = scheduler.Scheduler(6, clock=clock, runner=lambda c: runs.append(clock()))
    clock.advance(2)                      # 6시간 주기로 2시간 지남
    s.set_interval(1)                     # 1시간으로 바꿈 -> 지금부터 1시간 뒤
    assert s.next_run_at == clock() + 3600
    clock.advance(0.99)
    assert not s.tick(conn)
    clock.advance(0.01)
    assert s.tick(conn) and len(runs) == 1


def test_주기를_늘리면_다음_검색도_늦어진다(conn):
    clock = FakeClock()
    s = scheduler.Scheduler(1, clock=clock, runner=lambda c: None)
    clock.advance(0.5)
    s.set_interval(12)
    clock.advance(1)                      # 원래라면 검색할 시각이지만
    assert not s.tick(conn)               # 바꾼 시점 + 12시간 전이라 검색하지 않는다


def test_잘못된_주기로_바꾸려_하면_기존_주기를_유지한다(conn):
    clock = FakeClock()
    s = scheduler.Scheduler(6, clock=clock, runner=lambda c: None)
    before = s.next_run_at
    for bad in (0, -2, "abc"):
        with pytest.raises(ValueError):
            s.set_interval(bad)
    assert s.interval_hours == 6 and s.next_run_at == before


def test_검색_중_오류가_나도_다음_시각을_잡고_계속_돈다(conn):
    clock = FakeClock()

    def broken(c):
        raise RuntimeError("검색 실패")

    s = scheduler.Scheduler(1, clock=clock, runner=broken)
    clock.advance(1)
    assert s.tick(conn) and s.next_run_at == clock() + 3600


def test_도는_중에_주기를_바꾸면_서버_재시작_없이_바로_반영된다(tmp_path):
    ran = threading.Event()
    s = scheduler.Scheduler(1, db_path=tmp_path / "s.db", runner=lambda c: ran.set()).start()
    try:
        time.sleep(0.2)
        assert not ran.is_set()           # 1시간 주기라 아직 검색하지 않았다
        s.set_interval(1 / 3600)          # 1초로 바꾸면
        assert ran.wait(5)                # 기다리던 스레드가 깨어나 곧 검색한다
    finally:
        s.stop()


# ---------------- 저장 ----------------

def test_바꾼_주기는_저장되고_저장값이_없으면_env_값을_쓴다(conn, monkeypatch):
    monkeypatch.setenv("VULNWATCH_SCAN_INTERVAL_HOURS", "3")
    assert scheduler.load_interval(conn) == 3
    scheduler.save_interval(conn, 0.5)
    assert scheduler.load_interval(conn) == 0.5
    with pytest.raises(ValueError):
        scheduler.save_interval(conn, 0)
    assert scheduler.load_interval(conn) == 0.5


def test_저장값이_잘못돼_있으면_env_값으로_돌아간다(conn):
    storage.set_meta(conn, scheduler.INTERVAL_KEY, "-1")
    assert scheduler.load_interval(conn) == config.get_settings().scan_interval_hours


# ---------------- 설정 API ----------------

@pytest.fixture
def api(tmp_path, monkeypatch):
    """임시 DB를 쓰는 API 클라이언트."""
    monkeypatch.setenv("VULNWATCH_VAR_DIR", str(tmp_path))
    import app as app_module

    with TestClient(app_module.app) as c:
        yield c


def test_설정_조회는_누구나_할_수_있다(api):
    body = api.get("/settings").json()
    assert body["scan_interval_hours"] == 6 and body["scheduler_enabled"] is True
    assert body["last_run_at"] is None and body["next_run_at"]


def test_보안_담당자는_주기를_바꾸고_바로_반영된다(api):
    before = api.get("/settings").json()["next_run_at"]
    res = api.put("/settings/scan-interval", json={"hours": 0.5}, headers=ADMIN)
    assert res.status_code == 200
    assert res.json()["scan_interval_hours"] == 0.5
    assert res.json()["next_run_at"] < before          # 6시간 뒤에서 30분 뒤로 당겨졌다
    assert api.get("/settings").json()["scan_interval_hours"] == 0.5


@pytest.mark.parametrize("headers, status", [(TEAM_A, 403), ({}, 403), ({"Authorization": "Bearer wrong"}, 401)])
def test_보안_담당자가_아니면_주기를_바꿀_수_없다(api, headers, status):
    assert api.put("/settings/scan-interval", json={"hours": 1}, headers=headers).status_code == status
    assert api.get("/settings").json()["scan_interval_hours"] == 6


@pytest.mark.parametrize("hours", [0, -1, -0.1, "abc", None])
def test_0_이하나_숫자가_아닌_값은_422로_거부하고_주기를_바꾸지_않는다(api, hours):
    assert api.put("/settings/scan-interval", json={"hours": hours}, headers=ADMIN).status_code == 422
    assert api.get("/settings").json()["scan_interval_hours"] == 6


def test_바꾼_주기는_서버를_다시_띄워도_유지된다(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNWATCH_VAR_DIR", str(tmp_path))
    import app as app_module

    with TestClient(app_module.app) as c:
        c.put("/settings/scan-interval", json={"hours": 2}, headers=ADMIN)
    with TestClient(app_module.app) as c:
        assert c.get("/settings").json()["scan_interval_hours"] == 2


def test_주기_검색을_끈_서버에서도_주기를_저장한다(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNWATCH_VAR_DIR", str(tmp_path))
    monkeypatch.setenv("VULNWATCH_SCHEDULER_ENABLED", "false")
    import app as app_module

    with TestClient(app_module.app) as c:
        res = c.put("/settings/scan-interval", json={"hours": 3}, headers=ADMIN).json()
        assert res == {"scan_interval_hours": 3, "scheduler_enabled": False, "last_run_at": None, "next_run_at": None}
