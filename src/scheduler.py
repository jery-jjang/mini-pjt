"""주기 검색과 '지금 1회 실행'.

한 번의 검색: 스냅샷 읽기(실시간 모드면 NVD에서 새로 받기) -> 확정 항목의 해당 취약점 판정 -> 알림 대상 판정 -> 프로젝트별 메일 저장.
알림 여부는 matching.py의 일반 코드가 정한다.

직접 실행(시연용):
    .venv\\Scripts\\python -m src.scheduler --snapshot T2
"""

import argparse
import threading
import time
from datetime import datetime

from src import matching, notifier, sources, storage
from src.config import get_settings, validate_interval

FAILURES_KEY = "consecutive_failures"
BASELINE_KEY = "live_baseline:{project}:{product}:{version}"  # 실시간 데이터로 처음 검색한 항목 표시
INTERVAL_KEY = "scan_interval_hours"


def run_once(conn, llm=None, snapshot: str | None = None, loader=None, fetch=None) -> dict:
    """검색을 한 번 실행한다. loader는 취약점 목록을 돌려주는 함수(테스트에서 바꿔 끼운다).

    실시간 모드(VULNWATCH_LIVE_LOOKUP=true)에서 snapshot과 loader를 주지 않으면 먼저 NVD에서 새로 받는다.
    fetch는 그때 쓰는 조회 함수(테스트에서 가짜를 넣는다).
    """
    settings = get_settings()
    live = settings.live_lookup and snapshot is None and loader is None
    refresh = None
    try:
        if live:
            refresh = sources.refresh_live(conn, http=fetch)
            vulns = sources.load_live()
        elif loader:
            vulns = loader()
        else:
            # snapshot을 주지 않으면 화면에서 바꿔 저장한 시점(없으면 설정값)을 쓴다
            vulns = sources.load_snapshot(snapshot or sources.current_snapshot(conn))
    except sources.SourceError as exc:
        return _on_failure(conn, settings, str(exc))
    storage.set_meta(conn, FAILURES_KEY, 0)  # 성공하면 연속 실패 횟수를 지운다

    names = {p["key"]: p["name"] for p in storage.list_products(conn)}
    report = {"status": "ok", "checked_items": 0, "skipped_unmonitored": 0, "alerts": 0, "mails": []}
    if live:
        report |= {"refresh": refresh, "baseline": 0}
    now = datetime.now().isoformat(timespec="seconds")
    for project in storage.list_projects(conn):
        to_alert: dict[str, dict] = {}
        for item in storage.list_items(conn, project["id"]):
            if item["status"] != "confirmed":
                report["skipped_unmonitored"] += 1  # 매핑이 확정되지 않은 항목은 알림 대상에서 뺀다
                continue
            report["checked_items"] += 1
            # 실시간 데이터로 처음 검색하는 항목은 기준선만 잡는다: 이미 알려진 취약점을 메일로 쏟아 내지 않고
            # 알림 이력에 baseline으로 남겨, 그 뒤 새로 생기거나 점수·KEV가 바뀐 건만 알리게 한다
            baseline_key = BASELINE_KEY.format(project=project["id"], product=item["product"], version=item["version"])
            first = live and storage.get_meta(conn, baseline_key) is None
            for match in matching.match_item(vulns, item["product"], item["version"]):
                storage.save_finding(conn, project["id"], match)
                if match["id"] in to_alert:
                    continue  # 같은 프로젝트의 같은 취약점은 한 번만 알린다
                last = storage.last_alert(conn, project["id"], match["id"])
                reason = matching.alert_reason(match["score"], match["kev"], last, settings.alert_cvss_threshold)
                if reason and first:
                    storage.add_alert(conn, project["id"], match["id"], "baseline", match["score"], match["kev"], now, None)
                    report["baseline"] += 1
                elif reason:
                    to_alert[match["id"]] = {**match, "name": names[item["product"]], "reason": reason}
            if first:
                storage.set_meta(conn, baseline_key, now)
        if to_alert:
            mail_id = notifier.save_alert_mail(conn, project, list(to_alert.values()), llm=llm)
            report["alerts"] += len(to_alert)
            report["mails"].append({"project": project["id"], "mail_id": mail_id,
                                    "vulns": [{"id": a["id"], "reason": a["reason"]} for a in to_alert.values()]})
    return report


def _on_failure(conn, settings, error: str) -> dict:
    """조회 실패를 세고, 정해 둔 횟수만큼 연속으로 실패하면 보안 담당자에게 알린다."""
    failures = int(storage.get_meta(conn, FAILURES_KEY) or 0) + 1
    storage.set_meta(conn, FAILURES_KEY, failures)
    report = {"status": "failed", "error": error, "consecutive_failures": failures, "alerts": 0, "mails": []}
    if failures == settings.failure_notice_threshold:
        report["failure_notice"] = notifier.save_failure_notice(conn, failures, error)  # 메일 번호
    return report


# ---------------- 검색 주기 ----------------

def load_interval(conn) -> float:
    """저장된 검색 주기(시간). 저장된 값이 없거나 잘못됐으면 설정값(.env, 기본 6시간)을 쓴다."""
    stored = storage.get_meta(conn, INTERVAL_KEY)
    if stored is not None:
        try:
            return validate_interval(stored)
        except ValueError:
            pass
    return get_settings().scan_interval_hours


def save_interval(conn, hours) -> float:
    """검색 주기를 검사해 저장한다. 서버를 다시 띄워도 이 값을 쓴다. 0 이하면 ValueError."""
    value = validate_interval(hours)
    storage.set_meta(conn, INTERVAL_KEY, value)
    return value


def _iso(timestamp: float | None) -> str | None:
    """초 단위 시각을 사람이 읽는 형식으로 바꾼다."""
    return datetime.fromtimestamp(timestamp).isoformat(timespec="seconds") if timestamp else None


class Scheduler:
    """주기 검색을 백그라운드에서 돌린다. 도는 중에도 주기를 바꿀 수 있다.

    주기를 바꾸면 바꾼 시각 + 새 주기에 다음 검색을 한다. 기다리던 중이면 바로 깨어나 다시 계산한다.
    clock과 runner는 테스트에서 시간과 검색 동작을 바꿔 끼우기 위한 것이다.
    """

    def __init__(self, interval_hours: float, db_path=None, clock=time.time, runner=None):
        self._interval = validate_interval(interval_hours)
        self._db_path = db_path or get_settings().db_path
        self._clock = clock
        self._runner = runner or run_once
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_run_at: float | None = None
        self.next_run_at = clock() + self._interval * 3600  # 첫 검색은 한 주기가 지난 뒤

    @property
    def interval_hours(self) -> float:
        return self._interval

    def set_interval(self, hours) -> float:
        """주기를 바꾼다. 다음 검색은 지금부터 새 주기 뒤. 0 이하면 ValueError를 내고 아무것도 바꾸지 않는다."""
        value = validate_interval(hours)
        with self._lock:
            self._interval = value
            self.next_run_at = self._clock() + value * 3600
        self._wake.set()  # 기다리던 스레드를 깨워 새 시각으로 다시 기다리게 한다
        return value

    def status(self) -> dict:
        """현재 주기와 실행 시각."""
        with self._lock:
            return {"scan_interval_hours": self._interval, "scheduler_enabled": True,
                    "last_run_at": _iso(self.last_run_at), "next_run_at": _iso(self.next_run_at)}

    def tick(self, conn) -> bool:
        """다음 검색 시각이 지났으면 한 번 검색한다. 검색했으면 True."""
        with self._lock:
            if self._clock() < self.next_run_at:
                return False
        try:
            self._runner(conn)
        except Exception:  # 한 번의 오류로 주기 검색이 멈추지 않게 한다
            pass
        with self._lock:
            self.last_run_at = self._clock()
            self.next_run_at = self.last_run_at + self._interval * 3600
        return True

    def start(self) -> "Scheduler":
        """백그라운드 스레드를 시작한다."""
        self._thread = threading.Thread(target=self._loop, name="vulnwatch-scheduler", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        """스레드를 멈춘다."""
        self._stop.set()
        self._wake.set()

    def _loop(self) -> None:
        conn = storage.connect(self._db_path)  # 요청 처리와 겹치지 않게 연결을 따로 쓴다
        while not self._stop.is_set():
            if self.tick(conn):
                continue
            with self._lock:
                delay = max(0.0, self.next_run_at - self._clock())
            self._wake.wait(delay)  # 다음 검색 시각까지, 또는 주기가 바뀔 때까지 기다린다
            self._wake.clear()
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="취약점 검색을 지금 한 번 실행한다")
    parser.add_argument("--snapshot", help="T1 또는 T2 (생략하면 설정값)")
    args = parser.parse_args()
    connection = storage.connect(get_settings().db_path)
    if not storage.list_projects(connection):
        storage.reset_from_seed(connection, get_settings().data_dir / "seed.json")
    result = run_once(connection, snapshot=args.snapshot)
    print(result)
