"""주기 검색과 '지금 1회 실행'.

한 번의 검색: 스냅샷 읽기 -> 확정 항목의 해당 취약점 판정 -> 알림 대상 판정 -> 프로젝트별 메일 저장.
알림 여부는 matching.py의 일반 코드가 정한다.

직접 실행(시연용):
    .venv\\Scripts\\python -m src.scheduler --snapshot T2
"""

import argparse
import threading

from src import matching, notifier, sources, storage
from src.config import get_settings

FAILURES_KEY = "consecutive_failures"


def run_once(conn, llm=None, snapshot: str | None = None, loader=None) -> dict:
    """검색을 한 번 실행한다. loader는 취약점 목록을 돌려주는 함수(테스트에서 바꿔 끼운다)."""
    settings = get_settings()
    load = loader or (lambda: sources.load_snapshot(snapshot))
    try:
        vulns = load()
    except sources.SourceError as exc:
        return _on_failure(conn, settings, str(exc))
    storage.set_meta(conn, FAILURES_KEY, 0)  # 성공하면 연속 실패 횟수를 지운다

    names = {p["key"]: p["name"] for p in storage.list_products(conn)}
    report = {"status": "ok", "checked_items": 0, "skipped_unmonitored": 0, "alerts": 0, "mails": []}
    for project in storage.list_projects(conn):
        to_alert: dict[str, dict] = {}
        for item in storage.list_items(conn, project["id"]):
            if item["status"] != "confirmed":
                report["skipped_unmonitored"] += 1  # 매핑이 확정되지 않은 항목은 알림 대상에서 뺀다
                continue
            report["checked_items"] += 1
            for match in matching.match_item(vulns, item["product"], item["version"]):
                storage.save_finding(conn, project["id"], match)
                if match["id"] in to_alert:
                    continue  # 같은 프로젝트의 같은 취약점은 한 번만 알린다
                last = storage.last_alert(conn, project["id"], match["id"])
                reason = matching.alert_reason(match["score"], match["kev"], last, settings.alert_cvss_threshold)
                if reason:
                    to_alert[match["id"]] = {**match, "name": names[item["product"]], "reason": reason}
        if to_alert:
            path = notifier.save_alert_mail(conn, project, list(to_alert.values()), settings.outbox_dir, llm=llm)
            report["alerts"] += len(to_alert)
            report["mails"].append({"project": project["id"], "file": path.name,
                                    "vulns": [{"id": a["id"], "reason": a["reason"]} for a in to_alert.values()]})
    return report


def _on_failure(conn, settings, error: str) -> dict:
    """조회 실패를 세고, 정해 둔 횟수만큼 연속으로 실패하면 보안 담당자에게 알린다."""
    failures = int(storage.get_meta(conn, FAILURES_KEY) or 0) + 1
    storage.set_meta(conn, FAILURES_KEY, failures)
    report = {"status": "failed", "error": error, "consecutive_failures": failures, "alerts": 0, "mails": []}
    if failures == settings.failure_notice_threshold:
        path = notifier.save_failure_notice(conn, failures, error, settings.outbox_dir)
        report["failure_notice"] = path.name
    return report


def start(interval_hours: float | None = None) -> threading.Event:
    """주기 검색을 백그라운드에서 시작한다. 돌려준 Event를 set()하면 멈춘다."""
    settings = get_settings()
    seconds = (interval_hours or settings.scan_interval_hours) * 3600
    stop = threading.Event()

    def loop():
        conn = storage.connect(settings.db_path)  # 요청 처리와 겹치지 않게 연결을 따로 쓴다
        while not stop.wait(seconds):
            try:
                run_once(conn)
            except Exception:  # 한 번의 오류로 주기 검색이 멈추지 않게 한다
                pass
        conn.close()

    threading.Thread(target=loop, name="vulnwatch-scheduler", daemon=True).start()
    return stop


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="취약점 검색을 지금 한 번 실행한다")
    parser.add_argument("--snapshot", help="T1 또는 T2 (생략하면 설정값)")
    args = parser.parse_args()
    connection = storage.connect(get_settings().db_path)
    if not storage.list_projects(connection):
        storage.reset_from_seed(connection, get_settings().data_dir / "seed.json")
    result = run_once(connection, snapshot=args.snapshot)
    print(result)
