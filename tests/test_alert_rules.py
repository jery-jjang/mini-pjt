"""알림 규칙 테스트. 두 시점 고정 데이터로 '지금 1회 실행'을 차례로 돌리고 저장된 메일 파일을 확인한다."""

from src import scheduler, storage, tools

T1_EXPECTED = {
    "pay-api": {"CVE-2021-44228", "CVE-2023-44487", "CVE-2024-50379", "CVE-2022-22965"},
    "portal": {"CVE-2023-44487"},
    "batch": {"CVE-2023-4911"},
}


def alerted(report):
    """실행 결과에서 프로젝트별 알림 취약점 ID 집합."""
    return {m["project"]: {v["id"] for v in m["vulns"]} for m in report["mails"]}


def reasons(report, project):
    """실행 결과에서 한 프로젝트의 {취약점 ID: 알림 이유}."""
    return {v["id"]: v["reason"] for m in report["mails"] if m["project"] == project for v in m["vulns"]}


def mails(outbox):
    return sorted(outbox.glob("*.txt")) if outbox.exists() else []


def test_1차_시점_알림은_누락도_초과도_없다(conn, outbox, summary_llm):
    report = scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    assert report["status"] == "ok" and alerted(report) == T1_EXPECTED
    assert report["alerts"] == 6 and len(mails(outbox)) == 3  # 프로젝트마다 한 통
    assert report["checked_items"] == 6 and report["skipped_unmonitored"] == 1


def test_알림_조건에_못_미치는_건은_기록만_한다(conn, outbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    found = {r["vuln_id"] for r in conn.execute("SELECT vuln_id FROM findings WHERE project = 'pay-api'")}
    assert len(found) == 10  # 해당 취약점은 모두 기록
    sent = {a["vuln_id"] for a in storage.list_alerts(conn, "pay-api")}
    assert "CVE-2021-45046" not in sent  # 1차 시점 3.7점, KEV 미등재
    assert "CVE-2025-24813" not in sent  # 1차 시점 점수 미정
    assert "CVE-2023-46589" not in sent  # 7.5점


def test_같은_데이터로_다시_돌리면_중복_알림이_없다(conn, outbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    again = scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    assert again["alerts"] == 0 and again["mails"] == [] and len(mails(outbox)) == 3


def test_2차_시점에는_달라진_건만_알린다(conn, outbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    second = scheduler.run_once(conn, llm=summary_llm, snapshot="T2")
    assert set(alerted(second)) == {"pay-api"} and len(mails(outbox)) == 4
    assert reasons(second, "pay-api") == {
        "CVE-2021-45046": "new",        # 점수 3.7 -> 9.0 으로 올라 처음 알림
        "CVE-2025-24813": "new",        # 점수 미정 -> 9.8 이 부여돼 나중에 알림
        "CVE-2022-22965": "kev_added",  # 이미 알렸지만 KEV에 새로 올라 한 번 더
    }
    third = scheduler.run_once(conn, llm=summary_llm, snapshot="T2")
    assert third["alerts"] == 0 and len(mails(outbox)) == 4  # 재알림도 한 번뿐


def test_프로젝트와_취약점마다_알림_횟수(conn, outbox, summary_llm):
    for snapshot in ("T1", "T1", "T2", "T2"):
        scheduler.run_once(conn, llm=summary_llm, snapshot=snapshot)
    counts = {}
    for project in ("pay-api", "portal", "batch"):
        for a in storage.list_alerts(conn, project):
            counts[(project, a["vuln_id"])] = counts.get((project, a["vuln_id"]), 0) + 1
    assert counts.pop(("pay-api", "CVE-2022-22965")) == 2  # 재알림 1회
    assert set(counts.values()) == {1} and len(counts) == 7


def test_메일에는_ID_점수나_KEV_제품과_버전이_들어간다(conn, outbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    text = next(p for p in mails(outbox) if "pay-api" in p.name).read_text(encoding="utf-8")
    assert "To: pay-api-alerts@example.com" in text and "프로젝트: 결제 API" in text
    assert "CVE-2021-44228 [신규]" in text and "Apache Log4j 2.14.1" in text
    assert "점수: 10.0 (NVD) / KEV: 등재" in text
    assert "CVE-2021-44228 가짜 요약" in text  # LLM 요약이 들어간다


def test_요약_모델에는_프로젝트명과_수신_주소가_가지_않는다(conn, outbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    sent = "\n".join(summary_llm.seen)
    assert "CVE-2021-44228" in sent and "Apache Log4j 2.14.1" in sent
    for secret in ("결제 API", "사내 포털", "배치 서버", "팀 A", "example.com", "pay-api"):
        assert secret not in sent


def test_새로_등록한_항목은_다음_실행에서_알린다(conn, outbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    storage.add_item(conn, "portal", "Log4j 2.14.1", "log4j", "2.14.1", "confirmed")
    report = scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    assert alerted(report) == {"portal": {"CVE-2021-44228"}}


def test_지금_1회_실행_도구는_볼_수_있는_프로젝트만_알려_준다(conn, outbox, summary_llm, vulns_t1):
    session = tools.Session(conn=conn, account=storage.get_account(conn, "team_b_member"),
                            vulns=vulns_t1, llm=summary_llm)
    result = tools.run_scan_now(session)
    assert result["status"] == "ok" and result["saved_mails"] == 1
    assert [m["project"] for m in result["mails"]] == ["배치 서버"]
    assert len(mails(outbox)) == 3  # 검색 자체는 전체 프로젝트를 대상으로 한다
