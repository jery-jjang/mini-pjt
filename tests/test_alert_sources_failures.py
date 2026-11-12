"""점수 출처 대체, 별칭 통일, 조회 실패 재처리, 연속 실패 통지, 요약 실패 대응 테스트."""

from src import notifier, scheduler, sources, storage
from tests.conftest import FakeSummaryLLM


def mails(conn):
    """DB에 저장된 메일(오래된 것부터). 각 메일의 text는 머리글을 붙인 읽는 모양."""
    return [m | {"text": notifier.format_mail(m)} for m in reversed(storage.list_mails(conn))]


def mail_text(conn, project):
    """한 프로젝트 알림 메일의 읽는 모양."""
    return next(m["text"] for m in mails(conn) if m["project"] == project)


def failing_loader():
    """조회 실패를 일부러 일으킨다."""
    raise sources.SourceError("정보원 응답 없음")


def demo_vuln(score, kev=False, other=None):
    """시험용 취약점 한 건 (Nginx 1.24.0에 해당)."""
    return [{
        "id": "CVE-2000-0001", "aliases": ["GHSA-test-test-test"], "description": "Test vulnerability. Details.",
        "scores": {"nvd": score, "other": other, "other_source": "CNA(시험)" if other is not None else None},
        "kev": kev, "affects": [{"product": "nginx", "ranges": [{"introduced": "1.0.0", "fixed": "2.0.0"}]}],
    }]


def test_NVD_점수가_없으면_다른_출처_점수로_알린다(conn, mailbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    text = mail_text(conn, "pay-api")
    assert "CVE-2024-50379 [신규]" in text and "점수: 9.8 (CISA-ADP)" in text


def test_다른_출처_점수만_있어도_기준_이상이면_알린다(conn, mailbox, summary_llm):
    report = scheduler.run_once(conn, llm=summary_llm, loader=lambda: demo_vuln(None, other=9.1))
    assert report["alerts"] == 1
    assert "점수: 9.1 (CNA(시험))" in mails(conn)[0]["text"]


def test_점수가_없으면_알리지_않다가_점수가_생기면_알린다(conn, mailbox, summary_llm):
    assert scheduler.run_once(conn, llm=summary_llm, loader=lambda: demo_vuln(None))["alerts"] == 0
    assert scheduler.run_once(conn, llm=summary_llm, loader=lambda: demo_vuln(9.5))["alerts"] == 1


def test_이미_알린_뒤_점수가_오르면_한_번_더_알린다(conn, mailbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, loader=lambda: demo_vuln(9.1))
    raised = scheduler.run_once(conn, llm=summary_llm, loader=lambda: demo_vuln(9.8))
    assert raised["mails"][0]["vulns"] == [{"id": "CVE-2000-0001", "reason": "score_raised"}]
    assert scheduler.run_once(conn, llm=summary_llm, loader=lambda: demo_vuln(9.8))["alerts"] == 0
    assert scheduler.run_once(conn, llm=summary_llm, loader=lambda: demo_vuln(9.0))["alerts"] == 0  # 내려가면 알리지 않는다


def test_알림과_이력은_CVE_ID로_남는다(conn, mailbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, loader=lambda: demo_vuln(9.5))
    assert [a["vuln_id"] for a in storage.list_alerts(conn, "portal")] == ["CVE-2000-0001"]
    assert "GHSA-test" not in mails(conn)[0]["text"]


def test_조회에_실패하면_다음_실행에서_놓친_알림을_보낸다(conn, mailbox, summary_llm):
    failed = scheduler.run_once(conn, llm=summary_llm, loader=failing_loader)
    assert failed["status"] == "failed" and failed["consecutive_failures"] == 1
    assert mails(conn) == []  # 1회 실패로는 통지하지 않는다
    recovered = scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    assert recovered["status"] == "ok" and recovered["alerts"] == 6
    assert storage.get_meta(conn, scheduler.FAILURES_KEY) == "0"


def test_2회_연속_실패하면_보안_담당자에게_한_번_알린다(conn, mailbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, loader=failing_loader)
    second = scheduler.run_once(conn, llm=summary_llm, loader=failing_loader)
    assert second["consecutive_failures"] == 2 and "failure_notice" in second
    text = mails(conn)[0]["text"]
    assert "To: security@example.com" in text and "2회 연속 실패" in text
    third = scheduler.run_once(conn, llm=summary_llm, loader=failing_loader)
    assert "failure_notice" not in third and len(mails(conn)) == 1  # 같은 장애로 다시 보내지 않는다


def test_실패_사이에_성공이_끼면_연속_횟수를_다시_센다(conn, mailbox, summary_llm):
    scheduler.run_once(conn, llm=summary_llm, loader=failing_loader)
    scheduler.run_once(conn, llm=summary_llm, loader=lambda: [])
    again = scheduler.run_once(conn, llm=summary_llm, loader=failing_loader)
    assert again["consecutive_failures"] == 1 and mails(conn) == []


def test_연속_실패_통지_횟수는_설정으로_바꾼다(conn, mailbox, summary_llm, monkeypatch):
    monkeypatch.setenv("VULNWATCH_FAILURE_NOTICE_THRESHOLD", "3")
    for _ in range(2):
        scheduler.run_once(conn, llm=summary_llm, loader=failing_loader)
    assert mails(conn) == []
    assert "failure_notice" in scheduler.run_once(conn, llm=summary_llm, loader=failing_loader)


def test_요약_모델이_실패해도_알림은_빠지지_않는다(conn, mailbox):
    report = scheduler.run_once(conn, llm=FakeSummaryLLM(fail=True), snapshot="T1")
    assert report["alerts"] == 6 and len(mails(conn)) == 3
    text = mail_text(conn, "pay-api")
    assert "요약: Apache Log4j2 2.0-beta9 through 2.15.0" in text  # 설명문 첫 문장으로 대신한다


def test_알림_기준_점수는_설정으로_바꾼다(conn, mailbox, summary_llm, monkeypatch):
    monkeypatch.setenv("VULNWATCH_ALERT_CVSS_THRESHOLD", "7.0")
    report = scheduler.run_once(conn, llm=summary_llm, snapshot="T1")
    assert report["alerts"] > 6
