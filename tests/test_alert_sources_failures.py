"""점수 출처 대체, 별칭 통일, 조회 실패 재처리, 연속 실패 통지, 요약 실패 대응 테스트."""

import json
import urllib.parse

import pytest

from src import matching, notifier, scheduler, sources, storage
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


# ---------------- 실시간 NVD 갱신 (가짜 조회 함수. 실제 NVD를 부르지 않는다) ----------------

NGINX = "cpe:2.3:a:f5:nginx"


def nvd_cve(cve_id, start="1.0.0", end="2.0.0", score=9.8, kev=None, criteria=NGINX + ":*:*:*:*:*:*:*:*", vulnerable=True):
    """NVD API가 돌려주는 모양의 CVE 한 건."""
    match = {"vulnerable": vulnerable, "criteria": criteria}
    if start:
        match["versionStartIncluding"] = start
    if end:
        match["versionEndExcluding"] = end
    cve = {"id": cve_id, "published": "2026-01-02T03:04:05.000", "lastModified": "2026-02-03T00:00:00.000",
           "descriptions": [{"lang": "es", "value": "Prueba."}, {"lang": "en", "value": f"Test flaw {cve_id}."}],
           "metrics": {}, "configurations": [{"nodes": [{"cpeMatch": [match]}]}]}
    if score is not None:
        cve["metrics"]["cvssMetricV31"] = [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": score}}]
    if kev:
        cve["cisaExploitAdd"] = kev
    return cve


class FakeNVD:
    """제품 식별자별로 정해 둔 CVE를 돌려주는 가짜 NVD. 받은 주소를 기록한다."""

    def __init__(self, by_cpe=None, fail=False):
        self.by_cpe = by_cpe or {}
        self.fail = fail
        self.urls = []

    def __call__(self, url, headers):
        self.urls.append(url)
        if self.fail:
            raise OSError("연결 실패")
        cpe = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["virtualMatchString"][0]
        found = [c for prefix, cves in self.by_cpe.items() if cpe.startswith(prefix + ":") for c in cves]
        return {"resultsPerPage": len(found), "startIndex": 0, "totalResults": len(found),
                "vulnerabilities": [{"cve": c} for c in found]}


@pytest.fixture
def live(conn, tmp_path, monkeypatch):
    """실시간 모드. 받은 데이터는 임시 폴더에 저장하고, 조회 사이의 대기를 없앤다."""
    monkeypatch.setenv("VULNWATCH_LIVE_LOOKUP", "true")
    monkeypatch.setenv("VULNWATCH_VAR_DIR", str(tmp_path))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(sources.time, "sleep", lambda _s: None)
    return conn


def test_NVD_레코드를_고정_사본과_같은_형식으로_바꾼다():
    cve = nvd_cve("CVE-2026-0001", start="1.9.5", end="1.25.3", score=7.5, kev="2026-03-01")
    cve["metrics"]["cvssMetricV31"].append({"source": sources.CISA_ADP_SOURCE, "cvssData": {"baseScore": 8.1}})
    record, unreadable = sources.convert_nvd(cve, "nginx", NGINX)
    assert unreadable == 0 and record["id"] == "CVE-2026-0001" and record["aliases"] == []
    assert record["description"] == "Test flaw CVE-2026-0001." and record["published"] == "2026-01-02"
    assert record["scores"] == {"nvd": 7.5, "other": 8.1, "other_source": "CISA-ADP"}
    assert record["kev"] is True and record["kev_date_added"] == "2026-03-01"
    assert record["affects"] == [{"product": "nginx", "ranges": [{"introduced": "1.9.5", "fixed": "1.25.3"}]}]
    assert matching.is_affected(record, "nginx", "1.24.0") and not matching.is_affected(record, "nginx", "1.25.3")


def test_취약하지_않다고_표시된_항목과_다른_제품은_범위에_넣지_않는다():
    cve = nvd_cve("CVE-2026-0002", vulnerable=False)
    cve["configurations"][0]["nodes"][0]["cpeMatch"] += [
        {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx_plus:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.0"},
        {"vulnerable": True, "criteria": NGINX + ":*:*:*:*:*:*:*:*", "versionEndIncluding": "beta"},  # 읽을 수 없는 표기
    ]
    record, unreadable = sources.convert_nvd(cve, "nginx", NGINX)
    assert record["affects"] == [] and unreadable == 1
    assert not matching.is_affected(record, "nginx", "1.24.0")  # NVD가 후보로 돌려줘도 해당하지 않는다


def test_점수가_없으면_점수_미정이고_버전_하나를_집은_표기는_그_버전만_해당한다():
    cve = nvd_cve("CVE-2026-0003", start=None, end=None, score=None, criteria=NGINX + ":1.24.0:*:*:*:*:*:*:*")
    record, _ = sources.convert_nvd(cve, "nginx", NGINX)
    assert matching.effective_score(record) == (None, "점수 미정")
    assert matching.is_affected(record, "nginx", "1.24.0") and not matching.is_affected(record, "nginx", "1.24.1")


def test_갱신은_등록된_제품과_버전만_보내고_직전_데이터를_남긴다(live, tmp_path):
    nvd = FakeNVD({NGINX: [nvd_cve("CVE-2026-0001", score=5.0)]})
    first = sources.refresh_live(live, http=nvd)
    assert first["count"] == 1 and first["first"] is True and first["queries"] == 6  # 감시 중 항목 6개
    sent = " ".join(urllib.parse.unquote(u) for u in nvd.urls)
    assert "cpe:2.3:a:f5:nginx:1.24.0" in sent
    for secret in ("결제", "포털", "배치", "팀 A", "pay-api", "portal", "batch"):
        assert secret not in sent  # 프로젝트·팀 이름은 외부로 가지 않는다
    assert not (tmp_path / sources.LIVE_PREV_FILE).exists()

    nvd.by_cpe[NGINX] = [nvd_cve("CVE-2026-0001", score=9.8), nvd_cve("CVE-2026-0009")]
    second = sources.refresh_live(live, http=nvd)
    assert (second["count"], second["added"], second["changed"], second["first"]) == (2, 1, 1, False)
    assert [v["id"] for v in sources.load_live(previous=True)] == ["CVE-2026-0001"]  # 직전(T1)은 비교용으로 남는다
    assert len(sources.load_live()) == 2 and len(sources.load_current(live)) == 2    # 답변과 판정은 최신(T2)


def test_조회가_실패하면_저장된_데이터를_그대로_둔다(live):
    sources.refresh_live(live, http=FakeNVD({NGINX: [nvd_cve("CVE-2026-0001")]}))
    with pytest.raises(sources.SourceError):
        sources.refresh_live(live, http=FakeNVD(fail=True))
    assert [v["id"] for v in sources.load_live()] == ["CVE-2026-0001"]


def test_받아_둔_데이터가_없으면_확인할_수_없다고_알린다(live):
    with pytest.raises(sources.SourceError):
        sources.load_current(live)


def test_처음_검색은_기준선만_잡고_그_뒤_새로_생기거나_바뀐_건만_알린다(live, summary_llm):
    nvd = FakeNVD({NGINX: [nvd_cve("CVE-2026-0001", score=9.8), nvd_cve("CVE-2026-0002", score=5.0)]})
    first = scheduler.run_once(live, llm=summary_llm, fetch=nvd)
    assert first["status"] == "ok" and first["baseline"] == 1 and first["alerts"] == 0 and mails(live) == []
    assert [a["reason"] for a in storage.list_alerts(live, "portal")] == ["baseline"]  # 이력에는 남는다

    again = scheduler.run_once(live, llm=summary_llm, fetch=nvd)  # 데이터가 그대로면 아무것도 알리지 않는다
    assert again["alerts"] == 0 and again["baseline"] == 0 and mails(live) == []

    nvd.by_cpe[NGINX] = [nvd_cve("CVE-2026-0001", score=9.8),               # 그대로: 알리지 않는다
                         nvd_cve("CVE-2026-0002", score=5.0, kev="2026-04-01"),  # KEV에 새로 오름
                         nvd_cve("CVE-2026-0003", score=10.0)]              # 새로 생김
    third = scheduler.run_once(live, llm=summary_llm, fetch=nvd)
    assert sorted(v["id"] for v in third["mails"][0]["vulns"]) == ["CVE-2026-0002", "CVE-2026-0003"]
    assert third["refresh"]["added"] == 1 and third["refresh"]["changed"] == 1
    text = mail_text(live, "portal")
    assert "CVE-2026-0003" in text and "CVE-2026-0001" not in text


def test_기준선을_잡은_뒤_점수가_오르면_다시_알린다(live, summary_llm):
    nvd = FakeNVD({NGINX: [nvd_cve("CVE-2026-0001", score=9.0)]})
    scheduler.run_once(live, llm=summary_llm, fetch=nvd)
    nvd.by_cpe[NGINX] = [nvd_cve("CVE-2026-0001", score=9.8)]
    report = scheduler.run_once(live, llm=summary_llm, fetch=nvd)
    assert report["mails"][0]["vulns"] == [{"id": "CVE-2026-0001", "reason": "score_raised"}]


def test_실시간_조회_실패도_연속_실패로_세고_통지한다(live, summary_llm):
    down = FakeNVD(fail=True)
    assert scheduler.run_once(live, llm=summary_llm, fetch=down)["consecutive_failures"] == 1
    second = scheduler.run_once(live, llm=summary_llm, fetch=down)
    assert second["status"] == "failed" and "failure_notice" in second
    ok = scheduler.run_once(live, llm=summary_llm, fetch=FakeNVD({NGINX: [nvd_cve("CVE-2026-0001")]}))
    assert ok["status"] == "ok" and storage.get_meta(live, scheduler.FAILURES_KEY) == "0"  # 다음 주기에 다시 처리된다


def test_시점을_직접_주면_실시간_모드에서도_고정_사본으로_검색한다(live, mailbox, summary_llm):
    nvd = FakeNVD()
    report = scheduler.run_once(live, llm=summary_llm, snapshot="T1", fetch=nvd)
    assert report["status"] == "ok" and "refresh" not in report and nvd.urls == [] and report["alerts"] > 0
