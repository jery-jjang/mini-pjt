"""해당 여부 판정, 점수 출처, 알림 대상 판정 테스트."""

import pytest

from src import matching


def ids(vulns, product, version):
    """해당하는 취약점 ID 집합."""
    return {m["id"] for m in matching.match_item(vulns, product, version)}


def test_버전_비교는_길이가_달라도_맞다():
    assert matching.version_in_range("2.16", {"introduced": "2.13.0", "last_affected": "2.16.0"})
    assert not matching.version_in_range("2.16.1", {"introduced": "2.13.0", "last_affected": "2.16.0"})
    assert not matching.version_in_range("9.0.80", {"introduced": "9.0.0", "last_affected": "9.0.79"})
    assert matching.version_in_range("9.0.80", {"introduced": "9.0.0", "fixed": "9.0.81"})
    assert not matching.version_in_range("9.0.81", {"introduced": "9.0.0", "fixed": "9.0.81"})


def test_버전을_읽을_수_없으면_오류():
    with pytest.raises(ValueError):
        matching.parse_version("최신")


@pytest.mark.parametrize("product, version, expected", [
    ("tomcat", "9.0.80", {"CVE-2023-42795", "CVE-2023-44487", "CVE-2023-46589", "CVE-2024-50379", "CVE-2025-24813"}),
    ("log4j", "2.14.1", {"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"}),
    ("spring_framework", "5.3.17", {"CVE-2022-22965", "CVE-2022-22968"}),
    ("nginx", "1.24.0", {"CVE-2023-44487", "CVE-2024-7347", "GHSA-0000-demo-0001"}),
    ("openssl", "3.0.6", {"CVE-2022-3602", "CVE-2023-0286"}),
    ("ubuntu", "22.04", {"CVE-2023-4911", "CVE-2024-6387"}),
])
def test_등록_버전에_해당하는_취약점만_나온다(vulns_t1, product, version, expected):
    assert ids(vulns_t1, product, version) == expected


@pytest.mark.parametrize("product, version, not_affected", [
    ("spring_framework", "5.3.17", "CVE-2022-22950"),
    ("tomcat", "9.0.80", "CVE-2023-41080"),
    ("nginx", "1.24.0", "CVE-2022-41741"),
    ("openssl", "3.0.6", "CVE-2022-0778"),
])
def test_영향_없음이_정답인_사례는_걸러진다(vulns_t1, product, version, not_affected):
    assert not_affected not in ids(vulns_t1, product, version)


def test_고쳐진_버전은_해당하지_않는다(vulns_t1):
    assert ids(vulns_t1, "log4j", "2.17.1") == set()
    assert ids(vulns_t1, "redis", "7.2") == set()


def test_점수는_NVD_우선_없으면_다른_출처_없으면_미정(vulns_t1):
    by_id = {v["id"]: v for v in vulns_t1}
    assert matching.effective_score(by_id["CVE-2021-44228"]) == (10.0, "NVD")
    assert matching.effective_score(by_id["CVE-2024-50379"]) == (9.8, "CISA-ADP")
    assert matching.effective_score(by_id["CVE-2025-24813"]) == (None, "점수 미정")


def test_GHSA_별칭은_CVE로_찾는다(vulns_t1):
    assert matching.resolve_id(vulns_t1, "ghsa-jfh8-c2jp-5v3q")["id"] == "CVE-2021-44228"
    assert matching.resolve_id(vulns_t1, "GHSA-0000-demo-0001")["id"] == "GHSA-0000-demo-0001"
    assert matching.resolve_id(vulns_t1, "CVE-2099-12345") is None


def test_알림_조건은_9점_이상_또는_KEV():
    assert matching.should_alert(9.0, False)
    assert matching.should_alert(7.5, True)
    assert not matching.should_alert(8.9, False)
    assert not matching.should_alert(None, False)


def test_알림은_한_번_점수_상승이나_KEV_등재_때_한_번_더():
    assert matching.alert_reason(9.8, False, None) == "new"
    assert matching.alert_reason(9.8, False, {"score": 9.8, "kev": False}) is None
    assert matching.alert_reason(9.8, True, {"score": 9.8, "kev": False}) == "kev_added"
    assert matching.alert_reason(10.0, False, {"score": 9.8, "kev": False}) == "score_raised"
    assert matching.alert_reason(5.0, False, None) is None
