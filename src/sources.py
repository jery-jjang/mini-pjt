"""취약점 정보원. PoC에서는 data/의 오프라인 스냅샷만 읽는다."""

import json
from pathlib import Path

from src.config import get_settings


class SourceError(Exception):
    """정보원을 읽지 못했을 때. 스케줄러는 이 오류를 '조회 실패'로 센다."""


def load_snapshot(snapshot: str | None = None, data_dir=None) -> list[dict]:
    """지정한 시점(T1 또는 T2)의 취약점 목록을 읽는다. 생략하면 설정값을 쓴다."""
    settings = get_settings()
    if settings.live_lookup:
        raise SourceError("실시간 NVD/OSV 조회는 이 PoC에서 만들지 않았습니다. 오프라인 스냅샷을 쓰세요.")
    name = (snapshot or settings.snapshot).lower()
    path = Path(data_dir or settings.data_dir) / f"vulns_{name}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))["vulnerabilities"]
    except (OSError, ValueError, KeyError) as exc:
        raise SourceError(f"스냅샷을 읽지 못했습니다: {path.name}") from exc


# ---------------- 참고 링크 ----------------
# 근거 문서에 붙이는 공개 정보원 주소. 취약점 ID로 정해진 규칙에 따라 만든다(LLM이 만들지 않는다).
NVD_URL = "https://nvd.nist.gov/vuln/detail/{id}"
OSV_URL = "https://osv.dev/vulnerability/{id}"
GHSA_URL = "https://github.com/advisories/{id}"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def reference_links(vuln: dict) -> list[dict]:
    """취약점 레코드의 참고 링크 목록 [{name, url}]. 교육용 가상 항목은 빈 목록.

    NVD는 CVE일 때, OSV는 항상, GitHub Advisory는 GHSA ID(본 ID 또는 별칭)가 있을 때,
    CISA KEV는 KEV에 등재됐을 때 붙인다.
    """
    if vuln.get("synthetic"):
        return []
    vid = vuln["id"]
    links = []
    if vid.upper().startswith("CVE-"):
        links.append({"name": "NVD", "url": NVD_URL.format(id=vid)})
    links.append({"name": "OSV", "url": OSV_URL.format(id=vid)})
    ghsa = [a for a in [vid, *vuln.get("aliases", [])] if a.upper().startswith("GHSA-")]
    if ghsa:
        links.append({"name": "GitHub Advisory", "url": GHSA_URL.format(id=ghsa[0])})
    if vuln.get("kev"):
        links.append({"name": "CISA KEV", "url": KEV_URL})
    return links
