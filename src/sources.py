"""취약점 정보원. 기본은 data/의 오프라인 스냅샷을 읽고, 설정으로 켜면 NVD에서 받아 var/에 저장한 데이터를 쓴다."""

import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from src import matching, storage
from src.config import get_settings

SNAPSHOTS = ("T1", "T2")  # 고정 사본의 두 시점
SNAPSHOT_KEY = "snapshot"  # meta 표에 저장하는 이름


class SourceError(Exception):
    """정보원을 읽지 못했을 때. 스케줄러는 이 오류를 '조회 실패'로 센다."""


def load_snapshot(snapshot: str | None = None, data_dir=None) -> list[dict]:
    """지정한 시점(T1 또는 T2)의 취약점 목록을 읽는다. 생략하면 설정값을 쓴다."""
    settings = get_settings()
    name = (snapshot or settings.snapshot).lower()
    path = Path(data_dir or settings.data_dir) / f"vulns_{name}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))["vulnerabilities"]
    except (OSError, ValueError, KeyError) as exc:
        raise SourceError(f"스냅샷을 읽지 못했습니다: {path.name}") from exc


def validate_snapshot(name) -> str:
    """시점 이름을 검사해 대문자로 돌려준다. T1, T2가 아니면 ValueError."""
    value = str(name).strip().upper() if name is not None else ""
    if value not in SNAPSHOTS:
        raise ValueError(f"취약점 데이터 시점은 T1 또는 T2여야 합니다: {name!r}")
    return value


def current_snapshot(conn) -> str:
    """지금 쓰는 시점. 화면에서 바꿔 저장한 값이 있으면 그 값, 없거나 잘못됐으면 설정값(.env, 기본 T1)."""
    stored = storage.get_meta(conn, SNAPSHOT_KEY)
    if stored is not None:
        try:
            return validate_snapshot(stored)
        except ValueError:
            pass
    return get_settings().snapshot


def save_snapshot(conn, name) -> str:
    """시점을 검사해 저장한다. 서버를 다시 띄워도 이 값을 쓴다. T1, T2가 아니면 ValueError."""
    value = validate_snapshot(name)
    storage.set_meta(conn, SNAPSHOT_KEY, value)
    return value


# ---------------- 실시간 NVD 갱신 ----------------
# VULNWATCH_LIVE_LOOKUP=true일 때만 쓴다. 등록된 (제품 식별자, 버전)으로 NVD API 2.0을 조회해
# 고정 사본과 같은 형식으로 바꾸고 var/에 저장한다. 외부로 보내는 것은 제품 식별자와 버전뿐이다.
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SOURCE = "nvd@nist.gov"
CISA_ADP_SOURCE = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
SCORE_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")  # 앞의 것을 먼저 쓴다
LIVE_FILE = "vulns_live.json"            # 최신 (T2)
LIVE_PREV_FILE = "vulns_live_prev.json"  # 직전 (T1). 무엇이 바뀌었는지 비교하는 데만 쓴다


def _http_get(url: str, headers: dict) -> dict:
    """주소를 불러 JSON으로 읽는다. 테스트에서는 이 자리에 가짜 함수를 넣는다."""
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def fetch_nvd(cpe: str, http=None, api_key: str | None = None, pause: float = 0.7) -> list[dict]:
    """제품 식별자와 버전(cpe)에 걸리는 CVE 원본 목록을 NVD에서 받는다. 실패하면 SourceError."""
    http = http or _http_get
    headers = {"User-Agent": "vulnwatch-poc"}
    if api_key:
        headers["apiKey"] = api_key
    found, start = [], 0
    while True:
        url = NVD_API + "?" + urllib.parse.urlencode({"virtualMatchString": cpe, "startIndex": start})
        try:
            page = http(url, headers)
            found += [entry["cve"] for entry in page.get("vulnerabilities", [])]
            size, total = int(page.get("resultsPerPage", 0)), int(page.get("totalResults", 0))
        except Exception as exc:
            raise SourceError(f"NVD 조회에 실패했습니다({cpe}): {type(exc).__name__}") from exc
        start += size
        if size == 0 or start >= total:
            return found
        time.sleep(pause)  # 여러 쪽으로 나뉘면 호출 한도를 넘지 않게 쉰다


def _scores(cve: dict) -> dict:
    """NVD가 매긴 점수와 다른 출처(CNA, CISA-ADP)의 점수를 고른다. 없으면 None."""
    nvd = other = other_source = None
    for key in SCORE_KEYS:
        for metric in cve.get("metrics", {}).get(key, []):
            score = metric.get("cvssData", {}).get("baseScore")
            if score is None:
                continue
            if metric.get("source") == NVD_SOURCE:
                nvd = score if nvd is None else nvd
            elif other is None:
                other = score
                other_source = "CISA-ADP" if metric.get("source") == CISA_ADP_SOURCE else "CNA"
    return {"nvd": nvd, "other": other, "other_source": other_source}


def _affects(cve: dict, product: str, identifier: str) -> tuple[list[dict], int]:
    """NVD의 영향 범위에서 이 제품 것만 골라 판정용 형식으로 바꾼다. (영향 대상 목록, 읽지 못한 표기 수).

    취약하다고 표시된(vulnerable=true) 항목만 옮긴다. NVD의 버전 지정 조회는 취약하지 않은 항목도
    함께 돌려주므로, 해당 여부는 여기서 만든 범위로 matching.py가 다시 판정한다.
    """
    is_os = identifier.startswith("cpe:2.3:o:")
    ranges, versions, unreadable = [], [], 0
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable") or not match.get("criteria", "").startswith(identifier + ":"):
                    continue
                version = match["criteria"].split(":")[5]
                if version in ("*", "-"):
                    # 시작 버전이 '초과'로 적힌 경우도 '이상'으로 본다(조금 넓게 잡힌다)
                    rng = {"introduced": match.get("versionStartIncluding") or match.get("versionStartExcluding") or "0"}
                    if match.get("versionEndExcluding"):
                        rng["fixed"] = match["versionEndExcluding"]
                    elif match.get("versionEndIncluding"):
                        rng["last_affected"] = match["versionEndIncluding"]
                else:
                    rng = {"introduced": version, "last_affected": version}  # 버전 하나를 콕 집은 경우
                try:
                    for value in rng.values():
                        matching.parse_version(value)
                except ValueError:
                    unreadable += 1
                    continue
                if is_os and version not in ("*", "-"):
                    if version not in versions:
                        versions.append(version)  # 배포판은 앞 두 자리(22.04)로 비교하는 목록에 넣는다
                elif rng not in ranges:
                    ranges.append(rng)
    targets = []
    if ranges:
        targets.append({"product": product, "ranges": ranges})
    if versions:
        targets.append({"product": product, "versions": versions})
    return targets, unreadable


def convert_nvd(cve: dict, product: str, identifier: str) -> tuple[dict, int]:
    """NVD의 CVE 한 건을 고정 사본과 같은 형식의 레코드로 바꾼다. (레코드, 읽지 못한 버전 표기 수)."""
    affects, unreadable = _affects(cve, product, identifier)
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    kev_date = cve.get("cisaExploitAdd")
    record = {
        "id": cve["id"],
        "aliases": [],  # NVD는 GHSA 별칭을 주지 않는다
        "published": (cve.get("published") or "")[:10],
        "last_modified": (cve.get("lastModified") or "")[:10],
        "description": description,
        "scores": _scores(cve),
        "kev": bool(kev_date),
        "kev_date_added": kev_date,
        "affects": affects,
    }
    return record, unreadable


def _live_dir() -> Path:
    """실시간으로 받은 데이터를 두는 곳(var/)."""
    return get_settings().db_path.parent


def _read_live(name: str) -> dict | None:
    """저장된 실시간 데이터 파일을 읽는다. 없거나 깨졌으면 None."""
    try:
        return json.loads((_live_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _changes(previous: list[dict], current: list[dict]) -> dict:
    """직전 데이터와 견줘 새로 생긴 건, 점수나 KEV가 바뀐 건, 사라진 건의 ID."""
    def key(vuln):
        return matching.effective_score(vuln)[0], vuln["kev"]

    before = {v["id"]: key(v) for v in previous}
    after = {v["id"]: key(v) for v in current}
    return {"added": sorted(set(after) - set(before)),
            "changed": sorted(i for i in after if i in before and after[i] != before[i]),
            "removed": sorted(set(before) - set(after))}


def refresh_live(conn, http=None, now: datetime | None = None, pause: float = 0.7) -> dict:
    """등록된 감시 중 항목의 (제품, 버전)마다 NVD를 조회해 var/에 저장한다. 갱신 결과를 돌려준다.

    직전 데이터는 vulns_live_prev.json으로 남긴다. 조회가 하나라도 실패하면 SourceError를 내고
    저장된 데이터는 그대로 둔다.
    """
    products = {p["key"]: p for p in storage.list_products(conn)}
    targets = sorted({(item["product"], item["version"])
                      for project in storage.list_projects(conn)
                      for item in storage.list_items(conn, project["id"]) if item["status"] == "confirmed"})
    api_key = os.environ.get("NVD_API_KEY") or None
    merged: dict[str, dict] = {}
    unreadable, queries = 0, []
    for index, (product, version) in enumerate(targets):
        identifier = products[product]["identifier"]
        cpe = f"{identifier}:{version}"
        if index:
            time.sleep(pause)
        found = fetch_nvd(cpe, http=http, api_key=api_key, pause=pause)
        queries.append({"cpe": cpe, "found": len(found)})
        for cve in found:
            record, bad = convert_nvd(cve, product, identifier)
            unreadable += bad
            if record["id"] in merged:  # 같은 CVE가 다른 제품에도 걸리면 영향 대상을 합친다
                known = merged[record["id"]]["affects"]
                known += [t for t in record["affects"] if t not in known]
            else:
                merged[record["id"]] = record
    vulns = sorted(merged.values(), key=lambda v: v["id"])

    previous = _read_live(LIVE_FILE)
    changes = _changes(previous["vulnerabilities"], vulns) if previous else {"added": [], "changed": [], "removed": []}
    refreshed_at = (now or datetime.now()).isoformat(timespec="seconds")
    payload = {
        "_notice": "NVD 공개 API에서 받은 취약점 데이터입니다. 등록된 제품과 버전에 걸리는 것만 담습니다.",
        "refreshed_at": refreshed_at,
        "queries": queries,
        "unreadable_ranges": unreadable,
        "first": previous is None,
        "changes": changes,
        "vulnerabilities": vulns,
    }
    folder = _live_dir()
    folder.mkdir(parents=True, exist_ok=True)
    temp = folder / (LIVE_FILE + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    if previous is not None:
        os.replace(folder / LIVE_FILE, folder / LIVE_PREV_FILE)
    os.replace(temp, folder / LIVE_FILE)
    return live_status()


def live_status() -> dict | None:
    """마지막 실시간 갱신의 요약(시각, 건수, 바뀐 건수). 받은 적이 없으면 None."""
    data = _read_live(LIVE_FILE)
    if data is None:
        return None
    changes = data.get("changes", {})
    return {"refreshed_at": data.get("refreshed_at"), "count": len(data["vulnerabilities"]),
            "queries": len(data.get("queries", [])), "unreadable_ranges": data.get("unreadable_ranges", 0),
            "first": bool(data.get("first")),
            "added": len(changes.get("added", [])), "changed": len(changes.get("changed", [])),
            "removed": len(changes.get("removed", []))}


def load_live(previous: bool = False) -> list[dict]:
    """실시간으로 받아 둔 취약점 목록. previous=True면 직전 것. 없으면 SourceError."""
    data = _read_live(LIVE_PREV_FILE if previous else LIVE_FILE)
    if data is None:
        raise SourceError("실시간 취약점 데이터를 아직 받지 못했습니다. 잠시 뒤 다시 시도하거나 '지금 검색 실행해줘'로 받아 주세요.")
    return data["vulnerabilities"]


def is_live() -> bool:
    """실시간 NVD 갱신을 쓰는 설정인지."""
    return get_settings().live_lookup


def load_current(conn) -> list[dict]:
    """지금 답변과 판정에 쓸 취약점 목록. 실시간 모드면 받아 둔 최신 데이터, 아니면 고른 시점의 고정 사본."""
    if is_live():
        return load_live()
    return load_snapshot(current_snapshot(conn))


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
