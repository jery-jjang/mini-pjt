"""취약점 해당 여부와 알림 대상을 판정한다. 일반 코드만 쓰고 LLM은 부르지 않는다."""

import re


# ---------------- 버전 비교 ----------------

def parse_version(text: str) -> tuple[int, ...]:
    """'9.0.80' 같은 버전을 숫자 묶음 (9, 0, 80)으로 바꾼다. 숫자가 없으면 ValueError."""
    numbers = re.findall(r"\d+", str(text))
    if not numbers:
        raise ValueError(f"버전을 읽을 수 없습니다: {text!r}")
    return tuple(int(n) for n in numbers)


def _compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """두 버전을 비교한다. 길이가 다르면 0으로 채운다. a<b면 -1, 같으면 0, a>b면 1."""
    size = max(len(a), len(b))
    a, b = a + (0,) * (size - len(a)), b + (0,) * (size - len(b))
    return (a > b) - (a < b)


def version_in_range(version: str, rng: dict) -> bool:
    """버전이 영향 범위 안에 있는지. fixed는 '미만', last_affected는 '이하'."""
    v = parse_version(version)
    if _compare(v, parse_version(rng["introduced"])) < 0:
        return False
    if "fixed" in rng and _compare(v, parse_version(rng["fixed"])) >= 0:
        return False
    if "last_affected" in rng and _compare(v, parse_version(rng["last_affected"])) > 0:
        return False
    return True


def is_affected(vuln: dict, product: str, version: str) -> bool:
    """이 취약점이 (제품, 버전)에 해당하는지."""
    for target in vuln["affects"]:
        if target["product"] != product:
            continue
        if "versions" in target:
            # 배포판처럼 버전을 나열한 경우: 앞 두 자리(22.04)로 비교한다
            mine = parse_version(version)[:2]
            if any(parse_version(v)[:2] == mine for v in target["versions"]):
                return True
        elif any(version_in_range(version, rng) for rng in target["ranges"]):
            return True
    return False


# ---------------- 점수와 ID ----------------

def effective_score(vuln: dict) -> tuple[float | None, str]:
    """점수와 출처. NVD 우선, 없으면 다른 출처(CNA/OSV 등), 둘 다 없으면 '점수 미정'."""
    scores = vuln["scores"]
    if scores.get("nvd") is not None:
        return scores["nvd"], "NVD"
    if scores.get("other") is not None:
        return scores["other"], scores.get("other_source") or "기타"
    return None, "점수 미정"


def resolve_id(vulns: list[dict], any_id: str):
    """CVE ID 또는 별칭(GHSA 등)으로 취약점을 찾는다. 대소문자는 무시한다."""
    key = any_id.strip().upper()
    for vuln in vulns:
        if key == vuln["id"].upper() or key in (a.upper() for a in vuln["aliases"]):
            return vuln
    return None


# ---------------- 해당 여부 판정 ----------------

def match_item(vulns: list[dict], product: str, version: str) -> list[dict]:
    """(제품, 버전)에 해당하는 취약점을 찾아 근거와 함께 돌려준다."""
    found = []
    for vuln in vulns:
        if is_affected(vuln, product, version):
            score, source = effective_score(vuln)
            found.append({
                "id": vuln["id"],
                "aliases": vuln["aliases"],
                "product": product,
                "version": version,
                "score": score,
                "score_source": source,
                "kev": vuln["kev"],
                "description": vuln["description"],
            })
    return found


# ---------------- 알림 대상 판정 ----------------

def should_alert(score: float | None, kev: bool, threshold: float = 9.0) -> bool:
    """알림 조건: 점수가 기준 이상이거나 KEV에 올라 있을 때."""
    return bool(kev) or (score is not None and score >= threshold)


def alert_reason(score: float | None, kev: bool, last_alert: dict | None, threshold: float = 9.0):
    """이번에 알릴 이유를 돌려준다. 알릴 필요가 없으면 None.

    last_alert는 이 (프로젝트, 취약점)에 대해 마지막으로 보낸 알림의 score와 kev.
    - 보낸 적이 없으면: 알림 조건을 만족할 때 'new'
    - 보낸 적이 있으면: KEV에 새로 올랐을 때 'kev_added', 점수가 올랐을 때 'score_raised'
    """
    if not should_alert(score, kev, threshold):
        return None
    if last_alert is None:
        return "new"
    if kev and not last_alert["kev"]:
        return "kev_added"
    if score is not None and (last_alert["score"] is None or score > last_alert["score"]):
        return "score_raised"
    return None
