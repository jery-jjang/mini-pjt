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
