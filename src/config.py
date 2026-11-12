"""설정값을 한곳에 모은다. 환경 변수에서 읽고, 없으면 기본값을 쓴다."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent

# .env의 비밀 값(AWS 키 등)을 환경 변수로 올린다. 값은 코드에 적지 않는다.
load_dotenv(ROOT / ".env")

# LangSmith 추적은 .env에 값이 있어도 항상 끈다. (외부로 대화 내용이 나가지 않게)
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"


def _flag(name: str, default: bool) -> bool:
    """환경 변수를 참/거짓으로 읽는다."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    """실행에 쓰는 설정값 묶음."""

    data_dir: Path
    db_path: Path
    outbox_dir: Path
    trace_path: Path
    snapshot: str  # 사용할 취약점 스냅샷 시점: "T1" 또는 "T2"
    scan_interval_hours: float  # 스케줄러 주기
    scheduler_enabled: bool  # 서버가 뜰 때 주기 검색을 시작할지
    failure_notice_threshold: int  # 연속 실패 몇 회에 보안 담당자에게 알릴지
    alert_cvss_threshold: float  # 알림 기준 점수
    send_real_mail: bool  # 실제 발송 여부 (PoC에서는 파일 저장만 한다)
    live_lookup: bool  # 실시간 NVD/OSV 조회 여부 (PoC에서는 만들지 않는다)
    model_id: str
    region: str


def get_settings() -> Settings:
    """현재 환경 변수 기준의 설정값을 돌려준다."""
    var_dir = Path(os.environ.get("VULNWATCH_VAR_DIR", ROOT / "var"))
    return Settings(
        data_dir=Path(os.environ.get("VULNWATCH_DATA_DIR", ROOT / "data")),
        db_path=Path(os.environ.get("VULNWATCH_DB_PATH", var_dir / "vulnwatch.db")),
        outbox_dir=Path(os.environ.get("VULNWATCH_OUTBOX_DIR", ROOT / "outbox")),
        trace_path=Path(os.environ.get("VULNWATCH_TRACE_PATH", var_dir / "traces.jsonl")),
        snapshot=os.environ.get("VULNWATCH_SNAPSHOT", "T1").upper(),
        scan_interval_hours=float(os.environ.get("VULNWATCH_SCAN_INTERVAL_HOURS", "6")),
        scheduler_enabled=_flag("VULNWATCH_SCHEDULER_ENABLED", True),
        failure_notice_threshold=int(os.environ.get("VULNWATCH_FAILURE_NOTICE_THRESHOLD", "2")),
        alert_cvss_threshold=float(os.environ.get("VULNWATCH_ALERT_CVSS_THRESHOLD", "9.0")),
        send_real_mail=_flag("VULNWATCH_SEND_REAL_MAIL", False),
        live_lookup=_flag("VULNWATCH_LIVE_LOOKUP", False),
        model_id=os.environ.get("VULNWATCH_MODEL_ID", "global.anthropic.claude-sonnet-4-5-20250929-v1:0"),
        region=os.environ.get("VULNWATCH_REGION", "us-east-1"),
    )
