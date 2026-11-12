"""테스트 공통 준비. 실제 LLM과 외부 API는 부르지 않고, DB는 임시 경로에 만든다."""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 테스트는 외부로 아무것도 보내지 않는다. .env보다 먼저 정해 두면 load_dotenv가 덮어쓰지 않는다.
os.environ["LANGSMITH_TRACING"] = "false"

from src import sources, storage  # noqa: E402


@pytest.fixture
def conn(tmp_path):
    """초기 시드로 채운 임시 SQLite 연결."""
    connection = storage.connect(tmp_path / "test.db")
    storage.reset_from_seed(connection, ROOT / "data" / "seed.json")
    yield connection
    connection.close()


@pytest.fixture
def mailbox(conn, monkeypatch):
    """알림 메일이 저장되는 곳(임시 SQLite의 mails 표)."""
    monkeypatch.setenv("VULNWATCH_DATA_DIR", str(ROOT / "data"))
    return conn


class FakeSummaryLLM:
    """알림 요약용 가짜 모델. 받은 내용을 기록하고 취약점마다 정해진 요약을 돌려준다."""

    def __init__(self, fail=False):
        self.fail = fail
        self.seen = []

    def with_structured_output(self, schema):
        import re

        from langchain_core.runnables import RunnableLambda

        def run(prompt_value):
            text = prompt_value.to_string()
            self.seen.append(text)
            if self.fail:
                raise RuntimeError("모델 호출 실패")
            ids = re.findall(r"\[((?:CVE|GHSA)-[^\]]+)\]", text)
            return schema(items=[{"vuln_id": i, "summary": f"{i} 가짜 요약"} for i in ids])
        return RunnableLambda(run)


@pytest.fixture
def summary_llm():
    return FakeSummaryLLM()


@pytest.fixture
def vulns_t1():
    """1차 시점 스냅샷."""
    return sources.load_snapshot("T1", ROOT / "data")


@pytest.fixture
def vulns_t2():
    """2차 시점 스냅샷."""
    return sources.load_snapshot("T2", ROOT / "data")
