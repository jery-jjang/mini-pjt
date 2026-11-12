"""POST /query 진입점 (FastAPI)."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src import agent, auth, scheduler, storage
from src.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """시작할 때 DB에 연결하고, 비어 있으면 초기 시드로 채운다."""
    settings = get_settings()
    conn = storage.connect(settings.db_path)
    if not storage.list_projects(conn):
        storage.reset_from_seed(conn, settings.data_dir / "seed.json")
    app.state.conn = conn
    if not hasattr(app.state, "llm"):
        app.state.llm = None  # None이면 요청 때 실제 Bedrock 모델을 만든다. 테스트는 가짜 모델을 넣는다
    stop = scheduler.start() if settings.scheduler_enabled else None  # 주기 검색 시작
    yield
    if stop:
        stop.set()
    conn.close()


class UTF8JSONResponse(JSONResponse):
    """응답 헤더에 문자 인코딩을 밝힌다. (PowerShell 같은 클라이언트에서 한글이 깨지지 않게)"""

    media_type = "application/json; charset=utf-8"


app = FastAPI(title="VulnWatch", lifespan=lifespan, default_response_class=UTF8JSONResponse)


class QueryRequest(BaseModel):
    """요청 본문. question만 필수다."""

    question: str = Field(min_length=1, description="사용자 질의")


class QueryResponse(BaseModel):
    """응답 본문. 여섯 키를 항상 모두 채운다."""

    answer: str
    contexts: list[dict]
    trace: list[dict]
    label: str
    cve_ids: list[str]
    tools_called: list[str]


@app.post("/query", response_model=QueryResponse)
def query(body: QueryRequest, authorization: str | None = Header(default=None)):
    """질문을 받아 답한다. Authorization 헤더가 없으면 기본 평가 계정(팀 A 팀원)으로 처리한다."""
    conn = app.state.conn
    try:
        account = auth.resolve_account(conn, authorization)
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return agent.answer_question(conn, account, body.question, llm=app.state.llm)
