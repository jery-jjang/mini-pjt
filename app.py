"""API 진입점 (FastAPI). POST /query와, UI가 쓰는 등록 목록·주기 검색 설정 API, 화면 파일(/ui)."""

import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, Header, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel, Field

from src import agent, auth, scheduler, storage
from src.config import ROOT, get_settings


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
    app.state.scheduler = None
    if settings.scheduler_enabled:  # 주기 검색 시작. 주기는 저장된 값(없으면 .env 값)
        app.state.scheduler = scheduler.Scheduler(scheduler.load_interval(conn), settings.db_path).start()
    yield
    if app.state.scheduler:
        app.state.scheduler.stop()
    conn.close()


class UTF8JSONResponse(JSONResponse):
    """응답 헤더에 문자 인코딩을 밝힌다. (PowerShell 같은 클라이언트에서 한글이 깨지지 않게)"""

    media_type = "application/json; charset=utf-8"


app = FastAPI(title="VulnWatch", lifespan=lifespan, default_response_class=UTF8JSONResponse)


@app.exception_handler(StarletteHTTPException)
async def http_error(request, exc: StarletteHTTPException):
    """오류 응답에도 문자 인코딩을 밝힌다. (한글 오류 문구가 깨지지 않게)"""
    return UTF8JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc: RequestValidationError):
    """요청 형식 오류(422)에도 문자 인코딩을 밝힌다."""
    return UTF8JSONResponse({"detail": jsonable_encoder(exc.errors())}, status_code=422)


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


class IntervalRequest(BaseModel):
    """검색 주기 변경 요청."""

    hours: float = Field(gt=0, allow_inf_nan=False, description="검색 주기(시간). 0보다 커야 한다. 예: 0.5는 30분")


class SettingsResponse(BaseModel):
    """주기 검색 설정과 실행 시각."""

    scan_interval_hours: float
    scheduler_enabled: bool
    last_run_at: str | None
    next_run_at: str | None


class ItemOut(BaseModel):
    """프로젝트에 등록된 SW 항목."""

    id: int  # 삭제할 때 쓰는 항목 번호
    raw_text: str  # 사용자가 등록할 때 쓴 문장
    product: str | None  # 확정된 표준 제품 이름. 매핑이 확정되지 않았으면 None
    version: str | None
    monitored: bool  # 매핑이 확정돼 감시 중인지. False면 '감시 불가'


class ProjectOut(BaseModel):
    """계정이 볼 수 있는 프로젝트와 등록 항목."""

    id: str
    name: str
    team: str
    items: list[ItemOut]


class ProjectsResponse(BaseModel):
    """요청한 계정과, 그 계정이 볼 수 있는 프로젝트 목록."""

    account: dict
    projects: list[ProjectOut]


def _account(authorization: str | None) -> dict:
    """요청한 계정을 찾는다. 모르는 토큰이면 401."""
    try:
        return auth.resolve_account(app.state.conn, authorization)
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def _settings_status() -> dict:
    """지금의 주기 검색 설정. 주기 검색을 끈 서버는 저장된 주기만 돌려준다."""
    if app.state.scheduler:
        return app.state.scheduler.status()
    return {"scan_interval_hours": scheduler.load_interval(app.state.conn), "scheduler_enabled": False,
            "last_run_at": None, "next_run_at": None}


logger = logging.getLogger("vulnwatch")

# 호출 한도 초과로 보는 Bedrock 오류 코드
THROTTLE_CODES = {"ThrottlingException", "TooManyRequestsException", "ServiceQuotaExceededException"}


def _model_error(exc: Exception) -> HTTPException:
    """모델(Bedrock) 호출 오류를 사용자에게 보여 줄 HTTP 오류로 바꾼다. 트레이스백은 보내지 않는다."""
    code = exc.response.get("Error", {}).get("Code", "") if isinstance(exc, ClientError) else type(exc).__name__
    logger.warning("모델 호출 실패: %s (%s)", code, str(exc)[:200])
    if code in THROTTLE_CODES:
        return HTTPException(status_code=429, detail="모델 호출 한도를 넘었습니다. 잠시 뒤 다시 시도해 주세요.")
    return HTTPException(status_code=503, detail="모델을 호출하지 못했습니다. 자격 증명과 연결 상태를 확인해 주세요.")


@app.post("/query", response_model=QueryResponse)
def query(body: QueryRequest, authorization: str | None = Header(default=None)):
    """질문을 받아 답한다. Authorization 헤더가 없으면 기본 평가 계정(팀 A 팀원)으로 처리한다.

    모델 호출이 실패하면 답 대신 오류로 알린다: 한도 초과는 429, 그 밖의 호출 실패는 503.
    """
    account = _account(authorization)
    try:
        return agent.answer_question(app.state.conn, account, body.question, llm=app.state.llm)
    except (ClientError, BotoCoreError) as exc:
        raise _model_error(exc) from None


@app.get("/projects", response_model=ProjectsResponse)
def read_projects(authorization: str | None = Header(default=None)):
    """요청한 계정이 볼 수 있는 프로젝트와 등록된 SW 목록. 팀원은 자기 팀, 보안 담당자는 전체를 본다.

    모델을 부르지 않는 읽기 전용 조회다. 알림 수신 주소는 돌려주지 않는다.
    """
    conn = app.state.conn
    account = _account(authorization)
    teams = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM teams").fetchall()}
    names = {p["key"]: p["name"] for p in storage.list_products(conn)}
    projects = []
    for p in auth.accessible_projects(conn, account):
        items = [_item_out(i, names) for i in storage.list_items(conn, p["id"])]
        projects.append({"id": p["id"], "name": p["name"], "team": teams.get(p["team"], p["team"]), "items": items})
    return {"account": {"id": account["id"], "name": account["name"], "role": account["role"]},
            "projects": projects}


def _item_out(item: dict, names: dict) -> dict:
    """등록 항목을 화면에 보낼 모양으로 바꾼다."""
    return {"id": item["id"], "raw_text": item["raw_text"],
            "product": names.get(item["product"]) if item["product"] else None,
            "version": item["version"], "monitored": item["status"] == "confirmed"}


class RemovedResponse(BaseModel):
    """지운 항목."""

    project: str
    removed: ItemOut


@app.delete("/projects/{project_id}/items/{item_id}", response_model=RemovedResponse)
def delete_item(project_id: str, item_id: int, authorization: str | None = Header(default=None)):
    """등록한 SW 하나를 지운다(삭제 표시). 화면의 삭제 버튼이 확인 창을 거쳐 부른다. LLM을 거치지 않는다.

    팀원은 자기 팀 프로젝트, 보안 담당자는 전체를 지울 수 있다. 권한은 코드가 확인한다.
    지운 항목은 감시와 알림에서 빠지고, 알림 이력은 남는다. 같은 SW를 다시 등록하면 다시 알린다.
    모르는 토큰 401, 다른 팀 프로젝트 403, 없거나 이미 지운 항목 404.
    """
    conn = app.state.conn
    account = _account(authorization)
    project = next((p for p in storage.list_projects(conn) if p["id"] == project_id), None)
    if project is None:
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.")
    if not auth.can_access(account, project):
        raise HTTPException(status_code=403, detail="다른 팀 프로젝트의 SW는 지울 수 없습니다.")
    removed = storage.remove_item(conn, project_id, item_id, account["id"],
                                  datetime.now(timezone.utc).isoformat(timespec="seconds"))
    if removed is None:
        raise HTTPException(status_code=404, detail="지울 항목이 없습니다. 이미 지웠을 수 있습니다.")
    names = {p["key"]: p["name"] for p in storage.list_products(conn)}
    return {"project": project["name"], "removed": _item_out(removed, names)}


@app.get("/settings", response_model=SettingsResponse)
def read_settings():
    """주기 검색 설정(주기, 사용 여부, 마지막·다음 검색 시각)을 본다. 누구나 볼 수 있다."""
    return _settings_status()


@app.put("/settings/scan-interval", response_model=SettingsResponse)
def change_scan_interval(body: IntervalRequest, authorization: str | None = Header(default=None)):
    """검색 주기를 바꾼다. 서버를 다시 띄우지 않아도 바로 반영되고, 다음 검색은 지금부터 새 주기 뒤다.

    주기는 모든 팀에 한꺼번에 적용되므로 보안 담당자만 바꿀 수 있다. 0 이하는 422로 거부한다.
    """
    account = _account(authorization)
    if account["role"] != "security_admin":
        raise HTTPException(status_code=403, detail="검색 주기는 보안 담당자만 바꿀 수 있습니다.")
    try:
        hours = scheduler.save_interval(app.state.conn, body.hours)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if app.state.scheduler:
        app.state.scheduler.set_interval(hours)
    return _settings_status()


# ---------------- 화면 (로컬 UI) ----------------
# 빌드 없는 정적 파일(web/)을 /ui에서 내준다. 같은 주소에서 API를 부르므로 CORS 설정이 필요 없다.
app.mount("/ui", StaticFiles(directory=ROOT / "web", html=True), name="ui")


@app.get("/", include_in_schema=False)
def home():
    """첫 주소로 오면 화면으로 보낸다."""
    return RedirectResponse(url="/ui/")
