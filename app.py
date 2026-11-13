"""API 진입점 (FastAPI). POST /query와, UI가 쓰는 등록 목록·주기 검색 설정 API, 화면 파일(/ui)."""

import logging
import threading
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

from src import agent, auth, scheduler, sources, storage
from src.config import ROOT, get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """시작할 때 DB에 연결하고, 비어 있으면 초기 시드로 채운다."""
    settings = get_settings()
    conn = storage.connect(settings.db_path)
    if not storage.list_projects(conn):
        storage.reset_from_seed(conn, settings.data_dir / "seed.json")
    app.state.conn = conn  # 시작 작업과 테스트가 쓰는 연결. 요청 처리는 _conn()으로 작업 스레드마다 따로 연다
    app.state.db_path = settings.db_path
    app.state.db_generation = getattr(app.state, "db_generation", 0) + 1  # 다시 시작하면 스레드별 연결을 새로 연다
    if not hasattr(app.state, "llm"):
        app.state.llm = None  # None이면 요청 때 실제 Bedrock 모델을 만든다. 테스트는 가짜 모델을 넣는다
    if settings.live_lookup and sources.live_status() is None:
        # 실시간 모드인데 받아 둔 데이터가 없으면 한 번 받아 온다. 실패해도 서버는 뜨고 다음 주기에 다시 받는다
        try:
            sources.refresh_live(conn)
        except sources.SourceError as exc:
            logger.warning("처음 취약점 데이터를 받지 못했습니다: %s", exc)
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


class SnapshotRequest(BaseModel):
    """취약점 데이터 시점 변경 요청."""

    snapshot: str = Field(description="T1 또는 T2")


class SettingsResponse(BaseModel):
    """주기 검색 설정과 실행 시각."""

    scan_interval_hours: float
    scheduler_enabled: bool
    last_run_at: str | None
    next_run_at: str | None
    snapshot: str  # 지금 쓰는 취약점 데이터 시점 (T1 또는 T2). 실시간 모드에서는 쓰이지 않는다
    data_source: str  # fixed(고정 사본) 또는 live(NVD에서 주기적으로 받음)
    live: dict | None = None  # 실시간 모드의 마지막 갱신 요약(시각, 건수, 새로 생긴·바뀐 건수). 받은 적이 없으면 None


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


_local = threading.local()


def _conn():
    """이 요청을 처리하는 작업 스레드의 SQLite 연결. 없으면 연다.

    요청들이 연결 하나를 함께 쓰면, 계정을 바꿀 때처럼 요청이 동시에 들어올 때 sqlite3 오류(500)나
    잘못된 401이 났다. 작업 스레드마다 연결을 따로 두고, 쓰기는 SQLite가 차례로 처리한다.
    """
    key = (str(app.state.db_path), app.state.db_generation)
    if getattr(_local, "key", None) != key:
        _local.conn = storage.connect(app.state.db_path)
        _local.key = key
    return _local.conn


def _account(authorization: str | None) -> dict:
    """요청한 계정을 찾는다. 모르는 토큰이면 401."""
    try:
        return auth.resolve_account(_conn(), authorization)
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def _settings_status() -> dict:
    """지금의 주기 검색 설정. 주기 검색을 끈 서버는 저장된 주기만 돌려준다."""
    live = sources.is_live()
    data = {"snapshot": sources.current_snapshot(_conn()), "data_source": "live" if live else "fixed",
            "live": sources.live_status() if live else None}
    if app.state.scheduler:
        return app.state.scheduler.status() | data
    return {"scan_interval_hours": scheduler.load_interval(_conn()), "scheduler_enabled": False,
            "last_run_at": None, "next_run_at": None} | data


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
        return agent.answer_question(_conn(), account, body.question, llm=app.state.llm)
    except (ClientError, BotoCoreError) as exc:
        raise _model_error(exc) from None
    except sources.SourceError as exc:  # 실시간 모드인데 받아 둔 취약점 데이터가 없을 때
        raise HTTPException(status_code=503, detail=str(exc)) from None


@app.get("/projects", response_model=ProjectsResponse)
def read_projects(authorization: str | None = Header(default=None)):
    """요청한 계정이 볼 수 있는 프로젝트와 등록된 SW 목록. 팀원은 자기 팀, 보안 담당자는 전체를 본다.

    모델을 부르지 않는 읽기 전용 조회다. 알림 수신 주소는 돌려주지 않는다.
    """
    conn = _conn()
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
    conn = _conn()
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


class MailOut(BaseModel):
    """저장된 알림 메일 한 통. 받는 주소는 보안 담당자에게만 준다."""

    id: int
    kind: str  # alert(프로젝트 알림) 또는 scan_failure(조회 연속 실패 통지)
    project: str | None  # 프로젝트 이름. 조회 실패 통지는 None
    subject: str
    created_at: str
    vuln_ids: list[str]
    recipient: str | None = None
    body: str | None = None  # 목록에서는 비우고 한 통을 볼 때만 채운다
    read: bool = False  # 요청한 계정이 읽었는지. 읽음 현황은 계정마다 따로다
    read_at: str | None = None
    readers: list[dict] | None = None  # 보안 담당자에게만: 볼 수 있는 계정마다 {account, name, read_at}


class MailsResponse(BaseModel):
    """볼 수 있는 메일 목록(최근 것부터)."""

    mails: list[MailOut]
    unread_count: int  # 요청한 계정이 아직 읽지 않은 메일 수


def _visible_mails(account: dict) -> list[dict]:
    """계정이 볼 수 있는 메일. 팀원은 자기 팀 프로젝트 알림만, 보안 담당자는 조회 실패 통지까지 전체."""
    conn = _conn()
    if account["role"] == "security_admin":
        return storage.list_mails(conn)
    ids = {p["id"] for p in auth.accessible_projects(conn, account)}
    return storage.list_mails(conn, project_ids=ids, include_system=False)


def _mail_out(mail: dict, account: dict, with_body: bool = False) -> dict:
    """메일을 화면에 보낼 모양으로 바꾼다."""
    conn = _conn()
    names = {p["id"]: p["name"] for p in storage.list_projects(conn)}
    admin = account["role"] == "security_admin"
    return {"id": mail["id"], "kind": mail["kind"], "project": names.get(mail["project"]) if mail["project"] else None,
            "subject": mail["subject"], "created_at": mail["created_at"],
            "vuln_ids": storage.mail_vulns(conn, mail["id"]),
            "recipient": mail["recipient"] if admin else None,
            "body": mail["body"] if with_body else None,
            "read_at": (read_at := storage.read_time(conn, mail["id"], account["id"])), "read": read_at is not None,
            "readers": _readers(mail) if admin and with_body else None}


def _readers(mail: dict) -> list[dict]:
    """이 메일을 볼 수 있는 계정마다 읽었는지와 읽은 시각. 보안 담당자가 전달 여부를 확인할 때 쓴다."""
    conn = _conn()
    read = storage.mail_readers(conn, mail["id"])
    project = next((p for p in storage.list_projects(conn) if p["id"] == mail["project"]), None)
    accounts = [dict(r) for r in conn.execute("SELECT * FROM accounts ORDER BY id")]
    viewers = [a for a in accounts if a["role"] == "security_admin" or (project and auth.can_access(a, project))]
    return [{"account": a["id"], "name": a["name"], "read_at": read.get(a["id"])} for a in viewers]


@app.get("/mails", response_model=MailsResponse)
def read_mails(authorization: str | None = Header(default=None)):
    """화면 '알림함'의 메일 목록. 가짜 발송한 메일은 파일이 아니라 DB에 있다. 모르는 토큰 401."""
    account = _account(authorization)
    mails = [_mail_out(m, account) for m in _visible_mails(account)]
    return {"mails": mails, "unread_count": sum(not m["read"] for m in mails)}


@app.post("/mails/read-all", response_model=MailsResponse)
def mark_all_read(authorization: str | None = Header(default=None)):
    """요청한 계정이 볼 수 있는 메일을 모두 읽음으로 표시한다. 다른 계정의 읽음 현황은 바꾸지 않는다."""
    account = _account(authorization)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for mail in _visible_mails(account):
        storage.mark_read(_conn(), mail["id"], account["id"], now)
    return read_mails(authorization)


@app.post("/mails/{mail_id}/read", response_model=MailOut)
def mark_mail_read(mail_id: int, authorization: str | None = Header(default=None)):
    """메일 한 통을 요청한 계정 기준으로 읽음 표시한다. 볼 수 없거나 없는 메일은 404."""
    account = _account(authorization)
    mail = next((m for m in _visible_mails(account) if m["id"] == mail_id), None)
    if mail is None:
        raise HTTPException(status_code=404, detail="메일을 찾을 수 없습니다.")
    storage.mark_read(_conn(), mail_id, account["id"], datetime.now(timezone.utc).isoformat(timespec="seconds"))
    return _mail_out(mail, account, with_body=True)


@app.get("/mails/{mail_id}", response_model=MailOut)
def read_mail(mail_id: int, authorization: str | None = Header(default=None)):
    """메일 한 통의 본문. 볼 수 없거나 없는 메일은 404(있는지도 알리지 않는다). 모르는 토큰 401."""
    account = _account(authorization)
    mail = next((m for m in _visible_mails(account) if m["id"] == mail_id), None)
    if mail is None:
        raise HTTPException(status_code=404, detail="메일을 찾을 수 없습니다.")
    return _mail_out(mail, account, with_body=True)


@app.get("/settings", response_model=SettingsResponse)
def read_settings():
    """주기 검색 설정(주기, 사용 여부, 마지막·다음 검색 시각)을 본다. 누구나 볼 수 있다."""
    return _settings_status()


@app.put("/settings/snapshot", response_model=SettingsResponse)
def change_snapshot(body: SnapshotRequest, authorization: str | None = Header(default=None)):
    """취약점 데이터 시점(T1 또는 T2)을 바꾼다. 이후의 주기 검색, '지금 검색', 답변이 그 시점을 쓴다.

    실시간 조회 대신 두 시점의 고정 사본을 쓰므로, 시연에서 '데이터가 갱신됐다'를 흉내 내는 설정이다.
    모든 팀에 적용되므로 보안 담당자만 바꿀 수 있다. 검색을 바로 돌리지는 않는다. 다른 값은 422.
    """
    account = _account(authorization)
    if account["role"] != "security_admin":
        raise HTTPException(status_code=403, detail="취약점 데이터 시점은 보안 담당자만 바꿀 수 있습니다.")
    try:
        sources.save_snapshot(_conn(), body.snapshot)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
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
        hours = scheduler.save_interval(_conn(), body.hours)
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
