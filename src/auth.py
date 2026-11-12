"""토큰으로 계정을 확인하고, 프로젝트 접근 권한을 코드로 판정한다. (LLM 판단에 맡기지 않는다)"""

from src import storage


class AuthError(Exception):
    """토큰이 올바르지 않을 때."""


def resolve_account(conn, authorization: str | None) -> dict:
    """Authorization 헤더로 계정을 찾는다. 헤더가 없으면 기본 평가 계정(팀 A 팀원)을 쓴다."""
    if not authorization or not authorization.strip():
        return storage.get_account(conn, storage.get_meta(conn, "default_account"))
    token = authorization.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    account = storage.get_account_by_token(conn, token)
    if account is None:
        raise AuthError("알 수 없는 토큰입니다.")
    return account


def can_access(account: dict, project: dict) -> bool:
    """이 계정이 이 프로젝트를 볼 수 있는지. 보안 담당자는 전체, 팀원은 자기 팀만."""
    if account["role"] == "security_admin":
        return True
    return account["team"] == project["team"]


def accessible_projects(conn, account: dict) -> list[dict]:
    """이 계정이 볼 수 있는 프로젝트 목록."""
    return [p for p in storage.list_projects(conn) if can_access(account, p)]
