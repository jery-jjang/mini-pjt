"""SQLite 접근. 표를 만들고, 초기 시드로 되돌리고, 읽고 쓰는 함수를 둔다."""

import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, team TEXT, role TEXT NOT NULL, token TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, team TEXT NOT NULL, alert_email TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products (
    key TEXT PRIMARY KEY, name TEXT NOT NULL, identifier TEXT NOT NULL, aliases TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, raw_text TEXT NOT NULL,
    product TEXT, version TEXT, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mappings (raw_key TEXT PRIMARY KEY, product TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_candidates (
    account TEXT PRIMARY KEY, project TEXT NOT NULL, raw_text TEXT NOT NULL,
    version TEXT, candidates TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (
    project TEXT NOT NULL, vuln_id TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL,
    score REAL, score_source TEXT, kev INTEGER NOT NULL, PRIMARY KEY (project, vuln_id, product));
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, vuln_id TEXT NOT NULL,
    reason TEXT NOT NULL, score REAL, kev INTEGER NOT NULL, sent_at TEXT NOT NULL, file TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS item_removals (
    item_id INTEGER PRIMARY KEY, previous_status TEXT NOT NULL, removed_at TEXT NOT NULL, removed_by TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alert_resets (
    project TEXT NOT NULL, vuln_id TEXT NOT NULL, after_alert_id INTEGER NOT NULL);
"""

TABLES = ["meta", "teams", "accounts", "projects", "products", "items", "mappings",
          "pending_candidates", "findings", "alerts", "item_removals", "alert_resets"]


def connect(db_path) -> sqlite3.Connection:
    """DB 파일에 연결한다. 폴더가 없으면 만든다."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def reset_from_seed(conn: sqlite3.Connection, seed_path) -> None:
    """모든 표를 비우고 초기 시드(data/seed.json)로 다시 채운다."""
    seed = json.loads(Path(seed_path).read_text(encoding="utf-8"))
    for table in TABLES:
        conn.execute(f"DELETE FROM {table}")
    conn.execute("DELETE FROM sqlite_sequence")
    conn.execute("INSERT INTO meta VALUES ('default_account', ?)", (seed["default_account"],))
    conn.execute("INSERT INTO meta VALUES ('security_admin_email', ?)", (seed["security_admin_email"],))
    conn.executemany("INSERT INTO teams VALUES (:id, :name)", seed["teams"])
    conn.executemany("INSERT INTO accounts VALUES (:id, :name, :team, :role, :token)", seed["accounts"])
    conn.executemany("INSERT INTO projects VALUES (:id, :name, :team, :alert_email)", seed["projects"])
    for p in seed["products"]:
        conn.execute("INSERT INTO products VALUES (?, ?, ?, ?)",
                     (p["key"], p["name"], p["identifier"], json.dumps(p["aliases"], ensure_ascii=False)))
    for item in seed["items"]:
        add_item(conn, item["project"], item["raw_text"], item["product"], item["version"], item["status"])
        if item["status"] == "confirmed":
            save_mapping(conn, item["raw_text"], item["product"])
    conn.commit()


# ---------------- 읽기 ----------------

def get_meta(conn, key: str):
    """meta 표의 값을 읽는다."""
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def get_account(conn, account_id: str):
    """계정 ID로 계정을 찾는다."""
    row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    return dict(row) if row else None


def get_account_by_token(conn, token: str):
    """토큰으로 계정을 찾는다."""
    row = conn.execute("SELECT * FROM accounts WHERE token = ?", (token,)).fetchone()
    return dict(row) if row else None


def list_projects(conn, team: str | None = None) -> list[dict]:
    """프로젝트 목록. team을 주면 그 팀 것만 돌려준다."""
    if team is None:
        rows = conn.execute("SELECT * FROM projects ORDER BY id").fetchall()
    else:
        rows = conn.execute("SELECT * FROM projects WHERE team = ? ORDER BY id", (team,)).fetchall()
    return [dict(r) for r in rows]


def find_project(conn, name_or_id: str):
    """프로젝트를 ID 또는 이름으로 찾는다. 띄어쓰기와 대소문자는 무시한다."""
    key = _norm(name_or_id)
    for p in list_projects(conn):
        if key in (_norm(p["id"]), _norm(p["name"])):
            return p
    return None


def list_products(conn) -> list[dict]:
    """등록할 수 있는 제품(표준 식별자) 목록."""
    rows = conn.execute("SELECT * FROM products ORDER BY key").fetchall()
    return [dict(r) | {"aliases": json.loads(r["aliases"])} for r in rows]


def list_items(conn, project_id: str) -> list[dict]:
    """프로젝트에 등록된 항목 목록. 삭제한 항목(status='removed')은 뺀다.

    조회·현황·주기 검색·중복 확인이 모두 이 함수를 거치므로, 지운 항목은 모든 곳에서 빠진다.
    """
    rows = conn.execute("SELECT * FROM items WHERE project = ? AND status != 'removed' ORDER BY id",
                        (project_id,)).fetchall()
    return [dict(r) for r in rows]


def find_item(conn, project_id: str, product: str, version) -> dict | None:
    """프로젝트에 같은 표준 제품·버전으로 확정된 항목이 있으면 돌려준다(중복 등록 확인용).

    버전은 띄어쓰기·대소문자만 무시하고 표기는 맞추지 않는다("1.24"와 "1.24.0"은 다르다).
    """
    for item in list_items(conn, project_id):
        if item["status"] == "confirmed" and item["product"] == product and _norm(item["version"] or "") == _norm(version or ""):
            return item
    return None


def find_item_by_text(conn, project_id: str, raw_text: str) -> dict | None:
    """프로젝트에 입력 문장이 같은 항목이 있으면 돌려준다. 띄어쓰기·대소문자는 무시한다(중복 등록 확인용)."""
    key = _norm(raw_text)
    return next((i for i in list_items(conn, project_id) if _norm(i["raw_text"]) == key), None)


def list_alerts(conn, project_id: str) -> list[dict]:
    """프로젝트의 알림 이력(보낸 순서대로)."""
    rows = conn.execute("SELECT * FROM alerts WHERE project = ? ORDER BY id", (project_id,)).fetchall()
    return [dict(r) for r in rows]


def get_mapping(conn, raw_text: str):
    """이전에 확정한 '입력 문장 -> 제품' 매핑을 찾는다."""
    row = conn.execute("SELECT product FROM mappings WHERE raw_key = ?", (_raw_key(raw_text),)).fetchone()
    return row["product"] if row else None


def get_pending(conn, account_id: str):
    """계정의 대기 중인 등록 후보를 읽는다."""
    row = conn.execute("SELECT * FROM pending_candidates WHERE account = ?", (account_id,)).fetchone()
    if not row:
        return None
    return dict(row) | {"candidates": json.loads(row["candidates"])}


# ---------------- 쓰기 ----------------

def add_item(conn, project_id: str, raw_text: str, product, version, status: str) -> int:
    """프로젝트에 항목을 등록한다."""
    cur = conn.execute(
        "INSERT INTO items (project, raw_text, product, version, status) VALUES (?, ?, ?, ?, ?)",
        (project_id, raw_text, product, version, status))
    conn.commit()
    return cur.lastrowid


def get_item(conn, project_id: str, item_id: int) -> dict | None:
    """프로젝트의 삭제되지 않은 항목 하나. 없거나 이미 지웠으면 None."""
    row = conn.execute("SELECT * FROM items WHERE id = ? AND project = ? AND status != 'removed'",
                       (item_id, project_id)).fetchone()
    return dict(row) if row else None


def remove_item(conn, project_id: str, item_id: int, account_id: str, removed_at: str) -> dict | None:
    """항목을 삭제 표시한다(soft delete). 지운 항목을 돌려주고, 없거나 이미 지웠으면 None.

    - 항목 상태를 removed로 바꾸고 삭제 기록(이전 상태, 시각, 계정)을 남긴다. 알림 이력은 지우지 않는다.
    - 이 삭제로 프로젝트에 같은 표준 제품이 하나도 남지 않으면, 그 제품의 탐지 기록을 지우고
      관련 취약점의 알림을 초기화한다. 같은 SW를 다시 등록하면 알림 조건에 따라 다시 알린다.
    """
    item = get_item(conn, project_id, item_id)
    if item is None:
        return None
    conn.execute("UPDATE items SET status = 'removed' WHERE id = ?", (item_id,))
    conn.execute("INSERT OR REPLACE INTO item_removals VALUES (?, ?, ?, ?)",
                 (item_id, item["status"], removed_at, account_id))
    product = item["product"]
    still_used = product and any(i["product"] == product for i in list_items(conn, project_id))
    if product and not still_used:
        vulns = [r["vuln_id"] for r in conn.execute(
            "SELECT vuln_id FROM findings WHERE project = ? AND product = ?", (project_id, product))]
        for vuln_id in vulns:
            last = conn.execute("SELECT COALESCE(MAX(id), 0) FROM alerts WHERE project = ? AND vuln_id = ?",
                                (project_id, vuln_id)).fetchone()[0]
            conn.execute("INSERT INTO alert_resets VALUES (?, ?, ?)", (project_id, vuln_id, last))
        conn.execute("DELETE FROM findings WHERE project = ? AND product = ?", (project_id, product))
    conn.commit()
    return item


def save_mapping(conn, raw_text: str, product: str) -> None:
    """확정한 매핑을 저장해 다음 등록에서 다시 쓴다."""
    conn.execute("INSERT OR REPLACE INTO mappings VALUES (?, ?)", (_raw_key(raw_text), product))
    conn.commit()


def save_pending(conn, account_id: str, project_id: str, raw_text: str, version, candidates: list) -> None:
    """계정의 대기 중인 후보를 저장한다. 계정당 하나만 둔다."""
    conn.execute("INSERT OR REPLACE INTO pending_candidates VALUES (?, ?, ?, ?, ?)",
                 (account_id, project_id, raw_text, version, json.dumps(candidates, ensure_ascii=False)))
    conn.commit()


def set_meta(conn, key: str, value) -> None:
    """meta 표에 값을 쓴다."""
    conn.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, str(value)))
    conn.commit()


def save_finding(conn, project_id: str, match: dict) -> None:
    """탐지한 취약점을 기록한다. 같은 (프로젝트, 취약점, 제품)은 최신 값으로 덮어쓴다."""
    conn.execute("INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (project_id, match["id"], match["product"], match["version"],
                  match["score"], match["score_source"], int(match["kev"])))
    conn.commit()


def last_alert(conn, project_id: str, vuln_id: str):
    """이 (프로젝트, 취약점)에 마지막으로 보낸 알림. 없으면 None.

    SW를 지워 알림을 초기화한 적이 있으면(alert_resets) 그 뒤에 보낸 알림만 본다.
    그래서 지운 SW를 다시 등록하면 처음 등록한 것처럼 다시 알린다.
    """
    row = conn.execute(
        "SELECT * FROM alerts WHERE project = ? AND vuln_id = ? AND id > COALESCE("
        "(SELECT MAX(after_alert_id) FROM alert_resets WHERE project = ? AND vuln_id = ?), 0) "
        "ORDER BY id DESC LIMIT 1",
        (project_id, vuln_id, project_id, vuln_id)).fetchone()
    return dict(row) | {"kev": bool(row["kev"])} if row else None


def add_alert(conn, project_id: str, vuln_id: str, reason: str, score, kev: bool, sent_at: str, file: str) -> None:
    """보낸 알림을 이력에 남긴다."""
    conn.execute("INSERT INTO alerts (project, vuln_id, reason, score, kev, sent_at, file) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (project_id, vuln_id, reason, score, int(kev), sent_at, file))
    conn.commit()


def clear_pending(conn, account_id: str) -> None:
    """계정의 대기 중인 후보를 지운다."""
    conn.execute("DELETE FROM pending_candidates WHERE account = ?", (account_id,))
    conn.commit()


# ---------------- 내부 도우미 ----------------

def _norm(text: str) -> str:
    """비교용으로 띄어쓰기를 없애고 소문자로 바꾼다."""
    return "".join(str(text).split()).lower()


def _raw_key(raw_text: str) -> str:
    """매핑 키. 버전 숫자를 뺀 제품 이름 부분만 쓴다."""
    words = [w for w in str(raw_text).split() if not w[0].isdigit()]
    return _norm(" ".join(words))
