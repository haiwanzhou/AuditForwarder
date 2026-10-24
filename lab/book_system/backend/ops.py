"""受管系统的"运维面"接口。

为什么需要这个模块
------------------
合谋检测的规则库（server/src/collusion/collusion.cpp）是按"服务器运维"语义写的：
删备份 / 卸载卷 / 删快照 / 改配置 / 重启服务 / 清日志 / 生成密钥 / 分发密钥。
原版图书系统只有图书 CRUD，凑不出这些动作，R-001/002/003/004 永远不会命中。

设计约束（与 docs/CODE_CHANGE_PLAN.md 0.4 一致）
----------------------------------------------
1. 所有接口只允许管理员级角色（admin / librarian）调用。普通读者 member 一律 403。
   合谋主体是高权限用户，普通用户不参与。
2. 每个接口单独看都是合法运维动作，权限校验全部通过——单步合规，靠组合才构成危害。
3. URL 路径刻意包含资产组关键词，因为服务端按 target(URL 路径) 做通配匹配：
      *backup* / *snapshot* / *storage* / *volume*  → backup-group
      *key* / *secret*                             → key-mgmt-group
      *system* / *config*                          → sys-config-group
      *books* / *export* / *audit*                 → db-group
"""

import csv
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, g, jsonify, request
from werkzeug.security import generate_password_hash as _hash_password

try:
    from .auth import role_required
    from .database import BASE_DIR, DB_PATH, db_session
except ImportError:
    from auth import role_required
    from database import BASE_DIR, DB_PATH, db_session


ops_bp = Blueprint("ops", __name__, url_prefix="/api")

RUNTIME_DIR = BASE_DIR / "runtime"
BACKUP_DIR = RUNTIME_DIR / "backups"
SNAPSHOT_DIR = RUNTIME_DIR / "snapshots"
CONFIG_PATH = RUNTIME_DIR / "system_config.json"

ADMIN_ROLES = ("admin", "librarian")

DEFAULT_CONFIG = {
    "retention_days": 30,
    "backup_enabled": True,
    "export_quota": 10000,
    "log_level": "info",
}


# ---------------------------------------------------------------------------
# 基础设施
# ---------------------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _who():
    user = getattr(g, "current_user", None) or {}
    return user.get("username", "unknown"), user.get("role", "unknown")


def _ok(data=None, message="success", code=200):
    body = {"status": "success", "message": message}
    if data is not None:
        body["data"] = data
    return jsonify(body), code


def _err(message, code=400):
    return jsonify({"status": "error", "message": message}), code


def _audit(action, target, detail=""):
    """系统自身的操作审计。攻击者可以清掉它，但外部转发已经留证。"""
    user, role = _who()
    with db_session() as conn:
        conn.execute(
            "INSERT INTO ops_audit_logs (ts, username, role, action, target, detail)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (_now(), user, role, action, target, detail[:500]),
        )


def ensure_ops_schema():
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

    with db_session() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ops_volumes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                mount_point TEXT NOT NULL,
                size_mb INTEGER NOT NULL DEFAULT 0,
                mounted INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS ops_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                distributed INTEGER NOT NULL DEFAULT 0,
                created_by TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS ops_privileges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                privilege TEXT NOT NULL,
                granted_by TEXT,
                granted_at TEXT
            );
            CREATE TABLE IF NOT EXISTS ops_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                username TEXT,
                role TEXT,
                action TEXT NOT NULL,
                target TEXT,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ops_audit_ts ON ops_audit_logs(ts);
            """
        )

        # 初始存储卷：一个备份盘，默认已挂载
        exists = conn.execute("SELECT COUNT(*) AS c FROM ops_volumes").fetchone()["c"]
        if exists == 0:
            conn.executemany(
                "INSERT INTO ops_volumes (name, mount_point, size_mb, mounted)"
                " VALUES (?, ?, ?, ?)",
                [
                    ("backup-disk-1", "/mnt/backup", 51200, 1),
                    ("backup-disk-2", "/mnt/backup2", 51200, 1),
                ],
            )

    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(
            json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2), encoding="utf-8"
        )


def _copy_db(dest: Path):
    """用 SQLite 在线备份 API 做一致性副本（不是简单文件复制）。"""
    if dest.exists():
        dest.unlink()
    src = sqlite3.connect(DB_PATH)
    try:
        dst = sqlite3.connect(dest)
        try:
            with dst:
                src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def _safe_name(name: str):
    """只允许访问本目录下的普通文件名，挡住 ../。"""
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        return None
    return name


# ---------------------------------------------------------------------------
# 备份（backup-group）→ R-001 第 1 步
# ---------------------------------------------------------------------------

@ops_bp.route("/backup", methods=["GET"])
@role_required(*ADMIN_ROLES)
def list_backup():
    files = sorted(
        (
            {
                "name": p.name,
                "size": p.stat().st_size,
                "created_at": datetime.fromtimestamp(
                    p.stat().st_mtime, timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            for p in BACKUP_DIR.glob("*.db")
        ),
        key=lambda x: x["created_at"],
        reverse=True,
    )
    return _ok({"backups": files, "count": len(files)})


@ops_bp.route("/backup", methods=["POST"])
@role_required(*ADMIN_ROLES)
def create_backup():
    data = request.get_json(silent=True) or {}
    name = data.get("name") or datetime.now().strftime("backup_%Y%m%d_%H%M%S")
    name = _safe_name(name)
    if name is None:
        return _err("invalid backup name")
    if not name.endswith(".db"):
        name += ".db"

    dest = BACKUP_DIR / name
    _copy_db(dest)
    _audit("create_backup", f"/api/backup/{name}", "backup created")
    return _ok({"name": name, "size": dest.stat().st_size}, "backup created", 201)


@ops_bp.route("/backup/<name>", methods=["DELETE"])
@role_required(*ADMIN_ROLES)
def delete_backup(name):
    name = _safe_name(name)
    if name is None:
        return _err("invalid backup name")
    dest = BACKUP_DIR / name
    if not dest.exists():
        return _err("backup not found", 404)

    dest.unlink()
    _audit("delete_backup", f"/api/backup/{name}", "backup deleted")
    return _ok({"name": name}, "backup deleted")


@ops_bp.route("/backup/<name>/restore", methods=["POST"])
@role_required(*ADMIN_ROLES)
def restore_backup(name):
    name = _safe_name(name)
    if name is None:
        return _err("invalid backup name")
    src = BACKUP_DIR / name
    if not src.exists():
        return _err("backup not found", 404)

    con = sqlite3.connect(src)
    try:
        dst = sqlite3.connect(DB_PATH)
        try:
            with dst:
                con.backup(dst)
        finally:
            dst.close()
    finally:
        con.close()

    _audit("restore_backup", f"/api/backup/{name}", "database restored")
    return _ok({"name": name}, "database restored")


# ---------------------------------------------------------------------------
# 快照（snapshot，同属 backup-group）→ R-001 第 3 步
# ---------------------------------------------------------------------------

@ops_bp.route("/snapshot", methods=["GET"])
@role_required(*ADMIN_ROLES)
def list_snapshot():
    files = sorted(
        (
            {
                "name": p.name,
                "size": p.stat().st_size,
                "created_at": datetime.fromtimestamp(
                    p.stat().st_mtime, timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            for p in SNAPSHOT_DIR.glob("*.snap")
        ),
        key=lambda x: x["created_at"],
        reverse=True,
    )
    return _ok({"snapshots": files, "count": len(files)})


@ops_bp.route("/snapshot", methods=["POST"])
@role_required(*ADMIN_ROLES)
def create_snapshot():
    data = request.get_json(silent=True) or {}
    name = data.get("name") or datetime.now().strftime("snapshot_%Y%m%d_%H%M%S")
    name = _safe_name(name)
    if name is None:
        return _err("invalid snapshot name")
    if not name.endswith(".snap"):
        name += ".snap"

    dest = SNAPSHOT_DIR / name
    _copy_db(dest)
    _audit("create_snapshot", f"/api/snapshot/{name}", "snapshot created")
    return _ok({"name": name, "size": dest.stat().st_size}, "snapshot created", 201)


@ops_bp.route("/snapshot/<name>", methods=["DELETE"])
@role_required(*ADMIN_ROLES)
def delete_snapshot(name):
    name = _safe_name(name)
    if name is None:
        return _err("invalid snapshot name")
    dest = SNAPSHOT_DIR / name
    if not dest.exists():
        return _err("snapshot not found", 404)

    dest.unlink()
    _audit("delete_snapshot", f"/api/snapshot/{name}", "snapshot deleted")
    return _ok({"name": name}, "snapshot deleted")


# ---------------------------------------------------------------------------
# 存储卷（storage/volume，并入 backup-group）→ R-001 第 2 步
# ---------------------------------------------------------------------------

@ops_bp.route("/storage/volume", methods=["GET"])
@role_required(*ADMIN_ROLES)
def list_volume():
    with db_session() as conn:
        rows = conn.execute(
            "SELECT id, name, mount_point, size_mb, mounted FROM ops_volumes ORDER BY id"
        ).fetchall()
    return _ok({"volumes": [dict(r) for r in rows]})


@ops_bp.route("/storage/volume/<int:volume_id>/unmount", methods=["PATCH"])
@role_required(*ADMIN_ROLES)
def unmount_volume(volume_id):
    with db_session() as conn:
        row = conn.execute(
            "SELECT id, name, mount_point, mounted FROM ops_volumes WHERE id = ?",
            (volume_id,),
        ).fetchone()
        if row is None:
            return _err("volume not found", 404)
        if row["mounted"] == 0:
            return _ok({"id": volume_id, "mounted": 0}, "volume already unmounted")

        conn.execute("UPDATE ops_volumes SET mounted = 0 WHERE id = ?", (volume_id,))

    _audit(
        "unmount_volume",
        f"/api/storage/volume/{volume_id}/unmount",
        f"{row['name']} @ {row['mount_point']}",
    )
    return _ok(
        {"id": volume_id, "name": row["name"], "mount_point": row["mount_point"], "mounted": 0},
        "volume unmounted",
    )


@ops_bp.route("/storage/volume/<int:volume_id>/mount", methods=["PATCH"])
@role_required(*ADMIN_ROLES)
def mount_volume(volume_id):
    with db_session() as conn:
        row = conn.execute(
            "SELECT id, name, mount_point FROM ops_volumes WHERE id = ?", (volume_id,)
        ).fetchone()
        if row is None:
            return _err("volume not found", 404)
        conn.execute("UPDATE ops_volumes SET mounted = 1 WHERE id = ?", (volume_id,))

    _audit("mount_volume", f"/api/storage/volume/{volume_id}/mount", row["name"])
    return _ok({"id": volume_id, "mounted": 1}, "volume mounted")


# ---------------------------------------------------------------------------
# 系统配置 / 服务 / 日志（sys-config-group）→ R-003 三步
# ---------------------------------------------------------------------------

@ops_bp.route("/system/config", methods=["GET"])
@role_required(*ADMIN_ROLES)
def get_config():
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return _ok({"config": cfg})


@ops_bp.route("/system/config", methods=["PUT"])
@role_required(*ADMIN_ROLES)
def put_config():
    data = request.get_json(silent=True) or {}
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    changed = {k: v for k, v in data.items() if k in DEFAULT_CONFIG}
    cfg.update(changed)
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")

    _audit("modify_config", "/api/system/config", json.dumps(changed, ensure_ascii=False))
    return _ok({"config": cfg, "changed": changed}, "config modified")


@ops_bp.route("/system/service/restart", methods=["POST"])
@role_required(*ADMIN_ROLES)
def restart_service():
    _audit("restart_service", "/api/system/service/restart", "app service restarted")
    return _ok(
        {"service": "book-system", "restarted_at": _now(), "status": "running"},
        "service restarted",
    )


@ops_bp.route("/system/logs", methods=["GET"])
@role_required(*ADMIN_ROLES)
def list_system_logs():
    with db_session() as conn:
        rows = conn.execute(
            "SELECT id, ts, username, action, target FROM ops_audit_logs"
            " ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return _ok({"logs": [dict(r) for r in rows], "count": len(rows)})


@ops_bp.route("/system/logs/clear", methods=["DELETE"])
@role_required("admin")
def clear_system_logs():
    """清空系统自身审计日志。只有 admin 能清（librarian 不行）——单步仍然合规。"""
    with db_session() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM ops_audit_logs").fetchone()["c"]
        conn.execute("DELETE FROM ops_audit_logs")

    _audit("clear_logs", "/api/system/logs/clear", f"{count} rows removed")
    return _ok({"deleted": count}, "system logs cleared")


# ---------------------------------------------------------------------------
# 密钥管理（key-mgmt-group）→ R-002 三步
# ---------------------------------------------------------------------------

@ops_bp.route("/key", methods=["GET"])
@role_required(*ADMIN_ROLES)
def list_key():
    with db_session() as conn:
        rows = conn.execute(
            "SELECT id, name, fingerprint, distributed, created_by, created_at"
            " FROM ops_keys ORDER BY id DESC"
        ).fetchall()
    return _ok({"keys": [dict(r) for r in rows], "count": len(rows)})


@ops_bp.route("/key", methods=["POST"])
@role_required(*ADMIN_ROLES)
def create_key():
    data = request.get_json(silent=True) or {}
    name = data.get("name") or datetime.now().strftime("key_%Y%m%d_%H%M%S")
    user, _role = _who()

    import hashlib
    import os

    raw = os.urandom(24).hex()
    fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:32]

    with db_session() as conn:
        cur = conn.execute(
            "INSERT INTO ops_keys (name, fingerprint, distributed, created_by, created_at)"
            " VALUES (?, ?, 0, ?, ?)",
            (name, fingerprint, user, _now()),
        )
        key_id = cur.lastrowid

    _audit("create_key", f"/api/key/{key_id}", name)
    return _ok({"id": key_id, "name": name, "fingerprint": fingerprint}, "key generated", 201)


@ops_bp.route("/key/<int:key_id>/distribute", methods=["POST"])
@role_required(*ADMIN_ROLES)
def distribute_key(key_id):
    data = request.get_json(silent=True) or {}
    target_user = data.get("to", "")

    with db_session() as conn:
        row = conn.execute(
            "SELECT id, name FROM ops_keys WHERE id = ?", (key_id,)
        ).fetchone()
        if row is None:
            return _err("key not found", 404)
        conn.execute("UPDATE ops_keys SET distributed = 1 WHERE id = ?", (key_id,))

    _audit("distribute_key", f"/api/key/{key_id}/distribute", f"to={target_user}")
    return _ok({"id": key_id, "distributed": 1, "to": target_user}, "key distributed")


@ops_bp.route("/key/audit/clear", methods=["DELETE"])
@role_required("admin")
def clear_key_audit():
    """清除密钥分发审计痕迹（R-002 第 3 步）。"""
    with db_session() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM ops_audit_logs WHERE action LIKE '%key%'"
        ).fetchone()["c"]
        conn.execute("DELETE FROM ops_audit_logs WHERE action LIKE '%key%'")

    _audit("clear_key_audit", "/api/key/audit/clear", f"{count} rows removed")
    return _ok({"deleted": count}, "key audit cleared")


# ---------------------------------------------------------------------------
# 数据导出 / 提权（db-group）→ R-004、R-007
# ---------------------------------------------------------------------------

@ops_bp.route("/books/export", methods=["GET"])
@role_required(*ADMIN_ROLES)
def export_books():
    with db_session() as conn:
        rows = conn.execute(
            "SELECT id, isbn, title, author, genre, publication_year,"
            " total_copies, available_copies FROM books ORDER BY id"
        ).fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["id", "isbn", "title", "author", "genre", "publication_year",
         "total_copies", "available_copies"]
    )
    for r in rows:
        writer.writerow(list(r))

    _audit("export_books", "/api/books/export", f"{len(rows)} rows exported")

    payload = buf.getvalue()
    return _ok(
        {"rows": len(rows), "content_type": "text/csv", "size": len(payload)},
        "books exported",
    )


@ops_bp.route("/users/<int:user_id>/privilege", methods=["PATCH"])
@role_required("admin")
def grant_export_privilege(user_id):
    """给某个账号追加"导出"权限标记。执行人必须是 admin —— 但这一步本身完全合规。"""
    data = request.get_json(silent=True) or {}
    privilege = data.get("privilege", "export")

    with db_session() as conn:
        row = conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None:
            return _err("user not found", 404)
        conn.execute(
            "INSERT INTO ops_privileges (user_id, privilege, granted_by, granted_at)"
            " VALUES (?, ?, ?, ?)",
            (user_id, privilege, _who()[0], _now()),
        )

    _audit("grant_privilege", f"/api/users/{user_id}/privilege",
           f"{privilege} -> {row['username']}")
    return _ok(
        {"user_id": user_id, "username": row["username"], "privilege": privilege},
        "privilege granted",
    )


@ops_bp.route("/books/audit/clear", methods=["DELETE"])
@role_required("admin")
def clear_book_audit():
    """清除图书/数据域的审计痕迹（R-004 第 3 步）。"""
    with db_session() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM ops_audit_logs"
            " WHERE action IN ('export_books', 'grant_privilege')"
        ).fetchone()["c"]
        conn.execute(
            "DELETE FROM ops_audit_logs"
            " WHERE action IN ('export_books', 'grant_privilege')"
        )

    _audit("clear_book_audit", "/api/books/audit/clear", f"{count} rows removed")
    return _ok({"deleted": count}, "data audit cleared")


# ---------------------------------------------------------------------------
# 管理员账号编排（general-group）→ R-005 三步
# 注意：三步天然就是三个不同管理员各自合规的动作，谁也看不出问题。
# ---------------------------------------------------------------------------

@ops_bp.route("/admin/user", methods=["POST"])
@role_required("admin")
def admin_create_user(username=None):
    """创建账号，可以指定角色。原版 /api/auth/register 只能建普通读者。"""
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "member")

    if not username or not password:
        return _err("username and password are required")
    if role not in ("admin", "librarian", "member"):
        return _err("invalid role")

    try:
        with db_session() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, _hash_password(password), role),
            )
            user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return _err("username already exists", 409)

    _audit("admin_create_user", f"/api/admin/user/{user_id}", f"{username} as {role}")
    return _ok({"id": user_id, "username": username, "role": role}, "user created", 201)


@ops_bp.route("/admin/user/<int:user_id>/assign-admin", methods=["POST"])
@role_required("admin")
def admin_assign_role(user_id):
    """把账号提升为管理员。单看就是一次普通的人员调整。"""
    with db_session() as conn:
        row = conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None:
            return _err("user not found", 404)
        conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))

    _audit("assign_admin", f"/api/admin/user/{user_id}/assign-admin", row["username"])
    return _ok({"id": user_id, "username": row["username"], "role": "admin"}, "role assigned")


@ops_bp.route("/admin/exec", methods=["POST"])
@role_required("admin")
def admin_exec():
    """管理员执行敏感动作。单看是合法运维，叠加前两步就是给自己留后门。

    动作名放在请求体里，**刻意不进 URL**：URL 会被服务端当作 res_key 做资产组匹配，
    `/api/admin/exec/purge_books` 里的 books 会把它拉进 db-group，
    导致 R-005 的三步分属两个资产组、聚合不到一起，规则永远不命中。
    """
    data = request.get_json(silent=True) or {}
    action = data.get("action", "")

    if action == "purge_books":
        with db_session() as conn:
            count = conn.execute("SELECT COUNT(*) AS c FROM books").fetchone()["c"]
            conn.execute("DELETE FROM loans")
            conn.execute("DELETE FROM books")
        _audit("admin_exec_purge", f"/api/admin/exec/{action}", f"{count} books purged")
        return _ok({"action": action, "purged": count}, "books purged")

    if action == "export_all":
        with db_session() as conn:
            count = conn.execute("SELECT COUNT(*) AS c FROM books").fetchone()["c"]
        _audit("admin_exec_export", f"/api/admin/exec/{action}", f"{count} books exported")
        return _ok({"action": action, "exported": count}, "all data exported")

    return _err("unknown action, expect purge_books or export_all", 404)
