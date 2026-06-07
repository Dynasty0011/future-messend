from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, ValidationError

from .db import DB_PATH, DATA_DIR, connect, ensure_folder, execute, fetch_all, fetch_one, init_db, session
from .security import (
    constant_time_equals,
    create_access_token,
    decode_access_token,
    hash_password,
    new_csrf_token,
    now_utc,
    random_id,
    sha256_hex,
    verify_password,
)

BASE_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = BASE_DIR / "app" / "static"
UPLOAD_DIR = DATA_DIR / "uploads"
AVATAR_DIR = DATA_DIR / "avatars"
KEY_DIR = DATA_DIR / "keys"
CONFIG_PATH = DATA_DIR / "config.json"
ALLOWED_FILE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".webm", ".mp3", ".ogg", ".pdf", ".zip", ".txt", ".json", ".csv", ".docx", ".xlsx"
}
MAX_UPLOAD_SIZE = 150 * 1024 * 1024

app = FastAPI(title="Future Messenger", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=64)
    public_key: str = ""


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ProfileUpdateIn(BaseModel):
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    bio: Optional[str] = Field(default=None, max_length=500)
    public_key: Optional[str] = None


class ConversationCreateIn(BaseModel):
    type: str
    title: str
    direct_peer_id: Optional[int] = None
    member_ids: list[int] = Field(default_factory=list)


class MessageSendIn(BaseModel):
    ciphertext: str
    envelope: dict[str, Any] = Field(default_factory=dict)
    reply_to_id: Optional[int] = None
    forwarded_from_id: Optional[int] = None


class MessageEditIn(BaseModel):
    ciphertext: str
    envelope: dict[str, Any] = Field(default_factory=dict)


class ReactionIn(BaseModel):
    emoji: str = Field(min_length=1, max_length=8)


class CallSignalIn(BaseModel):
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)


class PasswordResetRequestIn(BaseModel):
    email: EmailStr


class PasswordResetCompleteIn(BaseModel):
    email: EmailStr
    code: str
    new_password: str = Field(min_length=8, max_length=128)


class ConversationJoinIn(BaseModel):
    invite_code: str
    secret: str = ""


class WorkspaceState:
    def __init__(self) -> None:
        self.user_connections: dict[int, set[WebSocket]] = {}
        self.conv_connections: dict[int, set[WebSocket]] = {}
        self.user_online_count: dict[int, int] = {}

    async def connect(self, websocket: WebSocket, user_id: int, conv_id: Optional[int] = None) -> None:
        await websocket.accept()
        self.user_connections.setdefault(user_id, set()).add(websocket)
        self.user_online_count[user_id] = self.user_online_count.get(user_id, 0) + 1
        if conv_id is not None:
            self.conv_connections.setdefault(conv_id, set()).add(websocket)

    async def disconnect(self, websocket: WebSocket, user_id: int, conv_id: Optional[int] = None) -> None:
        if user_id in self.user_connections:
            self.user_connections[user_id].discard(websocket)
            if not self.user_connections[user_id]:
                self.user_connections.pop(user_id, None)
                self.user_online_count[user_id] = 0
        if conv_id is not None and conv_id in self.conv_connections:
            self.conv_connections[conv_id].discard(websocket)
            if not self.conv_connections[conv_id]:
                self.conv_connections.pop(conv_id, None)

    async def broadcast_conv(self, conv_id: int, payload: dict[str, Any]) -> None:
        targets = list(self.conv_connections.get(conv_id, set()))
        for ws in targets:
            try:
                await ws.send_json(payload)
            except Exception:
                pass

state = WorkspaceState()


def utcnow() -> str:
    return now_utc().isoformat()


def safe_json_loads(raw: str, default: Any) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return default


def ensure_runtime() -> None:
    for p in [DATA_DIR, UPLOAD_DIR, AVATAR_DIR, KEY_DIR, STATIC_DIR]:
        ensure_folder(p)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(
            json.dumps(
                {
                    "app_name": "Future Messenger",
                    "created_at": utcnow(),
                    "jwt_secret": secrets.token_urlsafe(48),
                    "invite_secret": secrets.token_urlsafe(32),
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
    init_db()


def load_config() -> dict[str, Any]:
    ensure_runtime()
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def save_config(cfg: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


def get_jwt_secret() -> str:
    return load_config()["jwt_secret"]


def get_current_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_access_token(token, get_jwt_secret())
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        user_id = int(payload["sub"])
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid subject") from exc
    with session() as conn:
        user = fetch_one(conn, "SELECT * FROM users WHERE id=?", (user_id,))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def get_current_user_optional(request: Request) -> dict[str, Any] | None:
    try:
        return get_current_user(request)
    except HTTPException:
        return None


def set_auth_cookies(response: Response, user_id: int, csrf_token: str) -> None:
    token = create_access_token(str(user_id), get_jwt_secret())
    response.set_cookie("access_token", token, httponly=True, secure=False, samesite="lax", path="/")
    response.set_cookie("csrf_token", csrf_token, httponly=False, secure=False, samesite="lax", path="/")


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("csrf_token", path="/")


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not request.url.path.startswith("/api/auth/"):
        csrf_cookie = request.cookies.get("csrf_token")
        csrf_header = request.headers.get("x-csrf-token")
        if not csrf_cookie or not csrf_header or not constant_time_equals(csrf_cookie, csrf_header):
            return JSONResponse({"detail": "CSRF verification failed"}, status_code=403)
    return await call_next(request)


@app.on_event("startup")
async def startup() -> None:
    ensure_runtime()


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "time": utcnow()}


@app.post("/api/auth/register")
async def register(data: RegisterIn, response: Response) -> dict[str, Any]:
    with session() as conn:
        existing = fetch_one(conn, "SELECT id FROM users WHERE email=?", (data.email.lower(),))
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")
        user_id = execute(
            conn,
            """
            INSERT INTO users (email, password_hash, display_name, public_key, created_at, updated_at, csrf_token)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.email.lower(),
                hash_password(data.password),
                data.display_name.strip(),
                data.public_key or "",
                utcnow(),
                utcnow(),
                new_csrf_token(),
            ),
        )
        user = fetch_one(conn, "SELECT * FROM users WHERE id=?", (user_id,))
    set_auth_cookies(response, user_id, user["csrf_token"])
    return {"user": public_user(user)}


@app.post("/api/auth/login")
async def login(data: LoginIn, response: Response) -> dict[str, Any]:
    with session() as conn:
        user = fetch_one(conn, "SELECT * FROM users WHERE email=?", (data.email.lower(),))
        if not user or not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=400, detail="Invalid credentials")
        csrf_token = new_csrf_token()
        conn.execute("UPDATE users SET is_online=1, csrf_token=?, updated_at=? WHERE id=?", (csrf_token, utcnow(), user["id"]))
        user = fetch_one(conn, "SELECT * FROM users WHERE id=?", (user["id"],))
    set_auth_cookies(response, int(user["id"]), csrf_token)
    return {"user": public_user(user)}


@app.post("/api/auth/logout")
async def logout(response: Response, request: Request) -> dict[str, Any]:
    user = get_current_user_optional(request)
    if user:
        with session() as conn:
            conn.execute("UPDATE users SET is_online=0, typing_conv_id=NULL, last_seen=?, updated_at=? WHERE id=?", (utcnow(), utcnow(), user["id"]))
    clear_auth_cookies(response)
    return {"ok": True}


@app.get("/api/auth/me")
async def me(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    return {"user": public_user(user), "csrf_token": request.cookies.get("csrf_token", "")}


@app.post("/api/auth/recovery/request")
async def recovery_request(data: PasswordResetRequestIn) -> dict[str, Any]:
    # In-app recovery flow: returns a one-time code to the authenticated user flow.
    with session() as conn:
        user = fetch_one(conn, "SELECT * FROM users WHERE email=?", (data.email.lower(),))
        if not user:
            return {"ok": True, "sent": False}
        code = secrets.token_urlsafe(10)
        conn.execute(
            "UPDATE users SET recovery_code_hash=?, updated_at=? WHERE id=?",
            (sha256_hex(code), utcnow(), user["id"]),
        )
    return {"ok": True, "sent": True, "code": code}


@app.post("/api/auth/recovery/complete")
async def recovery_complete(data: PasswordResetCompleteIn) -> dict[str, Any]:
    with session() as conn:
        user = fetch_one(conn, "SELECT * FROM users WHERE email=?", (data.email.lower(),))
        if not user or not user["recovery_code_hash"] or sha256_hex(data.code) != user["recovery_code_hash"]:
            raise HTTPException(status_code=400, detail="Invalid recovery code")
        conn.execute(
            "UPDATE users SET password_hash=?, recovery_code_hash='', updated_at=? WHERE id=?",
            (hash_password(data.new_password), utcnow(), user["id"]),
        )
    return {"ok": True}


@app.get("/api/users/search")
async def search_users(q: str = "", request: Request = None) -> dict[str, Any]:
    current = get_current_user(request)
    with session() as conn:
        rows = fetch_all(
            conn,
            """
            SELECT id, email, display_name, avatar_path, bio, public_key, is_online, last_seen
            FROM users
            WHERE id != ? AND (email LIKE ? OR display_name LIKE ?)
            ORDER BY display_name ASC
            LIMIT 50
            """,
            (current["id"], f"%{q}%", f"%{q}%"),
        )
    return {"users": rows}


@app.get("/api/profile")
async def profile(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    return {"user": public_user(user)}


@app.put("/api/profile")
async def update_profile(data: ProfileUpdateIn, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    updates = []
    values: list[Any] = []
    if data.display_name is not None:
        updates.append("display_name=?")
        values.append(data.display_name.strip())
    if data.bio is not None:
        updates.append("bio=?")
        values.append(data.bio)
    if data.public_key is not None:
        updates.append("public_key=?")
        values.append(data.public_key)
    if not updates:
        return {"user": public_user(user)}
    updates.append("updated_at=?")
    values.append(utcnow())
    values.append(user["id"])
    with session() as conn:
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", tuple(values))
        user = fetch_one(conn, "SELECT * FROM users WHERE id=?", (user["id"],))
    return {"user": public_user(user)}


@app.post("/api/profile/avatar")
async def upload_avatar(request: Request, file: UploadFile = File(...)) -> dict[str, Any]:
    user = get_current_user(request)
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
        raise HTTPException(status_code=400, detail="Unsupported avatar format")
    content = await file.read()
    if len(content) > 8 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Avatar too large")
    name = f"user_{user['id']}_{secrets.token_hex(16)}{suffix}"
    target = AVATAR_DIR / name
    target.write_bytes(content)
    with session() as conn:
        conn.execute("UPDATE users SET avatar_path=?, updated_at=? WHERE id=?", (f"/api/files/avatar/{name}", utcnow(), user["id"]))
    return {"avatar_url": f"/api/files/avatar/{name}"}


@app.get("/api/files/avatar/{name}")
async def get_avatar(name: str) -> Response:
    path = AVATAR_DIR / name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(path)


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "email": user["email"],
        "display_name": user["display_name"],
        "avatar_path": user.get("avatar_path") or "",
        "bio": user.get("bio") or "",
        "public_key": user.get("public_key") or "",
        "is_online": bool(user.get("is_online")),
        "last_seen": user.get("last_seen") or "",
        "typing_conv_id": user.get("typing_conv_id"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
    }


def conversation_members(conn, conversation_id: int) -> list[dict[str, Any]]:
    return fetch_all(
        conn,
        """
        SELECT u.id, u.email, u.display_name, u.avatar_path, u.public_key, u.is_online, u.last_seen, p.role
        FROM participants p
        JOIN users u ON u.id = p.user_id
        WHERE p.conversation_id=?
        ORDER BY p.id ASC
        """,
        (conversation_id,),
    )


def ensure_participant(conn, conversation_id: int, user_id: int, role: str = "member") -> None:
    conn.execute(
        "INSERT OR IGNORE INTO participants (conversation_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
        (conversation_id, user_id, role, utcnow()),
    )


def get_conversation(conn, conversation_id: int) -> dict[str, Any] | None:
    return fetch_one(conn, "SELECT * FROM conversations WHERE id=?", (conversation_id,))


def assert_can_access_conversation(conn, conversation_id: int, user_id: int) -> dict[str, Any]:
    conv = get_conversation(conn, conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    participant = fetch_one(
        conn,
        "SELECT id FROM participants WHERE conversation_id=? AND user_id=?",
        (conversation_id, user_id),
    )
    if not participant:
        raise HTTPException(status_code=403, detail="Access denied")
    return conv


@app.get("/api/conversations")
async def list_conversations(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        rows = fetch_all(
            conn,
            """
            SELECT c.*
            FROM conversations c
            JOIN participants p ON p.conversation_id = c.id
            WHERE p.user_id = ?
            ORDER BY c.updated_at DESC, c.id DESC
            """,
            (user["id"],),
        )
        result = []
        for row in rows:
            result.append(
                {
                    **row,
                    "members": conversation_members(conn, row["id"]),
                    "last_message": fetch_one(
                        conn,
                        "SELECT id, sender_id, ciphertext, envelope, created_at, edited_at, deleted_at FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 1",
                        (row["id"],),
                    ),
                }
            )
    return {"conversations": result}


@app.post("/api/conversations")
async def create_conversation(data: ConversationCreateIn, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    type_ = data.type.strip().lower()
    if type_ not in {"direct", "group", "channel"}:
        raise HTTPException(status_code=400, detail="Invalid conversation type")
    with session() as conn:
        if type_ == "direct":
            if not data.direct_peer_id:
                raise HTTPException(status_code=400, detail="direct_peer_id is required")
            peer = fetch_one(conn, "SELECT * FROM users WHERE id=?", (data.direct_peer_id,))
            if not peer:
                raise HTTPException(status_code=404, detail="Peer not found")
            existing = fetch_one(
                conn,
                """
                SELECT c.*
                FROM conversations c
                JOIN participants p1 ON p1.conversation_id = c.id
                JOIN participants p2 ON p2.conversation_id = c.id
                WHERE c.type='direct' AND p1.user_id=? AND p2.user_id=?
                LIMIT 1
                """,
                (user["id"], peer["id"]),
            )
            if existing:
                return {"conversation": conversation_payload(conn, existing["id"]) }
            title = f"{user['display_name']} • {peer['display_name']}"
        else:
            title = data.title.strip()
            if not title:
                raise HTTPException(status_code=400, detail="Title is required")
        conv_id = execute(
            conn,
            "INSERT INTO conversations (type, title, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (type_, title[:120], user["id"], utcnow(), utcnow()),
        )
        ensure_participant(conn, conv_id, user["id"], "owner" if type_ != "direct" else "member")
        if type_ == "direct":
            ensure_participant(conn, conv_id, int(data.direct_peer_id), "member")
        else:
            for member_id in data.member_ids:
                if member_id == user["id"]:
                    continue
                if fetch_one(conn, "SELECT id FROM users WHERE id=?", (member_id,)):
                    ensure_participant(conn, conv_id, int(member_id), "member")
        conv = conversation_payload(conn, conv_id)
    return {"conversation": conv}


@app.post("/api/conversations/join")
async def join_conversation(data: ConversationJoinIn, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    # Invite code format: conv_<id>_<secret> or secure raw tokens created by the frontend.
    if not data.invite_code.startswith("conv_"):
        raise HTTPException(status_code=400, detail="Invalid invite code")
    try:
        parts = data.invite_code.split("_", 2)
        conv_id = int(parts[1])
        secret = parts[2]
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid invite code") from exc
    if data.secret and data.secret != secret:
        raise HTTPException(status_code=400, detail="Invalid secret")
    with session() as conn:
        conv = get_conversation(conn, conv_id)
        if not conv:
            raise HTTPException(status_code=404, detail="Conversation not found")
        ensure_participant(conn, conv_id, user["id"], "member")
        conv = conversation_payload(conn, conv_id)
    return {"conversation": conv}


@app.get("/api/conversations/{conversation_id}")
async def get_conversation_detail(conversation_id: int, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        assert_can_access_conversation(conn, conversation_id, user["id"])
        return {"conversation": conversation_payload(conn, conversation_id)}


def conversation_payload(conn, conversation_id: int) -> dict[str, Any]:
    conv = get_conversation(conn, conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {
        **conv,
        "members": conversation_members(conn, conversation_id),
        "last_message": fetch_one(
            conn,
            "SELECT id, sender_id, ciphertext, envelope, reply_to_id, forwarded_from_id, created_at, edited_at, deleted_at, pinned, reaction_summary, read_by, delivered_to FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 1",
            (conversation_id,),
        ),
    }


@app.get("/api/conversations/{conversation_id}/messages")
async def list_messages(conversation_id: int, request: Request, before_id: int = 0, limit: int = 80) -> dict[str, Any]:
    user = get_current_user(request)
    limit = max(1, min(limit, 200))
    with session() as conn:
        assert_can_access_conversation(conn, conversation_id, user["id"])
        if before_id > 0:
            rows = fetch_all(
                conn,
                """
                SELECT * FROM messages
                WHERE conversation_id=? AND id < ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (conversation_id, before_id, limit),
            )
        else:
            rows = fetch_all(
                conn,
                """
                SELECT * FROM messages
                WHERE conversation_id=?
                ORDER BY id DESC
                LIMIT ?
                """,
                (conversation_id, limit),
            )
    return {"messages": list(reversed(rows))}


@app.post("/api/conversations/{conversation_id}/messages")
async def send_message_api(conversation_id: int, data: MessageSendIn, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        assert_can_access_conversation(conn, conversation_id, user["id"])
        message_id = execute(
            conn,
            """
            INSERT INTO messages (conversation_id, sender_id, ciphertext, envelope, reply_to_id, forwarded_from_id, created_at, reaction_summary, read_by, delivered_to)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                conversation_id,
                user["id"],
                data.ciphertext,
                json.dumps(data.envelope, ensure_ascii=False),
                data.reply_to_id,
                data.forwarded_from_id,
                utcnow(),
                "{}",
                json.dumps({str(user["id"]): utcnow()}),
                json.dumps({str(user["id"]): utcnow()}),
            ),
        )
        message = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
        conn.execute("UPDATE conversations SET updated_at=? WHERE id=?", (utcnow(), conversation_id))
    await state.broadcast_conv(conversation_id, {"type": "message:new", "message": message})
    return {"message": message}


@app.put("/api/messages/{message_id}")
async def edit_message(message_id: int, data: MessageEditIn, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        msg = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")
        assert_can_access_conversation(conn, msg["conversation_id"], user["id"])
        if int(msg["sender_id"]) != int(user["id"]):
            raise HTTPException(status_code=403, detail="Only the sender can edit this message")
        conn.execute(
            "UPDATE messages SET ciphertext=?, envelope=?, edited_at=? WHERE id=?",
            (data.ciphertext, json.dumps(data.envelope, ensure_ascii=False), utcnow(), message_id),
        )
        updated = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
    await state.broadcast_conv(int(msg["conversation_id"]), {"type": "message:edit", "message": updated})
    return {"message": updated}


@app.delete("/api/messages/{message_id}")
async def delete_message(message_id: int, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        msg = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")
        assert_can_access_conversation(conn, msg["conversation_id"], user["id"])
        if int(msg["sender_id"]) != int(user["id"]) and not is_admin_in_conversation(conn, msg["conversation_id"], user["id"]):
            raise HTTPException(status_code=403, detail="Not allowed")
        conn.execute("UPDATE messages SET deleted_at=?, ciphertext=?, envelope=? WHERE id=?", (utcnow(), "", "{}", message_id))
        updated = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
    await state.broadcast_conv(int(msg["conversation_id"]), {"type": "message:delete", "message": updated})
    return {"ok": True}


@app.post("/api/messages/{message_id}/pin")
async def pin_message(message_id: int, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        msg = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")
        assert_can_access_conversation(conn, msg["conversation_id"], user["id"])
        if not is_admin_in_conversation(conn, msg["conversation_id"], user["id"]):
            raise HTTPException(status_code=403, detail="Only admins can pin")
        conn.execute("UPDATE messages SET pinned=1 WHERE id=?", (message_id,))
        updated = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
    await state.broadcast_conv(int(msg["conversation_id"]), {"type": "message:pin", "message": updated})
    return {"message": updated}


@app.post("/api/messages/{message_id}/reaction")
async def add_reaction(message_id: int, data: ReactionIn, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        msg = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")
        assert_can_access_conversation(conn, msg["conversation_id"], user["id"])
        reactions = safe_json_loads(msg["reaction_summary"], {})
        reactions[str(user["id"])] = {"emoji": data.emoji, "at": utcnow()}
        conn.execute("UPDATE messages SET reaction_summary=? WHERE id=?", (json.dumps(reactions, ensure_ascii=False), message_id))
        updated = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
    await state.broadcast_conv(int(msg["conversation_id"]), {"type": "message:reaction", "message": updated})
    return {"message": updated}


@app.post("/api/conversations/{conversation_id}/read")
async def mark_read(conversation_id: int, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        assert_can_access_conversation(conn, conversation_id, user["id"])
        rows = fetch_all(conn, "SELECT id, read_by FROM messages WHERE conversation_id=?", (conversation_id,))
        for row in rows:
            read_by = safe_json_loads(row["read_by"], {})
            read_by[str(user["id"])] = utcnow()
            conn.execute("UPDATE messages SET read_by=? WHERE id=?", (json.dumps(read_by, ensure_ascii=False), row["id"]))
        conn.execute("UPDATE users SET typing_conv_id=NULL, updated_at=? WHERE id=?", (utcnow(), user["id"]))
    await state.broadcast_conv(conversation_id, {"type": "conversation:read", "user_id": user["id"]})
    return {"ok": True}


@app.post("/api/conversations/{conversation_id}/typing")
async def typing(conversation_id: int, request: Request, is_typing: bool = True) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        assert_can_access_conversation(conn, conversation_id, user["id"])
        conn.execute("UPDATE users SET typing_conv_id=?, updated_at=? WHERE id=?", (conversation_id if is_typing else None, utcnow(), user["id"]))
    await state.broadcast_conv(conversation_id, {"type": "conversation:typing", "user_id": user["id"], "is_typing": is_typing})
    return {"ok": True}


@app.post("/api/conversations/{conversation_id}/members")
async def add_member(conversation_id: int, member_id: int = Form(...), request: Request = None) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        conv = assert_can_access_conversation(conn, conversation_id, user["id"])
        if conv["type"] == "direct":
            raise HTTPException(status_code=400, detail="Direct chats cannot have members added")
        if not is_admin_in_conversation(conn, conversation_id, user["id"]):
            raise HTTPException(status_code=403, detail="Only admins can add members")
        peer = fetch_one(conn, "SELECT id FROM users WHERE id=?", (member_id,))
        if not peer:
            raise HTTPException(status_code=404, detail="User not found")
        ensure_participant(conn, conversation_id, int(member_id), "member")
        conv = conversation_payload(conn, conversation_id)
    await state.broadcast_conv(conversation_id, {"type": "conversation:members", "conversation": conv})
    return {"conversation": conv}


@app.post("/api/conversations/{conversation_id}/calls/start")
async def start_call(conversation_id: int, request: Request, kind: str = Form("audio")) -> dict[str, Any]:
    user = get_current_user(request)
    kind = "video" if kind == "video" else "audio"
    with session() as conn:
        assert_can_access_conversation(conn, conversation_id, user["id"])
        call_id = execute(
            conn,
            "INSERT INTO call_sessions (conversation_id, initiator_id, kind, status, signaling, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (conversation_id, user["id"], kind, "ringing", "{}", utcnow(), utcnow()),
        )
        call = fetch_one(conn, "SELECT * FROM call_sessions WHERE id=?", (call_id,))
    await state.broadcast_conv(conversation_id, {"type": "call:incoming", "call": call})
    return {"call": call}


@app.post("/api/files/upload")
async def upload_file(
    request: Request,
    conversation_id: int = Form(...),
    original_name: str = Form(...),
    mime_type: str = Form(...),
    file: UploadFile = File(...),
) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        assert_can_access_conversation(conn, conversation_id, user["id"])
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=400, detail="File too large")
    ext = Path(original_name).suffix.lower()
    if ext and ext not in ALLOWED_FILE_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type not allowed")
    stored_name = f"f_{secrets.token_hex(24)}{ext}"
    target = UPLOAD_DIR / stored_name
    target.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    with session() as conn:
        file_id = execute(
            conn,
            """
            INSERT INTO files (owner_id, conversation_id, original_name, stored_name, mime_type, size_bytes, sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user["id"], conversation_id, original_name, stored_name, mime_type, len(content), sha, utcnow()),
        )
        meta = fetch_one(conn, "SELECT * FROM files WHERE id=?", (file_id,))
    return {"file": file_payload(meta)}


@app.get("/api/files/{file_id}")
async def download_file(file_id: int, request: Request) -> Response:
    user = get_current_user(request)
    with session() as conn:
        meta = fetch_one(conn, "SELECT * FROM files WHERE id=?", (file_id,))
        if not meta:
            raise HTTPException(status_code=404, detail="File not found")
        assert_can_access_conversation(conn, meta["conversation_id"], user["id"])
    path = UPLOAD_DIR / meta["stored_name"]
    if not path.exists():
        raise HTTPException(status_code=404, detail="File missing")
    return FileResponse(path, media_type=meta["mime_type"], filename=meta["original_name"])


def file_payload(meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": meta["id"],
        "owner_id": meta["owner_id"],
        "conversation_id": meta["conversation_id"],
        "original_name": meta["original_name"],
        "mime_type": meta["mime_type"],
        "size_bytes": meta["size_bytes"],
        "sha256": meta["sha256"],
        "created_at": meta["created_at"],
        "url": f"/api/files/{meta['id']}",
    }


@app.websocket("/ws/{conversation_id}")
async def websocket_endpoint(websocket: WebSocket, conversation_id: int):
    token = websocket.cookies.get("access_token")
    if not token:
        await websocket.close(code=4401)
        return
    payload = decode_access_token(token, get_jwt_secret())
    if not payload:
        await websocket.close(code=4401)
        return
    try:
        user_id = int(payload["sub"])
    except Exception:
        await websocket.close(code=4401)
        return
    with session() as conn:
        user = fetch_one(conn, "SELECT * FROM users WHERE id=?", (user_id,))
        if not user:
            await websocket.close(code=4401)
            return
        try:
            assert_can_access_conversation(conn, conversation_id, user_id)
        except HTTPException:
            await websocket.close(code=4403)
            return
    await state.connect(websocket, user_id, conversation_id)
    try:
        with session() as conn:
            conn.execute("UPDATE users SET is_online=1, last_seen=?, updated_at=? WHERE id=?", (utcnow(), utcnow(), user_id))
        await state.broadcast_conv(conversation_id, {"type": "presence", "user_id": user_id, "online": True})
        while True:
            data = await websocket.receive_text()
            try:
                payload = json.loads(data)
            except Exception:
                continue
            kind = payload.get("kind")
            if kind == "ping":
                await websocket.send_json({"kind": "pong", "ts": utcnow()})
                continue
            if kind == "typing":
                with session() as conn:
                    conn.execute("UPDATE users SET typing_conv_id=?, updated_at=? WHERE id=?", (conversation_id if payload.get("typing") else None, utcnow(), user_id))
                await state.broadcast_conv(conversation_id, {"type": "conversation:typing", "user_id": user_id, "is_typing": bool(payload.get("typing"))})
            elif kind == "read":
                with session() as conn:
                    rows = fetch_all(conn, "SELECT id, read_by FROM messages WHERE conversation_id=?", (conversation_id,))
                    for row in rows:
                        read_by = safe_json_loads(row["read_by"], {})
                        read_by[str(user_id)] = utcnow()
                        conn.execute("UPDATE messages SET read_by=? WHERE id=?", (json.dumps(read_by, ensure_ascii=False), row["id"]))
                await state.broadcast_conv(conversation_id, {"type": "conversation:read", "user_id": user_id})
            elif kind == "message":
                message = payload.get("message") or {}
                ciphertext = message.get("ciphertext")
                if not ciphertext:
                    continue
                envelope = message.get("envelope") or {}
                reply_to_id = message.get("reply_to_id")
                forwarded_from_id = message.get("forwarded_from_id")
                with session() as conn:
                    msg_id = execute(
                        conn,
                        """
                        INSERT INTO messages (conversation_id, sender_id, ciphertext, envelope, reply_to_id, forwarded_from_id, created_at, reaction_summary, read_by, delivered_to)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            conversation_id,
                            user_id,
                            ciphertext,
                            json.dumps(envelope, ensure_ascii=False),
                            reply_to_id,
                            forwarded_from_id,
                            utcnow(),
                            "{}",
                            json.dumps({str(user_id): utcnow()}),
                            json.dumps({str(user_id): utcnow()}),
                        ),
                    )
                    msg = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (msg_id,))
                    conn.execute("UPDATE conversations SET updated_at=? WHERE id=?", (utcnow(), conversation_id))
                await state.broadcast_conv(conversation_id, {"type": "message:new", "message": msg})
            elif kind == "edit_message":
                message_id = int(payload.get("message_id") or 0)
                ciphertext = payload.get("ciphertext") or ""
                envelope = payload.get("envelope") or {}
                with session() as conn:
                    msg = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
                    if not msg or int(msg["sender_id"]) != user_id:
                        continue
                    conn.execute("UPDATE messages SET ciphertext=?, envelope=?, edited_at=? WHERE id=?", (ciphertext, json.dumps(envelope, ensure_ascii=False), utcnow(), message_id))
                    updated = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
                await state.broadcast_conv(conversation_id, {"type": "message:edit", "message": updated})
            elif kind == "delete_message":
                message_id = int(payload.get("message_id") or 0)
                with session() as conn:
                    msg = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
                    if not msg or int(msg["sender_id"]) != user_id:
                        continue
                    conn.execute("UPDATE messages SET deleted_at=?, ciphertext=?, envelope=? WHERE id=?", (utcnow(), "", "{}", message_id))
                    updated = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
                await state.broadcast_conv(conversation_id, {"type": "message:delete", "message": updated})
            elif kind == "reaction":
                message_id = int(payload.get("message_id") or 0)
                emoji = str(payload.get("emoji") or "👍")
                with session() as conn:
                    msg = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
                    if not msg:
                        continue
                    reactions = safe_json_loads(msg["reaction_summary"], {})
                    reactions[str(user_id)] = {"emoji": emoji, "at": utcnow()}
                    conn.execute("UPDATE messages SET reaction_summary=? WHERE id=?", (json.dumps(reactions, ensure_ascii=False), message_id))
                    updated = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (message_id,))
                await state.broadcast_conv(conversation_id, {"type": "message:reaction", "message": updated})
            elif kind == "call_signal":
                signal = payload.get("signal") or {}
                await state.broadcast_conv(conversation_id, {"type": "call:signal", "from_user_id": user_id, "signal": signal})
            elif kind == "call_end":
                await state.broadcast_conv(conversation_id, {"type": "call:end", "from_user_id": user_id})
    except WebSocketDisconnect:
        pass
    finally:
        await state.disconnect(websocket, user_id, conversation_id)
        with session() as conn:
            # if no active sockets remain for user mark offline
            if state.user_online_count.get(user_id, 0) <= 0:
                conn.execute("UPDATE users SET is_online=0, last_seen=?, typing_conv_id=NULL, updated_at=? WHERE id=?", (utcnow(), utcnow(), user_id))
        await state.broadcast_conv(conversation_id, {"type": "presence", "user_id": user_id, "online": False})


def is_admin_in_conversation(conn, conversation_id: int, user_id: int) -> bool:
    row = fetch_one(
        conn,
        "SELECT role FROM participants WHERE conversation_id=? AND user_id=?",
        (conversation_id, user_id),
    )
    return bool(row and row["role"] in {"owner", "admin"})


@app.exception_handler(ValidationError)
async def validation_handler(request: Request, exc: ValidationError):
    return JSONResponse({"detail": exc.errors()}, status_code=422)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.get("/{path:path}")
async def spa_fallback(path: str):
    target = STATIC_DIR / path
    if target.exists() and target.is_file():
        if path.endswith(".css"):
            return FileResponse(target, media_type="text/css")
        if path.endswith(".js"):
            return FileResponse(target, media_type="text/javascript")
        if path.endswith(".jsx"):
            return FileResponse(target, media_type="text/javascript")
        return FileResponse(target)
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))
