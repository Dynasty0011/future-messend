from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from .db import DATA_DIR, connect, ensure_folder, execute, fetch_all, fetch_one, init_db, session
from .security import (
    constant_time_equals,
    create_access_token,
    decode_access_token,
    hash_password,
    new_csrf_token,
    now_utc,
    random_id,
    verify_password,
)

BASE_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = BASE_DIR / "app" / "static"
UPLOAD_DIR = DATA_DIR / "uploads"
AVATAR_DIR = DATA_DIR / "avatars"
KEY_DIR = DATA_DIR / "keys"
CONFIG_PATH = DATA_DIR / "config.json"

app = FastAPI(title="Future Messenger", version="2.0.0")
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


class ConversationCreateIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    member_ids: list[int] = Field(default_factory=list)
    direct_peer_id: Optional[int] = None


class MessageSendIn(BaseModel):
    ciphertext: str = Field(min_length=1, max_length=10000)
    envelope: dict[str, Any] = Field(default_factory=dict)
    reply_to_id: Optional[int] = None
    forwarded_from_id: Optional[int] = None


class WorkspaceState:
    def __init__(self) -> None:
        self.conv_connections: dict[int, set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, conv_id: int) -> None:
        await websocket.accept()
        self.conv_connections.setdefault(conv_id, set()).add(websocket)

    async def disconnect(self, websocket: WebSocket, conv_id: int) -> None:
        if conv_id in self.conv_connections:
            self.conv_connections[conv_id].discard(websocket)
            if not self.conv_connections[conv_id]:
                self.conv_connections.pop(conv_id, None)

    async def broadcast_conv(self, conv_id: int, payload: dict[str, Any]) -> None:
        for ws in list(self.conv_connections.get(conv_id, set())):
            try:
                await ws.send_json(payload)
            except Exception:
                pass


state = WorkspaceState()


def utcnow() -> str:
    return now_utc().isoformat()


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


def get_jwt_secret() -> str:
    return load_config()["jwt_secret"]


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "email": user["email"],
        "display_name": user["display_name"],
        "bio": user.get("bio", ""),
        "public_key": user.get("public_key", ""),
        "is_online": bool(user.get("is_online", 0)),
        "last_seen": user.get("last_seen"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
    }


def conversation_row(conv: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": conv["id"],
        "type": conv["type"],
        "title": conv["title"],
        "created_by": conv["created_by"],
        "created_at": conv["created_at"],
        "updated_at": conv["updated_at"],
    }


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
    token = create_access_token(str(user_id), get_jwt_secret(), extra={"csrf": csrf_token})
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
        csrf_token = new_csrf_token()
        user_id = execute(
            conn,
            """
            INSERT INTO users (email, password_hash, display_name, public_key, bio, created_at, updated_at, csrf_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (data.email.lower(), hash_password(data.password), data.display_name.strip(), data.public_key or "", "", utcnow(), utcnow(), csrf_token),
        )
        user = fetch_one(conn, "SELECT * FROM users WHERE id=?", (user_id,))
    set_auth_cookies(response, user_id, csrf_token)
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
            conn.execute("UPDATE users SET is_online=0, last_seen=?, updated_at=? WHERE id=?", (utcnow(), utcnow(), user["id"]))
    clear_auth_cookies(response)
    return {"ok": True}


@app.get("/api/auth/me")
async def me(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    return {"user": public_user(user), "csrf_token": request.cookies.get("csrf_token", "")}


@app.get("/api/users")
async def list_users(request: Request) -> dict[str, Any]:
    _ = get_current_user(request)
    with session() as conn:
        users = fetch_all(conn, "SELECT * FROM users ORDER BY display_name COLLATE NOCASE ASC")
    return {"users": [public_user(u) for u in users]}


@app.post("/api/conversations")
async def create_conversation(data: ConversationCreateIn, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        member_ids = {user["id"]}
        if data.direct_peer_id is not None:
            member_ids.add(int(data.direct_peer_id))
        member_ids.update(int(i) for i in data.member_ids if int(i) > 0)
        member_ids.discard(0)
        if len(member_ids) < 2:
            raise HTTPException(status_code=400, detail="Need at least two members")
        conv_type = "direct" if len(member_ids) == 2 and data.direct_peer_id is not None else "group"
        direct_peer_key = None
        if conv_type == "direct":
            direct_peer_key = ":".join(str(i) for i in sorted(member_ids))
            existing = fetch_one(conn, "SELECT * FROM conversations WHERE direct_peer_key=?", (direct_peer_key,))
            if existing:
                return {"conversation": conversation_row(existing)}
        conv_id = execute(
            conn,
            """
            INSERT INTO conversations (type, title, direct_peer_key, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (conv_type, data.title.strip(), direct_peer_key, user["id"], utcnow(), utcnow()),
        )
        for member_id in sorted(member_ids):
            conn.execute(
                "INSERT OR IGNORE INTO conversation_members (conversation_id, user_id, joined_at) VALUES (?, ?, ?)",
                (conv_id, member_id, utcnow()),
            )
        conv = fetch_one(conn, "SELECT * FROM conversations WHERE id=?", (conv_id,))
    return {"conversation": conversation_row(conv)}


@app.get("/api/conversations")
async def list_conversations(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        rows = fetch_all(
            conn,
            """
            SELECT c.*
            FROM conversations c
            JOIN conversation_members m ON m.conversation_id = c.id
            WHERE m.user_id = ?
            ORDER BY c.updated_at DESC
            """,
            (user["id"],),
        )
        result = []
        for conv in rows:
            members = fetch_all(
                conn,
                "SELECT u.id, u.display_name, u.email FROM users u JOIN conversation_members m ON m.user_id = u.id WHERE m.conversation_id=? ORDER BY u.display_name",
                (conv["id"],),
            )
            last_message = fetch_one(
                conn,
                "SELECT id, sender_id, ciphertext, created_at FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 1",
                (conv["id"],),
            )
            result.append({**conversation_row(conv), "members": members, "last_message": last_message})
    return {"conversations": result}


@app.get("/api/conversations/{conversation_id}/messages")
async def list_messages(conversation_id: int, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        member = fetch_one(conn, "SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?", (conversation_id, user["id"]))
        if not member:
            raise HTTPException(status_code=403, detail="Not a conversation member")
        messages = fetch_all(
            conn,
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY id ASC",
            (conversation_id,),
        )
    return {"messages": messages}


@app.post("/api/conversations/{conversation_id}/messages")
async def send_message(conversation_id: int, data: MessageSendIn, request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    with session() as conn:
        member = fetch_one(conn, "SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?", (conversation_id, user["id"]))
        if not member:
            raise HTTPException(status_code=403, detail="Not a conversation member")
        msg_id = execute(
            conn,
            """
            INSERT INTO messages (conversation_id, sender_id, ciphertext, envelope, reply_to_id, forwarded_from_id, reactions, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (conversation_id, user["id"], data.ciphertext, json.dumps(data.envelope, ensure_ascii=False), data.reply_to_id, data.forwarded_from_id, "{}", utcnow(), utcnow()),
        )
        conn.execute("UPDATE conversations SET updated_at=? WHERE id=?", (utcnow(), conversation_id))
        message = fetch_one(conn, "SELECT * FROM messages WHERE id=?", (msg_id,))
    payload = {"type": "message", "conversation_id": conversation_id, "message": message}
    await state.broadcast_conv(conversation_id, payload)
    return {"message": message}


@app.websocket("/ws/conversations/{conversation_id}")
async def ws_conversation(websocket: WebSocket, conversation_id: int) -> None:
    token = websocket.cookies.get("access_token")
    if not token:
        await websocket.close(code=4401)
        return
    payload = decode_access_token(token, get_jwt_secret())
    if not payload:
        await websocket.close(code=4401)
        return
    user_id = int(payload["sub"])
    with session() as conn:
        member = fetch_one(conn, "SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?", (conversation_id, user_id))
    if not member:
        await websocket.close(code=4403)
        return
    await state.connect(websocket, conversation_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await state.disconnect(websocket, conversation_id)


@app.get("/api/bootstrap")
async def bootstrap(request: Request) -> dict[str, Any]:
    user = get_current_user_optional(request)
    if not user:
        return {"user": None}
    return {"user": public_user(user), "csrf_token": request.cookies.get("csrf_token", "")}
