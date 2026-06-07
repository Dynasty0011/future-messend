const { useEffect, useMemo, useRef, useState } = React;

const API_BASE = "";

function readCookie(name) {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith(name + "="))
    ?.split("=")[1] || "";
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const csrf = readCookie("csrf_token");
  if (csrf && !headers.has("X-CSRF-Token")) headers.set("X-CSRF-Token", csrf);
  const opts = {
    credentials: "include",
    ...options,
    headers,
  };
  if (opts.body && !(opts.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
    if (typeof opts.body !== "string") opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(API_BASE + path, opts);
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!res.ok) throw new Error(data.detail || data.message || `HTTP ${res.status}`);
  return data;
}

function cls(...xs) { return xs.filter(Boolean).join(" "); }
function uid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function pad(n) { return String(n).padStart(2, "0"); }
function formatTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
function formatDay(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
function hashText(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36);
}
function b64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  arr.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}
function unb64(txt) {
  const bin = atob(txt);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function textToBytes(text) { return new TextEncoder().encode(text); }
function bytesToText(bytes) { return new TextDecoder().decode(bytes); }
function blobToArrayBuffer(blob) { return blob.arrayBuffer(); }

async function sha256Hex(text) {
  const hash = await crypto.subtle.digest("SHA-256", textToBytes(text));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Base64Bytes(bytes) {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return b64(hash);
}

const KEY_STORE = "fm_identity_v1";
const ROOM_STORE = "fm_room_secrets_v1";

function loadJsonStore(key, fallback = {}) {
  try { return JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback)); } catch { return fallback; }
}
function saveJsonStore(key, value) { localStorage.setItem(key, JSON.stringify(value)); }

async function generateIdentity() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const record = { publicJwk, privateJwk, createdAt: new Date().toISOString() };
  saveJsonStore(KEY_STORE, record);
  return record;
}

async function loadIdentity() {
  const stored = loadJsonStore(KEY_STORE, null);
  if (!stored?.publicJwk || !stored?.privateJwk) return generateIdentity();
  return stored;
}

async function importPublic(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
}
async function importPrivate(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
}

async function deriveDirectKey(identity, peerPublicJwk) {
  const priv = await importPrivate(identity.privateJwk);
  const pub = await importPublic(peerPublicJwk);
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: pub },
    priv,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function deriveRoomKey(secret, saltText) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    textToBytes(secret),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: textToBytes(saltText), iterations: 250000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptBytes(bytes, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  const payload = new Uint8Array(iv.length + ct.byteLength);
  payload.set(iv, 0);
  payload.set(new Uint8Array(ct), iv.length);
  return b64(payload);
}

async function decryptBytes(payloadB64, key) {
  const payload = unb64(payloadB64);
  const iv = payload.slice(0, 12);
  const ct = payload.slice(12);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

async function encryptMessage({ text, attachments, reply_to_id }, conv, identity, roomSecret) {
  const body = JSON.stringify({
    v: 1,
    text,
    attachments,
    reply_to_id: reply_to_id || null,
    ts: new Date().toISOString(),
  });

  let key;
  let envelope = { mode: "unknown", sender_id: null, ts: new Date().toISOString() };

  const senderPub = identity.publicJwk;
  envelope.sender_pub = senderPub;
  envelope.sender_name = null;
  envelope.kind = conv.type;

  if (conv.type === "direct") {
    const peer = (conv.members || []).find((m) => Number(m.id) !== Number(window.__FM_USER_ID__));
    if (!peer?.public_key) throw new Error("У собеседника не настроен публичный ключ E2EE");
    key = await deriveDirectKey(identity, JSON.parse(peer.public_key));
    envelope.mode = "direct";
  } else {
    const secret = roomSecret || getRoomSecret(conv.id);
    if (!secret) throw new Error("Для группы/канала нужен invite-секрет");
    key = await deriveRoomKey(secret, `conv:${conv.id}`);
    envelope.mode = "room";
    envelope.room_id = conv.id;
  }

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textToBytes(body));
  envelope.iv = b64(iv);
  return {
    ciphertext: b64(new Uint8Array(enc)),
    envelope,
  };
}

async function decryptMessagePayload(message, conv, identity, roomsById) {
  if (!message || message.deleted_at) {
    return { deleted: true, data: { text: "Сообщение удалено", attachments: [] } };
  }
  const envelope = typeof message.envelope === "string" && message.envelope ? JSON.parse(message.envelope) : (message.envelope || {});
  const ciphertext = message.ciphertext || "";
  if (!ciphertext) return { deleted: true, data: { text: "Сообщение удалено", attachments: [] } };
  let key;
  if (envelope.mode === "direct") {
    const sender = (conv.members || []).find((m) => Number(m.id) === Number(message.sender_id));
    if (!sender?.public_key) throw new Error("Нет публичного ключа отправителя");
    key = await deriveDirectKey(identity, JSON.parse(sender.public_key));
  } else {
    const secret = roomsById[String(conv.id)];
    if (!secret) throw new Error("Нет секретного ключа комнаты");
    key = await deriveRoomKey(secret, `conv:${conv.id}`);
  }
  const payload = unb64(ciphertext);
  const iv = unb64(envelope.iv);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, payload);
  return { deleted: false, data: JSON.parse(bytesToText(new Uint8Array(pt))), envelope };
}

function getRoomSecret(convId) {
  const rooms = loadJsonStore(ROOM_STORE, {});
  return rooms[String(convId)] || "";
}
function setRoomSecret(convId, secret) {
  const rooms = loadJsonStore(ROOM_STORE, {});
  if (secret) rooms[String(convId)] = secret;
  saveJsonStore(ROOM_STORE, rooms);
}
function removeRoomSecret(convId) {
  const rooms = loadJsonStore(ROOM_STORE, {});
  delete rooms[String(convId)];
  saveJsonStore(ROOM_STORE, rooms);
}

function ToastStack({ items, onClose }) {
  useEffect(() => {
    if (!items.length) return;
    const t = setTimeout(() => onClose(items[0]?.id), 3500);
    return () => clearTimeout(t);
  }, [items, onClose]);
  return (
    <div className="toast-stack">
      {items.map((t) => (
        <div key={t.id} className="toast glass">
          <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
            <strong>{t.title}</strong>
            <button className="icon-btn" onClick={() => onClose(t.id)}>×</button>
          </div>
          <div className="small" style={{ marginTop: 8 }}>{t.body}</div>
        </div>
      ))}
    </div>
  );
}

function Avatar({ user, size = 48 }) {
  const letters = (user?.display_name || user?.email || "?")
    .split(" ")
    .map((x) => x[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
  const src = user?.avatar_path ? user.avatar_path : "";
  return (
    <div className="avatar" style={{ width: size, height: size, borderRadius: size * 0.3 }}>
      {src ? <img src={src} alt="" /> : <span>{letters}</span>}
    </div>
  );
}

function App() {
  const [auth, setAuth] = useState(null);
  const [csrf, setCsrf] = useState("");
  const [identity, setIdentity] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [decrypted, setDecrypted] = useState([]);
  const [query, setQuery] = useState("");
  const [users, setUsers] = useState([]);
  const [toasts, setToasts] = useState([]);
  const [composer, setComposer] = useState("");
  const [attachments, setAttachments] = useState([]);
  const [replyTo, setReplyTo] = useState(null);
  const [selectedMessageId, setSelectedMessageId] = useState(null);
  const [showAuthMode, setShowAuthMode] = useState("login");
  const [registerForm, setRegisterForm] = useState({ email: "", password: "", display_name: "" });
  const [loginForm, setLoginForm] = useState({ email: "", password: "" });
  const [recoveryForm, setRecoveryForm] = useState({ email: "", code: "", new_password: "" });
  const [recoveryCode, setRecoveryCode] = useState("");
  const [profileDraft, setProfileDraft] = useState({ display_name: "", bio: "" });
  const [profileOpen, setProfileOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [joinOpen, setJoinOpen] = useState(false);
  const [createForm, setCreateForm] = useState({ type: "direct", title: "", direct_peer_id: "", member_ids: "" });
  const [joinInvite, setJoinInvite] = useState("");
  const [inviteSecret, setInviteSecret] = useState("");
  const [callState, setCallState] = useState({
    open: false,
    kind: "audio",
    incoming: null,
    active: null,
    localStream: null,
    remoteStream: null,
    muted: false,
    cameraOff: false,
  });
  const [typingUsers, setTypingUsers] = useState({});
  const [searchText, setSearchText] = useState("");
  const wsRef = useRef(null);
  const pcRef = useRef(null);
  const localVideoRef = useRef(null);
  const remoteVideoRef = useRef(null);
  const messagesRef = useRef(null);
  const fileInputRef = useRef(null);
  const typingTimer = useRef(null);
  const pendingSignalRef = useRef(null);

  const selectedConversation = useMemo(
    () => conversations.find((c) => Number(c.id) === Number(selectedId)) || null,
    [conversations, selectedId]
  );

  function pushToast(title, body) {
    const id = uid();
    setToasts((xs) => [...xs, { id, title, body }]);
  }

  function closeToast(id) {
    setToasts((xs) => xs.filter((x) => x.id !== id));
  }

  async function loadMe() {
    const data = await api("/api/auth/me");
    setAuth(data.user);
    setCsrf(data.csrf_token || readCookie("csrf_token"));
    window.__FM_USER_ID__ = data.user.id;
    setProfileDraft({ display_name: data.user.display_name || "", bio: data.user.bio || "" });
  }

  async function bootstrap() {
    const id = await loadIdentity();
    setIdentity(id);
    try {
      await loadMe();
    } catch {
      setAuth(null);
    }
  }

  useEffect(() => {
    bootstrap();
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission().catch(() => {});
    }
  }, []);

  useEffect(() => {
    if (!auth) return;
    loadConversations();
    loadUsers("");
    const rooms = loadJsonStore(ROOM_STORE, {});
    if (auth?.id && identity?.publicJwk) {
      // profile update handled after identity load
    }
  }, [auth]);

  useEffect(() => {
    if (!auth || !selectedConversation || !identity) return;
    loadMessages(selectedConversation.id);
    const wsUrl = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/${selectedConversation.id}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ kind: "ping" }));
      markRead(selectedConversation.id);
    };
    ws.onmessage = async (event) => {
      let payload = {};
      try { payload = JSON.parse(event.data); } catch { return; }
      if (payload.type === "message:new") {
        setMessages((xs) => {
          const next = xs.some((m) => Number(m.id) === Number(payload.message.id)) ? xs : [...xs, payload.message];
          return next;
        });
        if (Number(payload.message.sender_id) !== Number(auth.id)) {
          maybeNotify(selectedConversation, payload.message);
          markRead(selectedConversation.id);
        }
      } else if (payload.type === "message:edit") {
        setMessages((xs) => xs.map((m) => Number(m.id) === Number(payload.message.id) ? payload.message : m));
      } else if (payload.type === "message:delete") {
        setMessages((xs) => xs.map((m) => Number(m.id) === Number(payload.message.id) ? payload.message : m));
      } else if (payload.type === "message:reaction") {
        setMessages((xs) => xs.map((m) => Number(m.id) === Number(payload.message.id) ? payload.message : m));
      } else if (payload.type === "conversation:typing") {
        if (Number(payload.user_id) !== Number(auth.id)) {
          setTypingUsers((prev) => ({ ...prev, [payload.user_id]: payload.is_typing ? Date.now() : 0 }));
          clearTimeout(typingTimer.current);
          typingTimer.current = setTimeout(() => {
            setTypingUsers((prev) => {
              const clone = { ...prev };
              delete clone[payload.user_id];
              return clone;
            });
          }, 2500);
        }
      } else if (payload.type === "presence") {
        setConversations((xs) => xs.map((c) => {
          const members = (c.members || []).map((m) => Number(m.id) === Number(payload.user_id) ? { ...m, is_online: payload.online } : m);
          return { ...c, members };
        }));
      } else if (payload.type === "call:signal") {
        if (payload.signal?.type === "offer" && !pcRef.current) {
          pendingSignalRef.current = payload.signal;
        } else {
          handleIncomingSignal(payload.signal, payload.from_user_id);
        }
      } else if (payload.type === "call:incoming") {
        setCallState((s) => ({ ...s, open: true, incoming: payload.call, active: null }));
        pushToast("Вызов", `Новый ${payload.call.kind} вызов в чате ${selectedConversation.title}`);
      } else if (payload.type === "call:end") {
        endCall(true);
      }
    };
    ws.onclose = () => {};
    return () => {
      try { ws.close(); } catch {}
    };
  }, [auth, selectedConversation, identity]);

  useEffect(() => {
    if (!selectedConversation || !identity) return;
    (async () => {
      const decoded = [];
      for (const msg of messages) {
        try {
          const item = await decryptMessagePayload(msg, selectedConversation, identity, loadJsonStore(ROOM_STORE, {}));
          decoded.push({ ...msg, decoded: item });
        } catch (e) {
          decoded.push({ ...msg, decoded: { deleted: false, data: { text: "Не удалось расшифровать сообщение", attachments: [] }, envelope: {} } });
        }
      }
      setDecrypted(decoded);
      setTimeout(() => {
        if (messagesRef.current) messagesRef.current.scrollTop = messagesRef.current.scrollHeight;
      }, 50);
    })();
  }, [messages, selectedConversation, identity]);

  useEffect(() => {
    if (identity?.publicJwk && auth) {
      api("/api/profile", {
        method: "PUT",
        body: { public_key: JSON.stringify(identity.publicJwk) },
      }).then((r) => {
        if (r.user) setAuth(r.user);
      }).catch(() => {});
    }
  }, [identity, auth?.id]);

  useEffect(() => {
    if (selectedConversation) {
      const roomSecret = getRoomSecret(selectedConversation.id);
      if (roomSecret) setInviteSecret(roomSecret);
    }
  }, [selectedConversation]);

  async function loadConversations() {
    const data = await api("/api/conversations");
    setConversations(data.conversations || []);
    if (!selectedId && data.conversations?.length) setSelectedId(data.conversations[0].id);
  }

  async function loadUsers(q) {
    const data = await api(`/api/users/search?q=${encodeURIComponent(q)}`);
    setUsers(data.users || []);
  }

  async function loadMessages(convId) {
    const data = await api(`/api/conversations/${convId}/messages?limit=200`);
    setMessages(data.messages || []);
  }

  async function markRead(convId) {
    try {
      await api(`/api/conversations/${convId}/read`, { method: "POST" });
      if (wsRef.current?.readyState === 1) {
        wsRef.current.send(JSON.stringify({ kind: "read" }));
      }
    } catch {}
  }

  function maybeNotify(conv, msg) {
    const title = conv.title || "Новый чат";
    const body = msg?.deleted_at ? "Удалённое сообщение" : "Новое сообщение";
    if ("Notification" in window && Notification.permission === "granted") {
      new Notification(title, { body });
    }
    pushToast(title, body);
  }

  async function handleRegister(e) {
    e.preventDefault();
    try {
      await api("/api/auth/register", { method: "POST", body: { ...registerForm, public_key: JSON.stringify(identity.publicJwk) } });
      await loadMe();
      pushToast("Аккаунт создан", "Вы вошли в систему.");
    } catch (e2) {
      pushToast("Ошибка", e2.message);
    }
  }

  async function handleLogin(e) {
    e.preventDefault();
    try {
      await api("/api/auth/login", { method: "POST", body: loginForm });
      await loadMe();
      pushToast("Добро пожаловать", "Успешный вход.");
    } catch (e2) {
      pushToast("Ошибка", e2.message);
    }
  }

  async function handleLogout() {
    try { await api("/api/auth/logout", { method: "POST" }); } catch {}
    setAuth(null);
    setConversations([]);
    setSelectedId(null);
    setMessages([]);
    window.location.reload();
  }

  async function handleRecoveryRequest() {
    try {
      const res = await api("/api/auth/recovery/request", { method: "POST", body: { email: recoveryForm.email } });
      if (res.sent && res.code) {
        setRecoveryCode(res.code);
        pushToast("Код восстановления", res.code);
      } else {
        pushToast("Готово", "Если email существует, код создан.");
      }
    } catch (e) {
      pushToast("Ошибка", e.message);
    }
  }

  async function handleRecoveryComplete() {
    try {
      await api("/api/auth/recovery/complete", { method: "POST", body: recoveryForm });
      pushToast("Готово", "Пароль обновлён.");
      setShowAuthMode("login");
    } catch (e) {
      pushToast("Ошибка", e.message);
    }
  }

  async function handleProfileSave() {
    try {
      const res = await api("/api/profile", { method: "PUT", body: profileDraft });
      setAuth(res.user);
      setProfileOpen(false);
      pushToast("Профиль обновлён", "Изменения сохранены.");
      loadConversations();
    } catch (e) {
      pushToast("Ошибка", e.message);
    }
  }

  async function handleAvatarUpload(file) {
    if (!file) return;
    const fd = new FormData();
    fd.append("file", file);
    try {
      await api("/api/profile/avatar", { method: "POST", body: fd });
      await loadMe();
      pushToast("Аватар обновлён", "Новый аватар сохранён.");
    } catch (e) {
      pushToast("Ошибка", e.message);
    }
  }

  async function createConversation() {
    try {
      const type = createForm.type;
      const payload = { type, title: createForm.title };
      if (type === "direct") payload.direct_peer_id = Number(createForm.direct_peer_id);
      else payload.member_ids = createForm.member_ids.split(",").map((x) => Number(x.trim())).filter(Boolean);
      const res = await api("/api/conversations", { method: "POST", body: payload });
      let conv = res.conversation;
      if (type !== "direct") {
        const secret = crypto.getRandomValues(new Uint32Array(4)).join("-");
        setRoomSecret(conv.id, secret);
        setInviteSecret(secret);
        pushToast("Invite link", `${location.origin}/#invite=conv_${conv.id}_${secret}`);
      }
      await loadConversations();
      setSelectedId(conv.id);
      setCreateOpen(false);
    } catch (e) {
      pushToast("Ошибка", e.message);
    }
  }

  async function joinConversation() {
    try {
      const raw = joinInvite.trim();
      let inviteCode = raw;
      let secret = "";
      const m = raw.match(/invite=(conv_\d+_?.+)?/i) || raw.match(/conv_\d+_.+/i);
      if (raw.includes("#invite=")) {
        const frag = raw.split("#invite=")[1];
        inviteCode = frag;
      }
      if (inviteCode.startsWith("conv_")) {
        const parts = inviteCode.split("_");
        if (parts.length >= 3) secret = parts.slice(2).join("_");
      }
      if (secret) setRoomSecret(Number(inviteCode.split("_")[1]), secret);
      const res = await api("/api/conversations/join", { method: "POST", body: { invite_code: inviteCode, secret } });
      await loadConversations();
      setSelectedId(res.conversation.id);
      setJoinOpen(false);
      if (secret) setRoomSecret(res.conversation.id, secret);
      pushToast("Готово", "Вы присоединились к комнате.");
    } catch (e) {
      pushToast("Ошибка", e.message);
    }
  }

  async function uploadAndSend(text, conv, reply_to_id = null) {
    let fileMetas = [];
    const roomSecret = getRoomSecret(conv.id);
    const payload = { text, attachments: [], reply_to_id };
    if (attachments.length) {
      const key = conv.type === "direct"
        ? await deriveDirectKey(identity, JSON.parse(conv.members.find((m) => Number(m.id) !== Number(auth.id)).public_key))
        : await deriveRoomKey(roomSecret, `conv:${conv.id}`);
      for (const item of attachments) {
        const fileBytes = new Uint8Array(await blobToArrayBuffer(item.file));
        const encrypted = await encryptBytes(fileBytes, key);
        const fd = new FormData();
        fd.append("conversation_id", String(conv.id));
        fd.append("original_name", item.file.name);
        fd.append("mime_type", item.file.type || "application/octet-stream");
        fd.append("file", new Blob([unb64(encrypted)], { type: "application/octet-stream" }), item.file.name + ".enc");
        const meta = await api("/api/files/upload", { method: "POST", body: fd });
        fileMetas.push({ ...meta.file, decrypted_name: item.file.name, encrypted_payload: encrypted, size_bytes: item.file.size });
      }
      payload.attachments = fileMetas.map((f) => ({
        id: f.id,
        original_name: f.decrypted_name,
        mime_type: f.mime_type,
        size_bytes: f.size_bytes,
        url: f.url,
      }));
    }
    const encrypted = await encryptMessage(payload, conv, identity, roomSecret);
    const message = {
      ciphertext: encrypted.ciphertext,
      envelope: encrypted.envelope,
      reply_to_id,
      forwarded_from_id: null,
    };
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ kind: "message", message }));
    } else {
      await api(`/api/conversations/${conv.id}/messages`, { method: "POST", body: message });
    }
  }

  async function handleSend() {
    const text = composer.trim();
    if (!text && !attachments.length) return;
    if (!selectedConversation) return;
    try {
      await uploadAndSend(text, selectedConversation, replyTo?.id || null);
      setComposer("");
      setAttachments([]);
      setReplyTo(null);
      await loadMessages(selectedConversation.id);
      await loadConversations();
    } catch (e) {
      pushToast("Ошибка", e.message);
    }
  }

  async function handleAttach(files) {
    const picked = [...files].map((file) => ({ id: uid(), file }));
    setAttachments((xs) => [...xs, ...picked]);
  }

  async function sendTyping(isTyping) {
    if (!selectedConversation) return;
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ kind: "typing", typing: isTyping }));
    }
  }

  async function removeMessage(message) {
    if (!selectedConversation) return;
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ kind: "delete_message", message_id: message.id }));
    } else {
      await api(`/api/messages/${message.id}`, { method: "DELETE" });
    }
  }

  async function editExisting(message, newText) {
    if (!selectedConversation) return;
    const roomSecret = getRoomSecret(selectedConversation.id);
    const payload = await encryptMessage({ text: newText, attachments: [], reply_to_id: message.reply_to_id }, selectedConversation, identity, roomSecret);
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ kind: "edit_message", message_id: message.id, ciphertext: payload.ciphertext, envelope: payload.envelope }));
    } else {
      await api(`/api/messages/${message.id}`, { method: "PUT", body: { ciphertext: payload.ciphertext, envelope: payload.envelope } });
    }
  }

  async function toggleReaction(message, emoji) {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ kind: "reaction", message_id: message.id, emoji }));
    } else {
      await api(`/api/messages/${message.id}/reaction`, { method: "POST", body: { emoji } });
    }
  }

  async function pinMessage(message) {
    await api(`/api/messages/${message.id}/pin`, { method: "POST" });
  }

  async function startCall(kind) {
    if (!selectedConversation) return;
    try {
      const fd = new FormData();
      fd.append("kind", kind);
      const res = await api(`/api/conversations/${selectedConversation.id}/calls/start`, { method: "POST", body: fd });
      setCallState((s) => ({ ...s, open: true, kind, incoming: null, active: res.call }));
      await beginCall(kind, true);
    } catch (e) {
      pushToast("Ошибка", e.message);
    }
  }

  async function beginCall(kind, initiator) {
    const local = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: kind === "video",
    });
    const remote = new MediaStream();
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: ["stun:stun.l.google.com:19302"] }],
    });
    pcRef.current = pc;
    local.getTracks().forEach((t) => pc.addTrack(t, local));
    pc.ontrack = (event) => {
      event.streams[0].getTracks().forEach((t) => remote.addTrack(t));
      if (remoteVideoRef.current) remoteVideoRef.current.srcObject = remote;
    };
    pc.onicecandidate = (event) => {
      if (event.candidate && wsRef.current?.readyState === 1) {
        wsRef.current.send(JSON.stringify({ kind: "call_signal", signal: { type: "ice", candidate: event.candidate } }));
      }
    };
    if (localVideoRef.current) localVideoRef.current.srcObject = local;
    setCallState((s) => ({ ...s, localStream: local, remoteStream: remote, muted: false, cameraOff: kind !== "video" ? true : false }));
    if (initiator) {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      wsRef.current?.send(JSON.stringify({ kind: "call_signal", signal: { type: "offer", sdp: offer.sdp, kind } }));
    }
  }

  async function handleIncomingSignal(signal) {
    if (!signal) return;
    if (!pcRef.current) return;
    const pc = pcRef.current;
    if (signal.type === "offer") {
      await pc.setRemoteDescription({ type: "offer", sdp: signal.sdp });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      wsRef.current?.send(JSON.stringify({ kind: "call_signal", signal: { type: "answer", sdp: answer.sdp } }));
    } else if (signal.type === "answer") {
      await pc.setRemoteDescription({ type: "answer", sdp: signal.sdp });
    } else if (signal.type === "ice" && signal.candidate) {
      try { await pc.addIceCandidate(signal.candidate); } catch {}
    }
  }

  async function acceptIncomingCall() {
    const call = callState.incoming;
    if (!call) return;
    setCallState((s) => ({ ...s, incoming: null, open: true, kind: call.kind, active: call }));
    await beginCall(call.kind, false);
    const pending = pendingSignalRef.current;
    if (pending?.type === "offer" && pcRef.current) {
      await pcRef.current.setRemoteDescription({ type: "offer", sdp: pending.sdp });
      const answer = await pcRef.current.createAnswer();
      await pcRef.current.setLocalDescription(answer);
      wsRef.current?.send(JSON.stringify({ kind: "call_signal", signal: { type: "answer", sdp: answer.sdp } }));
      pendingSignalRef.current = null;
    }
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ kind: "call_signal", signal: { type: "accept", call_id: call.id } }));
    }
  }

  async function declineIncomingCall() {
    setCallState((s) => ({ ...s, incoming: null, open: false }));
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ kind: "call_end" }));
    }
  }

  async function endCall(silent = false) {
    try {
      if (pcRef.current) {
        pcRef.current.close();
        pcRef.current = null;
      }
      if (callState.localStream) {
        callState.localStream.getTracks().forEach((t) => t.stop());
      }
      setCallState({
        open: false,
        kind: "audio",
        incoming: null,
        active: null,
        localStream: null,
        remoteStream: null,
        muted: false,
        cameraOff: false,
      });
      if (!silent && wsRef.current?.readyState === 1) {
        wsRef.current.send(JSON.stringify({ kind: "call_end" }));
      }
    } catch {}
  }

  function toggleMic() {
    if (!callState.localStream) return;
    const muted = !callState.muted;
    callState.localStream.getAudioTracks().forEach((t) => (t.enabled = !muted));
    setCallState((s) => ({ ...s, muted }));
  }

  function toggleCam() {
    if (!callState.localStream) return;
    const cameraOff = !callState.cameraOff;
    callState.localStream.getVideoTracks().forEach((t) => (t.enabled = !cameraOff));
    setCallState((s) => ({ ...s, cameraOff }));
  }

  async function shareScreen() {
    if (!pcRef.current) return;
    const stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
    const track = stream.getVideoTracks()[0];
    const sender = pcRef.current.getSenders().find((s) => s.track && s.track.kind === "video");
    if (sender && track) {
      await sender.replaceTrack(track);
      track.onended = () => {
        toggleCam();
      };
    }
  }

  async function searchUsersHandler(text) {
    setSearchText(text);
    try {
      await loadUsers(text);
    } catch {}
  }

  function selectedTypingLabel() {
    const ids = Object.keys(typingUsers).filter((id) => typingUsers[id]);
    if (!ids.length) return "";
    return "Печатает…";
  }

  const selectedMessages = decrypted;

  if (!auth) {
    return (
      <div className="auth-wrap">
        <div className="auth-card glass">
          <div className="auth-hero">
            <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 20 }}>
              <div className="logo"></div>
              <div>
                <div style={{ fontWeight: 800, letterSpacing: .3 }}>Future Messenger</div>
                <div className="small">E2EE · WebSocket · WebRTC · SQLite</div>
              </div>
            </div>
            <h1>Мессенджер нового поколения для личного использования</h1>
            <p>
              Встроенное сквозное шифрование, мгновенная доставка, группы, каналы, медиа, голос и видео,
              современный glassmorphism-интерфейс и работа без сложной настройки.
            </p>
            <div className="stack" style={{ marginTop: 22, flexWrap: "wrap" }}>
              <span className="chip">E2EE</span>
              <span className="chip">WebRTC</span>
              <span className="chip">JWT</span>
              <span className="chip">SQLite</span>
              <span className="chip">Responsive</span>
            </div>
          </div>
          <div className="auth-grid">
            <div className="switcher">
              <button className={cls("ghost-btn", showAuthMode === "login" && "primary-btn")} onClick={() => setShowAuthMode("login")}>Вход</button>
              <button className={cls("ghost-btn", showAuthMode === "register" && "primary-btn")} onClick={() => setShowAuthMode("register")}>Регистрация</button>
              <button className={cls("ghost-btn", showAuthMode === "recovery" && "primary-btn")} onClick={() => setShowAuthMode("recovery")}>Восстановление</button>
            </div>
            {showAuthMode === "login" && (
              <form onSubmit={handleLogin} className="stack-col">
                <div className="field"><label>Email</label><input value={loginForm.email} onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })} type="email" required /></div>
                <div className="field"><label>Пароль</label><input value={loginForm.password} onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })} type="password" required /></div>
                <button className="primary-btn" type="submit">Войти</button>
              </form>
            )}
            {showAuthMode === "register" && (
              <form onSubmit={handleRegister} className="stack-col">
                <div className="field"><label>Имя</label><input value={registerForm.display_name} onChange={(e) => setRegisterForm({ ...registerForm, display_name: e.target.value })} required /></div>
                <div className="field"><label>Email</label><input value={registerForm.email} onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })} type="email" required /></div>
                <div className="field"><label>Пароль</label><input value={registerForm.password} onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })} type="password" required /></div>
                <button className="primary-btn" type="submit">Создать аккаунт</button>
              </form>
            )}
            {showAuthMode === "recovery" && (
              <div className="stack-col">
                <div className="field"><label>Email</label><input value={recoveryForm.email} onChange={(e) => setRecoveryForm({ ...recoveryForm, email: e.target.value })} type="email" /></div>
                <button className="ghost-btn" onClick={handleRecoveryRequest}>Получить код</button>
                <div className="field"><label>Код</label><input value={recoveryForm.code} onChange={(e) => setRecoveryForm({ ...recoveryForm, code: e.target.value })} /></div>
                <div className="field"><label>Новый пароль</label><input value={recoveryForm.new_password} onChange={(e) => setRecoveryForm({ ...recoveryForm, new_password: e.target.value })} type="password" /></div>
                <button className="primary-btn" onClick={handleRecoveryComplete}>Сменить пароль</button>
                {recoveryCode ? <div className="small">Код: {recoveryCode}</div> : null}
              </div>
            )}
          </div>
        </div>
        <ToastStack items={toasts} onClose={closeToast} />
      </div>
    );
  }

  const selectedMembers = selectedConversation?.members || [];
  const activePeer = selectedMembers.find((m) => Number(m.id) !== Number(auth.id));

  return (
    <>
      <div className="app-shell">
        <aside className="sidebar glass">
          <div className="brand">
            <div className="logo"></div>
            <div style={{ minWidth: 0 }}>
              <h1>Future Messenger</h1>
              <p>{auth.display_name} · {auth.is_online ? "online" : "offline"}</p>
            </div>
          </div>
          <div className="search-box">
            <input value={searchText} onChange={(e) => searchUsersHandler(e.target.value)} placeholder="Поиск людей..." />
            <button className="icon-btn" onClick={() => setCreateOpen(true)}>＋</button>
            <button className="icon-btn" onClick={() => setJoinOpen(true)}>↗</button>
          </div>
          <div className="list">
            {conversations.map((conv) => {
              const last = conv.last_message;
              const member = (conv.members || []).find((m) => Number(m.id) !== Number(auth.id)) || conv.members?.[0];
              const online = (conv.members || []).some((m) => m.is_online && Number(m.id) !== Number(auth.id));
              return (
                <div key={conv.id} className={cls("chat-item", Number(selectedId) === Number(conv.id) && "active")} onClick={() => setSelectedId(conv.id)}>
                  <Avatar user={member || auth} />
                  <div className="meta">
                    <div className="title-row">
                      <div className="title">{conv.title}</div>
                      <div className="time">{formatTime(last?.created_at || conv.updated_at)}</div>
                    </div>
                    <div className="preview">
                      <span className={cls("status-dot", online && "online")} style={{ marginRight: 8 }}></span>
                      {last ? "Зашифрованное сообщение" : conv.type === "direct" ? "Прямой чат" : conv.type === "group" ? "Группа" : "Канал"}
                    </div>
                  </div>
                  {conv.last_message ? <div className="badge">•</div> : null}
                </div>
              );
            })}
            {!conversations.length ? <div className="small" style={{ padding: 12 }}>Создайте первый чат или группу.</div> : null}
          </div>
        </aside>

        <main className="chat glass">
          {selectedConversation ? (
            <>
              <div className="chat-header">
                <div className="chat-title">
                  <Avatar user={activePeer || auth} size={54} />
                  <div style={{ minWidth: 0 }}>
                    <h2>{selectedConversation.title}</h2>
                    <div className="sub">
                      {selectedConversation.type} · {selectedTypingLabel() || `${selectedMembers.length} участников`}
                    </div>
                  </div>
                </div>
                <div className="chat-tools">
                  <button className="ghost-btn" onClick={() => startCall("audio")}>Голос</button>
                  <button className="ghost-btn" onClick={() => startCall("video")}>Видео</button>
                  <button className="ghost-btn" onClick={() => setProfileOpen(true)}>Профиль</button>
                </div>
              </div>

              <div className="messages" ref={messagesRef}>
                {selectedMessages.map((m, idx) => {
                  const day = idx === 0 || formatDay(selectedMessages[idx - 1]?.created_at) !== formatDay(m.created_at);
                  const dec = m.decoded?.data || { text: "", attachments: [] };
                  const isMe = Number(m.sender_id) === Number(auth.id);
                  return (
                    <React.Fragment key={m.id}>
                      {day ? <div className="day-divider">{formatDay(m.created_at)}</div> : null}
                      <div className={cls("msg-row", isMe && "me")}>
                        <div className={cls("message", isMe && "me", m.deleted_at && "deleted")}>
                          <div className="head">
                            <div className="sender">{isMe ? "Вы" : (selectedMembers.find((u) => Number(u.id) === Number(m.sender_id))?.display_name || "Участник")}</div>
                            <div className="time">{formatTime(m.created_at)}{m.edited_at ? " · edited" : ""}{m.pinned ? " · pinned" : ""}</div>
                          </div>
                          <div className="body">{dec.text}</div>
                          {!!dec.attachments?.length && (
                            <div className="actions">
                              {dec.attachments.map((a) => (
                                <a key={a.id} className="chip" href={a.url} target="_blank" rel="noreferrer">📎 {a.original_name}</a>
                              ))}
                            </div>
                          )}
                          <div className="actions">
                            <button className="chip" onClick={() => setReplyTo(m)}>Ответить</button>
                            <button className="chip" onClick={() => toggleReaction(m, "👍")}>👍</button>
                            <button className="chip" onClick={() => toggleReaction(m, "❤️")}>❤️</button>
                            {isMe ? <button className="chip" onClick={() => {
                              const next = prompt("Новый текст сообщения", dec.text);
                              if (next != null) editExisting(m, next);
                            }}>Редактировать</button> : null}
                            {isMe ? <button className="chip" onClick={() => removeMessage(m)}>Удалить</button> : null}
                            <button className="chip" onClick={() => pinMessage(m)}>Закрепить</button>
                          </div>
                          {m.reaction_summary && m.reaction_summary !== "{}" ? (
                            <div className="small" style={{ marginTop: 8 }}>Реакции: {Object.values(JSON.parse(m.reaction_summary)).map((r) => r.emoji).join(" ")}</div>
                          ) : null}
                        </div>
                      </div>
                    </React.Fragment>
                  );
                })}
              </div>

              <div className="composer">
                <div className="box">
                  <button className="icon-btn" onClick={() => fileInputRef.current?.click()}>＋</button>
                  <input ref={fileInputRef} type="file" multiple className="hidden" onChange={(e) => handleAttach(e.target.files || [])} />
                  <textarea
                    value={composer}
                    onChange={(e) => {
                      setComposer(e.target.value);
                      if (wsRef.current?.readyState === 1) wsRef.current.send(JSON.stringify({ kind: "typing", typing: true }));
                      clearTimeout(typingTimer.current);
                      typingTimer.current = setTimeout(() => {
                        if (wsRef.current?.readyState === 1) wsRef.current.send(JSON.stringify({ kind: "typing", typing: false }));
                      }, 1200);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        handleSend();
                      }
                    }}
                    placeholder="Сообщение..."
                  />
                </div>
                <div className="stack" style={{ justifyContent: "space-between" }}>
                  <div className="small">
                    {replyTo ? `Ответ: #${replyTo.id}` : " "}
                    {attachments.length ? ` · файлов: ${attachments.length}` : ""}
                  </div>
                  <button className="primary-btn" onClick={handleSend}>Отправить</button>
                </div>
              </div>
            </>
          ) : (
            <div style={{ margin: "auto", textAlign: "center", maxWidth: 540, padding: 20 }}>
              <h2>Выберите чат</h2>
              <p className="small">Создайте личный диалог, группу или канал. Сообщения хранятся только в зашифрованном виде.</p>
            </div>
          )}
        </main>

        <aside className="rightbar glass">
          <div className="panel">
            <h3>Профиль</h3>
            <div className="row"><span>Имя</span><strong>{auth.display_name}</strong></div>
            <div className="row"><span>Email</span><strong>{auth.email}</strong></div>
            <div className="row"><span>Статус</span><strong>{auth.is_online ? "Онлайн" : "Оффлайн"}</strong></div>
            <div className="row"><span>Последний визит</span><strong>{auth.last_seen ? new Date(auth.last_seen).toLocaleString() : "—"}</strong></div>
            <div className="row"><button className="ghost-btn" onClick={() => setProfileOpen(true)}>Настройки</button></div>
          </div>
          <div className="panel">
            <h3>Секрет комнаты</h3>
            <div className="small">Для групп и каналов секрет хранится локально в браузере и нужен для расшифровки сообщений.</div>
            <div className="field" style={{ marginTop: 10 }}>
              <input value={selectedConversation ? (getRoomSecret(selectedConversation.id) || inviteSecret) : ""} onChange={(e) => {
                if (selectedConversation) setRoomSecret(selectedConversation.id, e.target.value);
                setInviteSecret(e.target.value);
              }} placeholder="room secret" />
            </div>
            <button className="ghost-btn" onClick={() => {
              if (selectedConversation) {
                const secret = getRoomSecret(selectedConversation.id);
                navigator.clipboard.writeText(`${location.origin}/#invite=conv_${selectedConversation.id}_${secret}`).then(() => pushToast("Скопировано", "Invite link сохранён в буфере."));
              }
            }}>Копировать invite</button>
          </div>
          <div className="panel">
            <h3>Онлайн</h3>
            <div className="stack-col">
              {(selectedMembers || []).slice(0, 8).map((m) => (
                <div key={m.id} className="row">
                  <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span className={cls("status-dot", m.is_online && "online")}></span>{m.display_name}
                  </span>
                  <strong>{Number(m.id) === Number(auth.id) ? "Вы" : (m.role || "member")}</strong>
                </div>
              ))}
            </div>
          </div>
          <div className="panel">
            <button className="danger-btn" onClick={handleLogout} style={{ width: "100%" }}>Выйти</button>
          </div>
        </aside>
      </div>

      {profileOpen ? (
        <div className="modal-backdrop" onClick={() => setProfileOpen(false)}>
          <div className="modal glass" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <strong>Настройки профиля</strong>
              <button className="icon-btn" onClick={() => setProfileOpen(false)}>×</button>
            </div>
            <div className="grid-2">
              <div className="stack-col">
                <div className="field"><label>Имя</label><input value={profileDraft.display_name} onChange={(e) => setProfileDraft({ ...profileDraft, display_name: e.target.value })} /></div>
                <div className="field"><label>Bio</label><textarea rows="5" value={profileDraft.bio} onChange={(e) => setProfileDraft({ ...profileDraft, bio: e.target.value })} /></div>
                <button className="primary-btn" onClick={handleProfileSave}>Сохранить</button>
              </div>
              <div className="stack-col">
                <div className="panel">
                  <h3>Аватар</h3>
                  <input type="file" accept="image/*" onChange={(e) => handleAvatarUpload(e.target.files?.[0])} />
                </div>
                <div className="panel">
                  <h3>Ключи E2EE</h3>
                  <div className="small">Публичный ключ отправляется на сервер для обмена ключами. Приватный хранится только в браузере.</div>
                  <textarea rows="10" readOnly value={JSON.stringify(identity?.publicJwk || {}, null, 2)} />
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {createOpen ? (
        <div className="modal-backdrop" onClick={() => setCreateOpen(false)}>
          <div className="modal glass" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <strong>Новый чат</strong>
              <button className="icon-btn" onClick={() => setCreateOpen(false)}>×</button>
            </div>
            <div className="grid-2">
              <div className="stack-col">
                <div className="field">
                  <label>Тип</label>
                  <select value={createForm.type} onChange={(e) => setCreateForm({ ...createForm, type: e.target.value })}>
                    <option value="direct">Личный чат</option>
                    <option value="group">Группа</option>
                    <option value="channel">Канал</option>
                  </select>
                </div>
                <div className="field"><label>Название</label><input value={createForm.title} onChange={(e) => setCreateForm({ ...createForm, title: e.target.value })} /></div>
                {createForm.type === "direct" ? (
                  <div className="field"><label>ID собеседника</label><input value={createForm.direct_peer_id} onChange={(e) => setCreateForm({ ...createForm, direct_peer_id: e.target.value })} /></div>
                ) : (
                  <div className="field"><label>ID участников через запятую</label><input value={createForm.member_ids} onChange={(e) => setCreateForm({ ...createForm, member_ids: e.target.value })} placeholder="2,5,8" /></div>
                )}
                <button className="primary-btn" onClick={createConversation}>Создать</button>
              </div>
              <div className="panel">
                <h3>Подсказка</h3>
                <div className="small">
                  Для личного чата укажите ID пользователя. Для групп и каналов после создания секрет комнаты можно сохранить и раздать через invite-link.
                </div>
                <div className="small" style={{ marginTop: 10 }}>
                  Invite-link будет отображён после создания и хранится только у вас.
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {joinOpen ? (
        <div className="modal-backdrop" onClick={() => setJoinOpen(false)}>
          <div className="modal glass" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <strong>Присоединиться по invite-link</strong>
              <button className="icon-btn" onClick={() => setJoinOpen(false)}>×</button>
            </div>
            <div className="stack-col">
              <div className="field"><label>Ссылка или код</label><textarea rows="4" value={joinInvite} onChange={(e) => setJoinInvite(e.target.value)} placeholder="https://.../#invite=conv_12_secret" /></div>
              <button className="primary-btn" onClick={joinConversation}>Присоединиться</button>
            </div>
          </div>
        </div>
      ) : null}

      {(callState.open || callState.incoming) ? (
        <div className="modal-backdrop" onClick={() => {}}>
          <div className="modal glass">
            <div className="modal-head">
              <strong>{callState.incoming ? "Входящий вызов" : `${callState.kind === "video" ? "Видеозвонок" : "Голосовой звонок"}`}</strong>
              <button className="icon-btn" onClick={() => endCall()}>×</button>
            </div>
            {callState.incoming ? (
              <div className="stack-col">
                <div className="small">Новый вызов в чате. Принять или отклонить?</div>
                <div className="stack">
                  <button className="primary-btn" onClick={acceptIncomingCall}>Принять</button>
                  <button className="danger-btn" onClick={declineIncomingCall}>Отклонить</button>
                </div>
              </div>
            ) : (
              <>
                <div className="video-grid">
                  <div className="video-box">
                    <video ref={localVideoRef} autoPlay playsInline muted />
                  </div>
                  <div className="video-box">
                    <video ref={remoteVideoRef} autoPlay playsInline />
                  </div>
                </div>
                <div className="stack" style={{ marginTop: 12, justifyContent: "space-between", flexWrap: "wrap" }}>
                  <div className="stack">
                    <button className="ghost-btn" onClick={toggleMic}>{callState.muted ? "Вкл. микрофон" : "Выкл. микрофон"}</button>
                    <button className="ghost-btn" onClick={toggleCam}>{callState.cameraOff ? "Вкл. камеру" : "Выкл. камеру"}</button>
                    <button className="ghost-btn" onClick={shareScreen}>Демонстрация</button>
                  </div>
                  <button className="danger-btn" onClick={() => endCall()}>Завершить</button>
                </div>
              </>
            )}
          </div>
        </div>
      ) : null}

      <ToastStack items={toasts} onClose={closeToast} />
    </>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
