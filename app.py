#!/usr/bin/env python3
"""
Chat app - Flask + Socket.IO application.

Features & fixes:
 - Room-scoped Socket.IO (sockets join/leave rooms properly)
 - Client uses websocket then polling fallback
 - Bleach sanitizer compatible with modern versions
 - No Query.get() legacy usage (uses db.session.get)
 - Timezone-aware datetimes
 - Long message handling: if > LONG_MESSAGE_LIMIT chars, store as .txt and attach
 - Default avatar uses provided URL
 - Improved mobile + desktop UI, settings cancel button, Telegram profile note
 - CSP header (development-friendly) to avoid eval-block issues (tighten for production)
"""

import os
import json
import secrets
import logging
import random
import tempfile
import shutil
import zipfile
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, send_from_directory, render_template,
    jsonify, flash, session as flask_session, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from flask_socketio import SocketIO, join_room, leave_room
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text as sa_text, or_

import requests

from config import Config

# Optional libs
try:
    import markdown
    def render_md(s):
        return markdown.markdown(s or "", extensions=["fenced_code", "codehilite"])
except Exception:
    def render_md(s):
        return "<pre>{}</pre>".format((s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    import bleach
    def sanitize_html(html):
        # handle bleach.sanitizer.ALLOWED_TAGS being a frozenset or list
        base_tags = getattr(bleach.sanitizer, "ALLOWED_TAGS", getattr(bleach, "ALLOWED_TAGS", []))
        allowed = set(base_tags) | {"pre","code","img"}
        return bleach.clean(html or "", tags=list(allowed),
                            attributes={"a":["href","title","rel","target"], "img":["src","alt","loading"]},
                            strip=True)
except Exception:
    def sanitize_html(html):
        return html or ""

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ghost_chat")

ADMIN_SETTINGS_KEYS = [
    "APP_NAME", "APP_ICON", "APP_TAGLINE", "LOGIN_SUBTITLE", "REGISTER_SUBTITLE",
    "DEFAULT_ROOM_NAME", "WELCOME_MESSAGE", "USER_JOIN_MESSAGE", "DEFAULT_AVATAR",
    "THEME_ACCENT", "THEME_ACCENT_2", "THEME_BG", "THEME_PANEL", "THEME_CARD",
    "THEME_TEXT", "THEME_MUTED", "THEME_BORDER"
]

def load_admin_settings():
    if not os.path.exists(SETTINGS_PATH):
        return
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh) or {}
        for k in ADMIN_SETTINGS_KEYS:
            if k in data:
                app.config[k] = data[k]
    except Exception:
        logger.exception("Failed to load admin settings")

def save_admin_settings(updates):
    try:
        data = {}
        if os.path.exists(SETTINGS_PATH):
            with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh) or {}
        data.update(updates)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        logger.exception("Failed to save admin settings")

def refresh_app_strings():
    global APP_NAME, APP_ICON, APP_TAGLINE, LOGIN_SUBTITLE, REGISTER_SUBTITLE
    global DEFAULT_ROOM_NAME, WELCOME_MESSAGE, USER_JOIN_MESSAGE, DEFAULT_AVATAR
    APP_NAME = app.config.get("APP_NAME", "Sukuna Chat 🔥")
    APP_ICON = app.config.get("APP_ICON", "👻")
    APP_TAGLINE = app.config.get("APP_TAGLINE", "Chat that feels alive")
    LOGIN_SUBTITLE = app.config.get("LOGIN_SUBTITLE", f"Sign in to {APP_NAME}")
    REGISTER_SUBTITLE = app.config.get("REGISTER_SUBTITLE", "Create your account to get started")
    DEFAULT_ROOM_NAME = app.config.get("DEFAULT_ROOM_NAME", f"{APP_NAME} chat")
    WELCOME_MESSAGE = app.config.get("WELCOME_MESSAGE", f"Welcome to {APP_NAME} chat! Be kind.")
    USER_JOIN_MESSAGE = app.config.get("USER_JOIN_MESSAGE", "👋 {user} joined {app} chat")
    DEFAULT_AVATAR = app.config.get("DEFAULT_AVATAR", "https://negative-orange-ql4jplfnvn.edgeone.app/1767275981651.jpg")

def now_utc():
    return datetime.now(timezone.utc)

def ensure_aware(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def is_expired(dt):
    dt_aware = ensure_aware(dt)
    return (not dt_aware) or (dt_aware < now_utc())

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(to_email, otp, purpose, display_name):
    api_key = app.config.get("VLY_API_KEY") or ""
    api_url = app.config.get("VLY_API_URL") or "https://email.vly.ai/send_otp"
    app_name = APP_NAME or "Chat App"
    if not api_key:
        logger.warning("VLY API key missing")
        return False
    custom_message = f"Hi {display_name}, use this OTP to {purpose} in {app_name}."
    try:
        data = {
            "to": to_email,
            "otp": otp,
            "appName": app_name,
            "customMessage": custom_message
        }
        headers = {
            "x-api-key": api_key,
            "Content-Type": "application/json"
        }
        resp = requests.post(api_url, json=data, headers=headers, timeout=15)
        if resp.status_code != 200:
            logger.error("VLY send failed: %s %s", resp.status_code, resp.text)
            return False
        return True
    except Exception:
        logger.exception("VLY send failed")
        return False

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "chat.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
STICKER_FOLDER = os.path.join(BASE_DIR, "stickers")
SETTINGS_PATH = os.path.join(BASE_DIR, "admin_settings.json")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STICKER_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config.from_object(Config)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["STICKER_FOLDER"] = STICKER_FOLDER

ALLOWED_IMAGE_EXT = {"png","jpg","jpeg","gif","webp"}
ALLOWED_VIDEO_EXT = {"mp4","webm","ogg","mov"}
MAX_FILE_SIZE = int(app.config.get("MAX_FILE_SIZE", 25 * 1024 * 1024))
MAX_FILES_PER_MESSAGE = int(app.config.get("MAX_FILES_PER_MESSAGE", 5))
THUMB_MAX_SIZE = (1024, 1024)
LONG_MESSAGE_LIMIT = int(app.config.get("LONG_MESSAGE_LIMIT", 300))  # chars; over this, server writes a .txt file and attaches it

DEFAULT_AVATAR = ""
APP_NAME = ""
APP_ICON = ""
APP_TAGLINE = ""
LOGIN_SUBTITLE = ""
REGISTER_SUBTITLE = ""
DEFAULT_ROOM_NAME = ""
WELCOME_MESSAGE = ""
USER_JOIN_MESSAGE = ""

app.config["MAX_CONTENT_LENGTH"] = 6 * MAX_FILE_SIZE

load_admin_settings()
refresh_app_strings()

EMAIL_VERIFY_TTL_MIN = int(app.config.get("EMAIL_VERIFY_TTL_MIN", 15))
RESET_TTL_MIN = int(app.config.get("RESET_TTL_MIN", 10))

app.logger.setLevel(logging.DEBUG)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------
# Models
# ---------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(190), unique=True, index=True)
    email_verified = db.Column(db.Boolean, default=False)
    email_verify_otp = db.Column(db.String(16))
    email_verify_expires = db.Column(db.DateTime)
    reset_otp = db.Column(db.String(16))
    reset_expires = db.Column(db.DateTime)
    display_name = db.Column(db.String(120))
    avatar = db.Column(db.String(256))
    bio = db.Column(db.Text)
    session_version = db.Column(db.Integer, default=0)
    last_seen = db.Column(db.DateTime)
    show_online = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    name = db.Column(db.String(120), nullable=False)
    room_key = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def check_password(self, pw):
        if not self.password_hash:
            return pw in (None, "", "")
        return check_password_hash(self.password_hash, pw or "")

class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("room.id"), index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    text = db.Column(db.Text)
    rendered = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), index=True)
    reply_to = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    edited = db.Column(db.Boolean, default=False)
    edited_at = db.Column(db.DateTime)
    pinned = db.Column(db.Boolean, default=False)
    pinned_at = db.Column(db.DateTime)
    chat_id = db.Column(db.Integer, nullable=False, default=1, server_default=sa_text("1"))
    attachments = db.Column(db.Text, nullable=True)  # json list of {"filename","type"}
    reactions = db.Column(db.Text, nullable=True)
    read_by = db.Column(db.Text, nullable=True)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    text = db.Column(db.Text)
    link = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    seen = db.Column(db.Boolean, default=False)

# ---------------------------
# Helpers & stickers
# ---------------------------
EMOJI_STICKERS = [
    "😀","😁","😂","🤣","😃","😄","😅","😆","😉","😊","😋","😎","😍","😘","🥰","😗",
    "😙","😚","🙂","🤗","🤩","🤔","🤨","😐","😑","😶","🙄","😏","😣","😥","😮","🤐",
    "😯","😪","😫","😴","😌","😛","😜","😝","🤤","😒","😓","😔","😕","🙃","🫠","🫡",
    "🤕","🤒","🤧","🥳","🥸","😷","🤢","🤮","🤯","🥶","🥵","😵","😵‍💫","🤠","🥺","😭",
    "😤","😡","🤬","😱","😨","😰","😳","😬","🫣","🫢","🫥","😇","🤓","🧐","🥹","😈",
    "👻","💀","☠️","👽","🤖","💩","😺","😸","😹","😻","😼","😽","🙀","😿","😾","🐶",
    "🐱","🐭","🐹","🐰","🦊","🐻","🐼","🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐧","🐦",
    "🦄","🐝","🦋","🐢","🦖","🦕","🐙","🦑","🐳","🐬","🦈","🐊","🐍","🦓","🦒","🐘",
    "🦛","🦥","🦦","🦨","🦔","🐿️","🍎","🍊","🍉","🍓","🍒","🍑","🍍","🥭","🍌","🥝",
    "🍇","🍔","🍟","🍕","🌮","🍣","🍜","🍩","🍪","🎂","🍦","🍭","🍫","🥤","☕","🧋",
    "⚽","🏀","🏈","⚾","🎾","🏐","🎮","🎧","🎸","🎹","🥁","🎷","🎯","🚀","🛸","🏆",
    "🌈","🌙","⭐","🌟","🔥","💎","🎁","💡","📌","📎","✏️","✅","❌","🟢","🟡","🔴",
    "🟣","🔵","🟠","⚡","💬","❤️","🧡","💛","💚","💙","🤍","🤎","💜"
]

EMOJI_PALETTE = [
    "#0f172a", "#1e293b", "#0b3d3b", "#16324f", "#2a2b52", "#2f2a40",
    "#3a1f2b", "#3b2f1f", "#2f3b1f", "#1f3b2a", "#1f2f3b", "#3b1f3a"
]

EMOJI_STICKER_MAP = {}

def emoji_to_filename(emoji):
    codes = "-".join(f"{ord(ch):x}" for ch in emoji)
    return f"emoji-{codes}.svg"

def build_emoji_svg(emoji, bg):
    return (
        "<svg xmlns='http://www.w3.org/2000/svg' width='256' height='256'>"
        f"<rect width='256' height='256' rx='32' fill='{bg}'/>"
        "<text x='50%' y='52%' text-anchor='middle' dominant-baseline='middle' "
        "font-size='140' font-family='Apple Color Emoji, Segoe UI Emoji, Noto Color Emoji, sans-serif'>"
        f"{emoji}</text></svg>"
    )

def init_stickers():
    for idx, emoji in enumerate(EMOJI_STICKERS):
        name = emoji_to_filename(emoji)
        EMOJI_STICKER_MAP[name] = emoji
        path = os.path.join(STICKER_FOLDER, name)
        if not os.path.exists(path):
            svg = build_emoji_svg(emoji, EMOJI_PALETTE[idx % len(EMOJI_PALETTE)])
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(svg)
    samples = {
        "sticker-smile.svg": "<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200'><rect width='200' height='200' rx='20' fill='#ffd54f'/><circle cx='100' cy='90' r='50' fill='#fff59d'/><circle cx='80' cy='80' r='8' fill='#000'/><circle cx='120' cy='80' r='8' fill='#000'/><path d='M70 120 Q100 150 130 120' stroke='#000' stroke-width='6' fill='none' stroke-linecap='round'/></svg>",
        "sticker-heart.svg": "<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200'><rect width='200' height='200' rx='20' fill='#f8bbd0'/><path d='M100 150 L80 130 C30 90 60 40 100 70 C140 40 170 90 120 130 Z' fill='#e91e63'/></svg>",
    }
    for name, svg in samples.items():
        path = os.path.join(STICKER_FOLDER, name)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(svg)

init_stickers()

def allowed_extension(filename):
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_IMAGE_EXT or ext in ALLOWED_VIDEO_EXT

def kind_from_ext(filename):
    ext = filename.rsplit(".", 1)[1].lower()
    if ext in ALLOWED_IMAGE_EXT: return "image"
    if ext in ALLOWED_VIDEO_EXT: return "video"
    return "file"

def url_upload(fn):
    if not fn: return ""
    try:
        return url_for("uploaded_file", filename=fn)
    except Exception:
        return ""

def url_sticker(fn):
    try:
        return url_for("sticker_file", filename=fn)
    except Exception:
        return ""

def list_stickers():
    out = []
    try:
        for fn in sorted(os.listdir(STICKER_FOLDER)):
            if fn.startswith("."):
                continue
            ext = fn.rsplit(".", 1)[-1].lower()
            if ext not in {"svg", "png", "webp", "gif", "jpg", "jpeg"}:
                continue
            out.append({
                "filename": fn,
                "url": url_sticker(fn),
                "emoji": EMOJI_STICKER_MAP.get(fn)
            })
    except Exception:
        logger.exception("Failed to list stickers")
    return out

def user_to_dict(u):
    if not u:
        return {"id": None, "username":"system","display_name":"System","avatar": DEFAULT_AVATAR}
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name or u.username,
        "avatar": url_upload(u.avatar) if u.avatar else DEFAULT_AVATAR,
        "bio": u.bio or "",
        "last_seen": u.last_seen.isoformat() if u.last_seen else None,
        "is_admin": bool(getattr(u, "is_admin", False))
    }

# ---------------------------
# Migration helper
# ---------------------------
def ensure_message_columns():
    conn = None
    try:
        conn = db.engine.connect()
        logger.info("Running migration check: PRAGMA table_info(message)")
        res = conn.execute(sa_text("PRAGMA table_info(message)")).fetchall()
        existing_cols = [r[1] for r in res]
        logger.debug("Message columns: %s", existing_cols)
        to_add = []
        if "attachments" not in existing_cols: to_add.append(("attachments","TEXT","''"))
        if "reactions" not in existing_cols: to_add.append(("reactions","TEXT","'{}'"))
        if "read_by" not in existing_cols: to_add.append(("read_by","TEXT","'[]'"))
        if "chat_id" not in existing_cols: to_add.append(("chat_id","INTEGER","1"))
        if "edited" not in existing_cols: to_add.append(("edited","BOOLEAN","0"))
        if "edited_at" not in existing_cols: to_add.append(("edited_at","DATETIME","NULL"))
        for name, typ, default in to_add:
            try:
                sql = f"ALTER TABLE message ADD COLUMN {name} {typ} DEFAULT {default}"
                logger.info("MIGRATE: %s", sql)
                conn.execute(sa_text(sql))
            except Exception:
                logger.exception("Failed to add column %s", name)
    except Exception:
        logger.exception("Migration check failed")
    finally:
        if conn: conn.close()

def ensure_user_columns():
    conn = None
    try:
        conn = db.engine.connect()
        res = conn.execute(sa_text("PRAGMA table_info(user)")).fetchall()
        existing_cols = [r[1] for r in res]
        to_add = []
        if "is_admin" not in existing_cols:
            to_add.append(("is_admin", "BOOLEAN", "0"))
        if "email" not in existing_cols:
            to_add.append(("email", "TEXT", "NULL"))
        if "email_verified" not in existing_cols:
            to_add.append(("email_verified", "BOOLEAN", "0"))
        if "email_verify_otp" not in existing_cols:
            to_add.append(("email_verify_otp", "TEXT", "NULL"))
        if "email_verify_expires" not in existing_cols:
            to_add.append(("email_verify_expires", "DATETIME", "NULL"))
        if "reset_otp" not in existing_cols:
            to_add.append(("reset_otp", "TEXT", "NULL"))
        if "reset_expires" not in existing_cols:
            to_add.append(("reset_expires", "DATETIME", "NULL"))
        for name, typ, default in to_add:
            try:
                sql = f"ALTER TABLE user ADD COLUMN {name} {typ} DEFAULT {default}"
                logger.info("MIGRATE: %s", sql)
                conn.execute(sa_text(sql))
            except Exception:
                logger.exception("Failed to add column %s", name)
    except Exception:
        logger.exception("User migration check failed")
    finally:
        if conn: conn.close()

# ---------------------------
# Flask-Login
# ---------------------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

@app.before_request
def ensure_room_in_session():
    if getattr(current_user, "is_authenticated", False):
        if flask_session.get("room_id") is None:
            flask_session["room_id"] = 1

# ---------------------------
# Presence / sid_room mapping
# ---------------------------
online_user_sids = {}
sid_user = {}
sid_room = {}  # sid -> room_id

def mark_online(uid, sid):
    online_user_sids.setdefault(uid, set()).add(sid)
    sid_user[sid] = uid
    u = db.session.get(User, uid)
    if u:
        u.last_seen = datetime.now(timezone.utc)
        db.session.commit()

def mark_offline(sid):
    uid = sid_user.pop(sid, None)
    if uid:
        s = online_user_sids.get(uid)
        if s:
            s.discard(sid)
            if not s:
                online_user_sids.pop(uid, None)
                u = db.session.get(User, uid)
                if u:
                    u.last_seen = datetime.now(timezone.utc)
                    db.session.commit()
    sid_room.pop(sid, None)

def push_notification(user_id, payload):
    try:
        n = Notification(user_id=user_id, text=payload.get("text",""), link=payload.get("link",""))
        db.session.add(n); db.session.commit()
        sids = online_user_sids.get(user_id, set())
        for sid in sids:
            socketio.emit("notification", {"id": n.id, "text": n.text, "link": n.link, "created_at": n.created_at.isoformat()}, room=sid)
    except Exception:
        logger.exception("Failed to push notification to user %s", user_id)

# ---------------------------
# CSP header (development)
# ---------------------------
@app.after_request
def add_csp_headers(response):
    # Dev-friendly CSP: allows 'unsafe-eval' for CDN socket.io usage.
    # Remove 'unsafe-eval' and restrict hosts for production.
    csp = (
        "default-src 'self' https: data:; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "connect-src 'self' ws: wss: https:; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    return response

# ---------------------------
# Static routes
# ---------------------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/stickers/<path:filename>")
def sticker_file(filename):
    return send_from_directory(app.config["STICKER_FOLDER"], filename)



# ---------------------------
# Context injection
# ---------------------------
@app.context_processor
def inject_globals():
    return dict(
        app_name=APP_NAME,
        app_icon=APP_ICON,
        app_tagline=APP_TAGLINE,
        login_subtitle=LOGIN_SUBTITLE,
        register_subtitle=REGISTER_SUBTITLE,
        theme={
            "accent": app.config.get("THEME_ACCENT", "#ff7a18"),
            "accent_2": app.config.get("THEME_ACCENT_2", "#ffb347"),
            "bg": app.config.get("THEME_BG", "#0b1214"),
            "panel": app.config.get("THEME_PANEL", "#101820"),
            "card": app.config.get("THEME_CARD", "#141f24"),
            "text": app.config.get("THEME_TEXT", "#f5f7fa"),
            "muted": app.config.get("THEME_MUTED", "#a3b3c2"),
            "border": app.config.get("THEME_BORDER", "rgba(255,122,24,0.2)")
        }
    )

# ---------------------------
# Auth routes & APIs
# ---------------------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        display = request.form.get("display_name") or username
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password")
        if not username or not password or not email:
            flash("username, email and password required")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("username taken")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("email already registered")
            return redirect(url_for("register"))
        try:
            u = User(username=username, display_name=display, email=email, email_verified=False)
            u.set_password(password)
            u.email_verify_otp = generate_otp()
            u.email_verify_expires = now_utc() + timedelta(minutes=EMAIL_VERIFY_TTL_MIN)
            db.session.add(u); db.session.commit()
            # auto-join default room 1
            if not RoomMember.query.filter_by(room_id=1, user_id=u.id).first():
                rm = RoomMember(room_id=1, user_id=u.id); db.session.add(rm); db.session.commit()
            if not send_otp_email(u.email, u.email_verify_otp, "verify your account", u.display_name or u.username):
                flash("Email send failed. Contact admin.")
                return redirect(url_for("login"))
            logger.info("New user registered (pending verify): %s", username)
            return render_template("verify_otp.html", email=u.email)
        except Exception:
            logger.exception("Registration failed")
            flash("Registration failed")
            return redirect(url_for("register"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        identifier = (request.form.get("username") or "").strip()
        password = request.form.get("password")
        remember = bool(request.form.get("remember"))
        ident_lower = identifier.lower()
        u = User.query.filter(or_(User.username == identifier, User.email == ident_lower)).first()
        if u and u.check_password(password):
            if u.email and not u.email_verified:
                flash("Please verify your email before logging in")
                return redirect(url_for("login"))
            login_user(u, remember=remember)
            if not RoomMember.query.filter_by(room_id=1, user_id=u.id).first():
                rm = RoomMember(room_id=1, user_id=u.id); db.session.add(rm); db.session.commit()
            flask_session["room_id"] = 1
            u.last_seen = now_utc(); db.session.commit()
            logger.info("User logged in: %s", identifier)
            return redirect(url_for("index"))
        flash("Invalid credentials")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/verify-otp", methods=["GET","POST"])
def verify_email_otp():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        otp = (request.form.get("otp") or "").strip()
        u = User.query.filter_by(email=email).first()
        if not u or not u.email_verify_otp or u.email_verify_otp != otp:
            flash("Invalid OTP")
            return redirect(url_for("verify_email_otp", email=email))
        if is_expired(u.email_verify_expires):
            flash("OTP expired")
            return redirect(url_for("verify_email_otp", email=email))
        u.email_verified = True
        u.email_verify_otp = None
        u.email_verify_expires = None
        db.session.commit()
        sys_text = USER_JOIN_MESSAGE.format(user=(u.display_name or u.username), app=APP_NAME)
        m = Message(sender_id=None, text=sys_text, rendered=render_md(sys_text), reactions=json.dumps({}), read_by=json.dumps([]), attachments=json.dumps([]), chat_id=1)
        db.session.add(m); db.session.commit()
        login_user(u, remember=True)
        if not RoomMember.query.filter_by(room_id=1, user_id=u.id).first():
            db.session.add(RoomMember(room_id=1, user_id=u.id)); db.session.commit()
        flask_session["room_id"] = 1
        u.last_seen = now_utc(); db.session.commit()
        return redirect(url_for("index"))
    return render_template("verify_otp.html", email=request.args.get("email") or "")

@app.route("/forgot", methods=["GET","POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if not email:
            flash("email required")
            return redirect(url_for("forgot_password"))
        u = User.query.filter_by(email=email).first()
        if u:
            u.reset_otp = generate_otp()
            u.reset_expires = now_utc() + timedelta(minutes=RESET_TTL_MIN)
            db.session.commit()
            send_otp_email(u.email, u.reset_otp, "reset your password", u.display_name or u.username)
        return render_template("reset_otp.html", email=email)
    return render_template("forgot.html")

@app.route("/reset-otp", methods=["GET","POST"])
def reset_password_otp():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        otp = (request.form.get("otp") or "").strip()
        password = (request.form.get("password") or "").strip()
        if not email or not otp or not password:
            flash("email, otp and password required")
            return redirect(url_for("reset_password_otp", email=email))
        u = User.query.filter_by(email=email).first()
        if not u or not u.reset_otp or u.reset_otp != otp:
            flash("Invalid OTP")
            return redirect(url_for("reset_password_otp", email=email))
        if is_expired(u.reset_expires):
            flash("OTP expired")
            return redirect(url_for("reset_password_otp", email=email))
        u.set_password(password)
        u.reset_otp = None
        u.reset_expires = None
        db.session.commit()
        return render_template("verify_result.html", ok=True, message="Password reset. You can log in now.")
    return render_template("reset_otp.html", email=request.args.get("email") or "")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flask_session.pop("room_id", None)
    return redirect(url_for("login"))

@app.route("/admin-pn", methods=["GET","POST"])
def admin_panel():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if username == app.config.get("ADMIN_USERNAME") and password == app.config.get("ADMIN_PASSWORD"):
            flask_session["admin_auth"] = True
            return redirect(url_for("admin_panel"))
        flash("Invalid admin credentials")
    return render_template("admin.html", admin_auth=bool(flask_session.get("admin_auth")))

@app.route("/admin/logout")
def admin_logout():
    flask_session.pop("admin_auth", None)
    return redirect(url_for("admin_panel"))

def require_json(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not request.is_json and request.method != "GET":
            return jsonify({"error":"JSON required"}), 400
        return f(*a, **kw)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not flask_session.get("admin_auth"):
            return jsonify({"error":"admin auth required"}), 403
        return f(*a, **kw)
    return wrapper

@app.route("/api/me")
@login_required
def api_me():
    u = db.session.get(User, current_user.id)
    return jsonify({"user": user_to_dict(u), "room_id": flask_session.get("room_id", 1)})

@app.route("/api/profile", methods=["POST"])
@login_required
def api_profile():
    display = request.form.get("display_name")
    bio = request.form.get("bio")
    username = request.form.get("username")
    u = db.session.get(User, current_user.id)
    if username and username != u.username:
        if User.query.filter_by(username=username).first():
            return jsonify({"error":"username taken"}), 400
        u.username = username
    if display is not None:
        u.display_name = display[:120]
    if bio is not None:
        u.bio = bio[:1000]
    if "avatar" in request.files:
        f = request.files["avatar"]
        if f and f.filename:
            fname = secure_filename(f.filename)
            fname = secrets.token_hex(8) + "-" + fname
            dest = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            try:
                f.save(dest)
                if PIL_AVAILABLE:
                    try:
                        im = Image.open(dest)
                        im.thumbnail(THUMB_MAX_SIZE)
                        im.save(dest, optimize=True, quality=85)
                    except Exception:
                        logger.exception("Avatar resize failed")
                u.avatar = fname
            except Exception:
                logger.exception("Failed to save avatar")
    db.session.commit()
    profile = user_to_dict(u)
    try:
        memberships = RoomMember.query.filter_by(user_id=u.id).all()
        for m in memberships:
            socketio.emit("profile_update", {"user": profile}, room=f"room_{m.room_id}")
    except Exception:
        logger.exception("Failed to emit profile update")
    return jsonify({"ok":True, "profile": profile})

@app.route("/api/rooms")
@login_required
def api_rooms():
    mids = RoomMember.query.filter_by(user_id=current_user.id).all()
    rooms = []
    for m in mids:
        r = db.session.get(Room, m.room_id)
        if r:
            rooms.append({
                "id": r.id,
                "name": r.name,
                "owned": (r.owner_id == current_user.id),
                "key": (r.room_key if r.owner_id == current_user.id else None),
                "has_password": bool(r.password_hash)
            })
    return jsonify({"rooms": rooms, "current": flask_session.get("room_id",1)})

@app.route("/api/room_create", methods=["POST"])
@login_required
def api_room_create():
    if Room.query.filter_by(owner_id=current_user.id).first():
        return jsonify({"error":"You already created a room"}), 400
    name = (request.form.get("name") or "").strip() or f"{current_user.username}'s room"
    password = request.form.get("password") or ""
    room_key = secrets.token_urlsafe(10)
    room = Room(owner_id=current_user.id, name=name, room_key=room_key)
    if password:
        room.password_hash = generate_password_hash(password)
    db.session.add(room); db.session.commit()
    rm = RoomMember(room_id=room.id, user_id=current_user.id); db.session.add(rm); db.session.commit()
    flask_session["room_id"] = room.id
    return jsonify({"ok":True, "room":{"id":room.id,"name":room.name,"key":room.room_key}, "password": password})

@app.route("/api/room_set_password", methods=["POST"])
@login_required
def api_room_set_password():
    room_id = int(request.form.get("room_id") or 0)
    new_pw = request.form.get("password") or ""
    if not room_id: return jsonify({"error":"room_id required"}), 400
    room = db.session.get(Room, room_id)
    if not room: return jsonify({"error":"no such room"}), 404
    if room.owner_id != current_user.id: return jsonify({"error":"not owner"}), 403
    if new_pw:
        room.password_hash = generate_password_hash(new_pw)
    else:
        room.password_hash = None
    db.session.commit()
    return jsonify({"ok":True, "password": new_pw})

@app.route("/api/room_join", methods=["POST"])
@login_required
def api_room_join():
    room_key = (request.form.get("room_key") or "").strip()
    password = request.form.get("password") or ""
    if not room_key:
        return jsonify({"error":"room_key required"}), 400
    room = Room.query.filter_by(room_key=room_key).first()
    if not room: return jsonify({"error":"no such room"}), 404
    if not room.check_password(password):
        return jsonify({"error":"bad password"}), 403
    if not RoomMember.query.filter_by(room_id=room.id, user_id=current_user.id).first():
        rm = RoomMember(room_id=room.id, user_id=current_user.id); db.session.add(rm); db.session.commit()
    flask_session["room_id"] = room.id
    return jsonify({"ok":True, "room": {"id":room.id, "name":room.name}})

@app.route("/api/switch_room", methods=["POST"])
@login_required
def api_switch_room():
    data = request.get_json() or {}
    rid = int(data.get("room_id") or 1)
    if not RoomMember.query.filter_by(room_id=rid, user_id=current_user.id).first():
        return jsonify({"error":"not a member"}), 403
    flask_session["room_id"] = rid
    return jsonify({"ok":True})

@app.route("/api/upload_multiple", methods=["POST"])
@login_required
def api_upload_multiple():
    files = request.files.getlist("files")
    logger.info("UPLOAD: received %d files from %s", len(files), current_user.username)
    if not files: return jsonify({"error":"no files"}), 400
    if len(files) > MAX_FILES_PER_MESSAGE: return jsonify({"error":"too many files"}), 400
    out=[]
    for f in files:
        if not f or not f.filename: continue
        fname = secure_filename(f.filename)
        if not allowed_extension(fname): return jsonify({"error":f"unsupported: {fname}"}), 400
        f.seek(0, os.SEEK_END); size=f.tell(); f.seek(0)
        if size > MAX_FILE_SIZE: return jsonify({"error":f"file too large: {fname}"}), 400
        saved = secrets.token_hex(8) + "-" + fname
        dest = os.path.join(app.config["UPLOAD_FOLDER"], saved)
        try:
            f.save(dest)
            k = kind_from_ext(fname)
            if k == "image" and PIL_AVAILABLE:
                try:
                    im = Image.open(dest); im.thumbnail(THUMB_MAX_SIZE); im.save(dest, optimize=True, quality=85)
                except Exception:
                    logger.exception("Image thumbnail failed")
            out.append({"filename": saved, "type": k})
            logger.info("UPLOAD saved %s -> %s", fname, saved)
        except Exception:
            logger.exception("Failed to save upload")
            return jsonify({"error":"save failed"}), 500
    return jsonify({"ok":True, "files": out})

@app.route("/api/messages", methods=["GET"])
@login_required
def api_messages():
    limit = int(request.args.get("limit", 200))
    before = request.args.get("before")
    room_id = flask_session.get("room_id", 1)
    q = Message.query.filter_by(chat_id=room_id).order_by(Message.created_at.desc())
    if before:
        try:
            dt = datetime.fromisoformat(before); q = q.filter(Message.created_at < dt)
        except Exception:
            pass
    rows = q.limit(limit).all(); rows.reverse()
    res=[]
    for r in rows:
        sender = db.session.get(User, r.sender_id) if r.sender_id else None
        try: attachments = json.loads(r.attachments) if r.attachments else []
        except: attachments=[]
        try: reactions = json.loads(r.reactions) if r.reactions else {}
        except: reactions={}
        try: read_by = json.loads(r.read_by) if r.read_by else []
        except: read_by=[]
        res.append({
            "id": r.id,
            "sender": user_to_dict(sender) if sender else {"username":"system","display_name":"System","avatar": DEFAULT_AVATAR},
            "text": r.text,
            "rendered": sanitize_html(r.rendered or render_md(r.text)),
            "created_at": r.created_at.isoformat(),
            "reply_to": r.reply_to,
            "edited": r.edited,
            "pinned": r.pinned,
            "attachments": [{"type":a.get("type"), "url": url_upload(a.get("filename")) if a.get("type")!="sticker" else url_sticker(a.get("filename")), "filename": a.get("filename")} for a in attachments],
            "reactions": reactions,
            "read_by": read_by,
            "chat_id": r.chat_id
        })
    room = db.session.get(Room, room_id)
    room_name = room.name if room else DEFAULT_ROOM_NAME
    return jsonify({"messages": res, "room": {"id": room_id, "name": room_name}})

@app.route("/api/message/<int:msg_id>/react", methods=["POST"])
@login_required
def api_react(msg_id):
    data = request.get_json() or {}
    emoji = data.get("emoji") or "👍"
    m = db.session.get(Message, msg_id)
    if not m: return jsonify({"error":"no such message"}), 404
    reactions = json.loads(m.reactions) if m.reactions else {}
    li = reactions.get(emoji, [])
    uname = current_user.username
    if uname in li: li.remove(uname)
    else: li.append(uname)
    reactions[emoji] = li
    m.reactions = json.dumps(reactions)
    db.session.commit()
    socketio.emit("reaction", {"message_id": m.id, "reactions": reactions, "chat_id": m.chat_id}, room=f"room_{m.chat_id}")
    return jsonify({"ok":True, "reactions": reactions})

@app.route("/api/message/<int:msg_id>/edit", methods=["POST"])
@login_required
def api_message_edit(msg_id):
    data = request.get_json() or {}
    text = (data.get("text") or "").strip()
    if not text: return jsonify({"error":"text required"}), 400
    m = db.session.get(Message, msg_id)
    if not m: return jsonify({"error":"no such message"}), 404
    if m.sender_id != current_user.id: return jsonify({"error":"not owner"}), 403
    m.text = text; m.rendered = render_md(text); m.edited = True; m.edited_at = datetime.now(timezone.utc)
    db.session.commit()
    socketio.emit("edit", {"message_id": m.id, "text": m.text, "rendered": m.rendered, "edited": True, "chat_id": m.chat_id}, room=f"room_{m.chat_id}")
    return jsonify({"ok":True})

@app.route("/api/message/<int:msg_id>/delete", methods=["POST"])
@login_required
def api_message_delete(msg_id):
    m = db.session.get(Message, msg_id)
    if not m: return jsonify({"error":"no such message"}), 404
    if m.sender_id != current_user.id: return jsonify({"error":"not owner"}), 403
    chat_id = m.chat_id
    db.session.delete(m); db.session.commit()
    socketio.emit("delete", {"message_id": msg_id, "chat_id": chat_id}, room=f"room_{chat_id}")
    return jsonify({"ok":True})

@app.route("/api/notifications")
@login_required
def api_notifications():
    rows = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(50).all()
    out = [{"id": n.id, "text": n.text, "link": n.link, "created_at": n.created_at.isoformat(), "seen": n.seen} for n in rows]
    return jsonify({"notifications": out})

@app.route("/api/stickers")
@login_required
def api_stickers():
    return jsonify({"stickers": list_stickers()})

@app.route("/api/admin/settings", methods=["GET","POST"])
@admin_required
def api_admin_settings():
    if request.method == "GET":
        out = {k: app.config.get(k) for k in ADMIN_SETTINGS_KEYS}
        return jsonify({"settings": out})
    data = request.get_json() or {}
    updates = {}
    for k in ADMIN_SETTINGS_KEYS:
        if k in data:
            updates[k] = data.get(k)
            app.config[k] = data.get(k)
    if updates:
        save_admin_settings(updates)
        refresh_app_strings()
    return jsonify({"ok": True, "settings": {k: app.config.get(k) for k in ADMIN_SETTINGS_KEYS}})

@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    users = User.query.order_by(User.id.asc()).all()
    out = []
    for u in users:
        out.append({
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name or u.username,
            "is_admin": bool(getattr(u, "is_admin", False)),
            "last_seen": u.last_seen.isoformat() if u.last_seen else None
        })
    return jsonify({"users": out})

@app.route("/api/admin/user/<int:user_id>/toggle_admin", methods=["POST"])
@admin_required
def api_admin_toggle_admin(user_id):
    data = request.get_json() or {}
    is_admin = bool(data.get("is_admin"))
    u = db.session.get(User, user_id)
    if not u:
        return jsonify({"error":"no such user"}), 404
    if u.username == app.config.get("ADMIN_USERNAME"):
        return jsonify({"error":"cannot change primary admin"}), 400
    u.is_admin = is_admin
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/admin/user/<int:user_id>/remove", methods=["POST"])
@admin_required
def api_admin_remove_user(user_id):
    u = db.session.get(User, user_id)
    if not u:
        return jsonify({"error":"no such user"}), 404
    if u.username == app.config.get("ADMIN_USERNAME"):
        return jsonify({"error":"cannot remove primary admin"}), 400
    Message.query.filter_by(sender_id=u.id).update({"sender_id": None})
    RoomMember.query.filter_by(user_id=u.id).delete()
    owned = Room.query.filter_by(owner_id=u.id).all()
    for r in owned:
        r.owner_id = None
    db.session.delete(u)
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/admin/broadcast", methods=["POST"])
@admin_required
def api_admin_broadcast():
    data = request.get_json() or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error":"text required"}), 400
    admin_user = User.query.filter_by(username=app.config.get("ADMIN_USERNAME")).first()
    sender_id = admin_user.id if admin_user else None
    rooms = Room.query.all()
    created = []
    for room in rooms:
        m = Message(
            sender_id=sender_id,
            text=text,
            rendered=render_md(text),
            reactions=json.dumps({}),
            read_by=json.dumps([]),
            attachments=json.dumps([]),
            chat_id=room.id
        )
        db.session.add(m)
        db.session.flush()
        created.append(m)
    for u in User.query.all():
        db.session.add(Notification(user_id=u.id, text=text, link="/"))
    db.session.commit()
    for m in created:
        sender_payload = user_to_dict(admin_user) if admin_user else {"username":"system","display_name":"System","avatar": DEFAULT_AVATAR}
        socketio.emit("new_message", {"message": {
            "id": m.id,
            "sender": sender_payload,
            "text": text,
            "rendered": sanitize_html(render_md(text)),
            "created_at": m.created_at.isoformat(),
            "reply_to": None,
            "edited": False,
            "pinned": False,
            "attachments": [],
            "reactions": {},
            "read_by": [],
            "chat_id": m.chat_id
        }, "chat_id": m.chat_id}, room=f"room_{m.chat_id}")
    return jsonify({"ok": True})

@app.route("/api/admin/backup/database")
@admin_required
def api_admin_backup_database():
    try:
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "database_backup.zip")

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if os.path.exists(DB_PATH):
                zipf.write(DB_PATH, os.path.basename(DB_PATH))

            if os.path.exists(SETTINGS_PATH):
                zipf.write(SETTINGS_PATH, os.path.basename(SETTINGS_PATH))

            if os.path.exists(UPLOAD_FOLDER):
                for root, dirs, files in os.walk(UPLOAD_FOLDER):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.join("uploads", os.path.relpath(file_path, UPLOAD_FOLDER))
                        zipf.write(file_path, arcname)

            if os.path.exists(STICKER_FOLDER):
                for root, dirs, files in os.walk(STICKER_FOLDER):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.join("stickers", os.path.relpath(file_path, STICKER_FOLDER))
                        zipf.write(file_path, arcname)

        def cleanup():
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                logger.exception("Failed to cleanup temp backup dir")

        response = send_file(
            zip_path,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'database-backup-{datetime.now().strftime("%Y%m%d-%H%M%S")}.zip'
        )

        @response.call_on_close
        def on_close():
            cleanup()

        return response
    except Exception:
        logger.exception("Database backup failed")
        return jsonify({"error": "Backup failed"}), 500

@app.route("/api/admin/backup/full")
@admin_required
def api_admin_backup_full():
    try:
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "full_backup.zip")

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(BASE_DIR):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'node_modules', 'venv', 'env']]

                for file in files:
                    if file.endswith('.pyc') or file.startswith('.'):
                        continue

                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, BASE_DIR)
                    zipf.write(file_path, arcname)

        def cleanup():
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                logger.exception("Failed to cleanup temp backup dir")

        response = send_file(
            zip_path,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'full-backup-{datetime.now().strftime("%Y%m%d-%H%M%S")}.zip'
        )

        @response.call_on_close
        def on_close():
            cleanup()

        return response
    except Exception:
        logger.exception("Full backup failed")
        return jsonify({"error": "Backup failed"}), 500

# ---------------------------
# Socket handlers
# ---------------------------
@socketio.on("connect")
def ws_connect():
    if not getattr(current_user, "is_authenticated", False):
        return
    sid = request.sid
    mark_online(current_user.id, sid)
    room_id = flask_session.get("room_id", 1)
    join_room(f"room_{room_id}")
    sid_room[sid] = room_id
    logger.info("Socket connected: user=%s sid=%s room=%s", current_user.username, sid, room_id)
    socketio.emit("presence", {"user": user_to_dict(db.session.get(User, current_user.id)), "online": True}, room=f"room_{room_id}")

@socketio.on("disconnect")
def ws_disconnect():
    sid = request.sid
    mark_offline(sid)

@socketio.on("switch_room")
def ws_switch_room(data):
    try:
        rid = int(data.get("room_id") or flask_session.get("room_id", 1))
    except Exception:
        rid = flask_session.get("room_id", 1)
    sid = request.sid
    old = sid_room.get(sid)
    try:
        if old:
            leave_room(f"room_{old}")
    except Exception:
        pass
    try:
        join_room(f"room_{rid}")
        sid_room[sid] = rid
    except Exception:
        logger.exception("Failed to switch socket room for sid=%s", sid)

@socketio.on("typing")
def ws_typing(data):
    is_typing = bool(data.get("is_typing"))
    sid = request.sid
    room_id = sid_room.get(sid, flask_session.get("room_id", 1))
    socketio.emit("typing", {"username": current_user.username, "is_typing": is_typing}, room=f"room_{room_id}")

@socketio.on("send_message")
def ws_send_message(data):
    text = (data.get("text") or "")
    attachments = data.get("attachments") or []
    reply_to = data.get("reply_to")
    room_id = sid_room.get(request.sid, flask_session.get("room_id", 1))
    if (not text or text.strip() == "") and not attachments:
        return

    # If text too long, save as .txt file and attach
    text_to_store = text
    attached_from_text = None
    if text and len(text) > LONG_MESSAGE_LIMIT:
        try:
            fname = secrets.token_hex(8) + "-longmsg.txt"
            dest = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(text)
            attached_from_text = {"filename": fname, "type": "file"}
            text_to_store = "[Long message attached]"
        except Exception:
            logger.exception("Failed to write long message to file")

    # Validate attachments exist on disk (except stickers)
    valid = []
    for a in attachments:
        fn = a.get("filename"); t = a.get("type")
        if not fn or not t: continue
        if t == "sticker":
            valid.append({"filename": fn, "type": t})
            continue
        if os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], fn)):
            valid.append({"filename": fn, "type": t})
    if attached_from_text:
        valid.append(attached_from_text)

    try:
        m = Message(
            sender_id=current_user.id,
            text=text_to_store,
            rendered=render_md(text_to_store),
            reply_to=reply_to,
            attachments=json.dumps(valid),
            reactions=json.dumps({}),
            read_by=json.dumps([]),
            chat_id=room_id
        )
        db.session.add(m); db.session.commit()
    except Exception:
        logger.exception("Failed to save message")
        return

    payload = {
        "id": m.id,
        "sender": user_to_dict(db.session.get(User, current_user.id)),
        "text": m.text,
        "rendered": sanitize_html(m.rendered),
        "created_at": m.created_at.isoformat(),
        "reply_to": m.reply_to,
        "edited": m.edited,
        "pinned": m.pinned,
        "attachments": [{"type": a["type"], "url": (url_sticker(a["filename"]) if a["type"]=="sticker" else url_upload(a["filename"])), "filename": a["filename"]} for a in valid],
        "reactions": {},
        "read_by": []
    }

    if reply_to:
        orig = db.session.get(Message, reply_to)
        if orig and orig.sender_id and orig.sender_id != current_user.id:
            push_notification(orig.sender_id, {"text": f"{current_user.display_name or current_user.username} replied to your message", "link": "/"})

    socketio.emit("new_message", {"message": payload, "chat_id": room_id}, room=f"room_{room_id}")
    logger.info("Broadcasted message id=%s room=%s", m.id, room_id)

@socketio.on("mark_read")
def ws_mark_read(data):
    ids = data.get("message_ids") or []
    for mid in ids:
        m = db.session.get(Message, mid)
        if m:
            read_by = json.loads(m.read_by) if m.read_by else []
            if current_user.username not in read_by:
                read_by.append(current_user.username)
                m.read_by = json.dumps(read_by)
                db.session.commit()
                socketio.emit("read_receipt", {"message_id": m.id, "username": current_user.username}, room=f"room_{m.chat_id}")

# ---------------------------
# Error handler & index
# ---------------------------
@app.errorhandler(404)
def not_found(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"error":"not found"}), 404
    return render_template("404.html"), 404

@app.route("/")
@login_required
def index():
    user = user_to_dict(db.session.get(User, current_user.id))
    mids = RoomMember.query.filter_by(user_id=current_user.id).all()
    rooms = []
    for m in mids:
        r = db.session.get(Room, m.room_id)
        if r:
            rooms.append({"id": r.id, "name": r.name})
    current_room = db.session.get(Room, flask_session.get("room_id",1))
    current_room_name = current_room.name if current_room else DEFAULT_ROOM_NAME
    ui_config = {
        "maxFiles": MAX_FILES_PER_MESSAGE,
        "imageExts": list(ALLOWED_IMAGE_EXT),
        "videoExts": list(ALLOWED_VIDEO_EXT),
        "maxFileSize": MAX_FILE_SIZE,
        "roomId": flask_session.get("room_id", 1),
        "user": user,
        "appName": APP_NAME,
        "appIcon": APP_ICON
    }
    return render_template("main.html", user=user, rooms=rooms, current_room_name=current_room_name, ui_config=ui_config)

# ---------------------------
# Startup: create tables & seed
# ---------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_message_columns()
        ensure_user_columns()
        if not db.session.get(Room, 1):
            r = Room(id=1, owner_id=None, name=DEFAULT_ROOM_NAME, room_key="global", password_hash=None)
            db.session.add(r); db.session.commit()
        else:
            room = db.session.get(Room, 1)
            legacy_room_names = {
                "Ghost Projects chat",
                "Ghost Projec chat",
                "Ghost chat",
                "Ghost Pot chat",
                "Sukuna Chat 🔥 chat"
            }
            if room and room.owner_id is None and room.name in legacy_room_names:
                room.name = DEFAULT_ROOM_NAME
                db.session.commit()
        admin_user = User.query.filter_by(username=app.config.get("ADMIN_USERNAME")).first()
        if not admin_user:
            admin_user = User(username=app.config.get("ADMIN_USERNAME"), display_name="Administrator", is_admin=True)
            admin_user.set_password(app.config.get("ADMIN_PASSWORD"))
            admin_user.email_verified = True
            db.session.add(admin_user)
            db.session.commit()
        else:
            admin_user.set_password(app.config.get("ADMIN_PASSWORD"))
            admin_user.is_admin = True
            if not admin_user.email_verified:
                admin_user.email_verified = True
            db.session.commit()
        if not RoomMember.query.filter_by(room_id=1, user_id=admin_user.id).first():
            db.session.add(RoomMember(room_id=1, user_id=admin_user.id)); db.session.commit()
        legacy_welcome = {
            "Welcome to Ghost Projects chat! Be kind.",
            "Welcome to Ghost Projec chat! Be kind.",
            "Welcome to Ghost chat! Be kind.",
            "Welcome to Ghost Pot chat! Be kind.",
            "Welcome to Sukuna Chat 🔥 chat! Be kind."
        }
        welcome_msgs = Message.query.filter_by(chat_id=1, sender_id=None).all()
        for msg in welcome_msgs:
            if msg.text in legacy_welcome:
                msg.text = WELCOME_MESSAGE
                msg.rendered = render_md(WELCOME_MESSAGE)
        db.session.commit()
        if not Message.query.filter_by(chat_id=1).first():
            sys_msg = Message(sender_id=None, text=WELCOME_MESSAGE, rendered=render_md(WELCOME_MESSAGE), reactions=json.dumps({}), read_by=json.dumps([]), attachments=json.dumps([]), chat_id=1)
            db.session.add(sys_msg); db.session.commit()
        logger.info("Admin ensured for %s", admin_user.username)
    logger.info("Starting %s Chat on http://127.0.0.1:5000", APP_NAME)
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=True, allow_unsafe_werkzeug=True)
