import os


class Config:
    APP_NAME = os.environ.get("APP_NAME", "Sukuna Chat 🔥")
    APP_ICON = os.environ.get("APP_ICON", "👻")
    APP_TAGLINE = os.environ.get("APP_TAGLINE", "Chat that feels alive")
    LOGIN_SUBTITLE = os.environ.get("LOGIN_SUBTITLE", f"Sign in to {APP_NAME}")
    REGISTER_SUBTITLE = os.environ.get("REGISTER_SUBTITLE", "Create your account to get started")
    DEFAULT_ROOM_NAME = os.environ.get("DEFAULT_ROOM_NAME", f"{APP_NAME} chat")
    WELCOME_MESSAGE = os.environ.get("WELCOME_MESSAGE", f"Welcome to {APP_NAME} chat! Be kind.")
    USER_JOIN_MESSAGE = os.environ.get("USER_JOIN_MESSAGE", "👋 {user} joined {app} chat")
    DEFAULT_AVATAR = os.environ.get("DEFAULT_AVATAR", "https://negative-orange-ql4jplfnvn.edgeone.app/1767275981651.jpg")

    MAX_FILES_PER_MESSAGE = int(os.environ.get("MAX_FILES_PER_MESSAGE", "5"))
    MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", str(25 * 1024 * 1024)))
    LONG_MESSAGE_LIMIT = int(os.environ.get("LONG_MESSAGE_LIMIT", "300"))

    THEME_ACCENT = os.environ.get("THEME_ACCENT", "#ff7a18")
    THEME_ACCENT_2 = os.environ.get("THEME_ACCENT_2", "#ffb347")
    THEME_BG = os.environ.get("THEME_BG", "#0b1214")
    THEME_PANEL = os.environ.get("THEME_PANEL", "#101820")
    THEME_CARD = os.environ.get("THEME_CARD", "#141f24")
    THEME_TEXT = os.environ.get("THEME_TEXT", "#f5f7fa")
    THEME_MUTED = os.environ.get("THEME_MUTED", "#a3b3c2")
    THEME_BORDER = os.environ.get("THEME_BORDER", "rgba(255,122,24,0.2)")

    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin@111983")

    VLY_API_KEY = os.environ.get("VLY_API_KEY", "vlytothemoon2025")
    VLY_API_URL = os.environ.get("VLY_API_URL", "https://email.vly.ai/send_otp")
    EMAIL_VERIFY_TTL_MIN = int(os.environ.get("EMAIL_VERIFY_TTL_MIN", "15"))
    RESET_TTL_MIN = int(os.environ.get("RESET_TTL_MIN", "10"))

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
