"""
Testing settings — usado por pytest-django.
Usa SQLite en memoria para velocidad máxima.
"""
from .base import *  # noqa: F401, F403

# ── Base de datos en memoria ──────────────────────────────────────────────────
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# ── Sin migraciones reales (más rápido) ───────────────────────────────────────
# pytest-django con --nomigrations crea las tablas directamente desde los modelos

# ── Contraseñas débiles OK en tests ───────────────────────────────────────────
AUTH_PASSWORD_VALIDATORS = []

# ── Email en memoria ──────────────────────────────────────────────────────────
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

# ── SMS desactivado (usar mocks) ──────────────────────────────────────────────
TWILIO_ACCOUNT_SID = "test_sid"
TWILIO_AUTH_TOKEN = "test_token"
TWILIO_PHONE_NUMBER = "+10000000000"

# ── JWT muy corto para tests ──────────────────────────────────────────────────
from datetime import timedelta  # noqa: E402

SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"] = timedelta(minutes=5)  # noqa: F405
SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"] = timedelta(days=1)  # noqa: F405

# ── SECRET_KEY fija para tests ────────────────────────────────────────────────
SECRET_KEY = "test-secret-key-not-for-production-use-only"

DEBUG = True

# ── Desactivar WhiteNoise en tests ────────────────────────────────────────────
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"
