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
# ✅ Mantener los validators activos en testing
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

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

REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"] = {
    "anon": "10000/min",
    "user": "10000/min",
    "login": "10000/min",
    "verify": "10000/min",
    "social": "10000/min",        # ← faltaba
    "password_reset": "10000/min", # ← faltaba
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.dummy.DummyCache",
    }
}