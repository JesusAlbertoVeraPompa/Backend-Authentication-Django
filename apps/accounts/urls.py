"""
URL patterns for the accounts app.
All routes are prefixed with /api/v1/auth/
"""
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    ChangePasswordView,
    LoginView,
    LogoutView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RegisterView,
    SendVerificationCodeView,
    SocialLoginView,
    VerifyPhoneView,
    VerifyEmailView
)

app_name = "accounts"

urlpatterns = [
    # ── Registration & Login ──────────────────────────
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # ── Token ─────────────────────────────────────────
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),

    # ── Social Login ──────────────────────────────────
    path("social/", SocialLoginView.as_view(), name="social-login"),

    # ── Phone Verification ────────────────────────────
    path("verify/send/", SendVerificationCodeView.as_view(), name="verify-send"),
    path("verify/confirm/", VerifyPhoneView.as_view(), name="verify-confirm"),
    
    # ── Email Verification ────────────────────────────
    path("verify/email/<uuid:token>/", VerifyEmailView.as_view(), name="verify-email"),

    # ── Password Management ───────────────────────────
    path("password/reset/", PasswordResetRequestView.as_view(), name="password-reset"),
    path("password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("password/change/", ChangePasswordView.as_view(), name="password-change"),
]
