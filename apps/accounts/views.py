"""
Authentication views:
    POST /auth/register/             → RegisterView
    POST /auth/login/                → LoginView
    POST /auth/logout/               → LogoutView
    POST /auth/social/               → SocialLoginView
    POST /auth/verify/send/          → SendVerificationCodeView
    POST /auth/verify/confirm/       → VerifyPhoneView
    POST /auth/password/reset/       → PasswordResetRequestView
    POST /auth/password/reset/confirm/ → PasswordResetConfirmView
    POST /auth/password/change/      → ChangePasswordView
    POST /auth/token/refresh/        → TokenRefreshView (from simplejwt)
"""
import logging

from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from apps.core.responses import error_response, success_response
from apps.core.utils import (
    generate_numeric_code,
    send_password_reset_email,
    send_sms_verification,
    send_welcome_email,
)

from .models import PasswordResetToken, User, VerificationCode
from .serializers import (
    ChangePasswordSerializer,
    CustomTokenObtainPairSerializer,
    LogoutSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    RegisterSerializer,
    SendVerificationCodeSerializer,
    SocialLoginSerializer,
    VerifyPhoneSerializer,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# REGISTER
# ─────────────────────────────────────────

class RegisterView(APIView):
    """
    Register a new user account.

    - Creates user with email + password.
    - Sends a welcome email.
    - Does NOT auto-login (user must verify phone first).
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                message="Error en los datos de registro.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user = serializer.save()
        send_welcome_email(user)

        return success_response(
            message="Cuenta creada exitosamente. Verifica tu número de teléfono para activarla.",
            data={"id": str(user.id), "email": user.email},
            status_code=status.HTTP_201_CREATED,
        )


# ─────────────────────────────────────────
# LOGIN
# ─────────────────────────────────────────

class LoginView(APIView):
    """
    Authenticate with email + password and receive JWT tokens.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CustomTokenObtainPairSerializer(
            data=request.data, context={"request": request}
        )
        if not serializer.is_valid():
            return error_response(
                message="Credenciales inválidas.",
                errors=serializer.errors,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        return success_response(
            message="Inicio de sesión exitoso.",
            data=serializer.validated_data,
        )


# ─────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────

class LogoutView(APIView):
    """
    Blacklist the refresh token, effectively logging the user out.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                message="Token inválido.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = RefreshToken(serializer.validated_data["refresh"])
            token.blacklist()
            return success_response(message="Sesión cerrada exitosamente.")
        except Exception as exc:
            logger.error("Logout error: %s", exc)
            return error_response(
                message="No se pudo cerrar la sesión.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )


# ─────────────────────────────────────────
# SOCIAL LOGIN
# ─────────────────────────────────────────

class SocialLoginView(APIView):
    """
    Exchange a Google or Facebook access token for JWT tokens.

    Request body:
        { "provider": "google" | "facebook", "access_token": "<token>" }
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SocialLoginSerializer(
            data=request.data, context={"request": request}
        )
        if not serializer.is_valid():
            return error_response(
                message="Error en la autenticación social.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user = serializer.validated_data["user"]
        tokens = serializer.validated_data["tokens"]

        return success_response(
            message="Autenticación social exitosa.",
            data={
                "tokens": tokens,
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "full_name": user.full_name,
                    "role": user.role,
                    "is_verified": user.is_verified,
                },
            },
        )


# ─────────────────────────────────────────
# PHONE VERIFICATION
# ─────────────────────────────────────────

class SendVerificationCodeView(APIView):
    """
    Send (or resend) a 6-digit SMS verification code to the user's phone.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SendVerificationCodeSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                message="Datos inválidos.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user
        phone = serializer.validated_data.get("phone_number") or user.phone_number

        if not phone:
            return error_response(
                message="No tienes un número de teléfono registrado.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Update phone if a new one was provided
        if serializer.validated_data.get("phone_number"):
            user.phone_number = phone
            user.save(update_fields=["phone_number"])

        # Invalidate old codes
        VerificationCode.objects.filter(user=user, is_used=False).update(is_used=True)

        # Create and send new code
        code = generate_numeric_code(6)
        VerificationCode.objects.create(user=user, code=code)

        sent = send_sms_verification(phone, code)
        if not sent:
            return error_response(
                message="No se pudo enviar el SMS. Intenta nuevamente.",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return success_response(
            message=f"Código enviado a {phone[-4:].rjust(len(phone), '*')}."
        )


class VerifyPhoneView(APIView):
    """
    Verify the user's phone using the 6-digit code from SMS.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = VerifyPhoneSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                message="Código inválido.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user
        code_value = serializer.validated_data["code"]

        # Find the latest unused code for this user
        verification = (
            VerificationCode.objects.filter(user=user, code=code_value, is_used=False)
            .order_by("-created_at")
            .first()
        )

        if not verification:
            return error_response(
                message="Código incorrecto.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        if verification.is_expired:
            return error_response(
                message="El código ha expirado. Solicita uno nuevo.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Mark code as used and verify user
        verification.is_used = True
        verification.save(update_fields=["is_used"])

        user.is_verified = True
        user.save(update_fields=["is_verified"])

        return success_response(message="Teléfono verificado exitosamente.")


# ─────────────────────────────────────────
# PASSWORD RESET
# ─────────────────────────────────────────

class PasswordResetRequestView(APIView):
    """
    Send a password-reset link to the user's email.
    Always returns 200 to prevent user enumeration.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                message="Datos inválidos.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email, is_active=True)
            # Invalidate previous tokens
            PasswordResetToken.objects.filter(user=user, is_used=False).update(is_used=True)
            # Create new token
            reset_token = PasswordResetToken.objects.create(user=user)
            send_password_reset_email(user)
            logger.info("Password reset requested for %s", email)
        except User.DoesNotExist:
            # Don't reveal whether the email exists
            logger.info("Password reset attempted for unknown email: %s", email)

        return success_response(
            message="Si el correo existe, recibirás un enlace para restablecer tu contraseña."
        )


class PasswordResetConfirmView(APIView):
    """
    Set a new password using the reset token received by email.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                message="Error al restablecer la contraseña.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        reset_token = serializer.validated_data["reset_token"]
        user = reset_token.user

        user.set_password(serializer.validated_data["password"])
        user.save(update_fields=["password"])

        reset_token.is_used = True
        reset_token.save(update_fields=["is_used"])

        logger.info("Password reset completed for %s", user.email)
        return success_response(message="Contraseña restablecida exitosamente.")


# ─────────────────────────────────────────
# CHANGE PASSWORD (authenticated)
# ─────────────────────────────────────────

class ChangePasswordView(APIView):
    """
    Change password for a logged-in user who knows their current password.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data, context={"request": request}
        )
        if not serializer.is_valid():
            return error_response(
                message="Error al cambiar la contraseña.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user
        user.set_password(serializer.validated_data["new_password"])
        user.save(update_fields=["password"])

        logger.info("Password changed for %s", user.email)
        return success_response(
            message="Contraseña actualizada. Por favor inicia sesión nuevamente."
        )
