"""
Authentication views — versión corregida.

Correcciones aplicadas:
  1. Código muerto eliminado después del return en RegisterView.
  2. VerifyEmailView: decorador @method_decorator movido a nivel de clase.
  3. VerifyPhoneView: se incrementa attempts antes de responder (anti-brute-force).
  4. VerifyEmailView: se usa transaction.atomic() para consistencia.
"""
import logging
import hmac
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.db import transaction
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework.throttling import ScopedRateThrottle

from apps.core.responses import error_response, success_response
from apps.core.utils import (
    generate_numeric_code,
    send_password_reset_email,
    send_sms_verification,
    send_welcome_email,
)

from .models import EmailVerificationToken, PasswordResetToken, User, VerificationCode
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
@method_decorator(ratelimit(key='ip', rate='10/h', method='POST', block=True), name='post')
class RegisterView(APIView):
    """
    Register a new user account.
    Sends a welcome email. Does NOT auto-login.
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

        # ── CORRECCIÓN 1 ──────────────────────────────────────────────
        # BUG (VULNERABILIDAD): El bloque de creación de EmailVerificationToken
        # y el envío del correo de verificación estaban DESPUÉS del return,
        # por lo que NUNCA se ejecutaban (código muerto).
        # Esto significa que ningún usuario recibía verificación de email,
        # dejando email_verified=False permanentemente y rompiendo is_verified.
        # CORRECCIÓN: Se crea el token y se envía el correo ANTES del return.
        # ─────────────────────────────────────────────────────────────
        token = EmailVerificationToken.objects.create(user=user)
        from django.conf import settings
        from django.core.mail import send_mail
        verification_link = f"{settings.FRONTEND_URL}/verify-email/{token.token}"
        send_mail(
            subject="Verifica tu correo",
            message=f"Verifica tu cuenta: {verification_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
        )

        return success_response(
            message="Cuenta creada exitosamente. Verifica tu correo y tu número de teléfono.",
            data={"id": str(user.id), "email": user.email},
            status_code=status.HTTP_201_CREATED,
        )


# ─────────────────────────────────────────
# LOGIN
# ─────────────────────────────────────────
@method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True), name='post')
class LoginView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"
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
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "social"
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
@method_decorator(ratelimit(key='user', rate='3/h', method='POST', block=True), name='post')
class SendVerificationCodeView(APIView):
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

        if serializer.validated_data.get("phone_number"):
            user.phone_number = phone
            user.save(update_fields=["phone_number"])

        VerificationCode.objects.filter(user=user, is_used=False).update(is_used=True)

        code = generate_numeric_code(6)
        sent = send_sms_verification(phone, code)
        if not sent:
            return error_response(
                message="No se pudo enviar el SMS. Intenta nuevamente.",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        VerificationCode.objects.create(user=user, code=code)
        return success_response(
            message=f"Código enviado a {phone[-4:].rjust(len(phone), '*')}."
        )


@method_decorator(ratelimit(key='user', rate='5/h', method='POST', block=True), name='post')
class VerifyPhoneView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "verify"
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

        verification = (
            VerificationCode.objects
            .filter(user=user, is_used=False)
            .order_by("-created_at")
            .first()
        )

        if verification and verification.attempts >= 5:
            return error_response(
                message="Demasiados intentos. Solicita un nuevo código.",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # ── CORRECCIÓN 3 ──────────────────────────────────────────────
        # BUG (VULNERABILIDAD): El contador de intentos `attempts` nunca
        # se incrementaba. Un atacante podía hacer brute-force ilimitado
        # al código de 6 dígitos (solo 1M combinaciones) sin ningún bloqueo.
        # CORRECCIÓN: Se incrementa attempts ANTES de validar el código.
        # ─────────────────────────────────────────────────────────────
        if verification:
            VerificationCode.objects.filter(pk=verification.pk).update(
                attempts=verification.attempts + 1
            )
            verification.refresh_from_db()

        stored_code = verification.code if verification else "000000"
        codes_match = hmac.compare_digest(stored_code, code_value)

        if verification and verification.is_expired:
            return error_response(
                message="El código ha expirado. Solicita uno nuevo.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        if not verification or not codes_match:
            return error_response(
                message="Código incorrecto.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            verification.is_used = True
            verification.save(update_fields=["is_used"])
            user.phone_verified = True
            user.save(update_fields=["phone_verified"])

        return success_response(message="Teléfono verificado exitosamente.")


# ─────────────────────────────────────────
# EMAIL VERIFICATION
# ─────────────────────────────────────────

# ── CORRECCIÓN 2 ──────────────────────────────────────────────────────────────
# BUG (VULNERABILIDAD): El decorador @method_decorator estaba DENTRO del
# método post(), lo cual es incorrecto — method_decorator en ese contexto
# no aplica el rate limit. El decorador debe estar a nivel de clase con
# name='post', igual que las otras vistas.
# Además, la vista no usaba transaction.atomic(), dejando posible estado
# inconsistente si fallaba la operación de guardado.
# ─────────────────────────────────────────────────────────────────────────────
@method_decorator(ratelimit(key='ip', rate='3/h', method='POST', block=True), name='post')
class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, token):
        verification = EmailVerificationToken.objects.filter(token=token).first()

        if not verification or not verification.is_valid:
            return error_response(
                message="Token inválido o expirado.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            user = verification.user
            user.email_verified = True
            user.save(update_fields=["email_verified"])
            verification.is_used = True
            verification.save(update_fields=["is_used"])

        return success_response(message="Email verificado correctamente.")


# ─────────────────────────────────────────
# PASSWORD RESET
# ─────────────────────────────────────────
class PasswordResetRequestView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_reset"
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
            PasswordResetToken.objects.filter(user=user, is_used=False).update(is_used=True)
            reset_token = PasswordResetToken.objects.create(user=user)
            send_password_reset_email(user, reset_token)
            logger.info("Password reset requested for %s", email)
        except User.DoesNotExist:
            logger.info("Password reset attempted for unknown email: %s", email)

        return success_response(
            message="Si el correo existe, recibirás un enlace para restablecer tu contraseña."
        )


class PasswordResetConfirmView(APIView):
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

        with transaction.atomic():
            user.set_password(serializer.validated_data["password"])
            user.save(update_fields=["password"])
            reset_token.is_used = True
            reset_token.save(update_fields=["is_used"])
            for token in OutstandingToken.objects.filter(user=user):
                BlacklistedToken.objects.get_or_create(token=token)

        return success_response(message="Contraseña restablecida exitosamente.")


# ─────────────────────────────────────────
# CHANGE PASSWORD
# ─────────────────────────────────────────
class ChangePasswordView(APIView):
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

        with transaction.atomic():
            user.set_password(serializer.validated_data["new_password"])
            user.save(update_fields=["password"])
            for token in OutstandingToken.objects.filter(user=user):
                BlacklistedToken.objects.get_or_create(token=token)

        logger.info("Password changed for %s", user.email)
        return success_response(
            message="Contraseña actualizada. Por favor inicia sesión nuevamente."
        )
