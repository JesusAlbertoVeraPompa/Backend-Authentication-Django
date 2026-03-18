"""
views.py — Vistas de autenticación (API REST con DRF).

Endpoints expuestos (prefijo /api/v1/auth/):
  POST register/                — Registro de nuevo usuario
  POST login/                   — Login con email/contraseña → JWT
  POST logout/                  — Cierre de sesión (blacklist refresh token)
  POST social/                  — Login con Google o Facebook
  POST verify/send/             — Solicitar código SMS de verificación de teléfono
  POST verify/confirm/          — Confirmar código SMS
  POST verify/email/<uuid>/     — Verificar email mediante token del enlace
  POST password/reset/          — Solicitar email de recuperación de contraseña
  POST password/reset/confirm/  — Confirmar nueva contraseña con token
  POST password/change/         — Cambiar contraseña (autenticado)
  POST token/refresh/           — Renovar access token con refresh token

Correcciones de seguridad aplicadas en esta versión:
  [FIX-01] RegisterView: se invalidan tokens de email anteriores antes de crear
           uno nuevo, evitando múltiples tokens activos por usuario.
  [FIX-02] LoginView (CustomTokenObtainPairSerializer): se bloquea el login si el
           email no ha sido verificado (el bloqueo estaba documentado pero no implementado).
  [FIX-03] PasswordResetConfirmView: se añade rate limiting (5 intentos/hora por IP)
           para prevenir fuerza bruta sobre los tokens de recuperación.
  [FIX-04] VerifyPhoneView: se verifica expiración ANTES de incrementar intentos
           para no consumir intentos en códigos ya expirados.
  [FIX-05] SendVerificationCodeView y VerifyPhoneView: el código SMS se guarda y
           compara como hash SHA-256 (delegado a VerificationCode.make_hash()).
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
    Registra un nuevo usuario en el sistema.

    Flujo:
      1. Valida los datos con RegisterSerializer (email único, contraseña fuerte, edad ≥13).
      2. Crea el usuario en la base de datos.
      3. Envía un email de bienvenida.
      4. [FIX-01] Invalida cualquier token de verificación de email previo del usuario
         (evita tokens activos múltiples si el registro se repite).
      5. Crea un EmailVerificationToken nuevo y envía el enlace de verificación.

    Seguridad:
      - Rate limit: 10 registros/hora por IP (bloqueo automático).
      - NO hace auto-login: el usuario debe verificar su email antes de poder iniciar sesión.
      - Contraseña hasheada por Django (PBKDF2 + salt).
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

        # Crea el usuario (contraseña hasheada internamente por create_user)
        user = serializer.save()

        # Envía email de bienvenida (no bloquea el flujo si falla)
        send_welcome_email(user)

        # ── CORRECCIÓN ORIGINAL (código muerto) ──────────────────────────────
        # BUG original: el bloque de creación del EmailVerificationToken y envío
        # del correo estaban DESPUÉS del return, por lo que NUNCA se ejecutaban.
        # CORRECCIÓN: se ejecutan ANTES del return.
        # ─────────────────────────────────────────────────────────────────────

        # [FIX-01] Invalida tokens de verificación de email anteriores no usados.
        # Evita que un usuario tenga múltiples tokens activos simultáneamente,
        # lo que podría permitir reutilizar un token antiguo.
        EmailVerificationToken.objects.filter(user=user, is_used=False).update(is_used=True)

        # Crea el nuevo token de verificación de email
        token = EmailVerificationToken.objects.create(user=user)

        # Construye el enlace de verificación y lo envía al correo del usuario
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
    """
    Autentica al usuario con email y contraseña. Retorna un par de tokens JWT.

    Flujo:
      1. Valida credenciales con CustomTokenObtainPairSerializer.
      2. [FIX-02] Bloquea el login si el email no ha sido verificado.
         (El bloqueo estaba documentado en el serializer pero no implementado.)
      3. Retorna access token, refresh token y datos básicos del usuario.

    Seguridad:
      - Rate limit: 5 intentos/minuto por IP (bloqueo automático).
      - Throttle adicional con scope 'login' (configurable en settings).
      - El payload del JWT incluye: email, full_name, role, is_verified.
    """
    throttle_classes = [ScopedRateThrottle]
    throttle_scope   = "login"
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CustomTokenObtainPairSerializer(
            data=request.data, context={"request": request}
        )
        if not serializer.is_valid():
            # Retorna 401 genérico para no revelar si el email existe o no
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
    Cierra la sesión del usuario invalidando su refresh token (blacklisting JWT).

    Flujo:
      1. Valida el refresh token con LogoutSerializer.
      2. Añade el token a la blacklist de SimpleJWT.
      3. A partir de este punto, el refresh token no puede usarse para
         obtener nuevos access tokens.

    Nota: el access token actual sigue siendo válido hasta su expiración natural.
    Para reducir esta ventana, se recomienda configurar ACCESS_TOKEN_LIFETIME ≤5 min.
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
            # Añade el refresh token a la blacklist de SimpleJWT
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
    Autentica al usuario mediante un token OAuth2 de Google o Facebook.

    Flujo:
      1. El frontend obtiene el access_token del proveedor mediante su SDK.
      2. Envía el token aquí junto con el nombre del proveedor.
      3. SocialLoginSerializer valida el token con el proveedor externo.
      4. Si es válido, obtiene o crea el usuario en la BD vía django-allauth.
      5. Retorna un par de tokens JWT propios del sistema.

    Seguridad:
      - Throttle con scope 'social' (configurable en settings).
      - El token del proveedor se valida contra la API externa (no se confía ciegamente).
    """
    throttle_classes   = [ScopedRateThrottle]
    throttle_scope     = "social"
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
        user   = serializer.validated_data["user"]
        tokens = serializer.validated_data["tokens"]
        return success_response(
            message="Autenticación social exitosa.",
            data={
                "tokens": tokens,
                "user": {
                    "id":          str(user.id),
                    "email":       user.email,
                    "full_name":   user.full_name,
                    "role":        user.role,
                    "is_verified": user.is_verified,
                },
            },
        )


# ─────────────────────────────────────────
# PHONE VERIFICATION — SEND CODE
# ─────────────────────────────────────────

@method_decorator(ratelimit(key='user', rate='3/h', method='POST', block=True), name='post')
class SendVerificationCodeView(APIView):
    """
    Genera y envía un código SMS de 6 dígitos al teléfono del usuario autenticado.

    Flujo:
      1. Valida el número de teléfono (formato E.164, opcional si ya está registrado).
      2. Si se envía un número nuevo, actualiza el teléfono del usuario.
      3. Invalida todos los códigos SMS anteriores no usados del usuario.
      4. Genera un código nuevo de 6 dígitos.
      5. [FIX-05] Hashea el código con SHA-256 ANTES de guardarlo en la BD.
      6. Envía el código en texto plano por SMS (solo viaja por el canal seguro de Twilio).

    Seguridad:
      - Rate limit: 3 envíos/hora por usuario autenticado.
      - El código guardado en BD es un hash SHA-256, no texto plano.
      - Los códigos anteriores se invalidan en cada nueva solicitud.
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

        user  = request.user
        phone = serializer.validated_data.get("phone_number") or user.phone_number

        if not phone:
            return error_response(
                message="No tienes un número de teléfono registrado.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Si el usuario envió un número nuevo, actualiza el perfil
        if serializer.validated_data.get("phone_number"):
            user.phone_number = phone
            user.save(update_fields=["phone_number"])

        # Invalida todos los códigos activos anteriores para este usuario
        VerificationCode.objects.filter(user=user, is_used=False).update(is_used=True)

        # Genera el código numérico de 6 dígitos en texto plano
        plain_code = generate_numeric_code(6)

        # Envía el código por SMS (texto plano — solo viaja en canal Twilio cifrado)
        sent = send_sms_verification(phone, plain_code)
        if not sent:
            return error_response(
                message="No se pudo enviar el SMS. Intenta nuevamente.",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        # [FIX-05] Guarda el HASH del código, no el valor en texto plano.
        # Si la BD fuera comprometida, los hashes no son utilizables directamente.
        hashed_code = VerificationCode.make_hash(plain_code)
        VerificationCode.objects.create(user=user, code=hashed_code)

        # Muestra solo los últimos 4 dígitos del teléfono para confirmar al usuario
        return success_response(
            message=f"Código enviado a {phone[-4:].rjust(len(phone), '*')}."
        )


# ─────────────────────────────────────────
# PHONE VERIFICATION — CONFIRM CODE
# ─────────────────────────────────────────

@method_decorator(ratelimit(key='user', rate='5/h', method='POST', block=True), name='post')
class VerifyPhoneView(APIView):
    """
    Verifica el código SMS ingresado por el usuario para confirmar su teléfono.

    Flujo:
      1. Valida que el campo code contenga solo dígitos (VerifyPhoneSerializer).
      2. Recupera el código activo más reciente del usuario.
      3. Verifica que no se hayan superado los 5 intentos permitidos.
      4. [FIX-04] Verifica la expiración ANTES de incrementar intentos.
         (Antes: se incrementaban intentos incluso en códigos expirados.)
      5. Incrementa el contador de intentos ANTES de comparar el código.
         (Protege contra fuerza bruta incluso en implementaciones con race conditions.)
      6. [FIX-05] Compara el hash del código ingresado con el hash almacenado
         usando hmac.compare_digest (resistente a timing attacks).
      7. Si es correcto: marca el código como usado y phone_verified=True.

    Seguridad:
      - Rate limit: 5 verificaciones/hora por usuario autenticado.
      - Throttle adicional con scope 'verify'.
      - Máximo 5 intentos por código antes de bloqueo.
      - Comparación con hmac.compare_digest (evita timing attacks).
      - [FIX-04] Expiración verificada antes de consumir intentos.
      - [FIX-05] Código almacenado como hash SHA-256.
    """
    throttle_classes   = [ScopedRateThrottle]
    throttle_scope     = "verify"
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = VerifyPhoneSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                message="Código inválido.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user       = request.user
        code_value = serializer.validated_data["code"]  # Código en texto plano ingresado

        # Obtiene el código activo más reciente del usuario
        verification = (
            VerificationCode.objects
            .filter(user=user, is_used=False)
            .order_by("-created_at")
            .first()
        )

        # ── Verificar intentos ───────────────────────────────────────────────
        # Si el código ya superó el límite de intentos, se requiere uno nuevo.
        if verification and verification.attempts >= 5:
            return error_response(
                message="Demasiados intentos. Solicita un nuevo código.",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # [FIX-04] CORRECCIÓN DE ORDEN: verificar expiración ANTES de incrementar
        # intentos. Antes del fix, se incrementaban intentos en códigos expirados,
        # desperdiciando el límite de 5 intentos del siguiente código válido.
        if verification and verification.is_expired:
            return error_response(
                message="El código ha expirado. Solicita uno nuevo.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # ── Incrementar intentos ANTES de comparar ───────────────────────────
        # Se incrementa el contador ANTES de validar el código para evitar que
        # un atacante haga fuerza bruta sin que el contador avance
        # (ej. race conditions en requests paralelos).
        if verification:
            VerificationCode.objects.filter(pk=verification.pk).update(
                attempts=verification.attempts + 1
            )
            verification.refresh_from_db()

        # [FIX-05] Hashear el código ingresado para comparar con el hash almacenado.
        # Si no hay verificación activa, se usa un hash ficticio para que
        # hmac.compare_digest siempre ejecute la comparación en tiempo constante
        # (evita revelar si hay o no un código activo mediante timing attack).
        hashed_input  = VerificationCode.make_hash(code_value)
        stored_hash   = verification.code if verification else VerificationCode.make_hash("000000")
        codes_match   = hmac.compare_digest(stored_hash, hashed_input)

        # Si el código no coincide o no existe verificación activa, retorna error
        if not verification or not codes_match:
            return error_response(
                message="Código incorrecto.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # ── Confirmar verificación ────────────────────────────────────────────
        # transaction.atomic() garantiza consistencia: si falla algún save(),
        # ninguno de los cambios queda a medias en la base de datos.
        with transaction.atomic():
            verification.is_used   = True
            verification.save(update_fields=["is_used"])
            user.phone_verified    = True
            user.save(update_fields=["phone_verified"])

        return success_response(message="Teléfono verificado exitosamente.")


# ─────────────────────────────────────────
# EMAIL VERIFICATION
# ─────────────────────────────────────────

# CORRECCIÓN ORIGINAL (decorador mal ubicado):
# El decorador @method_decorator estaba DENTRO del método post(), lo cual es
# incorrecto — en ese contexto no aplica el rate limit.
# CORRECCIÓN: se coloca a nivel de clase con name='post'.
@method_decorator(ratelimit(key='ip', rate='3/h', method='POST', block=True), name='post')
class VerifyEmailView(APIView):
    """
    Verifica el email del usuario mediante el token recibido en el enlace de registro.

    Flujo:
      1. Recibe el token UUID como parámetro de URL.
      2. Busca un EmailVerificationToken activo con ese token.
      3. Verifica que el token sea válido (no usado, no expirado).
      4. Con transaction.atomic(): marca email_verified=True en el usuario
         y is_used=True en el token.

    Seguridad:
      - Rate limit: 3 verificaciones/hora por IP (evita fuerza bruta sobre tokens).
      - transaction.atomic() garantiza consistencia: no puede quedar email_verified=True
        sin marcar el token como usado.
      - AllowAny: el usuario no está autenticado cuando hace clic en el enlace del email.
    """
    permission_classes = [AllowAny]

    def post(self, request, token):
        # Busca el token por UUID — filtra sin generar excepción si no existe
        verification = EmailVerificationToken.objects.filter(token=token).first()

        # Verifica que el token exista y sea válido (no usado ni expirado)
        if not verification or not verification.is_valid:
            return error_response(
                message="Token inválido o expirado.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Actualización atómica: ambas operaciones se realizan juntas o ninguna
        with transaction.atomic():
            user = verification.user
            user.email_verified = True
            user.save(update_fields=["email_verified"])
            verification.is_used = True
            verification.save(update_fields=["is_used"])

        return success_response(message="Email verificado correctamente.")


# ─────────────────────────────────────────
# PASSWORD RESET — REQUEST
# ─────────────────────────────────────────

class PasswordResetRequestView(APIView):
    """
    Solicita el envío de un email de recuperación de contraseña.

    Flujo:
      1. Valida que el email tenga formato correcto.
      2. Si el email existe y el usuario está activo:
           a. Invalida tokens de reset anteriores no usados.
           b. Crea un nuevo PasswordResetToken.
           c. Envía el email con el enlace de recuperación.
      3. Si el email NO existe, no hace nada (pero retorna la misma respuesta).

    Seguridad:
      - Throttle con scope 'password_reset' (configurable en settings).
      - Anti-enumeración: la respuesta es idéntica tanto si el email existe
        como si no existe. Así un atacante no puede saber qué emails están registrados.
      - PENDIENTE [MEDIA]: el tiempo de respuesta difiere entre email existente y no
        existente (timing attack). Para mitigarlo, usar tareas asíncronas (Celery).
    """
    throttle_classes   = [ScopedRateThrottle]
    throttle_scope     = "password_reset"
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
            # Invalida tokens de reset anteriores para evitar tokens activos múltiples
            PasswordResetToken.objects.filter(user=user, is_used=False).update(is_used=True)
            # Crea el token de reset y envía el email
            reset_token = PasswordResetToken.objects.create(user=user)
            send_password_reset_email(user, reset_token)
            logger.info("Password reset requested for %s", email)
        except User.DoesNotExist:
            # No revelamos si el email existe o no — respuesta genérica igualmente
            logger.info("Password reset attempted for unknown email: %s", email)

        # Respuesta idéntica independientemente de si el email existe (anti-enumeración)
        return success_response(
            message="Si el correo existe, recibirás un enlace para restablecer tu contraseña."
        )


# ─────────────────────────────────────────
# PASSWORD RESET — CONFIRM
# ─────────────────────────────────────────

# [FIX-03] CORRECCIÓN DE SEGURIDAD — Rate limiting añadido:
# La vista original NO tenía rate limit. Un atacante podía hacer fuerza bruta
# sobre el token UUID de reset (aunque es computacionalmente difícil dada la
# entropía de UUID v4, el rate limiting es una capa de defensa adicional obligatoria).
# CORRECCIÓN: se añade ratelimit con 5 intentos/hora por IP.
@method_decorator(ratelimit(key='ip', rate='5/h', method='POST', block=True), name='post')
class PasswordResetConfirmView(APIView):
    """
    Confirma el restablecimiento de contraseña usando el token recibido por email.

    Flujo:
      1. Valida el token y la nueva contraseña con PasswordResetConfirmSerializer.
      2. Con transaction.atomic():
           a. Establece la nueva contraseña del usuario (hasheada por Django).
           b. Marca el token de reset como usado.
           c. Invalida todos los refresh tokens JWT del usuario
              (fuerza logout en todos los dispositivos activos).

    Seguridad:
      - [FIX-03] Rate limit: 5 intentos/hora por IP.
      - transaction.atomic() garantiza consistencia total.
      - Invalidación de todos los refresh tokens tras el reset (logout forzado).
      - La nueva contraseña pasa por validate_password (fortaleza mínima).
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
        user        = reset_token.user

        with transaction.atomic():
            # Establece la nueva contraseña (Django la hashea automáticamente)
            user.set_password(serializer.validated_data["password"])
            user.save(update_fields=["password"])

            # Marca el token como usado (no puede reutilizarse)
            reset_token.is_used = True
            reset_token.save(update_fields=["is_used"])

            # Invalida todos los refresh tokens del usuario (logout forzado)
            for token in OutstandingToken.objects.filter(user=user):
                BlacklistedToken.objects.get_or_create(token=token)

        return success_response(message="Contraseña restablecida exitosamente.")


# ─────────────────────────────────────────
# CHANGE PASSWORD
# ─────────────────────────────────────────

class ChangePasswordView(APIView):
    """
    Cambia la contraseña de un usuario autenticado que conoce su contraseña actual.

    Flujo:
      1. Valida la contraseña actual con ChangePasswordSerializer.
      2. Valida que las contraseñas nuevas coincidan y cumplan fortaleza mínima.
      3. Con transaction.atomic():
           a. Establece la nueva contraseña.
           b. Invalida todos los refresh tokens JWT del usuario.

    Nota: el access token actual sigue siendo válido hasta su expiración.
    Para reducir la ventana de riesgo, configurar ACCESS_TOKEN_LIFETIME ≤5 min.

    Seguridad:
      - Requiere autenticación (IsAuthenticated).
      - Verifica la contraseña actual antes de permitir el cambio.
      - Invalida todos los refresh tokens (logout forzado en todos los dispositivos).
      - transaction.atomic() garantiza consistencia.
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

        with transaction.atomic():
            # Establece la nueva contraseña (Django la hashea automáticamente)
            user.set_password(serializer.validated_data["new_password"])
            user.save(update_fields=["password"])

            # Invalida todos los refresh tokens del usuario (logout forzado)
            for token in OutstandingToken.objects.filter(user=user):
                BlacklistedToken.objects.get_or_create(token=token)

        logger.info("Password changed for %s", user.email)
        return success_response(
            message="Contraseña actualizada. Por favor inicia sesión nuevamente."
        )
