"""
serializers.py — Serializadores para los flujos de autenticación.

Contenido:
  - RegisterSerializer             : Registro de nuevo usuario.
  - CustomTokenObtainPairSerializer: Login con JWT personalizado + bloqueo por email no verificado.
  - SendVerificationCodeSerializer : Solicitar código SMS.
  - VerifyPhoneSerializer          : Confirmar código SMS.
  - PasswordResetRequestSerializer : Solicitar email de recuperación.
  - PasswordResetConfirmSerializer : Confirmar nueva contraseña con token.
  - ChangePasswordSerializer       : Cambiar contraseña (usuario autenticado).
  - SocialLoginSerializer          : Login OAuth2 con Google o Facebook.
  - LogoutSerializer               : Validar refresh token para blacklisting.

Correcciones de seguridad aplicadas:
  [FIX-02] CustomTokenObtainPairSerializer.validate() ahora bloquea el login
           si el email del usuario no ha sido verificado. Este bloqueo estaba
           documentado en el docstring original pero no estaba implementado.
"""

import logging
from datetime import date
import re

from django.contrib.auth import authenticate
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from .models import PasswordResetToken, User, VerificationCode

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# REGISTER
# ─────────────────────────────────────────

class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer para el registro de un nuevo usuario.

    Validaciones:
      - Email único (garantizado por el modelo).
      - Contraseña fuerte (validate_password de Django: longitud, complejidad, etc.).
      - Las contraseñas password y password_confirm deben coincidir.
      - Edad mínima de 13 años si se proporciona birth_date.

    Campos de solo escritura:
      - password y password_confirm no se retornan en ninguna respuesta.
    """

    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],  # Aplica las validaciones de contraseña de Django
        style={"input_type": "password"},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
    )

    class Meta:
        model  = User
        fields = [
            "email",
            "first_name",
            "last_name",
            "birth_date",
            "phone_number",
            "password",
            "password_confirm",
        ]
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name":  {"required": True},
        }

    def validate(self, attrs):
        """
        Validaciones cruzadas entre campos:
          1. Las contraseñas deben coincidir.
          2. Si se proporciona fecha de nacimiento, el usuario debe tener ≥13 años.
        """
        # Verifica que ambas contraseñas sean iguales
        if attrs["password"] != attrs.pop("password_confirm"):
            raise serializers.ValidationError(
                {"password_confirm": "Las contraseñas no coinciden."}
            )

        # Validación de edad mínima (13 años) — opcional, solo si se envía birth_date
        birth_date = attrs.get("birth_date")
        if birth_date:
            today = date.today()
            age = (
                today.year
                - birth_date.year
                - ((today.month, today.day) < (birth_date.month, birth_date.day))
            )
            if age < 13:
                raise serializers.ValidationError(
                    {"birth_date": "Debes tener al menos 13 años para registrarte."}
                )

        return attrs

    def create(self, validated_data):
        """
        Crea el usuario en la base de datos.
        La contraseña se hashea internamente mediante create_user (PBKDF2 + salt).
        """
        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            birth_date=validated_data.get("birth_date"),
            phone_number=validated_data.get("phone_number"),
        )
        return user


# ─────────────────────────────────────────
# LOGIN — JWT payload personalizado
# ─────────────────────────────────────────

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Extiende el serializer JWT por defecto de SimpleJWT con:
      1. Claims adicionales en el payload del token: email, full_name, role, is_verified.
      2. Datos del usuario en la respuesta del login (para que el frontend no
         necesite hacer una petición adicional a /me/ tras el login).
      3. [FIX-02] Bloqueo de login para usuarios con email no verificado.

    [FIX-02] CORRECCIÓN DE SEGURIDAD:
      El docstring original documentaba que la clase "Also blocks login for
      unverified users (configurable)", pero el bloqueo NUNCA estaba implementado.
      Un usuario podía hacer login con email sin verificar y recibir tokens JWT válidos.
      CORRECCIÓN: se añade la verificación de email_verified en validate().
    """

    @classmethod
    def get_token(cls, user):
        """
        Genera el token JWT con claims personalizados adicionales.
        Estos claims van codificados en el payload del JWT y son accesibles
        por el frontend sin necesidad de llamadas adicionales a la API.
        """
        token = super().get_token(user)

        # Claims personalizados — se incluyen en el payload del JWT
        token["email"]       = user.email
        token["full_name"]   = user.full_name
        token["role"]        = user.role
        token["is_verified"] = user.is_verified

        return token

    def validate(self, attrs):
        """
        Valida las credenciales y aplica restricciones adicionales de acceso.

        Pasos:
          1. Llama al validate() del padre (verifica email + contraseña).
          2. [FIX-02] Verifica que el email esté confirmado antes de emitir tokens.
          3. Añade los datos del usuario al body de la respuesta.
        """
        # Autenticación estándar de SimpleJWT (verifica credenciales)
        data = super().validate(attrs)

        # [FIX-02] Bloquea el login si el email no ha sido verificado.
        # Sin esta verificación, un usuario podría hacer login sin confirmar su email,
        # lo que hace inútil el flujo de verificación y permite cuentas no confirmadas.
        if not self.user.email_verified:
            raise serializers.ValidationError(
                {
                    "email": (
                        "Debes verificar tu correo electrónico antes de iniciar sesión. "
                        "Revisa tu bandeja de entrada."
                    )
                }
            )

        # Incluye los datos del usuario en la respuesta del login
        # (el frontend puede usar estos datos sin necesidad de llamar a /me/)
        data["user"] = {
            "id":          str(self.user.id),
            "email":       self.user.email,
            "full_name":   self.user.full_name,
            "role":        self.user.role,
            "is_verified": self.user.is_verified,
        }

        return data


# ─────────────────────────────────────────
# PHONE VERIFICATION
# ─────────────────────────────────────────

class SendVerificationCodeSerializer(serializers.Serializer):
    """
    Serializer para solicitar un código SMS de verificación de teléfono.

    Campo opcional phone_number:
      - Si se envía, debe tener formato E.164 (ej: +573001234567).
      - Si no se envía, la vista usa el número ya registrado en el perfil del usuario.
    """

    phone_number = serializers.CharField(max_length=20, required=False)

    def validate_phone_number(self, value):
        """
        Valida que el número de teléfono tenga formato E.164 internacional.
        Formato esperado: + seguido de 8 a 15 dígitos (ej: +573001234567).
        """
        if not value:
            return value
        pattern = r'^\+[1-9]\d{7,14}$'  # Formato E.164 internacional
        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Formato inválido. Usa formato internacional: +573001234567 (8-15 dígitos)"
            )
        return value


class VerifyPhoneSerializer(serializers.Serializer):
    """
    Serializer para confirmar el código SMS de 6 dígitos.

    Validaciones:
      - El código debe contener únicamente dígitos (0-9).
      - Máximo 10 caracteres (para contemplar futuros cambios de longitud).
    """

    code = serializers.CharField(max_length=10)

    def validate_code(self, value):
        """Verifica que el código ingresado contenga solo dígitos."""
        if not value.isdigit():
            raise serializers.ValidationError("El código debe contener solo dígitos.")
        return value


# ─────────────────────────────────────────
# PASSWORD RESET
# ─────────────────────────────────────────

class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer para solicitar el envío de un email de recuperación de contraseña.

    Nota de seguridad (anti-enumeración):
      NO se valida si el email existe en la base de datos en este serializer.
      La validación de existencia se hace en la vista pero con respuesta genérica,
      evitando que un atacante pueda saber qué emails están registrados.
    """

    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Normaliza el email a minúsculas.
        No lanza error si el email no existe (anti-enumeración).
        """
        return value.lower()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer para confirmar el restablecimiento de contraseña.

    Valida:
      1. El token UUID recibido por email existe en la base de datos.
      2. El token es válido (no usado, no expirado).
      3. La nueva contraseña cumple los requisitos de fortaleza.
      4. Las contraseñas password y password_confirm coinciden.

    Si todo es válido, adjunta el objeto reset_token en validated_data
    para que la vista pueda marcarlo como usado.
    """

    token = serializers.UUIDField()
    password = serializers.CharField(
        write_only=True,
        validators=[validate_password],  # Fortaleza mínima de contraseña
        style={"input_type": "password"},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )

    def validate(self, attrs):
        """
        Valida que las contraseñas coincidan y que el token sea válido.
        Adjunta el objeto PasswordResetToken en validated_data para la vista.
        """
        # Las contraseñas nuevas deben coincidir
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Las contraseñas no coinciden."}
            )

        # Busca el token en la base de datos
        try:
            reset_token = PasswordResetToken.objects.select_related("user").get(
                token=attrs["token"]
            )
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError({"token": "Token inválido."})

        # Verifica que el token no haya expirado ni sido usado ya
        if not reset_token.is_valid:
            raise serializers.ValidationError(
                {"token": "El token ha expirado o ya fue utilizado."}
            )

        # Adjunta el objeto para que la vista no tenga que volver a buscarlo
        attrs["reset_token"] = reset_token
        return attrs


# ─────────────────────────────────────────
# CHANGE PASSWORD (usuario autenticado)
# ─────────────────────────────────────────

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer para cambiar la contraseña de un usuario autenticado.

    Requiere que el usuario conozca su contraseña actual (current_password).
    Valida:
      1. La contraseña actual es correcta.
      2. Las contraseñas nueva y de confirmación coinciden.
      3. La nueva contraseña cumple los requisitos de fortaleza.

    El usuario es obtenido desde el contexto del request (request.user),
    no desde los datos del body, para evitar cambiar la contraseña de otro usuario.
    """

    current_password = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )
    new_password = serializers.CharField(
        write_only=True,
        validators=[validate_password],  # Fortaleza mínima de contraseña
        style={"input_type": "password"},
    )
    new_password_confirm = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )

    def validate(self, attrs):
        """Verifica que las contraseñas nuevas coincidan."""
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "Las contraseñas nuevas no coinciden."}
            )
        return attrs

    def validate_current_password(self, value):
        """
        Verifica que la contraseña actual proporcionada sea correcta.
        El usuario se obtiene desde el contexto del request (usuario autenticado).
        """
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("La contraseña actual es incorrecta.")
        return value


# ─────────────────────────────────────────
# SOCIAL LOGIN
# ─────────────────────────────────────────

class SocialLoginSerializer(serializers.Serializer):
    """
    Serializer para intercambiar un token OAuth2 de Google o Facebook
    por un par de tokens JWT propios del sistema.

    Flujo esperado:
      1. El frontend usa el SDK del proveedor (Google Sign-In, Facebook Login)
         para obtener el access_token del proveedor.
      2. Envía ese token aquí junto con el nombre del proveedor.
      3. Este serializer valida el token contra el proveedor externo via django-allauth.
      4. Si es válido, obtiene o crea el usuario en la BD.
      5. Retorna los tokens JWT del sistema y los datos del usuario.

    Seguridad:
      - Solo se aceptan proveedores 'google' y 'facebook' (ChoiceField).
      - La validación del token se delega a django-allauth (no se confía ciegamente).
      - Los errores del proveedor externo se loguean pero se retorna un mensaje genérico
        para no revelar detalles de la integración interna.
    """

    provider     = serializers.ChoiceField(choices=["google", "facebook"])
    access_token = serializers.CharField()

    def validate(self, attrs):
        """
        Valida el token del proveedor social y obtiene/crea el usuario correspondiente.
        Retorna el usuario y los tokens JWT en validated_data.
        """
        provider     = attrs["provider"]
        access_token = attrs["access_token"]

        try:
            from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
            from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter

            # Mapa de proveedores a sus adaptadores de django-allauth
            adapter_map = {
                "google":   GoogleOAuth2Adapter,
                "facebook": FacebookOAuth2Adapter,
            }
            AdapterClass = adapter_map[provider]  # noqa: N806

            from allauth.socialaccount.helpers import complete_social_login
            from allauth.socialaccount.models import SocialToken, SocialApp

            # Construye la request mínima para django-allauth
            request = self.context.get("request")
            adapter = AdapterClass(request)

            # Obtiene la configuración del proveedor desde la BD (SocialApp de allauth)
            app   = SocialApp.objects.get(provider=provider)
            token = SocialToken(app=app, token=access_token)

            # Valida el token con el proveedor externo y obtiene/crea el usuario
            login = adapter.complete_login(request, app, token, response={})
            login.token = token
            complete_social_login(request, login)

            if login.account.user:
                user    = login.account.user
                refresh = RefreshToken.for_user(user)
                attrs["user"]   = user
                attrs["tokens"] = {
                    "refresh": str(refresh),
                    "access":  str(refresh.access_token),
                }
            else:
                raise serializers.ValidationError(
                    "No se pudo autenticar con el proveedor social."
                )

        except serializers.ValidationError:
            # Re-lanza errores de validación propios (no los oculta)
            raise
        except SocialApp.DoesNotExist:
            # El proveedor no está configurado en la BD de allauth
            raise serializers.ValidationError("Proveedor social no configurado.")
        except Exception as exc:
            # Error externo (token inválido, red, etc.) — se loguea internamente
            # pero se retorna mensaje genérico para no exponer detalles
            logger.error("Social login error [%s]: %s", provider, exc)
            raise serializers.ValidationError("Token social inválido o autenticación fallida.")

        return attrs


# ─────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────

class LogoutSerializer(serializers.Serializer):
    """
    Serializer para validar el refresh token antes de añadirlo a la blacklist.

    Solo verifica que el token tenga el formato JWT correcto.
    La comprobación de si ya está en la blacklist la hace SimpleJWT internamente.
    """

    refresh = serializers.CharField()

    def validate_refresh(self, value):
        """
        Verifica que el refresh token sea un JWT con formato válido.
        Si el formato es inválido, lanza ValidationError antes de intentar
        hacer blacklist (evita errores internos de SimpleJWT).
        """
        try:
            RefreshToken(value)
        except Exception:
            raise serializers.ValidationError("Token de refresco inválido.")
        return value
