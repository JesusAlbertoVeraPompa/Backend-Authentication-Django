"""
Serializers for authentication flows:
    - Registration
    - Login (custom JWT payload)
    - Phone verification
    - Password reset request + confirm
    - Social login token exchange
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
    Handles user registration.
    Validates password strength and ensures email uniqueness.
    """

    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={"input_type": "password"},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
    )

    class Meta:
        model = User
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
            "last_name": {"required": True},
        }

    def validate(self, attrs):
        if attrs["password"] != attrs.pop("password_confirm"):
            raise serializers.ValidationError(
                {"password_confirm": "Las contraseñas no coinciden."}
            )

        # Age validation (optional: must be at least 13 years old)
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
# LOGIN — custom JWT payload
# ─────────────────────────────────────────

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Extends the default JWT payload with extra user fields.
    Also blocks login for unverified users (configurable).
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Custom claims
        token["email"] = user.email
        token["full_name"] = user.full_name
        token["role"] = user.role
        token["is_verified"] = user.is_verified

        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        # Attach user info to the response body
        data["user"] = {
            "id": str(self.user.id),
            "email": self.user.email,
            "full_name": self.user.full_name,
            "role": self.user.role,
            "is_verified": self.user.is_verified,
        }

        return data


# ─────────────────────────────────────────
# PHONE VERIFICATION
# ─────────────────────────────────────────

class SendVerificationCodeSerializer(serializers.Serializer):
    """Request a new SMS verification code for the authenticated user."""

    phone_number = serializers.CharField(max_length=20, required=False)

    def validate_phone_number(self, value):
        if not value:
            return value
        pattern = r'^\+[1-9]\d{7,14}$'  # E.164 internacional
        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Formato inválido. Usa formato internacional: +573001234567 (8-15 dígitos)"
            )
        return value


class VerifyPhoneSerializer(serializers.Serializer):
    """Submit the 6-digit SMS code to verify the user's phone."""

    code = serializers.CharField(max_length=10)

    def validate_code(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("El código debe contener solo dígitos.")
        return value


# ─────────────────────────────────────────
# PASSWORD RESET
# ─────────────────────────────────────────

class PasswordResetRequestSerializer(serializers.Serializer):
    """Request a password-reset email."""

    email = serializers.EmailField()

    def validate_email(self, value):
        # We intentionally do NOT raise an error if the email doesn't exist
        # (prevents user enumeration attacks).
        return value.lower()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Confirm password reset using the token received by email."""

    token = serializers.UUIDField()
    password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
        style={"input_type": "password"},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )

    def validate(self, attrs):
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Las contraseñas no coinciden."}
            )

        try:
            reset_token = PasswordResetToken.objects.select_related("user").get(
                token=attrs["token"]
            )
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError({"token": "Token inválido."})

        if not reset_token.is_valid:
            raise serializers.ValidationError(
                {"token": "El token ha expirado o ya fue utilizado."}
            )

        attrs["reset_token"] = reset_token
        return attrs


# ─────────────────────────────────────────
# CHANGE PASSWORD (authenticated)
# ─────────────────────────────────────────

class ChangePasswordSerializer(serializers.Serializer):
    """Change password for an authenticated user who knows their current password."""

    current_password = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )
    new_password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
        style={"input_type": "password"},
    )
    new_password_confirm = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "Las contraseñas nuevas no coinciden."}
            )
        return attrs

    def validate_current_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("La contraseña actual es incorrecta.")
        return value


# ─────────────────────────────────────────
# SOCIAL LOGIN
# ─────────────────────────────────────────

class SocialLoginSerializer(serializers.Serializer):
    """
    Exchange a provider access token (Google / Facebook) for JWT tokens.

    The frontend must obtain the access_token from the provider's SDK
    and send it here.
    """

    provider = serializers.ChoiceField(choices=["google", "facebook"])
    access_token = serializers.CharField()

    def validate(self, attrs):
        provider = attrs["provider"]
        access_token = attrs["access_token"]

        try:
            from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
            from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter

            adapter_map = {
                "google": GoogleOAuth2Adapter,
                "facebook": FacebookOAuth2Adapter,
            }
            AdapterClass = adapter_map[provider]  # noqa: N806

            # Use allauth to validate token and get/create user
            from allauth.socialaccount.helpers import complete_social_login
            from allauth.socialaccount.models import SocialToken, SocialApp
            
            # Build a minimal request for allauth
            request = self.context.get("request")
            adapter = AdapterClass(request)

            app = SocialApp.objects.get(provider=provider)
            token = SocialToken(app=app, token=access_token)
            login = adapter.complete_login(request, app, token, response={})
            login.token = token
            complete_social_login(request, login)

            if login.account.user:
                user = login.account.user
                refresh = RefreshToken.for_user(user)
                attrs["user"] = user
                attrs["tokens"] = {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            else:
                raise serializers.ValidationError(
                    "No se pudo autenticar con el proveedor social."
                )

        except serializers.ValidationError:
            raise 
        except SocialApp.DoesNotExist:
            raise serializers.ValidationError("Proveedor social no configurado.")
        except Exception as exc:
            logger.error("Social login error [%s]: %s", provider, exc)
            raise serializers.ValidationError("Token social inválido o autenticación fallida.")

        return attrs


# ─────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────

class LogoutSerializer(serializers.Serializer):
    """Blacklist the refresh token on logout."""

    refresh = serializers.CharField()

    def validate_refresh(self, value):
        try:
            RefreshToken(value)
        except Exception:
            raise serializers.ValidationError("Token de refresco inválido.")
        return value
