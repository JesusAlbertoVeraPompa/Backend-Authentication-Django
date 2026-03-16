"""
Tests for uncovered lines in multiple modules.

Este archivo existe para cubrir líneas que quedaron sin cobertura
en el reporte de coverage.

Cobertura objetivo:

apps/accounts/models.py
    - line 20
    - lines 29-38
    - line 131
    - line 140
    - line 169

apps/accounts/serializers.py
    - lines 261-308 (SocialLoginSerializer)

apps/accounts/views.py
    - lines 133-135 (logout exception)

apps/users/serializers.py
    - lines 70
    - lines 83-88
    - line 94
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import timedelta

from django.utils import timezone
from django.contrib.sites.models import Site


# ─────────────────────────────────────────
# accounts/models.py
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestUserManager:
    """
    Tests para el UserManager personalizado.

    Verifica validaciones al crear usuarios y superusuarios.
    """

    def test_create_user_raises_if_no_email(self):
        """
        Línea 20 — create_user debe lanzar error si el email es vacío.
        """
        from apps.accounts.models import User

        with pytest.raises(ValueError, match="email es obligatorio"):
            User.objects.create_user(email="", password="Pass123!")

    def test_create_superuser_raises_if_not_staff(self):
        """
        Lines 29-38 — create_superuser debe exigir is_staff=True.
        """
        from apps.accounts.models import User

        with pytest.raises(ValueError, match="is_staff=True"):
            User.objects.create_superuser(
                email="s1@test.com",
                password="Pass123!",
                first_name="A",
                last_name="B",
                is_staff=False,
            )

    def test_create_superuser_raises_if_not_superuser(self):
        """
        Lines 29-38 — create_superuser debe exigir is_superuser=True.
        """
        from apps.accounts.models import User

        with pytest.raises(ValueError, match="is_superuser=True"):
            User.objects.create_superuser(
                email="s2@test.com",
                password="Pass123!",
                first_name="A",
                last_name="B",
                is_superuser=False,
            )


@pytest.mark.django_db
class TestVerificationCodeModel:
    """
    Tests para el modelo VerificationCode.

    Este modelo maneja códigos de verificación
    usados para SMS o email verification.
    """

    def test_str_active_code(self, make_user):
        """
        Línea 131 — __str__ debe indicar que el código está activo.
        """
        from apps.accounts.models import VerificationCode

        user = make_user(email="vc_str@test.com")
        code = VerificationCode.objects.create(user=user, code="123456")

        assert "activo" in str(code)

    def test_str_used_code(self, make_user):
        """
        Línea 131 — __str__ debe indicar que el código fue usado.
        """
        from apps.accounts.models import VerificationCode

        user = make_user(email="vc_used@test.com")
        code = VerificationCode.objects.create(
            user=user,
            code="654321",
            is_used=True
        )

        assert "usado" in str(code)

    def test_is_valid_false_when_used(self, make_user):
        """
        Línea 140 — is_valid debe ser False si el código ya fue usado.
        """
        from apps.accounts.models import VerificationCode

        user = make_user(email="vc_valid@test.com")
        code = VerificationCode.objects.create(
            user=user,
            code="111111",
            is_used=True
        )

        assert code.is_valid is False

    def test_is_valid_false_when_expired(self, make_user):
        """
        Línea 140 — is_valid debe ser False si el código expiró.
        """
        from apps.accounts.models import VerificationCode

        user = make_user(email="vc_exp@test.com")
        code = VerificationCode.objects.create(user=user, code="222222")

        # Simula un código creado hace 15 minutos
        VerificationCode.objects.filter(pk=code.pk).update(
            created_at=timezone.now() - timedelta(minutes=15)
        )

        code.refresh_from_db()

        assert code.is_valid is False

    def test_is_valid_true_when_active_and_not_expired(self, make_user):
        """
        Línea 140 — is_valid debe ser True si el código es reciente
        y no ha sido usado.
        """
        from apps.accounts.models import VerificationCode

        user = make_user(email="vc_ok@test.com")
        code = VerificationCode.objects.create(user=user, code="333333")

        assert code.is_valid is True


@pytest.mark.django_db
class TestPasswordResetTokenModel:
    """
    Tests para el modelo PasswordResetToken.

    Este modelo maneja tokens para restablecer contraseña.
    """

    def test_str(self, make_user):
        """
        Línea 169 — __str__ debe incluir el email del usuario.
        """
        from apps.accounts.models import PasswordResetToken

        user = make_user(email="prt_str@test.com")
        token = PasswordResetToken.objects.create(user=user)

        assert "Reset token para" in str(token)
        assert user.email in str(token)

    def test_is_valid_true_when_fresh(self, make_user):
        """
        Token recién creado debe ser válido.
        """
        from apps.accounts.models import PasswordResetToken

        user = make_user(email="prt_valid@test.com")
        token = PasswordResetToken.objects.create(user=user)

        assert token.is_valid is True

    def test_is_valid_false_when_used(self, make_user):
        """
        Token usado debe ser inválido.
        """
        from apps.accounts.models import PasswordResetToken

        user = make_user(email="prt_used@test.com")
        token = PasswordResetToken.objects.create(user=user, is_used=True)

        assert token.is_valid is False

    def test_is_expired_false_when_fresh(self, make_user):
        """
        Token recién creado no debe estar expirado.
        """
        from apps.accounts.models import PasswordResetToken

        user = make_user(email="prt_fresh@test.com")
        token = PasswordResetToken.objects.create(user=user)

        assert token.is_expired is False

    def test_is_expired_true_when_old(self, make_user):
        """
        Token creado hace más de 24 horas debe considerarse expirado.
        """
        from apps.accounts.models import PasswordResetToken

        user = make_user(email="prt_old@test.com")
        token = PasswordResetToken.objects.create(user=user)

        VerificationCode = None  # evitar shadow warnings

        from apps.accounts.models import PasswordResetToken as Token

        Token.objects.filter(pk=token.pk).update(
            created_at=timezone.now() - timedelta(hours=25)
        )

        token.refresh_from_db()

        assert token.is_expired is True


# ─────────────────────────────────────────
# accounts/views.py — logout exception
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestLogoutViewException:
    """
    Tests para el endpoint de logout cuando ocurre
    un error al hacer blacklist del refresh token.
    """

    def test_logout_returns_400_on_blacklist_error(self, auth_client):
        """
        Lines 133-135 — si falla blacklist() debe retornar HTTP 400.
        """
        from rest_framework_simplejwt.tokens import RefreshToken

        user = auth_client._user
        refresh = RefreshToken.for_user(user)

        with patch(
            "apps.accounts.views.RefreshToken",
            side_effect=Exception("blacklist error")
        ):
            response = auth_client.post(
                "/api/v1/auth/logout/",
                {"refresh": str(refresh)},
                format="json",
            )

        assert response.status_code == 400


# ─────────────────────────────────────────
# accounts/serializers.py — SocialLoginSerializer
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestSocialLoginSerializerDirectly:
    """
    Tests directos para SocialLoginSerializer.

    Simula login social con Google usando django-allauth.
    """

    def test_invalid_provider_raises_validation_error(self):
        """
        Provider inválido debe fallar por ChoiceField.
        """
        from apps.accounts.serializers import SocialLoginSerializer

        serializer = SocialLoginSerializer(data={
            "provider": "twitter",
            "access_token": "sometoken",
        })

        assert not serializer.is_valid()
        assert "provider" in serializer.errors

    def test_missing_access_token_raises_error(self):
        """
        access_token es obligatorio.
        """
        from apps.accounts.serializers import SocialLoginSerializer

        serializer = SocialLoginSerializer(data={"provider": "google"})

        assert not serializer.is_valid()
        assert "access_token" in serializer.errors

    def test_validate_raises_on_social_login_failure(self):
        """
        Token inválido debe causar ValidationError.
        """
        from apps.accounts.serializers import SocialLoginSerializer
        from rest_framework.test import APIRequestFactory

        factory = APIRequestFactory()
        request = factory.post("/")

        serializer = SocialLoginSerializer(
            data={"provider": "google", "access_token": "bad_token"},
            context={"request": request},
        )

        assert not serializer.is_valid()

    def test_validate_success_path(self, make_user):
        """
        Simula login social exitoso.
        """
        from apps.accounts.serializers import SocialLoginSerializer
        from allauth.socialaccount.models import SocialApp
        from rest_framework.test import APIRequestFactory

        site = Site.objects.get_current()

        # Crear app social
        app = SocialApp.objects.create(
            provider="google",
            name="Google",
            client_id="test-client-id",
            secret="test-secret",
        )

        app.sites.add(site)

        factory = APIRequestFactory()
        request = factory.post("/")

        user = make_user(email="social_ok@test.com")

        mock_login = MagicMock()
        mock_login.account.user = user

        # Mock de Google OAuth adapter
        with patch(
            "allauth.socialaccount.providers.google.views.GoogleOAuth2Adapter"
        ) as mock_adapter_cls, patch(
            "allauth.socialaccount.helpers.complete_social_login"
        ):

            mock_adapter = MagicMock()
            mock_adapter_cls.return_value = mock_adapter
            mock_adapter.complete_login.return_value = mock_login

            serializer = SocialLoginSerializer(
                data={"provider": "google", "access_token": "valid_token"},
                context={"request": request},
            )

            assert serializer.is_valid(), serializer.errors
            assert "user" in serializer.validated_data
            assert "tokens" in serializer.validated_data


# ─────────────────────────────────────────
# users/serializers.py
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestAdminUserUpdateSerializer:
    """
    Tests para AdminUserUpdateSerializer.

    Este serializer permite a administradores modificar usuarios,
    incluyendo su rol.
    """

    def test_validate_role_invalid(self):
        """
        Role inválido debe generar error de validación.
        """
        from apps.users.serializers import AdminUserUpdateSerializer

        serializer = AdminUserUpdateSerializer(
            data={"role": "Hacker"},
            partial=True,
        )

        assert not serializer.is_valid()
        assert "role" in serializer.errors

    def test_validate_role_valid(self):
        """
        Role válido debe pasar validación.
        """
        from apps.users.serializers import AdminUserUpdateSerializer

        serializer = AdminUserUpdateSerializer(
            data={"role": "Admin"},
            partial=True,
        )

        assert serializer.is_valid(), serializer.errors

    def test_update_assigns_role(self, make_user):
        """
        Línea 94 — update() debe aplicar el nuevo rol al usuario.
        """
        from apps.users.serializers import AdminUserUpdateSerializer

        user = make_user(email="admin_upd@test.com", role="Usuario")

        serializer = AdminUserUpdateSerializer(
            user,
            data={"role": "Admin"},
            partial=True,
        )

        assert serializer.is_valid(), serializer.errors

        updated_user = serializer.save()
        updated_user.refresh_from_db()

        assert updated_user.role == "Admin"

    def test_validate_role_invalid_error_message(self):
        """
        Llama directamente validate_role() para probar el mensaje
        personalizado de error.
        """
        from apps.users.serializers import AdminUserUpdateSerializer
        from rest_framework.exceptions import ValidationError

        serializer = AdminUserUpdateSerializer(partial=True)

        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_role("RolFalso")

        assert "Rol inválido" in str(exc_info.value.detail[0])


@pytest.mark.django_db
class TestUserUpdateSerializerPhoneValidation:
    """
    Tests para validación de teléfono en UserUpdateSerializer.
    """

    def test_invalid_phone_format(self, make_user):
        """
        Teléfono sin '+' debe ser inválido.
        """
        from apps.users.serializers import UserUpdateSerializer

        user = make_user(email="phone_val@test.com")

        serializer = UserUpdateSerializer(
            user,
            data={"phone_number": "3001234567"},
            partial=True,
        )

        assert not serializer.is_valid()
        assert "phone_number" in serializer.errors

    def test_valid_phone_format(self, make_user):
        """
        Teléfono con '+' debe ser válido.
        """
        from apps.users.serializers import UserUpdateSerializer

        user = make_user(email="phone_ok@test.com")

        serializer = UserUpdateSerializer(
            user,
            data={"phone_number": "+573001234567"},
            partial=True,
        )

        assert serializer.is_valid()