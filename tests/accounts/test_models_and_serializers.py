"""
Tests for uncovered lines in:
    - apps/accounts/models.py  (lines 20, 29-38, 131, 140, 169)
    - apps/accounts/serializers.py (lines 261-308 — SocialLoginSerializer)
    - apps/accounts/views.py (lines 133-135 — logout exception)
    - apps/users/serializers.py (lines 70, 83-88, 94)
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import timedelta
from django.utils import timezone


# ─────────────────────────────────────────
# accounts/models.py
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestUserManager:

    def test_create_user_raises_if_no_email(self):
        """Line 20 — ValueError when email is empty."""
        from apps.accounts.models import User
        with pytest.raises(ValueError, match="email es obligatorio"):
            User.objects.create_user(email="", password="Pass123!")

    def test_create_superuser_raises_if_not_staff(self):
        """Lines 29-38 — ValueError when is_staff=False."""
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
        """Lines 29-38 — ValueError when is_superuser=False."""
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

    def test_str_active_code(self, make_user):
        """Line 131 — __str__ for active code."""
        from apps.accounts.models import VerificationCode
        user = make_user(email="vc_str@test.com")
        code = VerificationCode.objects.create(user=user, code="123456")
        assert "activo" in str(code)

    def test_str_used_code(self, make_user):
        """Line 131 — __str__ for used code."""
        from apps.accounts.models import VerificationCode
        user = make_user(email="vc_used@test.com")
        code = VerificationCode.objects.create(user=user, code="654321", is_used=True)
        assert "usado" in str(code)

    def test_is_valid_false_when_used(self, make_user):
        """Line 140 — is_valid returns False when used."""
        from apps.accounts.models import VerificationCode
        user = make_user(email="vc_valid@test.com")
        code = VerificationCode.objects.create(user=user, code="111111", is_used=True)
        assert code.is_valid is False

    def test_is_valid_false_when_expired(self, make_user):
        """Line 140 — is_valid returns False when expired."""
        from apps.accounts.models import VerificationCode
        user = make_user(email="vc_exp@test.com")
        code = VerificationCode.objects.create(user=user, code="222222")
        VerificationCode.objects.filter(pk=code.pk).update(
            created_at=timezone.now() - timedelta(minutes=15)
        )
        code.refresh_from_db()
        assert code.is_valid is False

    def test_is_valid_true_when_active_and_not_expired(self, make_user):
        """Line 140 — is_valid returns True when fresh and unused."""
        from apps.accounts.models import VerificationCode
        user = make_user(email="vc_ok@test.com")
        code = VerificationCode.objects.create(user=user, code="333333")
        assert code.is_valid is True


@pytest.mark.django_db
class TestPasswordResetTokenModel:

    def test_str(self, make_user):
        """Line 169 — __str__ of PasswordResetToken."""
        from apps.accounts.models import PasswordResetToken
        user = make_user(email="prt_str@test.com")
        token = PasswordResetToken.objects.create(user=user)
        assert "Reset token para" in str(token)
        assert user.email in str(token)

    def test_is_valid_true_when_fresh(self, make_user):
        from apps.accounts.models import PasswordResetToken
        user = make_user(email="prt_valid@test.com")
        token = PasswordResetToken.objects.create(user=user)
        assert token.is_valid is True

    def test_is_valid_false_when_used(self, make_user):
        from apps.accounts.models import PasswordResetToken
        user = make_user(email="prt_used@test.com")
        token = PasswordResetToken.objects.create(user=user, is_used=True)
        assert token.is_valid is False

    def test_is_expired_false_when_fresh(self, make_user):
        from apps.accounts.models import PasswordResetToken
        user = make_user(email="prt_fresh@test.com")
        token = PasswordResetToken.objects.create(user=user)
        assert token.is_expired is False

    def test_is_expired_true_when_old(self, make_user):
        from apps.accounts.models import PasswordResetToken
        user = make_user(email="prt_old@test.com")
        token = PasswordResetToken.objects.create(user=user)
        PasswordResetToken.objects.filter(pk=token.pk).update(
            created_at=timezone.now() - timedelta(hours=25)
        )
        token.refresh_from_db()
        assert token.is_expired is True


# ─────────────────────────────────────────
# accounts/views.py — logout exception (lines 133-135)
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestLogoutViewException:

    def test_logout_returns_400_on_blacklist_error(self, auth_client):
        """Lines 133-135 — exception in blacklist returns 400."""
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
# accounts/serializers.py — SocialLoginSerializer (lines 284-298, 308)
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestSocialLoginSerializerDirectly:

    def test_invalid_provider_raises_validation_error(self):
        """Lines 261+ — invalid provider is caught by ChoiceField."""
        from apps.accounts.serializers import SocialLoginSerializer
        serializer = SocialLoginSerializer(data={
            "provider": "twitter",
            "access_token": "sometoken",
        })
        assert not serializer.is_valid()
        assert "provider" in serializer.errors

    def test_missing_access_token_raises_error(self):
        """Lines 261+ — missing access_token fails validation."""
        from apps.accounts.serializers import SocialLoginSerializer
        serializer = SocialLoginSerializer(data={"provider": "google"})
        assert not serializer.is_valid()
        assert "access_token" in serializer.errors

    def test_validate_raises_on_social_login_failure(self):
        """Lines 261-308 — exception path returns ValidationError."""
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
        """Lines 284-298, 308 — successful social login returns user and tokens."""
        from apps.accounts.serializers import SocialLoginSerializer
        from allauth.socialaccount.models import SocialApp
        from rest_framework.test import APIRequestFactory

        app = SocialApp.objects.create(
            provider="google",
            name="Google",
            client_id="test-client-id",
            secret="test-secret",
        )

        factory = APIRequestFactory()
        request = factory.post("/")
        user = make_user(email="social_ok@test.com")

        mock_login = MagicMock()
        mock_login.account.user = user

        # ✅ Todos los imports son locales dentro del try, por lo tanto
        # hay que parchear en sus módulos fuente originales, no en serializers.
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
# users/serializers.py (lines 70, 83-88, 94)
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestAdminUserUpdateSerializer:

    def test_validate_role_invalid(self):
        """Lines 83-88 — invalid role raises ValidationError via ChoiceField."""
        from apps.users.serializers import AdminUserUpdateSerializer
        serializer = AdminUserUpdateSerializer(
            data={"role": "Hacker"},
            partial=True,
        )
        assert not serializer.is_valid()
        assert "role" in serializer.errors

    def test_validate_role_valid(self):
        """Lines 83-88 — valid role passes."""
        from apps.users.serializers import AdminUserUpdateSerializer
        serializer = AdminUserUpdateSerializer(
            data={"role": "Admin"},
            partial=True,
        )
        assert serializer.is_valid(), serializer.errors
        assert "role" not in serializer.errors

    def test_update_assigns_role(self, make_user):
        """Line 94 — update() calls assign_role when role is provided."""
        from apps.users.serializers import AdminUserUpdateSerializer
        user = make_user(email="admin_upd@test.com", role="Usuario")
        serializer = AdminUserUpdateSerializer(
            user, data={"role": "Admin"}, partial=True
        )
        assert serializer.is_valid(), serializer.errors
        updated_user = serializer.save()
        updated_user.refresh_from_db()
        assert updated_user.role == "Admin"

    def test_validate_role_invalid_error_message(self):
        """Line 85 — validate_role() method raises with 'Rol inválido' message."""
        from apps.users.serializers import AdminUserUpdateSerializer
        from rest_framework.exceptions import ValidationError

        # ✅ Llamamos directamente al método para saltar el ChoiceField
        # que interceptaría el error antes de llegar a la línea 85.
        serializer = AdminUserUpdateSerializer(partial=True)
        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_role("RolFalso")
        assert "Rol inválido" in str(exc_info.value.detail[0])


@pytest.mark.django_db
class TestUserUpdateSerializerPhoneValidation:

    def test_invalid_phone_format(self, make_user):
        """Line 70 — phone without '+' is rejected."""
        from apps.users.serializers import UserUpdateSerializer
        user = make_user(email="phone_val@test.com")
        serializer = UserUpdateSerializer(
            user, data={"phone_number": "3001234567"}, partial=True
        )
        assert not serializer.is_valid()
        assert "phone_number" in serializer.errors

    def test_valid_phone_format(self, make_user):
        """Line 70 — phone with '+' passes."""
        from apps.users.serializers import UserUpdateSerializer
        user = make_user(email="phone_ok@test.com")
        serializer = UserUpdateSerializer(
            user, data={"phone_number": "+573001234567"}, partial=True
        )
        assert serializer.is_valid()
