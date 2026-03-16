"""
Tests for password reset and change endpoints.
POST /api/v1/auth/password/reset/
POST /api/v1/auth/password/reset/confirm/
POST /api/v1/auth/password/change/
"""
import uuid
import pytest
from unittest.mock import ANY, patch

from apps.accounts.models import PasswordResetToken

RESET_URL = "/api/v1/auth/password/reset/"
RESET_CONFIRM_URL = "/api/v1/auth/password/reset/confirm/"
CHANGE_URL = "/api/v1/auth/password/change/"


@pytest.mark.django_db
class TestPasswordResetRequestView:

    @patch("apps.accounts.views.send_password_reset_email", return_value=True)
    def test_reset_request_known_email(self, mock_email, api_client, regular_user):
        """Requesting reset for a known email returns 200."""
        response = api_client.post(
            RESET_URL, {"email": "regular@example.com"}, format="json"
        )
        assert response.status_code == 200
        assert response.data["success"] is True
        mock_email.assert_called_once_with(regular_user, ANY)

    @patch("apps.accounts.views.send_password_reset_email", return_value=True)
    def test_reset_request_unknown_email(self, mock_email, api_client):
        """Requesting reset for unknown email also returns 200 (no enumeration)."""
        response = api_client.post(
            RESET_URL, {"email": "nobody@example.com"}, format="json"
        )
        assert response.status_code == 200
        mock_email.assert_not_called()

    def test_reset_request_invalid_email(self, api_client):
        """Malformed email returns 400."""
        response = api_client.post(
            RESET_URL, {"email": "not-an-email"}, format="json"
        )
        assert response.status_code == 400

    @patch("apps.accounts.views.send_password_reset_email", return_value=True)
    def test_reset_creates_token(self, mock_email, api_client, regular_user):
        """A PasswordResetToken is created in the database."""
        api_client.post(RESET_URL, {"email": "regular@example.com"}, format="json")
        assert PasswordResetToken.objects.filter(user=regular_user).exists()

    @patch("apps.accounts.views.send_password_reset_email", return_value=True)
    def test_reset_invalidates_previous_tokens(self, mock_email, api_client, regular_user):
        """Requesting reset a second time invalidates the first token."""
        api_client.post(RESET_URL, {"email": "regular@example.com"}, format="json")
        first_token = PasswordResetToken.objects.filter(user=regular_user).first()

        api_client.post(RESET_URL, {"email": "regular@example.com"}, format="json")
        first_token.refresh_from_db()
        assert first_token.is_used is True


@pytest.mark.django_db
class TestPasswordResetConfirmView:

    def _make_token(self, user):
        return PasswordResetToken.objects.create(user=user)

    def test_confirm_success(self, api_client, regular_user):
        """Valid token + new password resets the password."""
        token = self._make_token(regular_user)
        response = api_client.post(
            RESET_CONFIRM_URL,
            {
                "token": str(token.token),
                "password": "NewSecurePass123!",
                "password_confirm": "NewSecurePass123!",
            },
            format="json",
        )
        assert response.status_code == 200
        assert response.data["success"] is True

        # Verify password actually changed
        regular_user.refresh_from_db()
        assert regular_user.check_password("NewSecurePass123!")

    def test_confirm_marks_token_used(self, api_client, regular_user):
        """Token is marked as used after a successful reset."""
        token = self._make_token(regular_user)
        api_client.post(
            RESET_CONFIRM_URL,
            {"token": str(token.token), "password": "NewP@ss123!", "password_confirm": "NewP@ss123!"},
            format="json",
        )
        token.refresh_from_db()
        assert token.is_used is True

    def test_confirm_invalid_token(self, api_client):
        """Non-existent token UUID returns 400."""
        response = api_client.post(
            RESET_CONFIRM_URL,
            {"token": str(uuid.uuid4()), "password": "NewP@ss123!", "password_confirm": "NewP@ss123!"},
            format="json",
        )
        assert response.status_code == 400

    def test_confirm_used_token_rejected(self, api_client, regular_user):
        """Used token returns 400."""
        token = self._make_token(regular_user)
        token.is_used = True
        token.save()

        response = api_client.post(
            RESET_CONFIRM_URL,
            {"token": str(token.token), "password": "NewP@ss123!", "password_confirm": "NewP@ss123!"},
            format="json",
        )
        assert response.status_code == 400

    def test_confirm_expired_token_rejected(self, api_client, regular_user):
        """Expired token returns 400."""
        from datetime import timedelta
        from django.utils import timezone

        token = self._make_token(regular_user)
        PasswordResetToken.objects.filter(pk=token.pk).update(
            created_at=timezone.now() - timedelta(hours=25)
        )
        response = api_client.post(
            RESET_CONFIRM_URL,
            {"token": str(token.token), "password": "NewP@ss123!", "password_confirm": "NewP@ss123!"},
            format="json",
        )
        assert response.status_code == 400

    def test_confirm_password_mismatch(self, api_client, regular_user):
        """Mismatched new passwords return 400."""
        token = self._make_token(regular_user)
        response = api_client.post(
            RESET_CONFIRM_URL,
            {"token": str(token.token), "password": "NewP@ss123!", "password_confirm": "DiffP@ss456!"},
            format="json",
        )
        assert response.status_code == 400


@pytest.mark.django_db
class TestChangePasswordView:

    def test_change_password_success(self, auth_client, regular_user):
        """Correct current password + new password changes it successfully."""
        response = auth_client.post(
            CHANGE_URL,
            {
                "current_password": "StrongPass123!",
                "new_password": "BrandNew@Pass1!",
                "new_password_confirm": "BrandNew@Pass1!",
            },
            format="json",
        )
        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.check_password("BrandNew@Pass1!")

    def test_change_password_wrong_current(self, auth_client):
        """Wrong current password returns 400."""
        response = auth_client.post(
            CHANGE_URL,
            {
                "current_password": "WrongOldPass!",
                "new_password": "BrandNew@Pass1!",
                "new_password_confirm": "BrandNew@Pass1!",
            },
            format="json",
        )
        assert response.status_code == 400

    def test_change_password_requires_auth(self, api_client):
        """Unauthenticated request returns 401."""
        response = api_client.post(CHANGE_URL, {}, format="json")
        assert response.status_code == 401

    def test_change_password_mismatch(self, auth_client):
        """Mismatched new passwords return 400."""
        response = auth_client.post(
            CHANGE_URL,
            {
                "current_password": "StrongPass123!",
                "new_password": "BrandNew@Pass1!",
                "new_password_confirm": "Different@Pass1!",
            },
            format="json",
        )
        assert response.status_code == 400
