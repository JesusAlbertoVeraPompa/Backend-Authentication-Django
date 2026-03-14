"""
Tests for phone verification endpoints.
POST /api/v1/auth/verify/send/
POST /api/v1/auth/verify/confirm/
"""
import pytest
from unittest.mock import patch

from apps.accounts.models import User, VerificationCode

SEND_URL = "/api/v1/auth/verify/send/"
CONFIRM_URL = "/api/v1/auth/verify/confirm/"


@pytest.mark.django_db
class TestSendVerificationCodeView:
    """Tests for sending the SMS verification code."""

    @patch("apps.accounts.views.send_sms_verification", return_value=True)
    def test_send_code_success(self, mock_sms, auth_client, regular_user):
        """Authenticated user with phone number can request a code."""
        regular_user.phone_number = "+573001234567"
        regular_user.save()

        response = auth_client.post(SEND_URL, {}, format="json")
        assert response.status_code == 200
        assert response.data["success"] is True
        mock_sms.assert_called_once()

        assert VerificationCode.objects.filter(user=regular_user).exists()

    @patch("apps.accounts.views.send_sms_verification", return_value=True)
    def test_send_code_updates_phone(self, mock_sms, auth_client, regular_user):
        """User can provide a new phone number in the request."""
        response = auth_client.post(
            SEND_URL, {"phone_number": "+573009876543"}, format="json"
        )
        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.phone_number == "+573009876543"

    @patch("apps.accounts.views.send_sms_verification", return_value=True)
    def test_resend_invalidates_old_code(self, mock_sms, auth_client, regular_user):
        """Re-sending marks previous codes as used."""
        regular_user.phone_number = "+573001234567"
        regular_user.save()

        # First send
        auth_client.post(SEND_URL, {}, format="json")
        old_code = VerificationCode.objects.filter(user=regular_user).first()

        # Second send
        auth_client.post(SEND_URL, {}, format="json")
        old_code.refresh_from_db()
        assert old_code.is_used is True

    def test_send_code_no_phone_returns_400(self, auth_client, regular_user):
        """User without a phone number gets a 400 error."""
        regular_user.phone_number = None
        regular_user.save()

        response = auth_client.post(SEND_URL, {}, format="json")
        assert response.status_code == 400

    def test_send_code_requires_authentication(self, api_client):
        """Unauthenticated request returns 401."""
        response = api_client.post(SEND_URL, {}, format="json")
        assert response.status_code == 401

    @patch("apps.accounts.views.send_sms_verification", return_value=False)
    def test_sms_service_failure_returns_503(self, mock_sms, auth_client, regular_user):
        """If SMS service fails, return 503."""
        regular_user.phone_number = "+573001234567"
        regular_user.save()

        response = auth_client.post(SEND_URL, {}, format="json")
        assert response.status_code == 503

    def test_invalid_phone_format_returns_400(self, auth_client):
        """Phone without '+' prefix is rejected."""
        response = auth_client.post(
            SEND_URL, {"phone_number": "3001234567"}, format="json"
        )
        assert response.status_code == 400
    

@pytest.mark.django_db
class TestVerifyPhoneView:
    """Tests for confirming the SMS code."""

    def _create_code(self, user, code="123456"):
        return VerificationCode.objects.create(user=user, code=code)

    def test_verify_success(self, auth_client, regular_user):
        """Valid, unexpired code verifies the user."""
        self._create_code(regular_user)
        response = auth_client.post(CONFIRM_URL, {"code": "123456"}, format="json")

        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.is_verified is True

    def test_verify_marks_code_as_used(self, auth_client, regular_user):
        """After verification the code is marked as used."""
        code_obj = self._create_code(regular_user)
        auth_client.post(CONFIRM_URL, {"code": "123456"}, format="json")

        code_obj.refresh_from_db()
        assert code_obj.is_used is True

    def test_verify_wrong_code(self, auth_client, regular_user):
        """Wrong code returns 400."""
        self._create_code(regular_user)
        response = auth_client.post(CONFIRM_URL, {"code": "000000"}, format="json")
        assert response.status_code == 400
        regular_user.refresh_from_db()
        assert regular_user.is_verified is False

    def test_verify_expired_code(self, auth_client, regular_user):
        """Expired code returns 400."""
        from datetime import timedelta
        from django.utils import timezone

        code_obj = self._create_code(regular_user)
        # Manually expire the code
        VerificationCode.objects.filter(pk=code_obj.pk).update(
            created_at=timezone.now() - timedelta(minutes=15)
        )

        response = auth_client.post(CONFIRM_URL, {"code": "123456"}, format="json")
        assert response.status_code == 400

    def test_verify_used_code_rejected(self, auth_client, regular_user):
        """Already-used code returns 400."""
        self._create_code(regular_user, code="654321")
        VerificationCode.objects.filter(user=regular_user).update(is_used=True)

        response = auth_client.post(CONFIRM_URL, {"code": "654321"}, format="json")
        assert response.status_code == 400

    def test_verify_requires_authentication(self, api_client):
        """Unauthenticated request returns 401."""
        response = api_client.post(CONFIRM_URL, {"code": "123456"}, format="json")
        assert response.status_code == 401

    def test_verify_non_numeric_code(self, auth_client):
        """Non-numeric code is rejected by serializer."""
        response = auth_client.post(CONFIRM_URL, {"code": "abcdef"}, format="json")
        assert response.status_code == 400
