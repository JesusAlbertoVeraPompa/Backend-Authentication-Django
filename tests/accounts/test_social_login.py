"""
Tests for social login endpoint (mocked — no real provider calls).
POST /api/v1/auth/social/
"""
import pytest
from unittest.mock import MagicMock, patch

SOCIAL_URL = "/api/v1/auth/social/"


@pytest.mark.django_db
class TestSocialLoginView:
    """
    Social login tests use mocks to avoid real HTTP calls to Google/Facebook.
    The serializer's validate() method is patched to simulate provider responses.
    """

    def _make_mock_user(self, make_user):
        return make_user(email="social@example.com", role="Usuario")

    # ── Google ────────────────────────────────────────────────────────────────

    @patch("apps.accounts.serializers.SocialLoginSerializer.validate")
    def test_google_login_success(self, mock_validate, api_client, make_user):
        """
        Mocked Google token exchange returns JWT tokens.
        """
        user = self._make_mock_user(make_user)
        mock_validate.return_value = {
            "provider": "google",
            "access_token": "fake-google-token",
            "user": user,
            "tokens": {
                "access": "mocked-access-token",
                "refresh": "mocked-refresh-token",
            },
        }

        response = api_client.post(
            SOCIAL_URL,
            {"provider": "google", "access_token": "fake-google-token"},
            format="json",
        )

        assert response.status_code == 200
        assert response.data["success"] is True
        data = response.data["data"]
        assert "tokens" in data
        assert data["tokens"]["access"] == "mocked-access-token"
        assert data["user"]["email"] == "social@example.com"

    # ── Facebook ──────────────────────────────────────────────────────────────

    @patch("apps.accounts.serializers.SocialLoginSerializer.validate")
    def test_facebook_login_success(self, mock_validate, api_client, make_user):
        """Mocked Facebook token exchange returns JWT tokens."""
        user = self._make_mock_user(make_user)
        mock_validate.return_value = {
            "provider": "facebook",
            "access_token": "fake-fb-token",
            "user": user,
            "tokens": {
                "access": "mocked-access-token",
                "refresh": "mocked-refresh-token",
            },
        }

        response = api_client.post(
            SOCIAL_URL,
            {"provider": "facebook", "access_token": "fake-fb-token"},
            format="json",
        )

        assert response.status_code == 200
        assert response.data["success"] is True

    # ── Validation errors ─────────────────────────────────────────────────────

    def test_social_login_invalid_provider(self, api_client):
        """Unknown provider is rejected before hitting the adapter."""
        response = api_client.post(
            SOCIAL_URL,
            {"provider": "twitter", "access_token": "some-token"},
            format="json",
        )
        assert response.status_code == 400
        assert response.data["success"] is False

    def test_social_login_missing_token(self, api_client):
        """Missing access_token returns 400."""
        response = api_client.post(
            SOCIAL_URL,
            {"provider": "google"},
            format="json",
        )
        assert response.status_code == 400

    def test_social_login_missing_provider(self, api_client):
        """Missing provider returns 400."""
        response = api_client.post(
            SOCIAL_URL,
            {"access_token": "some-token"},
            format="json",
        )
        assert response.status_code == 400

    @patch("apps.accounts.serializers.SocialLoginSerializer.validate")
    def test_social_login_bad_token_returns_400(self, mock_validate, api_client):
        """Invalid token from provider raises serializer error."""
        from rest_framework import serializers

        mock_validate.side_effect = serializers.ValidationError(
            "Token social inválido o autenticación fallida."
        )

        response = api_client.post(
            SOCIAL_URL,
            {"provider": "google", "access_token": "bad-token"},
            format="json",
        )
        assert response.status_code == 400

    def test_response_has_correct_structure_on_success(self, api_client, make_user):
        """Success response contains tokens and user info."""
        user = self._make_mock_user(make_user)

        with patch("apps.accounts.serializers.SocialLoginSerializer.validate") as m:
            m.return_value = {
                "provider": "google",
                "access_token": "t",
                "user": user,
                "tokens": {"access": "a", "refresh": "r"},
            }
            response = api_client.post(
                SOCIAL_URL,
                {"provider": "google", "access_token": "t"},
                format="json",
            )

        assert "tokens" in response.data["data"]
        assert "user" in response.data["data"]
        user_data = response.data["data"]["user"]
        for field in ("id", "email", "full_name", "role", "is_verified"):
            assert field in user_data, f"Missing field: {field}"
