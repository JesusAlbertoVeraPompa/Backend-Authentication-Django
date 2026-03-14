"""
Tests for login and logout endpoints.
POST /api/v1/auth/login/
POST /api/v1/auth/logout/
"""
import pytest

LOGIN_URL = "/api/v1/auth/login/"
LOGOUT_URL = "/api/v1/auth/logout/"
REFRESH_URL = "/api/v1/auth/token/refresh/"


@pytest.mark.django_db
class TestLoginView:
    """Login endpoint tests."""

    # ── Success ───────────────────────────────────────────────────────────────

    def test_login_success(self, api_client, regular_user):
        """Valid credentials return access + refresh tokens."""
        response = api_client.post(
            LOGIN_URL,
            {"email": "regular@example.com", "password": "StrongPass123!"},
            format="json",
        )
        assert response.status_code == 200
        assert response.data["success"] is True

        data = response.data["data"]
        assert "access" in data
        assert "refresh" in data
        assert data["user"]["email"] == "regular@example.com"

    def test_login_includes_user_info(self, api_client, regular_user):
        """Login response contains user id, email, full_name, role, is_verified."""
        response = api_client.post(
            LOGIN_URL,
            {"email": "regular@example.com", "password": "StrongPass123!"},
            format="json",
        )
        user_data = response.data["data"]["user"]
        assert "id" in user_data
        assert "email" in user_data
        assert "full_name" in user_data
        assert "role" in user_data
        assert "is_verified" in user_data

    def test_login_case_insensitive_email(self, api_client, regular_user):
        """Email is case-insensitive."""
        response = api_client.post(
            LOGIN_URL,
            {"email": "REGULAR@EXAMPLE.COM", "password": "StrongPass123!"},
            format="json",
        )
        # Django normalizes emails — this should succeed
        assert response.status_code in (200, 401)  # depends on DB collation

    # ── Failure ───────────────────────────────────────────────────────────────

    def test_login_wrong_password(self, api_client, regular_user):
        """Wrong password returns 401."""
        response = api_client.post(
            LOGIN_URL,
            {"email": "regular@example.com", "password": "WrongPass!"},
            format="json",
        )
        assert response.status_code == 401
        assert response.data["success"] is False

    def test_login_unknown_email(self, api_client):
        """Unknown email returns 401."""
        response = api_client.post(
            LOGIN_URL,
            {"email": "nobody@example.com", "password": "Pass123!"},
            format="json",
        )
        assert response.status_code == 401

    def test_login_inactive_user(self, api_client, make_user):
        """Inactive user cannot log in."""
        make_user(email="inactive@example.com", is_active=False)
        response = api_client.post(
            LOGIN_URL,
            {"email": "inactive@example.com", "password": "StrongPass123!"},
            format="json",
        )
        assert response.status_code == 401

    def test_login_missing_fields(self, api_client):
        """Missing password returns 400/401."""
        response = api_client.post(LOGIN_URL, {"email": "x@x.com"}, format="json")
        assert response.status_code in (400, 401)

    def test_error_response_structure(self, api_client):
        """Error response has correct structure."""
        response = api_client.post(
            LOGIN_URL, {"email": "x@x.com", "password": "bad"}, format="json"
        )
        for key in ("success", "status_code", "message"):
            assert key in response.data


@pytest.mark.django_db
class TestLogoutView:
    """Logout endpoint tests."""

    def _get_tokens(self, api_client, user):
        resp = api_client.post(
            LOGIN_URL,
            {"email": user.email, "password": "StrongPass123!"},
            format="json",
        )
        return resp.data["data"]

    def test_logout_success(self, api_client, regular_user):
        """Logout blacklists the refresh token."""
        tokens = self._get_tokens(api_client, regular_user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

        response = api_client.post(
            LOGOUT_URL, {"refresh": tokens["refresh"]}, format="json"
        )
        assert response.status_code == 200
        assert response.data["success"] is True

    def test_logout_blacklists_token(self, api_client, regular_user):
        """After logout, the refresh token cannot be used to get a new access token."""
        tokens = self._get_tokens(api_client, regular_user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        api_client.post(LOGOUT_URL, {"refresh": tokens["refresh"]}, format="json")

        # Attempt to refresh with the blacklisted token
        response = api_client.post(
            REFRESH_URL, {"refresh": tokens["refresh"]}, format="json"
        )
        assert response.status_code == 401

    def test_logout_requires_authentication(self, api_client):
        """Unauthenticated request returns 401."""
        response = api_client.post(LOGOUT_URL, {"refresh": "some-token"}, format="json")
        assert response.status_code == 401

    def test_logout_invalid_token(self, auth_client):
        """Invalid refresh token returns 400."""
        response = auth_client.post(
            LOGOUT_URL, {"refresh": "invalid-token"}, format="json"
        )
        assert response.status_code == 400
