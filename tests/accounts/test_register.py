"""
Tests for user registration endpoint.
POST /api/v1/auth/register/
"""
import pytest
from django.urls import reverse

from apps.accounts.models import User

REGISTER_URL = "/api/v1/auth/register/"


@pytest.mark.django_db
class TestRegisterView:
    """Registration endpoint tests."""

    def _valid_payload(self, **overrides):
        data = {
            "email": "newuser@example.com",
            "first_name": "Juan",
            "last_name": "Pérez",
            "birth_date": "1995-06-15",
            "phone_number": "+573001234567",
            "password": "SecurePass123!",
            "password_confirm": "SecurePass123!",
        }
        data.update(overrides)
        return data

    # ── Success ───────────────────────────────────────────────────────────────

    def test_register_success(self, api_client):
        """Valid data creates a user and returns 201."""
        response = api_client.post(REGISTER_URL, self._valid_payload(), format="json")

        assert response.status_code == 201
        assert response.data["success"] is True
        assert "email" in response.data["data"]

        user = User.objects.get(email="newuser@example.com")
        assert user.first_name == "Juan"
        assert user.last_name == "Pérez"
        assert not user.is_verified  # phone not yet verified

    def test_register_without_birth_date(self, api_client):
        """birth_date is optional."""
        payload = self._valid_payload()
        del payload["birth_date"]
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 201

    def test_register_without_phone(self, api_client):
        """phone_number is optional."""
        payload = self._valid_payload()
        del payload["phone_number"]
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 201

    # ── Validation errors ─────────────────────────────────────────────────────

    def test_register_duplicate_email(self, api_client, make_user):
        """Duplicate email returns 400."""
        make_user(email="newuser@example.com")
        response = api_client.post(REGISTER_URL, self._valid_payload(), format="json")
        assert response.status_code == 400
        assert response.data["success"] is False

    def test_register_password_mismatch(self, api_client):
        """Mismatched passwords return 400."""
        payload = self._valid_payload(password_confirm="WrongPass999!")
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400
        assert "password_confirm" in response.data["errors"]

    def test_register_weak_password(self, api_client):
        """Weak password returns 400."""
        payload = self._valid_payload(password="123", password_confirm="123")
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400

    def test_register_missing_required_fields(self, api_client):
        """Missing email returns 400."""
        payload = self._valid_payload()
        del payload["email"]
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400

    def test_register_invalid_email(self, api_client):
        """Malformed email returns 400."""
        payload = self._valid_payload(email="not-an-email")
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400

    def test_register_too_young(self, api_client):
        """Users under 13 are rejected."""
        payload = self._valid_payload(birth_date="2020-01-01")
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400
        assert "birth_date" in response.data["errors"]

    def test_register_assigns_usuario_group(self, api_client):
        """New user is automatically added to the 'Usuario' group."""
        api_client.post(REGISTER_URL, self._valid_payload(), format="json")
        user = User.objects.get(email="newuser@example.com")
        assert user.groups.filter(name="Usuario").exists()

    def test_response_structure(self, api_client):
        """Response always contains success, status_code, message, data keys."""
        response = api_client.post(REGISTER_URL, self._valid_payload(), format="json")
        for key in ("success", "status_code", "message", "data"):
            assert key in response.data
