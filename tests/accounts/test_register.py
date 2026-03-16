"""
Tests for user registration endpoint.
POST /api/v1/auth/register/
"""

import pytest
from apps.accounts.models import EmailVerificationToken, User

REGISTER_URL = "/api/v1/auth/register/"


@pytest.mark.django_db
class TestRegisterView:

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

    # ─── SUCCESS CASES ───────────────────────────────────────────────

    def test_register_success(self, api_client):
        response = api_client.post(REGISTER_URL, self._valid_payload(), format="json")

        assert response.status_code == 201
        assert response.data["success"] is True
        assert "email" in response.data["data"]

        user = User.objects.get(email="newuser@example.com")
        assert user.first_name == "Juan"
        assert user.last_name == "Pérez"
        assert user.phone_verified is False

    def test_register_without_birth_date(self, api_client):
        payload = self._valid_payload()
        del payload["birth_date"]
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 201

    def test_register_without_phone(self, api_client):
        payload = self._valid_payload()
        del payload["phone_number"]
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 201

    def test_register_assigns_usuario_group(self, api_client):
        """El signal assign_default_group debe agregar al grupo 'Usuario'."""
        api_client.post(REGISTER_URL, self._valid_payload(), format="json")
        user = User.objects.get(email="newuser@example.com")
        assert user.groups.filter(name="Usuario").exists()

    def test_response_structure(self, api_client):
        response = api_client.post(REGISTER_URL, self._valid_payload(), format="json")
        for key in ("success", "status_code", "message", "data"):
            assert key in response.data

    # CORRECCIÓN: La vista SÍ crea el EmailVerificationToken (el código muerto
    # fue corregido en views.py). El test anterior assertía `is False` — incorrecto.
    def test_register_creates_email_verification_token(self, api_client):
        """
        Al registrarse se crea un EmailVerificationToken y se envía el correo.
        """
        response = api_client.post(
            REGISTER_URL,
            self._valid_payload(email="test@example.com"),
            format="json",
        )
        assert response.status_code == 201

        token_exists = EmailVerificationToken.objects.filter(
            user__email="test@example.com"
        ).exists()
        assert token_exists is True

    # ─── VALIDATION ERRORS ───────────────────────────────────────────

    def test_register_duplicate_email(self, api_client, make_user):
        make_user(email="newuser@example.com")
        response = api_client.post(REGISTER_URL, self._valid_payload(), format="json")
        assert response.status_code == 400
        assert response.data["success"] is False

    def test_register_password_mismatch(self, api_client):
        payload = self._valid_payload(password_confirm="WrongPass999!")
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400
        assert "password_confirm" in response.data["errors"]

    def test_register_weak_password(self, api_client):
        payload = self._valid_payload(password="123", password_confirm="123")
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400

    def test_register_missing_required_fields(self, api_client):
        payload = self._valid_payload()
        del payload["email"]
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400

    def test_register_invalid_email(self, api_client):
        payload = self._valid_payload(email="not-an-email")
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400

    def test_register_too_young(self, api_client):
        payload = self._valid_payload(birth_date="2020-01-01")
        response = api_client.post(REGISTER_URL, payload, format="json")
        assert response.status_code == 400
        assert "birth_date" in response.data["errors"]
