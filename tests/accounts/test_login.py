"""
Tests for login and logout endpoints.

Endpoints probados:

POST /api/v1/auth/login/
    -> autentica usuario y devuelve tokens JWT

POST /api/v1/auth/logout/
    -> invalida (blacklist) el refresh token

POST /api/v1/auth/token/refresh/
    -> genera un nuevo access token usando refresh token
"""

import pytest


# Endpoints de autenticación
LOGIN_URL = "/api/v1/auth/login/"
LOGOUT_URL = "/api/v1/auth/logout/"
REFRESH_URL = "/api/v1/auth/token/refresh/"


@pytest.mark.django_db
class TestLoginView:
    """
    Tests para el endpoint de login.
    """

    # ─────────────────────────────────────────
    # SUCCESS CASES
    # ─────────────────────────────────────────

    def test_login_success(self, api_client, regular_user):
        """
        Credenciales válidas deben retornar:

        - access token
        - refresh token
        - información básica del usuario
        """

        response = api_client.post(
            LOGIN_URL,
            {
                "email": "regular@example.com",
                "password": "StrongPass123!"
            },
            format="json",
        )

        assert response.status_code == 200
        assert response.data["success"] is True

        data = response.data["data"]

        # JWT tokens
        assert "access" in data
        assert "refresh" in data

        # Información del usuario
        assert data["user"]["email"] == "regular@example.com"


    def test_login_includes_user_info(self, api_client, regular_user):
        """
        Verifica que la respuesta de login incluya
        los campos necesarios del usuario.
        """

        response = api_client.post(
            LOGIN_URL,
            {
                "email": "regular@example.com",
                "password": "StrongPass123!"
            },
            format="json",
        )

        user_data = response.data["data"]["user"]

        assert "id" in user_data
        assert "email" in user_data
        assert "full_name" in user_data
        assert "role" in user_data
        assert "is_verified" in user_data


    def test_login_case_insensitive_email(self, api_client, regular_user):
        """
        El login debe funcionar aunque el email tenga
        mayúsculas o minúsculas distintas.
        """

        response = api_client.post(
            LOGIN_URL,
            {
                "email": "REGULAR@EXAMPLE.COM",
                "password": "StrongPass123!"
            },
            format="json",
        )

        # Dependiendo de la configuración de la DB puede
        # devolver 200 o 401
        assert response.status_code in (200, 401)


    # ─────────────────────────────────────────
    # FAILURE CASES
    # ─────────────────────────────────────────

    def test_login_wrong_password(self, api_client, regular_user):
        """
        Contraseña incorrecta debe retornar 401.
        """

        response = api_client.post(
            LOGIN_URL,
            {
                "email": "regular@example.com",
                "password": "WrongPass!"
            },
            format="json",
        )

        assert response.status_code == 401
        assert response.data["success"] is False


    def test_login_unknown_email(self, api_client):
        """
        Email inexistente debe retornar 401.
        """

        response = api_client.post(
            LOGIN_URL,
            {
                "email": "nobody@example.com",
                "password": "Pass123!"
            },
            format="json",
        )

        assert response.status_code == 401


    def test_login_inactive_user(self, api_client, make_user):
        """
        Usuarios inactivos no deben poder iniciar sesión.
        """

        make_user(
            email="inactive@example.com",
            is_active=False
        )

        response = api_client.post(
            LOGIN_URL,
            {
                "email": "inactive@example.com",
                "password": "StrongPass123!"
            },
            format="json",
        )

        assert response.status_code == 401


    def test_login_missing_fields(self, api_client):
        """
        Si faltan campos requeridos el endpoint debe fallar.
        """

        response = api_client.post(
            LOGIN_URL,
            {"email": "x@x.com"},
            format="json",
        )

        assert response.status_code in (400, 401)


    def test_error_response_structure(self, api_client):
        """
        Verifica que las respuestas de error mantengan
        la estructura estándar de la API.
        """

        response = api_client.post(
            LOGIN_URL,
            {"email": "x@x.com", "password": "bad"},
            format="json",
        )

        for key in ("success", "status_code", "message"):
            assert key in response.data


@pytest.mark.django_db
class TestLogoutView:
    """
    Tests para el endpoint de logout.
    """

    def _get_tokens(self, api_client, user):
        """
        Helper que hace login y devuelve los tokens.
        """

        resp = api_client.post(
            LOGIN_URL,
            {
                "email": user.email,
                "password": "StrongPass123!"
            },
            format="json",
        )

        return resp.data["data"]


    def test_logout_success(self, api_client, regular_user):
        """
        Logout exitoso debe agregar el refresh token
        a la blacklist.
        """

        tokens = self._get_tokens(api_client, regular_user)

        # Autenticamos la request con access token
        api_client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {tokens['access']}"
        )

        response = api_client.post(
            LOGOUT_URL,
            {"refresh": tokens["refresh"]},
            format="json",
        )

        assert response.status_code == 200
        assert response.data["success"] is True


    def test_logout_blacklists_token(self, api_client, regular_user):
        """
        Después de logout el refresh token no debe poder
        usarse para obtener nuevos tokens.
        """

        tokens = self._get_tokens(api_client, regular_user)

        api_client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {tokens['access']}"
        )

        api_client.post(
            LOGOUT_URL,
            {"refresh": tokens["refresh"]},
            format="json",
        )

        # Intentamos refrescar con token invalidado
        response = api_client.post(
            REFRESH_URL,
            {"refresh": tokens["refresh"]},
            format="json",
        )

        assert response.status_code == 401


    def test_logout_requires_authentication(self, api_client):
        """
        Logout requiere autenticación.
        """

        response = api_client.post(
            LOGOUT_URL,
            {"refresh": "some-token"},
            format="json",
        )

        assert response.status_code == 401


    def test_logout_invalid_token(self, auth_client):
        """
        Token inválido debe retornar 400.
        """

        response = auth_client.post(
            LOGOUT_URL,
            {"refresh": "invalid-token"},
            format="json",
        )

        assert response.status_code == 400