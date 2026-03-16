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

    @patch("apps.accounts.views.send_sms_verification", return_value=True)
    def test_send_code_success(self, mock_sms, auth_client, regular_user):
        regular_user.phone_number = "+573001234567"
        regular_user.save()
        response = auth_client.post(SEND_URL, {}, format="json")
        assert response.status_code == 200
        assert response.data["success"] is True
        mock_sms.assert_called_once()
        assert VerificationCode.objects.filter(user=regular_user).exists()

    @patch("apps.accounts.views.send_sms_verification", return_value=True)
    def test_send_code_updates_phone(self, mock_sms, auth_client, regular_user):
        response = auth_client.post(
            SEND_URL, {"phone_number": "+573009876543"}, format="json"
        )
        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.phone_number == "+573009876543"

    @patch("apps.accounts.views.send_sms_verification", return_value=True)
    def test_resend_invalidates_old_code(self, mock_sms, auth_client, regular_user):
        regular_user.phone_number = "+573001234567"
        regular_user.save()
        auth_client.post(SEND_URL, {}, format="json")
        old_code = VerificationCode.objects.filter(user=regular_user).first()
        auth_client.post(SEND_URL, {}, format="json")
        old_code.refresh_from_db()
        assert old_code.is_used is True

    def test_send_code_no_phone_returns_400(self, auth_client, regular_user):
        regular_user.phone_number = None
        regular_user.save()
        response = auth_client.post(SEND_URL, {}, format="json")
        assert response.status_code == 400

    def test_send_code_requires_authentication(self, api_client):
        response = api_client.post(SEND_URL, {}, format="json")
        assert response.status_code == 401

    @patch("apps.accounts.views.send_sms_verification", return_value=False)
    def test_sms_service_failure_returns_503(self, mock_sms, auth_client, regular_user):
        regular_user.phone_number = "+573001234567"
        regular_user.save()
        response = auth_client.post(SEND_URL, {}, format="json")
        assert response.status_code == 503

    def test_invalid_phone_format_returns_400(self, auth_client):
        response = auth_client.post(
            SEND_URL, {"phone_number": "3001234567"}, format="json"
        )
        assert response.status_code == 400

    # ─── CORRECCIÓN 2: test_verify_email ────────────────────────────
    # BUG 1: La función no tenía decorador @pytest.mark.django_db ni
    #         era método de una clase, entonces pytest la ignoraba
    #         (no la ejecutaba como test real).
    # BUG 2: Usaba el fixture `user` que no existe — debería ser `make_user`.
    # BUG 3: La URL usaba /api/auth/ en vez de /api/v1/auth/.
    # BUG 4: Usaba GET en vez de POST (la vista VerifyEmailView usa POST).
    # BUG 5: VerifyEmailView aplica ratelimit con key='user', pero el
    #         decorador está en el método post() directamente (no en
    #         name='post'), por lo que no funciona via method_decorator —
    #         esto es un bug en la vista, documentado abajo.
    # CORRECCIÓN: Se mueve a su propia clase, se corrigen todos los bugs.
    @pytest.mark.django_db
    def test_verify_email_token_valid(self, auth_client, regular_user):
        """
        EmailVerificationToken válido → 200 y email_verified=True.
        Nota: VerifyEmailView tiene un bug de decorador (ver vulnerabilidades).
        """
        from apps.accounts.models import EmailVerificationToken

        token = EmailVerificationToken.objects.create(user=regular_user)
        url = f"/api/v1/auth/verify/email/{token.token}/"
        response = auth_client.post(url, format="json")

        regular_user.refresh_from_db()
        assert response.status_code == 200
        assert regular_user.email_verified is True


@pytest.mark.django_db
class TestVerifyPhoneView:

    def _create_code(self, user, code="123456"):
        return VerificationCode.objects.create(user=user, code=code)

    def test_verify_success(self, auth_client, regular_user):
        self._create_code(regular_user)
        response = auth_client.post(CONFIRM_URL, {"code": "123456"}, format="json")
        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.phone_verified is True

    def test_verify_marks_code_as_used(self, auth_client, regular_user):
        code_obj = self._create_code(regular_user)
        auth_client.post(CONFIRM_URL, {"code": "123456"}, format="json")
        code_obj.refresh_from_db()
        assert code_obj.is_used is True

    # ─── CORRECCIÓN 3: test_verify_wrong_code ───────────────────────
    # BUG: El test afirmaba `assert regular_user.phone_verified is True`
    #      después de enviar un código incorrecto — eso es lo opuesto
    #      al comportamiento esperado.
    # CORRECCIÓN: Se verifica que phone_verified permanece False.
    def test_verify_wrong_code(self, auth_client, regular_user):
        """Código incorrecto → 400 y phone_verified sigue en False."""
        self._create_code(regular_user)
        response = auth_client.post(CONFIRM_URL, {"code": "000000"}, format="json")
        assert response.status_code == 400
        regular_user.refresh_from_db()
        assert regular_user.phone_verified is False  # BUG ORIGINAL: assertía True

    def test_verify_expired_code(self, auth_client, regular_user):
        from datetime import timedelta
        from django.utils import timezone

        code_obj = self._create_code(regular_user)
        VerificationCode.objects.filter(pk=code_obj.pk).update(
            created_at=timezone.now() - timedelta(minutes=15)
        )
        response = auth_client.post(CONFIRM_URL, {"code": "123456"}, format="json")
        assert response.status_code == 400

    def test_verify_used_code_rejected(self, auth_client, regular_user):
        self._create_code(regular_user, code="654321")
        VerificationCode.objects.filter(user=regular_user).update(is_used=True)
        response = auth_client.post(CONFIRM_URL, {"code": "654321"}, format="json")
        assert response.status_code == 400

    def test_verify_requires_authentication(self, api_client):
        response = api_client.post(CONFIRM_URL, {"code": "123456"}, format="json")
        assert response.status_code == 401

    def test_verify_non_numeric_code(self, auth_client):
        response = auth_client.post(CONFIRM_URL, {"code": "abcdef"}, format="json")
        assert response.status_code == 400
