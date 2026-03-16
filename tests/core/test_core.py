"""
Tests for core utilities:
    - decorators.py
    - exceptions.py
    - middleware.py
    - permissions.py
    - utils.py
"""
import pytest
from unittest.mock import patch, MagicMock
from django.test import RequestFactory
from rest_framework.test import APIRequestFactory, APIClient
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound


# ─────────────────────────────────────────
# decorators.py
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestRoleRequiredDecorator:

    def _make_request(self, user=None):
        factory = RequestFactory()
        request = factory.get("/")
        request.user = user
        return request

    def test_unauthenticated_returns_401(self):
        from apps.core.decorators import role_required
        from django.contrib.auth.models import AnonymousUser

        @role_required("Admin")
        def my_view(request):
            return MagicMock(status_code=200)

        request = self._make_request(user=AnonymousUser())
        response = my_view(request)
        assert response.status_code == 401

    def test_superuser_bypasses_role_check(self, db):
        from apps.core.decorators import role_required
        from apps.accounts.models import User

        superuser = User.objects.create_superuser(
            email="sup@test.com", password="Pass123!", first_name="S", last_name="U"
        )

        @role_required("Admin")
        def my_view(request):
            return MagicMock(status_code=200)

        request = self._make_request(user=superuser)
        response = my_view(request)
        assert response.status_code == 200

    def test_user_without_role_returns_403(self, make_user):
        from apps.core.decorators import role_required

        user = make_user(email="norole@test.com", role="Usuario")
        user.groups.clear()

        @role_required("Admin")
        def my_view(request):
            return MagicMock(status_code=200)

        request = self._make_request(user=user)
        response = my_view(request)
        assert response.status_code == 403

    def test_user_with_correct_role_passes(self, make_user):
        from apps.core.decorators import role_required
        from django.contrib.auth.models import Group

        user = make_user(email="admin2@test.com", role="Admin")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.set([group])

        @role_required("Admin")
        def my_view(request):
            return MagicMock(status_code=200)

        request = self._make_request(user=user)
        response = my_view(request)
        assert response.status_code == 200

    def test_admin_required_shortcut(self, make_user):
        from apps.core.decorators import admin_required
        from django.contrib.auth.models import Group

        user = make_user(email="admshort@test.com", role="Admin")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.set([group])

        @admin_required
        def my_view(request):
            return MagicMock(status_code=200)

        request = self._make_request(user=user)
        response = my_view(request)
        assert response.status_code == 200

    def test_personal_required_shortcut(self, make_user):
        from apps.core.decorators import personal_required
        from django.contrib.auth.models import Group

        user = make_user(email="pers@test.com", role="Personal")
        group, _ = Group.objects.get_or_create(name="Personal")
        user.groups.set([group])

        @personal_required
        def my_view(request):
            return MagicMock(status_code=200)

        request = self._make_request(user=user)
        response = my_view(request)
        assert response.status_code == 200


# ─────────────────────────────────────────
# exceptions.py
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestCustomExceptionHandler:

    def test_handles_drf_validation_error(self):
        from apps.core.exceptions import custom_exception_handler
        exc = ValidationError({"field": "Este campo es requerido."})
        context = {}
        response = custom_exception_handler(exc, context)
        assert response is not None
        assert response.status_code == 400

    def test_handles_permission_denied(self):
        from apps.core.exceptions import custom_exception_handler
        exc = PermissionDenied("No tienes permiso.")
        context = {}
        response = custom_exception_handler(exc, context)
        assert response is not None
        assert response.status_code == 403

    def test_handles_not_found(self):
        from apps.core.exceptions import custom_exception_handler
        exc = NotFound("No encontrado.")
        context = {}
        response = custom_exception_handler(exc, context)
        assert response is not None
        assert response.status_code == 404

    def test_returns_500_for_unhandled_exception(self):
        from apps.core.exceptions import custom_exception_handler
        exc = ValueError("Error inesperado")
        context = {}
        response = custom_exception_handler(exc, context)
        assert response is not None
        assert response.status_code == 500

    def test_extracts_detail_as_message(self):
        from apps.core.exceptions import custom_exception_handler
        exc = PermissionDenied("Acceso denegado.")
        context = {}
        response = custom_exception_handler(exc, context)
        assert "Acceso denegado" in str(response.data)


# ─────────────────────────────────────────
# middleware.py
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestRoleMiddleware:

    def _get_middleware(self, get_response=None):
        from apps.core.middleware import RoleMiddleware
        if get_response is None:
            get_response = MagicMock(return_value=MagicMock())
        return RoleMiddleware(get_response)

    def test_sets_flags_for_unauthenticated_user(self):
        from django.contrib.auth.models import AnonymousUser
        middleware = self._get_middleware()
        factory = RequestFactory()
        request = factory.get("/")
        request.user = AnonymousUser()
        middleware(request)
        assert request.is_admin is False
        assert request.is_personal is False
        assert request.is_usuario is False

    def test_sets_is_admin_for_superuser(self, db):
        from apps.accounts.models import User
        middleware = self._get_middleware()
        factory = RequestFactory()
        request = factory.get("/")
        superuser = User.objects.create_superuser(
            email="mw_sup@test.com", password="Pass123!", first_name="S", last_name="U"
        )
        request.user = superuser
        middleware(request)
        assert request.is_admin is True
        assert request.is_personal is True
        assert request.is_usuario is True

    def test_sets_is_personal_for_personal_user(self, make_user):
        from django.contrib.auth.models import Group
        middleware = self._get_middleware()
        factory = RequestFactory()
        request = factory.get("/")
        user = make_user(email="mw_pers@test.com", role="Personal")
        group, _ = Group.objects.get_or_create(name="Personal")
        user.groups.set([group])
        request.user = user
        middleware(request)
        assert request.is_admin is False
        assert request.is_personal is True

    def test_sets_is_admin_for_admin_group(self, make_user):
        from django.contrib.auth.models import Group
        middleware = self._get_middleware()
        factory = RequestFactory()
        request = factory.get("/")
        user = make_user(email="mw_adm@test.com", role="Admin")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.set([group])
        request.user = user
        middleware(request)
        assert request.is_admin is True


# ─────────────────────────────────────────
# permissions.py
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestIsAdminPermission:

    def test_allows_superuser(self, db):
        from apps.core.permissions import IsAdmin
        from apps.accounts.models import User
        perm = IsAdmin()
        factory = APIRequestFactory()
        request = factory.get("/")
        user = User.objects.create_superuser(
            email="perm_sup@test.com", password="Pass123!", first_name="S", last_name="U"
        )
        request.user = user
        assert perm.has_permission(request, None) is True

    def test_allows_admin_group_user(self, make_user):
        from apps.core.permissions import IsAdmin
        from django.contrib.auth.models import Group
        perm = IsAdmin()
        factory = APIRequestFactory()
        request = factory.get("/")
        user = make_user(email="perm_adm@test.com", role="Admin")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.set([group])
        request.user = user
        assert perm.has_permission(request, None) is True

    def test_denies_regular_user(self, make_user):
        from apps.core.permissions import IsAdmin
        perm = IsAdmin()
        factory = APIRequestFactory()
        request = factory.get("/")
        user = make_user(email="perm_reg@test.com", role="Usuario")
        user.groups.clear()
        request.user = user
        assert perm.has_permission(request, None) is False


@pytest.mark.django_db
class TestIsPersonalPermission:

    def test_allows_personal_group(self, make_user):
        from apps.core.permissions import IsPersonal
        from django.contrib.auth.models import Group
        perm = IsPersonal()
        factory = APIRequestFactory()
        request = factory.get("/")
        user = make_user(email="perm_pers@test.com", role="Personal")
        group, _ = Group.objects.get_or_create(name="Personal")
        user.groups.set([group])
        request.user = user
        assert perm.has_permission(request, None) is True

    def test_denies_unauthenticated(self):
        from apps.core.permissions import IsPersonal
        from django.contrib.auth.models import AnonymousUser
        perm = IsPersonal()
        factory = APIRequestFactory()
        request = factory.get("/")
        request.user = AnonymousUser()
        assert perm.has_permission(request, None) is False


@pytest.mark.django_db
class TestIsOwnerOrAdminPermission:

    def test_owner_can_access_own_object(self, make_user):
        from apps.core.permissions import IsOwnerOrAdmin
        perm = IsOwnerOrAdmin()
        factory = APIRequestFactory()
        request = factory.get("/")
        user = make_user(email="owner@test.com")
        request.user = user
        assert perm.has_object_permission(request, None, user) is True

    def test_admin_can_access_any_object(self, make_user):
        from apps.core.permissions import IsOwnerOrAdmin
        from django.contrib.auth.models import Group
        perm = IsOwnerOrAdmin()
        factory = APIRequestFactory()
        request = factory.get("/")
        admin = make_user(email="adm_obj@test.com", role="Admin")
        group, _ = Group.objects.get_or_create(name="Admin")
        admin.groups.set([group])
        request.user = admin
        other_user = make_user(email="other_obj@test.com")
        assert perm.has_object_permission(request, None, other_user) is True

    def test_non_owner_cannot_access_object(self, make_user):
        from apps.core.permissions import IsOwnerOrAdmin
        perm = IsOwnerOrAdmin()
        factory = APIRequestFactory()
        request = factory.get("/")
        user = make_user(email="user_a@test.com")
        other = make_user(email="user_b@test.com")
        user.groups.clear()
        request.user = user
        assert perm.has_object_permission(request, None, other) is False

    def test_object_with_user_fk(self, make_user):
        from apps.core.permissions import IsOwnerOrAdmin
        perm = IsOwnerOrAdmin()
        factory = APIRequestFactory()
        request = factory.get("/")
        user = make_user(email="fk_owner@test.com")
        request.user = user
        obj = MagicMock()
        obj.user = user
        assert perm.has_object_permission(request, None, obj) is True

    def test_unauthenticated_denied(self):
        from apps.core.permissions import IsOwnerOrAdmin
        from django.contrib.auth.models import AnonymousUser
        perm = IsOwnerOrAdmin()
        factory = APIRequestFactory()
        request = factory.get("/")
        request.user = AnonymousUser()
        assert perm.has_object_permission(request, None, MagicMock()) is False


# ─────────────────────────────────────────
# utils.py
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestGenerateNumericCode:

    def test_default_length_is_6(self):
        from apps.core.utils import generate_numeric_code
        code = generate_numeric_code()
        assert len(code) == 6

    def test_custom_length(self):
        from apps.core.utils import generate_numeric_code
        code = generate_numeric_code(10)
        assert len(code) == 10

    def test_only_digits(self):
        from apps.core.utils import generate_numeric_code
        code = generate_numeric_code(20)
        assert code.isdigit()


@pytest.mark.django_db
class TestSendSmsVerification:

    @patch("twilio.rest.Client")
    def test_returns_true_on_success(self, mock_client):
        from apps.core.utils import send_sms_verification
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        result = send_sms_verification("+573001234567", "123456")
        assert result is True
        mock_instance.messages.create.assert_called_once()

    @patch("twilio.rest.Client")
    def test_returns_false_on_exception(self, mock_client):
        from apps.core.utils import send_sms_verification
        mock_client.side_effect = Exception("Twilio error")
        result = send_sms_verification("+573001234567", "123456")
        assert result is False


@pytest.mark.django_db
class TestSendPasswordResetEmail:

    # CORRECCIÓN: send_password_reset_email(user, reset_token) requiere dos
    # argumentos. Los tests anteriores solo pasaban `user` → TypeError.
    # Se crea un PasswordResetToken real antes de llamar la función.
    def test_returns_true_on_success(self, make_user):
        from apps.core.utils import send_password_reset_email
        from apps.accounts.models import PasswordResetToken

        user = make_user(email="resetmail@test.com")
        reset_token = PasswordResetToken.objects.create(user=user)
        result = send_password_reset_email(user, reset_token)
        assert result is True

    @patch("apps.core.utils.send_mail", side_effect=Exception("SMTP error"))
    def test_returns_false_on_exception(self, mock_mail, make_user):
        from apps.core.utils import send_password_reset_email
        from apps.accounts.models import PasswordResetToken

        user = make_user(email="failreset@test.com")
        reset_token = PasswordResetToken.objects.create(user=user)
        result = send_password_reset_email(user, reset_token)
        assert result is False


@pytest.mark.django_db
class TestSendWelcomeEmail:

    def test_returns_true_on_success(self, make_user):
        from apps.core.utils import send_welcome_email
        user = make_user(email="welcome@test.com")
        result = send_welcome_email(user)
        assert result is True

    @patch("apps.core.utils.send_mail", side_effect=Exception("SMTP error"))
    def test_returns_false_on_exception(self, mock_mail, make_user):
        from apps.core.utils import send_welcome_email
        user = make_user(email="failwelcome@test.com")
        result = send_welcome_email(user)
        assert result is False


@pytest.mark.django_db
class TestCustomPagination:

    def test_get_paginated_response_schema(self):
        """Line 23 — get_paginated_response_schema returns correct structure."""
        from apps.core.pagination import CustomPageNumberPagination
        paginator = CustomPageNumberPagination()
        schema = {"type": "array", "items": {}}
        result = paginator.get_paginated_response_schema(schema)
        assert result["type"] == "object"
        assert "properties" in result
        assert "results" in result["properties"]["data"]["properties"]
