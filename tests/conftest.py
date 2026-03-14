"""
Shared pytest fixtures available to all test modules.
"""
import pytest
from django.contrib.auth.models import Group
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken


# ─────────────────────────────────────────
# GROUPS / ROLES
# ─────────────────────────────────────────

@pytest.fixture(autouse=True)
def create_groups(db):
    """Ensure the three role groups exist before every test."""
    for name in ["Admin", "Personal", "Usuario"]:
        Group.objects.get_or_create(name=name)


# ─────────────────────────────────────────
# USER FACTORIES
# ─────────────────────────────────────────

@pytest.fixture
def make_user(db):
    """
    Factory fixture to create users with arbitrary attributes.

    Usage:
        user = make_user(email="x@x.com", role="Admin")
    """
    from apps.accounts.models import User

    def _factory(**kwargs):
        kwargs.setdefault("email", "user@example.com")
        kwargs.setdefault("first_name", "Test")
        kwargs.setdefault("last_name", "User")
        kwargs.setdefault("password", "StrongPass123!")
        kwargs.setdefault("is_verified", True)
        kwargs.setdefault("role", "Usuario")
        password = kwargs.pop("password")
        user = User.objects.create_user(password=password, **kwargs)
        return user

    return _factory


@pytest.fixture
def regular_user(make_user):
    from apps.accounts.models import User
    user = User.objects.create_user(
        email="regular@example.com",
        password="StrongPass123!",
        first_name="Test",
        last_name="User",
        is_verified=False,
        is_active=True,
    )
    return user


@pytest.fixture
def personal_user(make_user):
    user = make_user(email="personal@example.com", role="Personal")
    group, _ = Group.objects.get_or_create(name="Personal")
    user.groups.set([group])
    return user


@pytest.fixture
def admin_user(make_user):
    user = make_user(email="admin@example.com", role="Admin")
    group, _ = Group.objects.get_or_create(name="Admin")
    user.groups.set([group])
    return user


@pytest.fixture
def superuser(db):
    from apps.accounts.models import User
    return User.objects.create_superuser(
        email="super@example.com",
        password="SuperPass123!",
        first_name="Super",
        last_name="User",
    )


# ─────────────────────────────────────────
# API CLIENTS
# ─────────────────────────────────────────

@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def auth_client(api_client, regular_user):
    """Authenticated client for a regular user."""
    refresh = RefreshToken.for_user(regular_user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    api_client._user = regular_user
    return api_client


@pytest.fixture
def personal_client(api_client, personal_user):
    """Authenticated client for a Personal-role user."""
    refresh = RefreshToken.for_user(personal_user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    api_client._user = personal_user
    return api_client


@pytest.fixture
def admin_client(api_client, admin_user):
    """Authenticated client for an Admin-role user."""
    refresh = RefreshToken.for_user(admin_user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    api_client._user = admin_user
    return api_client
