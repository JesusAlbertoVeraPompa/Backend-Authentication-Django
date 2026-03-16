"""
Shared pytest fixtures available to all test modules.
"""
import pytest
from django.contrib.auth.models import Group
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken


# ─── GROUPS / ROLES ──────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def create_groups(db):
    """Ensure the three role groups exist before every test."""
    for name in ["Admin", "Personal", "Usuario"]:
        Group.objects.get_or_create(name=name)


# ─── USER FACTORIES ───────────────────────────────────────────────────────────

@pytest.fixture
def make_user(db):
    """
    Factory fixture to create users with arbitrary attributes.

    Usage:
        user = make_user(email="x@x.com", role="Admin")
    """
    from apps.accounts.models import User

    # ─── CORRECCIÓN 4: make_user pasaba is_verified=True como kwarg ──
    # BUG: User.objects.create_user(**kwargs) recibía is_verified=True
    #      pero `is_verified` es una @property calculada (no un campo de BD),
    #      por lo que Django lanzaba TypeError al intentar asignarlo en
    #      Model.__init__. Fallaba silenciosamente en algunos entornos o
    #      rompía tests que usaban make_user() con defaults.
    # CORRECCIÓN: Se elimina is_verified de los defaults del factory.
    #             Si un test necesita un usuario verificado, debe setear
    #             phone_verified=True y email_verified=True explícitamente.
    def _factory(**kwargs):
        kwargs.setdefault("email", "user@example.com")
        kwargs.setdefault("first_name", "Test")
        kwargs.setdefault("last_name", "User")
        kwargs.setdefault("role", "Usuario")
        is_verified = kwargs.pop("is_verified", None)  # extraer antes
        password = kwargs.pop("password", "StrongPass123!")
        user = User.objects.create_user(password=password, **kwargs)
        if is_verified is True:
            user.phone_verified = True
            user.email_verified = True
            user.save(update_fields=["phone_verified", "email_verified"])
        elif is_verified is False:
            user.phone_verified = False
            user.email_verified = False
            user.save(update_fields=["phone_verified", "email_verified"])
        return user

    return _factory


@pytest.fixture
def regular_user(db):
    from apps.accounts.models import User
    user = User.objects.create_user(
        email="regular@example.com",
        password="StrongPass123!",
        first_name="Test",
        last_name="User",
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


# ─── API CLIENTS ──────────────────────────────────────────────────────────────

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
