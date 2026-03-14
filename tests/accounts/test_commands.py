"""
Tests for management commands:
    python manage.py create_admin
    python manage.py seed_roles
"""
import pytest
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.contrib.auth.models import Group, Permission


# ─────────────────────────────────────────
# create_admin
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestCreateAdminCommand:

    def test_creates_superuser_from_env(self):
        """Creates a superuser when env vars are set."""
        env = {
            "DJANGO_SUPERUSER_EMAIL": "admin@test.com",
            "DJANGO_SUPERUSER_PASSWORD": "SuperPass123!",
            "DJANGO_SUPERUSER_FIRST_NAME": "Admin",
            "DJANGO_SUPERUSER_LAST_NAME": "Test",
        }
        with patch.dict("os.environ", env):
            out = StringIO()
            call_command("create_admin", stdout=out)

        from apps.accounts.models import User
        user = User.objects.get(email="admin@test.com")
        assert user.is_superuser is True
        assert user.first_name == "Admin"
        assert user.last_name == "Test"
        assert "Superusuario" in out.getvalue() or "admin@test.com" in out.getvalue()

    def test_skips_if_user_already_exists(self):
        """Prints warning and returns if superuser already exists."""
        from apps.accounts.models import User
        User.objects.create_superuser(
            email="existing@test.com",
            password="SuperPass123!",
            first_name="Already",
            last_name="Exists",
        )
        env = {
            "DJANGO_SUPERUSER_EMAIL": "existing@test.com",
            "DJANGO_SUPERUSER_PASSWORD": "SuperPass123!",
        }
        with patch.dict("os.environ", env):
            out = StringIO()
            call_command("create_admin", stdout=out)

        # Should only have 1 user, not duplicate
        assert User.objects.filter(email="existing@test.com").count() == 1
        assert "ya existe" in out.getvalue() or "Omitiendo" in out.getvalue()

    def test_raises_error_without_email(self):
        """Raises CommandError when DJANGO_SUPERUSER_EMAIL is missing."""
        with patch.dict("os.environ", {"DJANGO_SUPERUSER_PASSWORD": "pass"}, clear=False):
            with patch.dict("os.environ", {}, clear=False):
                import os
                os.environ.pop("DJANGO_SUPERUSER_EMAIL", None)
                with pytest.raises(CommandError):
                    call_command("create_admin")

    def test_raises_error_without_password(self):
        """Raises CommandError when DJANGO_SUPERUSER_PASSWORD is missing."""
        import os
        os.environ.pop("DJANGO_SUPERUSER_PASSWORD", None)
        env = {"DJANGO_SUPERUSER_EMAIL": "admin2@test.com"}
        with patch.dict("os.environ", env, clear=False):
            with pytest.raises(CommandError):
                call_command("create_admin")

    def test_uses_default_names_when_not_provided(self):
        """Uses 'Admin' and 'System' as defaults for first/last name."""
        import os
        os.environ.pop("DJANGO_SUPERUSER_FIRST_NAME", None)
        os.environ.pop("DJANGO_SUPERUSER_LAST_NAME", None)
        env = {
            "DJANGO_SUPERUSER_EMAIL": "defaultname@test.com",
            "DJANGO_SUPERUSER_PASSWORD": "SuperPass123!",
        }
        with patch.dict("os.environ", env, clear=False):
            call_command("create_admin")

        from apps.accounts.models import User
        user = User.objects.get(email="defaultname@test.com")
        assert user.first_name == "Admin"
        assert user.last_name == "System"


# ─────────────────────────────────────────
# seed_roles
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestSeedRolesCommand:

    def test_creates_three_groups(self):
        """Creates Admin, Personal and Usuario groups."""
        out = StringIO()
        call_command("seed_roles", stdout=out)

        assert Group.objects.filter(name="Admin").exists()
        assert Group.objects.filter(name="Personal").exists()
        assert Group.objects.filter(name="Usuario").exists()

    def test_idempotent_safe_to_run_twice(self):
        """Running twice does not duplicate groups."""
        call_command("seed_roles")
        call_command("seed_roles")

        assert Group.objects.filter(name="Admin").count() == 1
        assert Group.objects.filter(name="Personal").count() == 1
        assert Group.objects.filter(name="Usuario").count() == 1

    def test_assigns_permissions_to_admin_group(self):
        """Admin group receives user management permissions."""
        call_command("seed_roles")

        admin_group = Group.objects.get(name="Admin")
        perm_codenames = set(
            admin_group.permissions.values_list("codename", flat=True)
        )
        assert "view_user" in perm_codenames
        assert "change_user" in perm_codenames

    def test_assigns_view_permission_to_usuario(self):
        """Usuario group receives view_user permission."""
        call_command("seed_roles")

        usuario_group = Group.objects.get(name="Usuario")
        perm_codenames = set(
            usuario_group.permissions.values_list("codename", flat=True)
        )
        assert "view_user" in perm_codenames

    def test_output_contains_success_message(self):
        """Command prints success message."""
        out = StringIO()
        call_command("seed_roles", stdout=out)
        output = out.getvalue()
        assert "✅" in output or "correctamente" in output

    def test_warns_when_permission_not_found(self):
        """Lines 42-43 — Permission.DoesNotExist prints warning."""
        from unittest.mock import patch
        from django.contrib.auth.models import Permission

        # Patch para que Permission.objects.get siempre lance DoesNotExist
        with patch.object(
            Permission.objects,
            "get",
            side_effect=Permission.DoesNotExist
        ):
            out = StringIO()
            call_command("seed_roles", stdout=out)

        # Debe imprimir advertencia por cada permiso no encontrado
        assert "no encontrado" in out.getvalue()
