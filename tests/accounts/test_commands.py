"""
Tests for management commands:

    python manage.py create_admin
    python manage.py seed_roles

Estos tests verifican:

1. Creación automática de superusuario desde variables de entorno
2. Que el comando no cree duplicados
3. Que los grupos de roles se creen correctamente
4. Que los permisos se asignen correctamente
"""

import pytest

# StringIO se usa para capturar el output del comando
from io import StringIO

# patch permite modificar variables de entorno o funciones
from unittest.mock import patch

# Permite ejecutar management commands dentro de tests
from django.core.management import call_command

# Error estándar que lanzan los comandos Django
from django.core.management.base import CommandError

# Modelos de autenticación de Django
from django.contrib.auth.models import Group, Permission


# ─────────────────────────────────────────
# TESTS create_admin
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestCreateAdminCommand:
    """
    Tests para el comando:

        python manage.py create_admin
    """

    def test_creates_superuser_from_env(self):
        """
        Verifica que el comando cree un superusuario
        usando variables de entorno.
        """

        env = {
            "DJANGO_SUPERUSER_EMAIL": "admin@test.com",
            "DJANGO_SUPERUSER_PASSWORD": "SuperPass123!",
            "DJANGO_SUPERUSER_FIRST_NAME": "Admin",
            "DJANGO_SUPERUSER_LAST_NAME": "Test",
        }

        # Patch temporal de variables de entorno
        with patch.dict("os.environ", env):

            # Captura del output del comando
            out = StringIO()

            call_command("create_admin", stdout=out)

        from apps.accounts.models import User

        user = User.objects.get(email="admin@test.com")

        assert user.is_superuser is True
        assert user.first_name == "Admin"
        assert user.last_name == "Test"

        # Verifica que el comando imprimió algo útil
        assert "Superusuario" in out.getvalue() or "admin@test.com" in out.getvalue()


    def test_skips_if_user_already_exists(self):
        """
        Si el usuario ya existe el comando no debe duplicarlo.
        """

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

        # Debe existir solo un usuario
        assert User.objects.filter(email="existing@test.com").count() == 1

        # El comando debe mostrar advertencia
        assert "ya existe" in out.getvalue() or "Omitiendo" in out.getvalue()


    def test_raises_error_without_email(self):
        """
        Si falta DJANGO_SUPERUSER_EMAIL
        el comando debe lanzar CommandError.
        """

        with patch.dict("os.environ", {"DJANGO_SUPERUSER_PASSWORD": "pass"}, clear=False):

            with patch.dict("os.environ", {}, clear=False):

                import os
                os.environ.pop("DJANGO_SUPERUSER_EMAIL", None)

                with pytest.raises(CommandError):
                    call_command("create_admin")


    def test_raises_error_without_password(self):
        """
        Si falta DJANGO_SUPERUSER_PASSWORD
        el comando debe lanzar CommandError.
        """

        import os
        os.environ.pop("DJANGO_SUPERUSER_PASSWORD", None)

        env = {"DJANGO_SUPERUSER_EMAIL": "admin2@test.com"}

        with patch.dict("os.environ", env, clear=False):

            with pytest.raises(CommandError):
                call_command("create_admin")


    def test_uses_default_names_when_not_provided(self):
        """
        Si no se proporcionan nombres
        se deben usar valores por defecto.
        """

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
# TESTS seed_roles
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestSeedRolesCommand:
    """
    Tests para el comando:

        python manage.py seed_roles

    Este comando crea los grupos base del sistema.
    """

    def test_creates_three_groups(self):
        """
        Verifica que el comando cree los tres grupos base.
        """

        out = StringIO()

        call_command("seed_roles", stdout=out)

        assert Group.objects.filter(name="Admin").exists()
        assert Group.objects.filter(name="Personal").exists()
        assert Group.objects.filter(name="Usuario").exists()


    def test_idempotent_safe_to_run_twice(self):
        """
        El comando debe ser idempotente:
        ejecutarlo varias veces no debe crear duplicados.
        """

        call_command("seed_roles")
        call_command("seed_roles")

        assert Group.objects.filter(name="Admin").count() == 1
        assert Group.objects.filter(name="Personal").count() == 1
        assert Group.objects.filter(name="Usuario").count() == 1


    def test_assigns_permissions_to_admin_group(self):
        """
        El grupo Admin debe tener permisos de gestión de usuarios.
        """

        call_command("seed_roles")

        admin_group = Group.objects.get(name="Admin")

        perm_codenames = set(
            admin_group.permissions.values_list("codename", flat=True)
        )

        assert "view_user" in perm_codenames
        assert "change_user" in perm_codenames


    def test_assigns_view_permission_to_usuario(self):
        """
        El grupo Usuario solo debe tener permiso de lectura.
        """

        call_command("seed_roles")

        usuario_group = Group.objects.get(name="Usuario")

        perm_codenames = set(
            usuario_group.permissions.values_list("codename", flat=True)
        )

        assert "view_user" in perm_codenames


    def test_output_contains_success_message(self):
        """
        El comando debe mostrar un mensaje de éxito.
        """

        out = StringIO()

        call_command("seed_roles", stdout=out)

        output = out.getvalue()

        assert "✅" in output or "correctamente" in output


    def test_warns_when_permission_not_found(self):
        """
        Si un permiso no existe el comando debe imprimir advertencia.
        """

        # Patch para que Permission.objects.get siempre falle
        with patch.object(
            Permission.objects,
            "get",
            side_effect=Permission.DoesNotExist
        ):

            out = StringIO()

            call_command("seed_roles", stdout=out)

        # Debe imprimir advertencia
        assert "no encontrado" in out.getvalue()