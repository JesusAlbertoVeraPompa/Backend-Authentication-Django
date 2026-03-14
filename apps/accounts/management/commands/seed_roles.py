"""
Management command: python manage.py seed_roles

Creates the three base role groups (Admin, Personal, Usuario).
Safe to run multiple times (idempotent).
"""
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Seed default role groups: Admin, Personal, Usuario."

    ROLES = {
        "Admin": [
            # Admin gets all user-management permissions
            "add_user", "change_user", "delete_user", "view_user",
        ],
        "Personal": [
            "view_user", "change_user",
        ],
        "Usuario": [
            "view_user",
        ],
    }

    def handle(self, *args, **options):
        from apps.accounts.models import User

        user_ct = ContentType.objects.get_for_model(User)

        for role_name, perm_codenames in self.ROLES.items():
            group, created = Group.objects.get_or_create(name=role_name)
            status = "creado" if created else "ya existe"
            self.stdout.write(f"  Grupo '{role_name}' {status}.")

            for codename in perm_codenames:
                try:
                    perm = Permission.objects.get(codename=codename, content_type=user_ct)
                    group.permissions.add(perm)
                except Permission.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING(f"    Permiso '{codename}' no encontrado.")
                    )

        self.stdout.write(self.style.SUCCESS("\n✅ Roles creados/actualizados correctamente."))
