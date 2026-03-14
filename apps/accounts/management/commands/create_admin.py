"""
Management command: python manage.py create_admin

Creates a superuser from environment variables (useful for CI/CD pipelines).
"""
import os

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Create a superuser from environment variables (for deployment pipelines)."

    def handle(self, *args, **options):
        from apps.accounts.models import User

        email = os.environ.get("DJANGO_SUPERUSER_EMAIL")
        password = os.environ.get("DJANGO_SUPERUSER_PASSWORD")
        first_name = os.environ.get("DJANGO_SUPERUSER_FIRST_NAME", "Admin")
        last_name = os.environ.get("DJANGO_SUPERUSER_LAST_NAME", "System")

        if not email or not password:
            raise CommandError(
                "Debes definir DJANGO_SUPERUSER_EMAIL y DJANGO_SUPERUSER_PASSWORD."
            )

        if User.objects.filter(email=email).exists():
            self.stdout.write(
                self.style.WARNING(f"El superusuario '{email}' ya existe. Omitiendo.")
            )
            return

        User.objects.create_superuser(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        self.stdout.write(self.style.SUCCESS(f"✅ Superusuario '{email}' creado."))
