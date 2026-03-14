"""
Initial migration for the accounts app.
Creates: User, VerificationCode, PasswordResetToken tables.

Run with: python manage.py migrate
"""
import uuid

import django.contrib.auth.models
import django.contrib.auth.validators
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                ("password", models.CharField(max_length=128, verbose_name="password")),
                ("last_login", models.DateTimeField(blank=True, null=True, verbose_name="last login")),
                ("is_superuser", models.BooleanField(
                    default=False,
                    help_text="Designates that this user has all permissions without explicitly assigning them.",
                    verbose_name="superuser status",
                )),
                ("is_staff", models.BooleanField(
                    default=False,
                    help_text="Designates whether the user can log into this admin site.",
                    verbose_name="staff status",
                )),
                ("is_active", models.BooleanField(
                    default=True,
                    help_text="Designates whether this user should be treated as active.",
                    verbose_name="active",
                )),
                ("date_joined", models.DateTimeField(default=django.utils.timezone.now, verbose_name="date joined")),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("email", models.EmailField(max_length=254, unique=True, verbose_name="Correo electrónico")),
                ("first_name", models.CharField(max_length=150, verbose_name="Nombre")),
                ("last_name", models.CharField(max_length=150, verbose_name="Apellido")),
                ("birth_date", models.DateField(blank=True, null=True, verbose_name="Fecha de nacimiento")),
                ("phone_number", models.CharField(blank=True, max_length=20, null=True, verbose_name="Número de teléfono")),
                ("is_verified", models.BooleanField(default=False, verbose_name="Verificado")),
                ("role", models.CharField(
                    choices=[("Admin", "Administrador"), ("Personal", "Personal"), ("Usuario", "Usuario")],
                    default="Usuario",
                    max_length=20,
                    verbose_name="Rol",
                )),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("groups", models.ManyToManyField(
                    blank=True,
                    help_text="The groups this user belongs to.",
                    related_name="user_set",
                    related_query_name="user",
                    to="auth.group",
                    verbose_name="groups",
                )),
                ("user_permissions", models.ManyToManyField(
                    blank=True,
                    help_text="Specific permissions for this user.",
                    related_name="user_set",
                    related_query_name="user",
                    to="auth.permission",
                    verbose_name="user permissions",
                )),
            ],
            options={
                "verbose_name": "Usuario",
                "verbose_name_plural": "Usuarios",
                "ordering": ["-created_at"],
            },
            managers=[
                ("objects", django.contrib.auth.models.AbstractBaseUser),
            ],
        ),
        migrations.CreateModel(
            name="VerificationCode",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(max_length=10, verbose_name="Código")),
                ("is_used", models.BooleanField(default=False, verbose_name="Usado")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("user", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="verification_codes",
                    to=settings.AUTH_USER_MODEL,
                    verbose_name="Usuario",
                )),
            ],
            options={
                "verbose_name": "Código de verificación",
                "verbose_name_plural": "Códigos de verificación",
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="PasswordResetToken",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("token", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ("is_used", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("user", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="password_reset_tokens",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                "verbose_name": "Token de recuperación",
                "verbose_name_plural": "Tokens de recuperación",
                "ordering": ["-created_at"],
            },
        ),
    ]
