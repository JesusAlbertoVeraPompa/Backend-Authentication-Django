"""
Custom User model extending AbstractUser, plus SMS verification code model.
"""
import uuid
from datetime import timedelta

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone



class UserManager(BaseUserManager):
    """
    Custom manager that uses email as the unique identifier
    instead of username.
    """                                          # ← cierre del docstring

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("El email es obligatorio.")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("email_verified", True)

        if not extra_fields.get("is_staff"):
            raise ValueError("El superusuario debe tener is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("El superusuario debe tener is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Custom user model.

    - Uses email as the login identifier (username field is removed).
    - Adds: birth_date, phone_number, is_verified, role.
    """

    class Role(models.TextChoices):
        ADMIN = "Admin", "Administrador"
        PERSONAL = "Personal", "Personal"
        USUARIO = "Usuario", "Usuario"

    username = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email = models.EmailField(unique=True, verbose_name="Correo electrónico")
    first_name = models.CharField(max_length=150, verbose_name="Nombre")
    last_name = models.CharField(max_length=150, verbose_name="Apellido")
    birth_date = models.DateField(null=True, blank=True, verbose_name="Fecha de nacimiento")
    phone_number = models.CharField(
        max_length=20, blank=True, null=True, verbose_name="Número de teléfono"
    )

    phone_verified = models.BooleanField(default=False, verbose_name="Teléfono verificado")
    email_verified = models.BooleanField(default=False, verbose_name="Email verificado")
    
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.USUARIO,
        verbose_name="Rol",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = UserManager()

    class Meta:
        verbose_name = "Usuario"
        verbose_name_plural = "Usuarios"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.get_full_name()} <{self.email}>"

    @property
    def full_name(self):
        return self.get_full_name()

    def assign_role(self, role_name: str):
        """Assign a Django group (role) to this user."""
        from django.contrib.auth.models import Group

        group, _ = Group.objects.get_or_create(name=role_name)
        self.groups.clear()
        self.groups.add(group)
        self.role = role_name
        self.save(update_fields=["role"])
        
    @property
    def is_verified(self):
        return self.phone_verified and self.email_verified


# ─────────────────────────────────────────
# SMS VERIFICATION CODE
# ─────────────────────────────────────────

class VerificationCode(models.Model):
    """
    Stores a short-lived SMS verification code for a user.
    """

    EXPIRY_MINUTES = 10

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="verification_codes",
        verbose_name="Usuario",
    )
    code = models.CharField(max_length=10, verbose_name="Código")
    attempts = models.IntegerField(default=0)
    is_used = models.BooleanField(default=False, verbose_name="Usado")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Código de verificación"
        verbose_name_plural = "Códigos de verificación"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Código para {self.user.email} — {'usado' if self.is_used else 'activo'}"

    @property
    def is_expired(self) -> bool:
        expiry = self.created_at + timedelta(minutes=self.EXPIRY_MINUTES)
        return timezone.now() > expiry

    @property
    def is_valid(self) -> bool:
        return not self.is_used and not self.is_expired
    

# ─────────────────────────────────────────
# EMAIL VERIFICATION CODE
# ─────────────────────────────────────────

class EmailVerificationToken(models.Model):
    """
    Token de verificación por email.
    """

    EXPIRY_HOURS = 24

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="email_verifications",
    )

    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def is_expired(self):
        expiry = self.created_at + timedelta(hours=self.EXPIRY_HOURS)
        return timezone.now() > expiry

    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired

# ─────────────────────────────────────────
# PASSWORD RESET TOKEN
# ─────────────────────────────────────────

class PasswordResetToken(models.Model):
    """
    Stores a password-reset token (UUID-based, single-use).
    """

    EXPIRY_HOURS = 24

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="password_reset_tokens",
    )
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Token de recuperación"
        verbose_name_plural = "Tokens de recuperación"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Reset token para {self.user.email}"

    @property
    def is_expired(self) -> bool:
        expiry = self.created_at + timedelta(hours=self.EXPIRY_HOURS)
        return timezone.now() > expiry

    @property
    def is_valid(self) -> bool:
        return not self.is_used and not self.is_expired