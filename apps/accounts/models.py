"""
models.py — Modelos de autenticación y gestión de usuarios.

Contenido:
  - UserManager            : Manager personalizado que usa email como identificador único.
  - User                   : Modelo de usuario extendido (sin username, basado en email).
  - VerificationCode       : Código SMS de verificación de teléfono (6 dígitos, hash SHA-256).
  - EmailVerificationToken : Token UUID para verificar correo electrónico.
  - PasswordResetToken     : Token UUID de un solo uso para recuperar contraseña.

Correcciones de seguridad aplicadas:
  [FIX-01] VerificationCode.code ahora almacena el hash SHA-256 del código
           en lugar del valor en texto plano. Esto protege los códigos activos
           si la base de datos es comprometida.
  [FIX-02] Se añade VerificationCode.make_hash() para centralizar el hashing
           y usarlo tanto al crear como al comparar códigos (en views.py).
"""

import hashlib
import uuid
from datetime import timedelta

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone


# ─────────────────────────────────────────
# USER MANAGER
# ─────────────────────────────────────────

class UserManager(BaseUserManager):
    """
    Manager personalizado que usa email como identificador único
    en lugar de username.

    Métodos públicos:
      create_user      — Crea un usuario normal activo.
      create_superuser — Crea un superusuario con is_staff e is_superuser=True.
    """

    def create_user(self, email, password=None, **extra_fields):
        """
        Crea y guarda un usuario con el email y la contraseña dados.
        El email es normalizado (minúsculas en el dominio) antes de guardar.
        La contraseña se almacena hasheada mediante Django (PBKDF2 por defecto).
        """
        if not email:
            raise ValueError("El email es obligatorio.")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Crea y guarda un superusuario.
        Garantiza is_staff=True, is_superuser=True y email_verified=True
        para que pueda autenticarse sin restricciones.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("email_verified", True)

        if not extra_fields.get("is_staff"):
            raise ValueError("El superusuario debe tener is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("El superusuario debe tener is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


# ─────────────────────────────────────────
# USER MODEL
# ─────────────────────────────────────────

class User(AbstractUser):
    """
    Modelo de usuario personalizado.

    Diferencias con AbstractUser por defecto:
      - Se elimina el campo username; el email es el identificador de login.
      - Se añaden: birth_date, phone_number, phone_verified, email_verified, role.
      - La PK es un UUID v4 para evitar enumeración por ID secuencial.

    Propiedad is_verified:
      Retorna True únicamente cuando AMBAS verificaciones (email y teléfono)
      están completadas. Es usada en el JWT payload y en permisos de acceso.
    """

    class Role(models.TextChoices):
        """Roles disponibles para los usuarios del sistema."""
        ADMIN    = "Admin",    "Administrador"
        PERSONAL = "Personal", "Personal"
        USUARIO  = "Usuario",  "Usuario"

    # Se elimina el campo username heredado de AbstractUser
    username = None

    # Identificador principal: UUID v4 no editable (evita enumeración por ID secuencial)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Datos de identidad del usuario
    email        = models.EmailField(unique=True, verbose_name="Correo electrónico")
    first_name   = models.CharField(max_length=150, verbose_name="Nombre")
    last_name    = models.CharField(max_length=150, verbose_name="Apellido")
    birth_date   = models.DateField(null=True, blank=True, verbose_name="Fecha de nacimiento")
    phone_number = models.CharField(
        max_length=20, blank=True, null=True, verbose_name="Número de teléfono"
    )

    # Flags de verificación — ambos deben ser True para que is_verified sea True
    phone_verified = models.BooleanField(default=False, verbose_name="Teléfono verificado")
    email_verified = models.BooleanField(default=False, verbose_name="Email verificado")

    # Rol de negocio: separa los permisos de alto nivel de los grupos de Django
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.USUARIO,
        verbose_name="Rol",
    )

    # Auditoría de creación y última modificación
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # El campo de login es el email, NO el username
    USERNAME_FIELD  = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = UserManager()

    class Meta:
        verbose_name        = "Usuario"
        verbose_name_plural = "Usuarios"
        ordering            = ["-created_at"]

    def __str__(self):
        return f"{self.get_full_name()} <{self.email}>"

    @property
    def full_name(self):
        """Nombre completo del usuario (first_name + last_name)."""
        return self.get_full_name()

    def assign_role(self, role_name: str):
        """
        Asigna un rol (grupo Django) al usuario.
        Primero limpia los grupos actuales para garantizar un único rol activo.
        También actualiza el campo role del modelo para mantener consistencia.
        """
        from django.contrib.auth.models import Group
        group, _ = Group.objects.get_or_create(name=role_name)
        self.groups.clear()    # Elimina membresías de grupos previos
        self.groups.add(group) # Agrega el nuevo grupo/rol
        self.role = role_name
        self.save(update_fields=["role"])

    @property
    def is_verified(self):
        """
        True solo cuando el usuario ha verificado TANTO su email COMO su teléfono.
        Se expone en el JWT payload para que el frontend pueda tomar decisiones
        de UX sin necesidad de consultar la API en cada petición.
        """
        return self.phone_verified and self.email_verified


# ─────────────────────────────────────────
# SMS VERIFICATION CODE
# ─────────────────────────────────────────

class VerificationCode(models.Model):
    """
    Código numérico de 6 dígitos para verificar el teléfono del usuario vía SMS.

    Ciclo de vida:
      1. Se genera el código en texto plano con generate_numeric_code(6) en la vista.
      2. Se hashea con SHA-256 (make_hash) ANTES de guardarse en la base de datos.
      3. Al verificar, el código ingresado por el usuario también se hashea
         y se compara con hmac.compare_digest (protege contra timing attacks).
      4. Si el código es correcto, se marca is_used=True y phone_verified=True.

    [FIX-01] CORRECCIÓN DE SEGURIDAD — Almacenamiento hasheado:
      Antes: el campo `code` guardaba el código en texto plano (ej: "482031").
      Ahora: `code` guarda el hash SHA-256 hexadecimal (64 caracteres).
      Beneficio: si la BD es comprometida, los códigos activos no son directamente
      utilizables. Aunque el espacio es pequeño (1M combinaciones), la ventana
      de expiración de 10 minutos hace la explotación poco práctica.

    Control de intentos:
      - Máximo 5 intentos por código (campo attempts).
      - El contador se incrementa ANTES de validar (ver VerifyPhoneView).
      - Al superar el límite, se requiere solicitar un nuevo código.

    Expiración:
      - El código expira a los EXPIRY_MINUTES=10 minutos de su creación.
    """

    EXPIRY_MINUTES = 10  # Tiempo de vida del código (minutos)

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="verification_codes",
        verbose_name="Usuario",
    )

    # [FIX-01] Almacena el hash SHA-256 del código, NO el valor en texto plano.
    # max_length=64 corresponde a la longitud de un hash SHA-256 en hexadecimal.
    code = models.CharField(max_length=64, verbose_name="Hash del código")

    # Número de intentos de verificación realizados con este código
    attempts = models.IntegerField(default=0)

    # True cuando el código ya fue utilizado exitosamente
    is_used = models.BooleanField(default=False, verbose_name="Usado")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name        = "Código de verificación"
        verbose_name_plural = "Códigos de verificación"
        ordering            = ["-created_at"]

    def __str__(self):
        return f"Código para {self.user.email} — {'usado' if self.is_used else 'activo'}"

    @staticmethod
    def make_hash(plain_code: str) -> str:
        """
        Genera y retorna el hash SHA-256 (hexadecimal) de un código en texto plano.

        Se usa en dos momentos del ciclo de vida:
          1. Al CREAR: hashear el código antes de guardarlo en la BD.
          2. Al VERIFICAR: hashear el código ingresado por el usuario para
             compararlo con el hash almacenado.

        La centralización en este método garantiza que siempre se use el mismo
        algoritmo y encoding, evitando inconsistencias.

        Ejemplo:
            hashed = VerificationCode.make_hash("123456")
            # → "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
        """
        return hashlib.sha256(plain_code.encode("utf-8")).hexdigest()

    @property
    def is_expired(self) -> bool:
        """
        True si han pasado más de EXPIRY_MINUTES minutos desde la creación del código.
        Compara contra la hora actual con soporte de zona horaria (UTC).
        """
        expiry = self.created_at + timedelta(minutes=self.EXPIRY_MINUTES)
        return timezone.now() > expiry

    @property
    def is_valid(self) -> bool:
        """
        True si el código NO ha sido usado y NO ha expirado.
        Nota: la verificación de intentos (max 5) se maneja en la vista
        para poder retornar mensajes de error más descriptivos al usuario.
        """
        return not self.is_used and not self.is_expired


# ─────────────────────────────────────────
# EMAIL VERIFICATION TOKEN
# ─────────────────────────────────────────

class EmailVerificationToken(models.Model):
    """
    Token UUID para verificar la dirección de correo electrónico del usuario.

    Ciclo de vida:
      1. Se crea al registrar el usuario (RegisterView).
         Los tokens anteriores no usados se invalidan antes de crear uno nuevo.
      2. Se envía al email del usuario como enlace: /verify-email/<token>/
      3. El usuario hace clic en el enlace → VerifyEmailView:
           - Marca email_verified=True en el usuario.
           - Marca is_used=True en el token (uso único).
      4. El token expira en EXPIRY_HOURS=24 horas si no es utilizado.

    Seguridad:
      - UUID v4 (122 bits de entropía): prácticamente imposible de adivinar.
      - Expiración de 24 horas.
      - Uso único (is_used=True después de ser consumido).
      - Tokens anteriores se invalidan antes de crear uno nuevo
        (corrige la vulnerabilidad de múltiples tokens activos por usuario).
    """

    EXPIRY_HOURS = 24  # Tiempo de vida del token (horas)

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="email_verifications",
    )

    # UUID v4 único — es el token que viaja en el enlace de verificación
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    # True cuando el token ya fue utilizado para verificar el email
    is_used = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name        = "Token de verificación de email"
        verbose_name_plural = "Tokens de verificación de email"
        ordering            = ["-created_at"]

    def __str__(self):
        return f"EmailToken para {self.user.email} — {'usado' if self.is_used else 'activo'}"

    @property
    def is_expired(self) -> bool:
        """True si han pasado más de EXPIRY_HOURS horas desde la creación del token."""
        expiry = self.created_at + timedelta(hours=self.EXPIRY_HOURS)
        return timezone.now() > expiry

    @property
    def is_valid(self) -> bool:
        """True si el token NO ha sido usado y NO ha expirado."""
        return not self.is_used and not self.is_expired


# ─────────────────────────────────────────
# PASSWORD RESET TOKEN
# ─────────────────────────────────────────

class PasswordResetToken(models.Model):
    """
    Token UUID de un solo uso para restablecer la contraseña del usuario.

    Ciclo de vida:
      1. Se crea en PasswordResetRequestView cuando el usuario solicita el reset.
         Tokens anteriores no usados se invalidan antes de crear el nuevo.
      2. Se envía al email del usuario como enlace: /password/reset/confirm/
      3. El usuario lo usa en PasswordResetConfirmView junto con la nueva contraseña.
      4. Al confirmar exitosamente:
           - El token se marca is_used=True.
           - Todos los refresh tokens del usuario se invalidan
             (logout forzado en todos los dispositivos).

    Seguridad:
      - UUID v4 (122 bits de entropía): prácticamente imposible de adivinar.
      - Expiración de 24 horas.
      - Uso único (is_used=True después de ser consumido).
      - El endpoint de confirmación tiene rate limiting (ver PasswordResetConfirmView,
        decorador @method_decorator ratelimit en views.py — [FIX-03]).
    """

    EXPIRY_HOURS = 24  # Tiempo de vida del token (horas)

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="password_reset_tokens",
    )

    # UUID v4 único — es el token que viaja en el enlace de reset
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    # True cuando el token ya fue utilizado para restablecer la contraseña
    is_used = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name        = "Token de recuperación"
        verbose_name_plural = "Tokens de recuperación"
        ordering            = ["-created_at"]

    def __str__(self):
        return f"Reset token para {self.user.email}"

    @property
    def is_expired(self) -> bool:
        """True si han pasado más de EXPIRY_HOURS horas desde la creación del token."""
        expiry = self.created_at + timedelta(hours=self.EXPIRY_HOURS)
        return timezone.now() > expiry

    @property
    def is_valid(self) -> bool:
        """True si el token NO ha sido usado y NO ha expirado."""
        return not self.is_used and not self.is_expired
