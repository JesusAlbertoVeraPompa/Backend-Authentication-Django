"""
admin.py — Configuración del panel de administración Django.

Registra los modelos User, VerificationCode y PasswordResetToken con
configuraciones personalizadas para facilitar la gestión interna.

Correcciones de seguridad aplicadas:
  [FIX-A6] VerificationCodeAdmin: se eliminó el campo "code" de list_display.
           El campo code almacena ahora un hash SHA-256 (64 caracteres) que no
           tiene utilidad operativa en el listado y su exposición innecesaria
           en la interfaz podría facilitar análisis por parte de un admin
           comprometido. El hash sigue disponible en la vista de detalle
           (readonly_fields) para diagnóstico si fuera necesario.
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import PasswordResetToken, User, VerificationCode


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Panel de administración para el modelo User personalizado.

    Hereda de BaseUserAdmin para mantener el manejo seguro de contraseñas
    (formularios de cambio de contraseña, hashing automático, etc.).

    Secciones del formulario de detalle:
      - Credenciales   : id (UUID), email, contraseña hasheada.
      - Información    : nombre, apellido, fecha de nacimiento, teléfono.
      - Estado         : is_active, rol de negocio.
      - Permisos       : is_staff, is_superuser, grupos, permisos individuales.
      - Verificación   : flags email_verified y phone_verified.
      - Fechas         : last_login, created_at, updated_at (solo lectura).
    """

    # Columnas visibles en el listado de usuarios
    list_display = (
        "email",
        "full_name",
        "role",
        "is_active",
        "email_verified",
        "phone_verified",
        "created_at",
    )

    # Filtros laterales en el listado
    list_filter = (
        "role",
        "is_active",
        "email_verified",
        "phone_verified",
        "groups",
    )

    # Campos donde se puede buscar en el listado
    search_fields = ("email", "first_name", "last_name")

    # Orden por defecto: más recientes primero
    ordering = ("-created_at",)

    # Campos de solo lectura en el formulario de detalle
    readonly_fields = ("id", "created_at", "updated_at", "last_login")

    # Secciones del formulario de edición de usuario existente
    fieldsets = (
        ("Credenciales", {
            "fields": ("id", "email", "password"),
        }),
        ("Información personal", {
            "fields": ("first_name", "last_name", "birth_date", "phone_number"),
        }),
        ("Estado y rol", {
            "fields": ("is_active", "role"),
        }),
        ("Verificación", {
            "fields": ("email_verified", "phone_verified"),
            "description": (
                "Modificar estos flags manualmente solo en casos de soporte justificado. "
                "El flujo normal de verificación usa los endpoints de la API."
            ),
        }),
        ("Permisos Django", {
            "fields": ("is_staff", "is_superuser", "groups", "user_permissions"),
            "classes": ("collapse",),  # Colapsado por defecto para reducir ruido visual
        }),
        ("Fechas de auditoría", {
            "fields": ("last_login", "created_at", "updated_at"),
        }),
    )

    # Campos del formulario de creación de nuevo usuario desde el admin
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "first_name",
                    "last_name",
                    "password1",
                    "password2",
                ),
            },
        ),
    )


@admin.register(VerificationCode)
class VerificationCodeAdmin(admin.ModelAdmin):
    """
    Panel de administración para los códigos de verificación SMS.

    Uso principal: diagnóstico y soporte (verificar si un código está activo,
    cuántos intentos lleva, si expiró, etc.).

    [FIX-A6] El campo "code" (hash SHA-256) fue eliminado de list_display.
    Exponerlo en el listado no tiene utilidad operativa y expone el hash
    innecesariamente. Permanece en readonly_fields del detalle para diagnóstico.
    """

    # [FIX-A6] "code" eliminado del listado — ver docstring arriba
    list_display = ("user", "attempts", "is_used", "created_at")

    list_filter  = ("is_used",)
    search_fields = ("user__email",)

    # El hash del código y la fecha de creación son de solo lectura
    readonly_fields = ("code", "created_at")


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    """
    Panel de administración para los tokens de recuperación de contraseña.

    Uso principal: soporte (verificar si un token fue usado, cuándo fue emitido,
    invalidar manualmente un token marcándolo como used si fuera necesario).

    El token UUID es de solo lectura (generado automáticamente, no editable).
    """

    list_display  = ("user", "is_used", "created_at")
    list_filter   = ("is_used",)
    search_fields = ("user__email",)
    readonly_fields = ("token", "created_at")
