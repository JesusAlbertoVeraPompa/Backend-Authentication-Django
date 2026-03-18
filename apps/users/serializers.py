"""
serializers.py — Serializadores para la gestión de usuarios (CRUD, roles, perfil).

Contenido:
  - UserDetailSerializer      : Vista completa del usuario (perfil y lecturas de admin).
  - UserListSerializer        : Vista ligera para listados paginados.
  - UserUpdateSerializer      : Actualización del propio perfil (usuario autenticado).
  - AdminUserUpdateSerializer : Actualización por admin (incluye role e is_active).
  - AssignRoleSerializer      : Asignación de rol a un usuario.

Correcciones de seguridad aplicadas:
  [FIX-A5] UserUpdateSerializer.update(): al cambiar el phone_number, se resetea
           phone_verified=False para forzar la re-verificación del nuevo número.
           Antes, el usuario quedaba marcado como verificado con un número que
           nunca verificó, evadiendo el flujo de verificación SMS y manteniendo
           is_verified=True con datos no confirmados.
"""
from django.contrib.auth.models import Group
from rest_framework import serializers
import re

from apps.accounts.models import User


class UserDetailSerializer(serializers.ModelSerializer):
    """
    Serializer completo del usuario.
    Usado en: GET /users/me/, GET /users/{id}/, respuestas tras PATCH.

    Campos de solo lectura: id, email, is_verified, created_at, updated_at.
    El campo groups retorna los nombres de los grupos Django del usuario.
    El campo full_name es calculado (first_name + last_name).
    """

    full_name = serializers.SerializerMethodField()
    groups    = serializers.SerializerMethodField()

    class Meta:
        model  = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "birth_date",
            "phone_number",
            "role",
            "is_verified",
            "is_active",
            "groups",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "email", "is_verified", "created_at", "updated_at"]

    def get_full_name(self, obj):
        """Retorna first_name + last_name concatenados."""
        return obj.full_name

    def get_groups(self, obj):
        """Retorna la lista de nombres de grupos Django del usuario."""
        return list(obj.groups.values_list("name", flat=True))


class UserListSerializer(serializers.ModelSerializer):
    """
    Serializer ligero para listados paginados.
    Expone solo los campos necesarios para mostrar una fila en una tabla de usuarios.
    Usado en: GET /users/
    """

    full_name = serializers.SerializerMethodField()

    class Meta:
        model  = User
        fields = ["id", "email", "full_name", "role", "is_verified", "is_active", "created_at"]

    def get_full_name(self, obj):
        """Retorna first_name + last_name concatenados."""
        return obj.full_name


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer para que el propio usuario actualice su perfil.
    Usado en: PATCH /users/me/

    Campos actualizables: first_name, last_name, birth_date, phone_number.
    El email y la contraseña se gestionan en endpoints separados.

    [FIX-A5] CORRECCIÓN DE SEGURIDAD — Reset de phone_verified:
      Si el usuario cambia su phone_number, el campo phone_verified se resetea
      automáticamente a False. Esto obliga a verificar el nuevo número mediante
      el flujo SMS (/verify/send/ → /verify/confirm/).
      Sin esta corrección, el usuario quedaría marcado como verificado con un
      número diferente al que validó originalmente, evadiendo el flujo de
      verificación y manteniendo is_verified=True con datos no confirmados.
    """

    class Meta:
        model  = User
        fields = ["first_name", "last_name", "birth_date", "phone_number"]

    def validate_phone_number(self, value):
        """
        Valida que el número de teléfono tenga formato E.164 internacional.
        Formato esperado: + seguido de 8 a 15 dígitos (ej: +573001234567).
        """
        if not value:
            return value
        pattern = r'^\+[1-9]\d{7,14}$'  # E.164 internacional
        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Formato inválido. Usa formato internacional: +573001234567 (8-15 dígitos)"
            )
        return value

    def update(self, instance, validated_data):
        """
        Actualiza el perfil del usuario.

        [FIX-A5] Si el phone_number cambia, resetea phone_verified=False.
        El usuario deberá verificar el nuevo número con el flujo SMS.
        """
        new_phone = validated_data.get("phone_number")

        # Detecta si el teléfono realmente cambió (comparando con el valor actual)
        phone_changed = (
            new_phone is not None
            and new_phone != instance.phone_number
        )

        # Actualiza los campos con el comportamiento estándar del padre
        instance = super().update(instance, validated_data)

        # [FIX-A5] Si el número cambió, invalida la verificación anterior.
        # El usuario deberá re-verificar el nuevo número vía SMS.
        if phone_changed:
            instance.phone_verified = False
            instance.save(update_fields=["phone_verified"])

        return instance


class AdminUserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer de actualización para administradores.
    Permite modificar, además de los campos de perfil, el rol y el estado activo.
    Usado en: PATCH /users/{id}/

    Si se cambia el role, se actualiza también el grupo Django del usuario
    mediante instance.assign_role(role), que limpia grupos anteriores y asigna
    el nuevo. Esto mantiene consistencia entre el campo role y los grupos Django.
    """

    class Meta:
        model  = User
        fields = ["first_name", "last_name", "birth_date", "phone_number", "role", "is_active"]

    def validate_role(self, value):
        """Verifica que el rol enviado sea uno de los roles válidos del sistema."""
        valid_roles = [choice[0] for choice in User.Role.choices]
        if value not in valid_roles:
            raise serializers.ValidationError(
                f"Rol inválido. Opciones válidas: {', '.join(valid_roles)}."
            )
        return value

    def update(self, instance, validated_data):
        """
        Actualiza el usuario y, si se cambió el role, sincroniza el grupo Django.
        assign_role() limpia los grupos anteriores y asigna el nuevo.
        """
        role     = validated_data.get("role")
        instance = super().update(instance, validated_data)
        if role:
            instance.assign_role(role)
        return instance


class AssignRoleSerializer(serializers.Serializer):
    """
    Serializer para asignar un rol a un usuario.
    Usado en: POST /users/{id}/assign-role/

    Valida que el rol sea uno de los definidos en User.Role (Admin, Personal, Usuario).
    """

    role = serializers.ChoiceField(choices=User.Role.choices)

    def validate_role(self, value):
        """Retorna el valor del rol sin transformación adicional (validado por ChoiceField)."""
        return value
