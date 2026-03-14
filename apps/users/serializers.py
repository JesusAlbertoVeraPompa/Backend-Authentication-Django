"""
Serializers for user management (CRUD, role assignment, profile).
"""
from django.contrib.auth.models import Group
from rest_framework import serializers

from apps.accounts.models import User


class UserDetailSerializer(serializers.ModelSerializer):
    """Full user detail — used for profile view and admin reads."""

    full_name = serializers.SerializerMethodField()
    groups = serializers.SerializerMethodField()

    class Meta:
        model = User
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
        return obj.full_name

    def get_groups(self, obj):
        return list(obj.groups.values_list("name", flat=True))


class UserListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views."""

    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "email", "full_name", "role", "is_verified", "is_active", "created_at"]

    def get_full_name(self, obj):
        return obj.full_name


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Update user profile fields.
    Email and password are NOT updated here (separate endpoints).
    """

    class Meta:
        model = User
        fields = ["first_name", "last_name", "birth_date", "phone_number"]

    def validate_phone_number(self, value):
        if value and not value.startswith("+"):
            raise serializers.ValidationError(
                "El número debe estar en formato internacional (ej: +573001234567)."
            )
        return value


class AdminUserUpdateSerializer(serializers.ModelSerializer):
    """
    Admin-only serializer: can also change role and active status.
    """

    class Meta:
        model = User
        fields = ["first_name", "last_name", "birth_date", "phone_number", "role", "is_active"]

    def validate_role(self, value):
        valid_roles = [choice[0] for choice in User.Role.choices]
        if value not in valid_roles:
            raise serializers.ValidationError(
                f"Rol inválido. Opciones válidas: {', '.join(valid_roles)}."
            )
        return value

    def update(self, instance, validated_data):
        role = validated_data.get("role")
        instance = super().update(instance, validated_data)
        if role:
            instance.assign_role(role)
        return instance


class AssignRoleSerializer(serializers.Serializer):
    """Assign a role (group) to a user."""

    role = serializers.ChoiceField(choices=User.Role.choices)

    def validate_role(self, value):
        return value
