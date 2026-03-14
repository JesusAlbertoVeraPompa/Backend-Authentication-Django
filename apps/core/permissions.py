"""
Custom DRF permission classes for role-based access control.

Roles:
    - Admin   → Full access
    - Personal → Staff-level access
    - Usuario  → Regular user access
"""
from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """Allow access only to users in the 'Admin' group."""

    message = "Se requiere rol de Administrador para esta acción."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and (
                request.user.is_superuser
                or request.user.groups.filter(name="Admin").exists()
            )
        )


class IsPersonal(BasePermission):
    """Allow access to users in 'Admin' or 'Personal' groups."""

    message = "Se requiere rol de Personal o Administrador para esta acción."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return (
            request.user.is_superuser
            or request.user.groups.filter(name__in=["Admin", "Personal"]).exists()
        )


class IsOwnerOrAdmin(BasePermission):
    """Allow access to the object's owner or an Admin."""

    message = "No tienes permisos para acceder a este recurso."

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser or request.user.groups.filter(name="Admin").exists():
            return True
        # Check if the object IS the user or has a 'user' FK to the requesting user
        if hasattr(obj, "user"):
            return obj.user == request.user
        return obj == request.user
