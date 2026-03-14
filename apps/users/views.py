"""
User management views.

Endpoints:
    GET    /users/                → List users (Admin/Personal)
    GET    /users/me/             → Current user profile
    PATCH  /users/me/             → Update own profile
    GET    /users/{id}/           → Get user detail (Admin/Personal)
    PATCH  /users/{id}/           → Update user (Admin only)
    DELETE /users/{id}/           → Delete user (Admin only)
    POST   /users/{id}/assign-role/ → Assign role (Admin only)
"""
import logging

from django.contrib.auth.models import Group
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from apps.accounts.models import User
from apps.core.pagination import CustomPageNumberPagination
from apps.core.permissions import IsAdmin, IsPersonal, IsOwnerOrAdmin
from apps.core.responses import error_response, success_response

from .filters import UserFilter
from .serializers import (
    AdminUserUpdateSerializer,
    AssignRoleSerializer,
    UserDetailSerializer,
    UserListSerializer,
    UserUpdateSerializer,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# USER LIST (Admin / Personal)
# ─────────────────────────────────────────

class UserListView(APIView):
    """
    GET /users/
    List all users with optional search and filters.
    Access: Admin, Personal
    """

    permission_classes = [IsPersonal]

    def get(self, request):
        queryset = User.objects.prefetch_related("groups").order_by("-created_at")

        # Apply filters
        filterset = UserFilter(request.GET, queryset=queryset)
        if not filterset.is_valid():
            return error_response(
                message="Parámetros de filtro inválidos.",
                errors=filterset.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        queryset = filterset.qs

        # Paginate
        paginator = CustomPageNumberPagination()
        page = paginator.paginate_queryset(queryset, request)
        serializer = UserListSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


# ─────────────────────────────────────────
# OWN PROFILE
# ─────────────────────────────────────────

class UserMeView(APIView):
    """
    GET  /users/me/  → Get own profile
    PATCH /users/me/ → Update own profile
    Access: Any authenticated user
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserDetailSerializer(request.user)
        return success_response(
            message="Perfil obtenido correctamente.",
            data=serializer.data,
        )

    def patch(self, request):
        serializer = UserUpdateSerializer(
            request.user,
            data=request.data,
            partial=True,
        )
        if not serializer.is_valid():
            return error_response(
                message="Error al actualizar el perfil.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        serializer.save()
        return success_response(
            message="Perfil actualizado correctamente.",
            data=UserDetailSerializer(request.user).data,
        )


# ─────────────────────────────────────────
# USER DETAIL / UPDATE / DELETE
# ─────────────────────────────────────────

class UserDetailView(APIView):
    """
    GET    /users/{id}/  → Get user detail (Admin/Personal)
    PATCH  /users/{id}/  → Update user (Admin only)
    DELETE /users/{id}/  → Soft-delete user (Admin only)
    """

    def get_permissions(self):
        if self.request.method == "GET":
            return [IsPersonal()]
        return [IsAdmin()]

    def get_object(self, pk):
        return get_object_or_404(User, pk=pk)

    def get(self, request, pk):
        user = self.get_object(pk)
        serializer = UserDetailSerializer(user)
        return success_response(
            message="Usuario obtenido correctamente.",
            data=serializer.data,
        )

    def patch(self, request, pk):
        user = self.get_object(pk)
        serializer = AdminUserUpdateSerializer(user, data=request.data, partial=True)
        if not serializer.is_valid():
            return error_response(
                message="Error al actualizar el usuario.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        serializer.save()
        logger.info("Admin %s updated user %s", request.user.email, user.email)
        return success_response(
            message="Usuario actualizado correctamente.",
            data=UserDetailSerializer(user).data,
        )

    def delete(self, request, pk):
        user = self.get_object(pk)

        # Prevent self-deletion
        if user == request.user:
            return error_response(
                message="No puedes eliminar tu propia cuenta desde este endpoint.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Soft delete: deactivate instead of destroying
        user.is_active = False
        user.save(update_fields=["is_active"])

        logger.info("Admin %s deactivated user %s", request.user.email, user.email)
        return success_response(
            message=f"Usuario {user.email} eliminado correctamente.",
            status_code=status.HTTP_200_OK,
        )


# ─────────────────────────────────────────
# ASSIGN ROLE
# ─────────────────────────────────────────

class AssignRoleView(APIView):
    """
    POST /users/{id}/assign-role/
    Assign a role (Admin / Personal / Usuario) to a user.
    Access: Admin only
    """

    permission_classes = [IsAdmin]

    def post(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        serializer = AssignRoleSerializer(data=request.data)

        if not serializer.is_valid():
            return error_response(
                message="Rol inválido.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        role = serializer.validated_data["role"]
        user.assign_role(role)

        logger.info(
            "Admin %s assigned role '%s' to user %s",
            request.user.email,
            role,
            user.email,
        )
        return success_response(
            message=f"Rol '{role}' asignado a {user.email}.",
            data={"id": str(user.id), "email": user.email, "role": user.role},
        )
