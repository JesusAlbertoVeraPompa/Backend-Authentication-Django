"""
views.py — Vistas de gestión de usuarios (CRUD, roles, perfil).

Endpoints:
    GET    /users/                  → Listar usuarios (Admin/Personal)
    GET    /users/me/               → Perfil del usuario autenticado
    PATCH  /users/me/               → Actualizar propio perfil
    GET    /users/{id}/             → Detalle de usuario (Admin/Personal)
    PATCH  /users/{id}/             → Actualizar usuario (Admin only)
    DELETE /users/{id}/             → Desactivar usuario / soft-delete (Admin only)
    POST   /users/{id}/assign-role/ → Asignar rol (Admin only)

Correcciones de seguridad aplicadas:
  [FIX-A4] UserDetailView.delete(): al desactivar un usuario (soft-delete),
           ahora se invalidan todos sus refresh tokens JWT activos.
           Antes, un usuario "eliminado" podía seguir usando sus tokens
           hasta que expiraran (hasta 60 min con access, 7 días con refresh).
  [FIX-A5] UserUpdateSerializer: al cambiar el phone_number vía PATCH /me/,
           se resetea phone_verified=False para forzar la re-verificación.
           Antes, el usuario quedaba marcado como verificado con un número
           diferente al que validó, evadiendo el flujo de verificación SMS.
"""
import logging

from django.contrib.auth.models import Group
from django.db.models import F
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

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
    Lista todos los usuarios del sistema con soporte de búsqueda y filtros.

    Filtros disponibles (query params):
      ?search=nombre    → Busca en first_name, last_name o email.
      ?role=Admin       → Filtra por rol (Admin / Personal / Usuario).
      ?is_verified=true → Solo usuarios con email Y teléfono verificados.
      ?is_active=true   → Solo usuarios activos.

    Acceso: Admin y Personal.
    Paginado: 20 resultados por página (configurable con ?page_size=N, máx 100).
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
    GET  /users/me/  → Retorna el perfil completo del usuario autenticado.
    PATCH /users/me/ → Actualiza campos del perfil propio.

    Campos actualizables: first_name, last_name, birth_date, phone_number.
    El email y la contraseña se actualizan en endpoints separados.

    Nota de seguridad [FIX-A5]:
      Si se actualiza el phone_number, el campo phone_verified se resetea
      a False automáticamente (ver UserUpdateSerializer). El usuario deberá
      verificar el nuevo número vía /verify/send/ y /verify/confirm/.

    Acceso: cualquier usuario autenticado (IsAuthenticated).
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retorna el perfil completo del usuario autenticado."""
        serializer = UserDetailSerializer(request.user)
        return success_response(
            message="Perfil obtenido correctamente.",
            data=serializer.data,
        )

    def patch(self, request):
        """
        Actualiza campos del perfil propio de forma parcial.
        Si se cambia el phone_number, phone_verified se resetea a False.
        """
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
    GET    /users/{id}/  → Detalle de usuario (Admin/Personal).
    PATCH  /users/{id}/  → Actualizar usuario (Admin only).
    DELETE /users/{id}/  → Desactivar usuario / soft-delete (Admin only).

    El DELETE es un "soft delete": el usuario no se elimina de la base de datos,
    solo se marca como is_active=False. Esto permite auditabilidad y recuperación.

    [FIX-A4] Al desactivar un usuario, todos sus refresh tokens JWT se invalidan
    inmediatamente (blacklisting). Sin esto, el usuario "eliminado" podía seguir
    usando sus tokens hasta que expiraran de forma natural.
    """

    def get_permissions(self):
        """GET requiere Personal o Admin; PATCH y DELETE requieren Admin."""
        if self.request.method == "GET":
            return [IsPersonal()]
        return [IsAdmin()]

    def get_object(self, pk):
        """Obtiene el usuario por PK o retorna 404."""
        return get_object_or_404(User, pk=pk)

    def get(self, request, pk):
        """Retorna el detalle completo de un usuario."""
        user = self.get_object(pk)
        serializer = UserDetailSerializer(user)
        return success_response(
            message="Usuario obtenido correctamente.",
            data=serializer.data,
        )

    def patch(self, request, pk):
        """
        Actualiza campos de un usuario (solo Admin).
        Permite modificar: first_name, last_name, birth_date, phone_number, role, is_active.
        Si se cambia el role, se actualiza también el grupo Django del usuario.
        """
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
        """
        Desactiva (soft-delete) a un usuario. Solo Admin.

        Flujo:
          1. Verifica que el admin no se esté auto-eliminando.
          2. Marca is_active=False (el usuario no puede hacer login).
          3. [FIX-A4] Invalida todos los refresh tokens JWT del usuario.
             Esto asegura que el usuario desactivado no pueda seguir usando
             tokens previamente emitidos. El access token expirará de forma
             natural (máx. 15 min con la nueva configuración por defecto).
        """
        user = self.get_object(pk)

        # Previene que un admin se elimine a sí mismo por accidente
        if user == request.user:
            return error_response(
                message="No puedes eliminar tu propia cuenta desde este endpoint.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Soft delete: desactiva en lugar de destruir (mantiene trazabilidad)
        user.is_active = False
        user.save(update_fields=["is_active"])

        # [FIX-A4] Invalida todos los refresh tokens JWT del usuario desactivado.
        # Sin esto, el usuario podría seguir operando hasta que sus tokens
        # expiren de forma natural (hasta 7 días con el refresh token).
        for token in OutstandingToken.objects.filter(user=user):
            BlacklistedToken.objects.get_or_create(token=token)

        logger.info("Admin %s deactivated user %s", request.user.email, user.email)
        return success_response(
            message=f"Usuario {user.email} desactivado correctamente. Sus tokens han sido revocados.",
            status_code=status.HTTP_200_OK,
        )


# ─────────────────────────────────────────
# ASSIGN ROLE
# ─────────────────────────────────────────

class AssignRoleView(APIView):
    """
    POST /users/{id}/assign-role/
    Asigna un rol (Admin / Personal / Usuario) a un usuario.

    Flujo:
      1. Valida que el rol enviado sea uno de los roles válidos (AssignRoleSerializer).
      2. Llama a user.assign_role(role) que:
           - Limpia los grupos Django anteriores del usuario.
           - Añade el nuevo grupo.
           - Actualiza el campo role del modelo.

    Acceso: Admin only.
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
