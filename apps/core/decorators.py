"""
Decorators for protecting function-based views by role.
For class-based views, use the permission_classes in apps/core/permissions.py instead.
"""
from functools import wraps

from .responses import error_response


def role_required(*roles):
    """
    Decorator that restricts access to users belonging to one of the specified roles.

    Usage:
        @role_required("Admin", "Personal")
        def my_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user or not request.user.is_authenticated:
                return error_response("Autenticación requerida.", status_code=401)

            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)

            user_groups = set(request.user.groups.values_list("name", flat=True))
            if not user_groups.intersection(set(roles)):
                return error_response(
                    f"Se requiere uno de los siguientes roles: {', '.join(roles)}.",
                    status_code=403,
                )
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def admin_required(view_func):
    """Shortcut: only Admin role (or superuser)."""
    return role_required("Admin")(view_func)


def personal_required(view_func):
    """Shortcut: Admin or Personal role."""
    return role_required("Admin", "Personal")(view_func)
