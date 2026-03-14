"""
Middleware to attach role info to the request for easy access in views.
"""


class RoleMiddleware:
    """
    Attaches helper properties to the request:
        request.is_admin    → bool
        request.is_personal → bool
        request.is_usuario  → bool
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user and request.user.is_authenticated:
            groups = set(request.user.groups.values_list("name", flat=True))
            request.is_admin = request.user.is_superuser or "Admin" in groups
            request.is_personal = request.is_admin or "Personal" in groups
            request.is_usuario = True  # all authenticated users have basic access
        else:
            request.is_admin = False
            request.is_personal = False
            request.is_usuario = False

        return self.get_response(request)
