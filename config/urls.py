"""
urls.py — Configuración principal de URLs del proyecto.

Rutas registradas:
  /admin/          → Panel de administración Django.
  /api/v1/auth/    → Endpoints de autenticación (accounts app).
  /api/v1/users/   → Endpoints de gestión de usuarios (users app).

Correcciones de seguridad aplicadas:
  [FIX-A7] Se eliminó la ruta path("accounts/", include("allauth.socialaccount.urls")).
           Esas URLs exponen vistas HTML de allauth que el proyecto no usa
           (toda la autenticación social pasa por /api/v1/auth/social/).
           Mantenerlas abiertas añade superficie de ataque innecesaria:
           posible CSRF en formularios HTML de allauth, redirect abuse,
           session fixation, y endpoints no documentados ni testeados.
           El flujo OAuth2 propio del proyecto no requiere estas rutas.
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    # Panel de administración Django
    path("admin/", admin.site.urls),

    # API v1 — Autenticación (registro, login, verificación, recuperación de contraseña)
    path("api/v1/auth/", include("apps.accounts.urls", namespace="accounts")),

    # API v1 — Gestión de usuarios (perfil, listado, roles)
    path("api/v1/users/", include("apps.users.urls", namespace="users")),

    # [FIX-A7] Se eliminó:
    # path("accounts/", include("allauth.socialaccount.urls"))
    # Razón: expone vistas HTML de allauth no utilizadas por el proyecto.
    # El login social se gestiona exclusivamente vía POST /api/v1/auth/social/.
]

# En desarrollo, sirve los archivos de media directamente desde Django.
# En producción, los archivos de media deben servirse desde un CDN o servidor web (ej: nginx).
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
