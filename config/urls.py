"""
Main URL Configuration.
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    # Admin
    path("admin/", admin.site.urls),

    # API v1
    path("api/v1/auth/", include("apps.accounts.urls", namespace="accounts")),
    path("api/v1/users/", include("apps.users.urls", namespace="users")),

    # Social auth (allauth)
    path("accounts/", include("allauth.socialaccount.urls")),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
