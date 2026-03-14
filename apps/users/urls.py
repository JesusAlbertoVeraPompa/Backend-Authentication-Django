"""
URL patterns for the users app.
All routes are prefixed with /api/v1/users/
"""
from django.urls import path

from .views import AssignRoleView, UserDetailView, UserListView, UserMeView

app_name = "users"

urlpatterns = [
    path("", UserListView.as_view(), name="user-list"),
    path("me/", UserMeView.as_view(), name="user-me"),
    path("<uuid:pk>/", UserDetailView.as_view(), name="user-detail"),
    path("<uuid:pk>/assign-role/", AssignRoleView.as_view(), name="assign-role"),
]
