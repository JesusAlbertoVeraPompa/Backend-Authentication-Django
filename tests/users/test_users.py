"""
Tests for user management endpoints.
GET    /api/v1/users/
GET    /api/v1/users/me/
PATCH  /api/v1/users/me/
GET    /api/v1/users/{id}/
PATCH  /api/v1/users/{id}/
DELETE /api/v1/users/{id}/
POST   /api/v1/users/{id}/assign-role/
"""
import pytest

USERS_URL = "/api/v1/users/"
ME_URL = "/api/v1/users/me/"


def detail_url(user_id):
    return f"/api/v1/users/{user_id}/"


def assign_role_url(user_id):
    return f"/api/v1/users/{user_id}/assign-role/"


# ─────────────────────────────────────────
# LIST USERS
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestUserListView:

    def test_admin_can_list_users(self, admin_client, make_user):
        """Admin can retrieve the user list."""
        make_user(email="a@a.com")
        make_user(email="b@b.com")
        response = admin_client.get(USERS_URL)
        assert response.status_code == 200
        assert response.data["success"] is True
        assert response.data["data"]["count"] >= 2

    def test_personal_can_list_users(self, personal_client):
        """Personal-role user can list users."""
        response = personal_client.get(USERS_URL)
        assert response.status_code == 200

    def test_regular_user_cannot_list(self, auth_client):
        """Regular user gets 403."""
        response = auth_client.get(USERS_URL)
        assert response.status_code == 403

    def test_unauthenticated_cannot_list(self, api_client):
        """Unauthenticated request returns 401."""
        response = api_client.get(USERS_URL)
        assert response.status_code == 401

    def test_search_by_name(self, admin_client, make_user):
        """?search= filters by first_name, last_name, or email."""
        make_user(email="maria@example.com", first_name="Maria", last_name="Lopez")
        make_user(email="carlos@example.com", first_name="Carlos", last_name="Gomez")

        response = admin_client.get(USERS_URL + "?search=maria")
        assert response.status_code == 200
        emails = [u["email"] for u in response.data["data"]["results"]]
        assert "maria@example.com" in emails
        assert "carlos@example.com" not in emails

    def test_search_by_email(self, admin_client, make_user):
        """?search= also matches partial email."""
        make_user(email="unique123@example.com")
        response = admin_client.get(USERS_URL + "?search=unique123")
        assert response.status_code == 200
        assert response.data["data"]["count"] >= 1

    def test_filter_by_role(self, admin_client, make_user):
        """?role=Admin returns only Admin users."""
        admin = make_user(email="adminfilter@example.com", role="Admin")
        response = admin_client.get(USERS_URL + "?role=Admin")
        emails = [u["email"] for u in response.data["data"]["results"]]
        assert "adminfilter@example.com" in emails

    def test_filter_by_verified(self, admin_client, make_user):
        """?is_verified=true returns only verified users."""
        make_user(email="verified@example.com", is_verified=True)
        make_user(email="unverified@example.com", is_verified=False)

        response = admin_client.get(USERS_URL + "?is_verified=true")
        for user in response.data["data"]["results"]:
            assert user["is_verified"] is True

    def test_pagination(self, admin_client, make_user):
        """Response includes pagination meta: count, next, previous, results."""
        for i in range(5):
            make_user(email=f"pag{i}@example.com")

        response = admin_client.get(USERS_URL + "?page_size=2")
        assert response.status_code == 200
        assert "count" in response.data["data"]
        assert "results" in response.data["data"]
        
    def test_invalid_filter_returns_400(self, admin_client):
        """Line 57 — invalid filter params return 400."""
        from unittest.mock import patch, MagicMock

        mock_filterset = MagicMock()
        mock_filterset.is_valid.return_value = False
        mock_filterset.errors = {"field": ["Error"]}

        with patch("apps.users.views.UserFilter", return_value=mock_filterset):
            response = admin_client.get("/api/v1/users/", format="json")

        assert response.status_code == 400


# ─────────────────────────────────────────
# OWN PROFILE
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestUserMeView:

    def test_get_own_profile(self, auth_client, regular_user):
        """User retrieves their own profile."""
        response = auth_client.get(ME_URL)
        assert response.status_code == 200
        assert response.data["data"]["email"] == "regular@example.com"

    def test_profile_has_expected_fields(self, auth_client):
        """Profile response contains all expected fields."""
        response = auth_client.get(ME_URL)
        for field in ("id", "email", "first_name", "last_name", "role", "is_verified"):
            assert field in response.data["data"]

    def test_update_own_profile(self, auth_client, regular_user):
        """User can update their own first_name."""
        response = auth_client.patch(ME_URL, {"first_name": "Nuevo"}, format="json")
        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.first_name == "Nuevo"

    def test_update_phone_format_validation(self, auth_client):
        """Invalid phone format returns 400."""
        response = auth_client.patch(
            ME_URL, {"phone_number": "3001234567"}, format="json"
        )
        assert response.status_code == 400

    def test_unauthenticated_cannot_view_profile(self, api_client):
        """Unauthenticated request returns 401."""
        response = api_client.get(ME_URL)
        assert response.status_code == 401


# ─────────────────────────────────────────
# USER DETAIL
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestUserDetailView:

    def test_admin_get_user_detail(self, admin_client, regular_user):
        """Admin can view any user's detail."""
        response = admin_client.get(detail_url(regular_user.id))
        assert response.status_code == 200
        assert response.data["data"]["email"] == "regular@example.com"

    def test_personal_get_user_detail(self, personal_client, regular_user):
        """Personal-role user can view user detail."""
        response = personal_client.get(detail_url(regular_user.id))
        assert response.status_code == 200

    def test_regular_user_cannot_view_other(self, auth_client, admin_user):
        """Regular user cannot view another user's detail."""
        response = auth_client.get(detail_url(admin_user.id))
        assert response.status_code == 403

    def test_admin_update_user(self, admin_client, regular_user):
        """Admin can update any user's profile fields."""
        response = admin_client.patch(
            detail_url(regular_user.id),
            {"first_name": "AdminUpdated"},
            format="json",
        )
        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.first_name == "AdminUpdated"

    def test_admin_can_deactivate_user(self, admin_client, regular_user):
        """Admin can change is_active to False."""
        response = admin_client.patch(
            detail_url(regular_user.id),
            {"is_active": False},
            format="json",
        )
        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.is_active is False

    def test_nonexistent_user_returns_404(self, admin_client):
        """Request for non-existent UUID returns 404."""
        import uuid
        response = admin_client.get(detail_url(uuid.uuid4()))
        assert response.status_code == 404

    def test_admin_update_user_invalid_data(self, admin_client, make_user):
        """Line 142 — invalid PATCH data returns 400."""
        user = make_user(email="patch_invalid@test.com")
        response = admin_client.patch(
            f"/api/v1/users/{user.id}/",
            {"role": "RolInexistente"},
            format="json",
        )
        assert response.status_code == 400

# ─────────────────────────────────────────
# DELETE USER
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestDeleteUserView:

    def test_admin_can_delete_user(self, admin_client, regular_user):
        """Admin soft-deletes (deactivates) a user."""
        response = admin_client.delete(detail_url(regular_user.id))
        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.is_active is False

    def test_admin_cannot_delete_self(self, admin_client, admin_user):
        """Admin cannot delete their own account via this endpoint."""
        response = admin_client.delete(detail_url(admin_user.id))
        assert response.status_code == 400

    def test_regular_user_cannot_delete(self, auth_client, regular_user):
        """Regular user cannot delete anyone."""
        response = auth_client.delete(detail_url(regular_user.id))
        assert response.status_code == 403

    def test_unauthenticated_cannot_delete(self, api_client, regular_user):
        """Unauthenticated request returns 401."""
        response = api_client.delete(detail_url(regular_user.id))
        assert response.status_code == 401

    def test_delete_nonexistent_returns_404(self, admin_client):
        import uuid
        response = admin_client.delete(detail_url(uuid.uuid4()))
        assert response.status_code == 404


# ─────────────────────────────────────────
# ASSIGN ROLE
# ─────────────────────────────────────────

@pytest.mark.django_db
class TestAssignRoleView:

    def test_admin_assigns_role(self, admin_client, regular_user):
        """Admin can assign the 'Personal' role to a user."""
        response = admin_client.post(
            assign_role_url(regular_user.id),
            {"role": "Personal"},
            format="json",
        )
        assert response.status_code == 200
        regular_user.refresh_from_db()
        assert regular_user.role == "Personal"
        assert regular_user.groups.filter(name="Personal").exists()

    def test_admin_assigns_admin_role(self, admin_client, regular_user):
        """Admin can elevate a user to Admin role."""
        response = admin_client.post(
            assign_role_url(regular_user.id),
            {"role": "Admin"},
            format="json",
        )
        assert response.status_code == 200

    def test_invalid_role_returns_400(self, admin_client, regular_user):
        """Invalid role name returns 400."""
        response = admin_client.post(
            assign_role_url(regular_user.id),
            {"role": "SuperDuperAdmin"},
            format="json",
        )
        assert response.status_code == 400

    def test_regular_user_cannot_assign_role(self, auth_client, regular_user):
        """Regular user cannot assign roles."""
        response = auth_client.post(
            assign_role_url(regular_user.id),
            {"role": "Admin"},
            format="json",
        )
        assert response.status_code == 403

    def test_personal_cannot_assign_role(self, personal_client, regular_user):
        """Personal-role user cannot assign roles."""
        response = personal_client.post(
            assign_role_url(regular_user.id),
            {"role": "Admin"},
            format="json",
        )
        assert response.status_code == 403

    def test_assign_role_user_group_is_updated(self, admin_client, regular_user):
        """Assigning a new role removes old group and adds new one."""
        # First assign Personal
        admin_client.post(
            assign_role_url(regular_user.id),
            {"role": "Personal"},
            format="json",
        )
        regular_user.refresh_from_db()
        assert regular_user.groups.filter(name="Personal").exists()
        assert not regular_user.groups.filter(name="Usuario").exists()
