import django_filters

from apps.accounts.models import User


class UserFilter(django_filters.FilterSet):
    """
    Filter users by name, email, role, and verification status.

    Query params:
        ?search=john          → first_name, last_name, or email contains "john"
        ?role=Admin
        ?is_verified=true
        ?is_active=true
    """

    search = django_filters.CharFilter(method="filter_search", label="Buscar")
    role = django_filters.ChoiceFilter(choices=User.Role.choices)
    is_verified = django_filters.BooleanFilter()
    is_active = django_filters.BooleanFilter()

    class Meta:
        model = User
        fields = ["role", "is_verified", "is_active"]

    def filter_search(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(
            Q(first_name__icontains=value)
            | Q(last_name__icontains=value)
            | Q(email__icontains=value)
        )
