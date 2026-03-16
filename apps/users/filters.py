import django_filters

from apps.accounts.models import User


class UserFilter(django_filters.FilterSet):
    """
    Filter users by name, email, role, and verification status.

    Query params:
        ?search=john          → first_name, last_name, or email contains "john"
        ?role=Admin
        ?is_verified=true     → phone_verified=True AND email_verified=True
        ?is_active=true
    """

    search = django_filters.CharFilter(method="filter_search", label="Buscar")
    role = django_filters.ChoiceFilter(choices=User.Role.choices)
    is_active = django_filters.BooleanFilter()

    # CORRECCIÓN: is_verified es una @property calculada (phone_verified AND
    # email_verified), no un campo de BD. django-filters no puede hacer
    # queryset.filter(is_verified=...) → FieldError → HTTP 500.
    # Se reemplaza por un BooleanFilter con method personalizado que filtra
    # por los campos reales de la base de datos.
    is_verified = django_filters.BooleanFilter(method="filter_is_verified", label="Verificado")

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

    def filter_is_verified(self, queryset, name, value):
        """
        Filtra por phone_verified AND email_verified, que son los campos
        reales que componen la @property is_verified del modelo User.
        """
        return queryset.filter(phone_verified=value, email_verified=value)
