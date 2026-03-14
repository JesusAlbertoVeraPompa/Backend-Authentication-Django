"""
Signals for the accounts app.
"""
import logging

from django.contrib.auth.models import Group
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import User

logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def assign_default_group(sender, instance, created, **kwargs):
    """
    Automatically assign the 'Usuario' group to newly created users.
    The group is created if it doesn't exist yet.
    """
    if created:
        group, _ = Group.objects.get_or_create(name=instance.role or "Usuario")
        instance.groups.add(group)
        logger.debug("Grupo '%s' asignado al usuario %s", group.name, instance.email)
