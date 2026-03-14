"""
Shared utility functions used across multiple apps.
"""
import logging
import random
import string

from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# CODE GENERATION
# ─────────────────────────────────────────

def generate_numeric_code(length: int = 6) -> str:
    """Generate a random numeric verification code."""
    return "".join(random.choices(string.digits, k=length))


# ─────────────────────────────────────────
# SMS
# ─────────────────────────────────────────

def send_sms_verification(phone_number: str, code: str) -> bool:
    """
    Send a verification SMS via Twilio.

    Returns True on success, False on failure.
    """
    try:
        from twilio.rest import Client

        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=f"Tu código de verificación es: {code}. Válido por 10 minutos.",
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number,
        )
        logger.info("SMS de verificación enviado a %s", phone_number)
        return True
    except Exception as exc:
        logger.error("Error enviando SMS a %s: %s", phone_number, exc)
        return False


# ─────────────────────────────────────────
# EMAIL
# ─────────────────────────────────────────

def send_password_reset_email(user) -> bool:
    """
    Send a password-reset link to the user's email.

    Returns True on success, False on failure.
    """
    try:
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_url = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"

        send_mail(
            subject="Recuperación de contraseña",
            message=(
                f"Hola {user.first_name},\n\n"
                f"Haz clic en el siguiente enlace para restablecer tu contraseña:\n"
                f"{reset_url}\n\n"
                f"Este enlace expira en 24 horas.\n\n"
                f"Si no solicitaste esto, ignora este correo."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        logger.info("Email de recuperación enviado a %s", user.email)
        return True
    except Exception as exc:
        logger.error("Error enviando email de recuperación a %s: %s", user.email, exc)
        return False


def send_welcome_email(user) -> bool:
    """Send a welcome email after successful registration."""
    try:
        send_mail(
            subject="¡Bienvenido/a!",
            message=(
                f"Hola {user.first_name},\n\n"
                f"Tu cuenta ha sido creada exitosamente.\n\n"
                f"Por favor verifica tu número de teléfono para activar tu cuenta."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True,
        )
        return True
    except Exception as exc:
        logger.error("Error enviando email de bienvenida: %s", exc)
        return False
