"""
Shared utility functions used across multiple apps.
"""
import logging
import string
import secrets

from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# CODE GENERATION
# ─────────────────────────────────────────

def generate_numeric_code(length: int = 6) -> str:
    """Generate a secrets numeric verification code."""
    return "".join(secrets.choice(string.digits) for _ in range(length))


# ─────────────────────────────────────────
# SMS
# ─────────────────────────────────────────

def send_sms_verification(phone_number: str, code: str) -> bool:
    """
    Send a verification SMS via Twilio.

    Returns True on success, False on failure.
    """
  
    def mask_phone(phone: str) -> str:
        """Muestra solo los últimos 4 dígitos: +57******2962"""
        if not phone or len(phone) < 4:
            return "****"
        return phone[:-4].replace(phone[1:-4], "*" * len(phone[1:-4])) + phone[-4:]

    try:
        from twilio.rest import Client
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=f"Tu código de verificación es: {code}. Válido por 10 minutos.",
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number,
        )
        logger.info("SMS de verificación enviado a %s", mask_phone(phone_number))
        return True
    except Exception as exc:
        logger.error("Error enviando SMS a %s: %s", mask_phone(phone_number), exc)
        return False


# ─────────────────────────────────────────
# EMAIL
# ─────────────────────────────────────────

def send_password_reset_email(user, reset_token) -> bool:
    """
    Send a password-reset link to the user's email.

    Returns True on success, False on failure.
    """
    try:
        reset_url = f"{settings.FRONTEND_URL}/reset-password/{str(reset_token.token)}/"

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
