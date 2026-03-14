"""
Custom DRF exception handler.
Wraps all unhandled exceptions into the standard error_response format.
"""
import logging

from rest_framework.views import exception_handler

from .responses import error_response

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Override DRF's default exception handler to use our error_response format.
    """
    # Call DRF's default handler first
    response = exception_handler(exc, context)

    if response is not None:
        # Map DRF validation errors into our standard format
        errors = response.data if isinstance(response.data, dict) else {"detail": response.data}

        # Extract a clean message
        message = "Se produjo un error al procesar la solicitud."
        if "detail" in errors:
            message = str(errors.pop("detail"))

        return error_response(
            message=message,
            errors=errors if errors else None,
            status_code=response.status_code,
        )

    # Unexpected server error
    logger.exception("Unhandled exception in view: %s", exc)
    return error_response(
        message="Error interno del servidor.",
        status_code=500,
    )
