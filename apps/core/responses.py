"""
Standardized API response helpers.
All views should use these helpers to return consistent JSON responses.
"""
from rest_framework.response import Response


def success_response(message: str, data=None, status_code: int = 200) -> Response:
    """
    Return a standardized success response.

    Args:
        message: Human-readable success message.
        data: Response payload (dict, list, or None).
        status_code: HTTP status code (default 200).

    Returns:
        DRF Response with consistent structure.
    """
    return Response(
        {
            "success": True,
            "status_code": status_code,
            "message": message,
            "data": data,
        },
        status=status_code,
    )


def error_response(message: str, errors=None, status_code: int = 400) -> Response:
    """
    Return a standardized error response.

    Args:
        message: Human-readable error message.
        errors: Detailed error information (dict, list, or None).
        status_code: HTTP status code (default 400).

    Returns:
        DRF Response with consistent structure.
    """
    return Response(
        {
            "success": False,
            "status_code": status_code,
            "message": message,
            "errors": errors,
        },
        status=status_code,
    )
