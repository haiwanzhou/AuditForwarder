import base64
import hashlib
import hmac
import json
import os
import time
from functools import wraps

from flask import request, jsonify, g


SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-later")
TOKEN_EXPIRATION_SECONDS = 24 * 60 * 60  # 24 hours


def generate_token(user):
    """
    Creates a signed token for a logged-in user.
    The token contains the user's id, username, role, and expiration time.
    """
    payload = {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "exp": time.time() + TOKEN_EXPIRATION_SECONDS,
    }

    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_encoded = base64.urlsafe_b64encode(payload_json.encode()).decode()

    signature = hmac.new(
        SECRET_KEY.encode(),
        payload_encoded.encode(),
        hashlib.sha256,
    ).hexdigest()

    return f"{payload_encoded}.{signature}"


def verify_token(token):
    """
    Verifies the token signature and expiration.
    Returns the user payload if valid.
    Returns None if invalid.
    """
    try:
        payload_encoded, signature = token.split(".", 1)

        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            payload_encoded.encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return None

        payload_json = base64.urlsafe_b64decode(payload_encoded.encode()).decode()
        payload = json.loads(payload_json)

        if time.time() > payload["exp"]:
            return None

        return payload

    except Exception:
        return None


def get_token_from_header():
    """
    Reads the Authorization header.
    Expected format:
    Authorization: Bearer <token>
    """
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return None

    if not auth_header.startswith("Bearer "):
        return None

    return auth_header.replace("Bearer ", "", 1).strip()


def login_required(route_function):
    """
    Protects routes that require a logged-in user.
    If token is valid, current user is stored in g.current_user.
    """
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        token = get_token_from_header()

        if token is None:
            return jsonify({
                "status": "error",
                "message": "Missing or invalid Authorization header"
            }), 401

        user_payload = verify_token(token)

        if user_payload is None:
            return jsonify({
                "status": "error",
                "message": "Invalid or expired token"
            }), 401

        g.current_user = user_payload

        return route_function(*args, **kwargs)

    return wrapper


def role_required(*allowed_roles):
    """
    Protects routes that require a specific role.
    Example:
    @role_required("admin")
    @role_required("admin", "librarian")
    """
    def decorator(route_function):
        @wraps(route_function)
        @login_required
        def wrapper(*args, **kwargs):
            current_role = g.current_user["role"]

            if current_role not in allowed_roles:
                return jsonify({
                    "status": "error",
                    "message": "Insufficient permissions",
                    "required_roles": list(allowed_roles),
                    "your_role": current_role
                }), 403

            return route_function(*args, **kwargs)

        return wrapper

    return decorator