from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt
from app.constants.incident_constants import AdminMessages

def role_required(*allowed_roles):
    """
    Decorator to restrict route access to specific roles.
    Expects JWT token with a 'role' claim.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            user_role = claims.get("role")
            
            if user_role not in allowed_roles:
                return jsonify({"msg": AdminMessages.INSUFFICIENT_PERMISSIONS}), 403
            
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def get_current_role():
    """Extract role from JWT claims."""
    return get_jwt().get("role")
