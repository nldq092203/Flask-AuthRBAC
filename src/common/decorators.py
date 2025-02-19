from flask_jwt_extended import get_jwt, jwt_required
from flask_smorest import abort
from functools import wraps

def role_required(required_roles):
    """
    Decorator to enforce Role-Based Access Control (RBAC).
    """
    def decorator(fn):
        @wraps(fn)
        @jwt_required()  
        def wrapper(*args, **kwargs):
            jwt_claims = get_jwt()
            user_roles = jwt_claims.get("roles", [])
            print(user_roles)

            if not any(role in user_roles for role in required_roles):
                abort(403, message="You do not have permission to access this resource.")

            return fn(*args, **kwargs)
        return wrapper
    return decorator