from flask import current_app
from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token
from app.constants.auth_constants import AuthMessages, AuthRoles
from app.services.audit_service import log_activity
from app.constants.audit_constants import AuditEvents

def authenticate_user(serviceId, password, affiliation):
    """
    Authenticates a user and returns a token and user info, or an error message.
    """
    if not serviceId:
        return {"msg": AuthMessages.USERNAME_REQUIRED}, 400
    if not password:
        return {"msg": AuthMessages.PASSWORD_REQUIRED}, 400

    db = current_app.db
    # First, find the user by username to check their role
    user = db.users.find_one({ "username": serviceId })

    if not user:
        log_activity(actor=serviceId or "unknown", event_type=AuditEvents.LOGIN_FAILED, details={"reason": "User not found"})
        return {"msg": AuthMessages.INVALID_CREDENTIALS}, 401

    # Validate based on role
    role = user.get("role", AuthRoles.USER)
    
    # For regular users, we still might want to check affiliation if that's the business rule
    if role == AuthRoles.USER:
        expected_affiliation = "Service Personnel" if affiliation == "Service Personnel" else "family"
    
    # If the user exists and the password matches, we proceed
    if not check_password_hash(user["password"], password):
        log_activity(actor=serviceId, event_type=AuditEvents.LOGIN_FAILED, details={"reason": "Incorrect password"})
        return {"msg": AuthMessages.INVALID_CREDENTIALS}, 401

    role = user.get("role", AuthRoles.USER)

    token = create_access_token(
        identity=user["username"],
        additional_claims={"role": role}
    )

    log_activity(actor=serviceId, event_type=AuditEvents.USER_LOGIN, role=role)

    return {
        "token": token, 
        "user": {
            "username": user["username"],
            "role": role
        },
        "msg": AuthMessages.LOGIN_SUCCESS
    }, 200

def get_user_profile(username):
    """
    Retrieves the user profile from the database.
    """
    db = current_app.db
    user = db.users.find_one({"username": username}, {"password": 0})  # Exclude password
    
    if not user:
        return {"msg": AuthMessages.INVALID_CREDENTIALS}, 404
        
    return {
        "username": user["username"],
        "role": user.get("role", AuthRoles.USER)
    }, 200
