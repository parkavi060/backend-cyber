from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.constants.auth_constants import AuthMessages, AuthRoles
from app.services.auth_service import authenticate_user, get_user_profile

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    db = current_app.db
    data = request.get_json()

    serviceId = data.get("serviceId")
    password = data.get("password")

    if not serviceId:
        return jsonify({"msg": AuthMessages.USERNAME_REQUIRED}), 400
    if not password:
        return jsonify({"msg": AuthMessages.PASSWORD_REQUIRED}), 400

    if db.users.find_one({"username": serviceId}):
        return jsonify({"msg": AuthMessages.USER_ALREADY_EXISTS}), 409

    hashed = generate_password_hash(password)

    db.users.insert_one({
        "username": serviceId,
        "password": hashed,
        "role": AuthRoles.USER   
    })

    return jsonify({"msg": AuthMessages.REGISTER_SUCCESS}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    serviceId = data.get("serviceId")
    affiliation = data.get("affiliation")
    password = data.get("password")

    result, status_code = authenticate_user(serviceId, password, affiliation)
    return jsonify(result), status_code


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    username = get_jwt_identity()
    result, status_code = get_user_profile(username)
    return jsonify(result), status_code


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    # In a simple JWT setup, logout is often handled on the client side by discarding the token.
    # However, we can return a success message or implement a blacklist if needed.
    return jsonify({"msg": AuthMessages.LOGOUT_SUCCESS}), 200


@auth_bp.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    user = get_jwt_identity()
    return jsonify({
        "msg": AuthMessages.WELCOME_PROTECTED.format(user)
    }), 200
