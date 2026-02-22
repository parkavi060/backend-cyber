from flask import Blueprint, jsonify

test_bp = Blueprint('test', __name__)

@test_bp.route('/', methods=['GET'])
def root_route():
    return jsonify({
        "status": "CyberGuard Backend API is active",
        "version": "1.0.0",
        "health": "OK"
    }), 200

@test_bp.route('/test', methods=['GET'])
def test_route():
    return jsonify({"status": "Backend is running smoothly", "message": "OSError 10038 fix applied"}), 200
