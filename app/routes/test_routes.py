from flask import Blueprint, jsonify

test_bp = Blueprint('test', __name__)

@test_bp.route('/test', methods=['GET'])
def test_route():
    return jsonify({"status": "Backend is running smoothly", "message": "OSError 10038 fix applied"}), 200
