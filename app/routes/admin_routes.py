from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from bson.objectid import ObjectId
from datetime import datetime
from bson.json_util import dumps

from app.extensions import db   # ✅ correct import

admin_bp = Blueprint("admin", __name__)

#🔐 STAFF ACCESS CHECK (Admin or Analyst)
def staff_required():
    claims = get_jwt()
    return claims.get("role") in ["admin", "analyst"]

#🔐 ADMIN ACCESS CHECK
def admin_required():
    claims = get_jwt()
    return claims.get("role") == "admin"

#🧾 HISTORY LOGGER
def add_history(incident_id, action, actor):
    from app import db # Ensure db is available
    db.incidents.update_one(
        {"_id": ObjectId(incident_id)},
        {"$push": {
            "history": {
                "action": action,
                "by": actor,
                "time": datetime.utcnow()
            }
        }}
    )


#🚨 INCIDENTS PENDING REVIEW
@admin_bp.route("/incidents/pending", methods=["GET"])
@jwt_required()
def get_pending_incidents():
    if not staff_required():
        return jsonify({"msg": "Staff only"}), 403

    incidents = db.incidents.find(
        {"analyst_reviewed": False}
    ).sort("created_at", -1)

    return dumps(incidents), 200


# 🚨 HIGH-RISK ALERT QUEUE
@admin_bp.route("/incidents/high-risk", methods=["GET"])
@jwt_required()
def get_high_risk_incidents():
    if not staff_required():
        return jsonify({"msg": "Staff only"}), 403

    incidents = db.incidents.find({
        "risk_level": "HIGH",
        "analyst_reviewed": False
    }).sort("created_at", -1)

    return dumps(incidents), 200


#  📄 VIEW ALL INCIDENTS (ADMIN/ANALYST DASHBOARD)
@admin_bp.route("/incidents/all", methods=["GET"])
@jwt_required()
def get_all_incidents():
    if not staff_required():
        return jsonify({"msg": "Staff only"}), 403

    incidents = db.incidents.find().sort("created_at", -1)
    return dumps(incidents), 200


# 📄 SINGLE INCIDENT DETAILS
@admin_bp.route("/incident/<incident_id>", methods=["GET"])
@jwt_required()
def get_incident_detail(incident_id):
    if not staff_required():
        return jsonify({"msg": "Staff only"}), 403

    try:
        incident = db.incidents.find_one({"_id": ObjectId(incident_id)})
    except:
        return jsonify({"msg": "Invalid ID"}), 400

    if not incident:
        return jsonify({"msg": "Incident not found"}), 404

    return dumps(incident), 200


#▶ START REVIEW
@admin_bp.route("/incident/<incident_id>/start-review", methods=["PUT"])
@jwt_required()
def start_review(incident_id):
    if not staff_required():
        return jsonify({"msg": "Staff only"}), 403

    actor = get_jwt_identity()

    db.incidents.update_one(
        {"_id": ObjectId(incident_id)},
        {"$set": {
            "status": "under_review",
            "review_started_at": datetime.utcnow()
        }}
    )

    add_history(incident_id, "Review started", actor)

    return jsonify({"msg": "Review started"}), 200



#🧠 REVIEW & FINALIZE INCIDENT (ANALYST ACTION)
@admin_bp.route("/incident/<incident_id>/review", methods=["PUT"])
@jwt_required()
def review_incident(incident_id):
    if not staff_required():
        return jsonify({"msg": "Staff only"}), 403

    data = request.json
    analyst = get_jwt_identity()

    update_fields = {
        "analyst_reviewed": True,
        "status": data.get("status", "resolved"),
        "analyst_name": analyst,
        "reviewed_at": datetime.utcnow(),
        "threat_type": data.get("threat_type"),
        "final_verdict": data.get("final_verdict"),
        "analyst_notes": data.get("analyst_notes"),
        "response_actions": data.get("response_actions", []),
        "preventive_advice": data.get("preventive_advice", [])
    }

    # ✅ Allow manual risk score correction
    if "risk_score" in data:
        update_fields["risk_score"] = data["risk_score"]

    try:
        result = db.incidents.update_one(
            {"_id": ObjectId(incident_id)},
            {"$set": update_fields}
        )
    except:
        return jsonify({"msg": "Invalid ID"}), 400

    if result.matched_count == 0:
        return jsonify({"msg": "Incident not found"}), 404

    add_history(incident_id, "Incident reviewed and verified", analyst)

    return jsonify({"msg": "Incident reviewed successfully"}), 200


#🔄 UPDATE STATUS
@admin_bp.route("/incident/<incident_id>/status", methods=["PUT"])
@jwt_required()
def update_incident_status(incident_id):
    if not staff_required():
        return jsonify({"msg": "Staff only"}), 403

    status = request.json.get("status")
    actor = get_jwt_identity()

    if not status:
        return jsonify({"msg": "Status required"}), 400

    db.incidents.update_one(
        {"_id": ObjectId(incident_id)},
        {"$set": {
            "status": status,
            "updated_at": datetime.utcnow()
        }}
    )

    add_history(incident_id, f"Status changed to {status}", actor)

    return jsonify({"msg": "Status updated"}), 200


#🧾 VIEW INCIDENT HISTORY
@admin_bp.route("/incident/<incident_id>/history", methods=["GET"])
@jwt_required()
def get_history(incident_id):
    if not staff_required():
        return jsonify({"msg": "Staff only"}), 403

    incident = db.incidents.find_one(
        {"_id": ObjectId(incident_id)},
        {"history": 1}
    )

    if not incident:
        return jsonify({"msg": "Not found"}), 404

    return dumps(incident.get("history", [])), 200


#➕ ADMIN CREATE INCIDENT
@admin_bp.route("/incident/create", methods=["POST"])
@jwt_required()
def create_incident_admin():
    if not admin_required():
        return jsonify({"msg": "Admins only"}), 403

    data = request.json
    actor = get_jwt_identity()

    incident = {
        "title": data.get("title"),
        "description": data.get("description"),
        "reported_by": "ADMIN",
        "created_at": datetime.utcnow(),
        "status": "open",
        "analyst_reviewed": False,
        "history": [{
            "action": "Incident created by admin",
            "by": actor,
            "time": datetime.utcnow()
        }]
    }

    db.incidents.insert_one(incident)

    return jsonify({"msg": "Incident created"}), 201


#❌ DELETE INCIDENT
@admin_bp.route("/incident/<incident_id>", methods=["DELETE"])
@jwt_required()
def delete_incident(incident_id):
    if not admin_required():
        return jsonify({"msg": "Admins only"}), 403

    result = db.incidents.delete_one({"_id": ObjectId(incident_id)})

    if result.deleted_count == 0:
        return jsonify({"msg": "Not found"}), 404

    return jsonify({"msg": "Incident deleted"}), 200