from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from bson.objectid import ObjectId
from datetime import datetime
from bson.json_util import dumps
from app.constants.incident_constants import AdminMessages

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
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

    incidents = db.incidents.find(
        {"analyst_reviewed": False}
    ).sort("created_at", -1)

    return dumps(incidents), 200


# 🚨 HIGH-RISK ALERT QUEUE
@admin_bp.route("/incidents/high-risk", methods=["GET"])
@jwt_required()
def get_high_risk_incidents():
    if not staff_required():
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

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
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

    incidents = db.incidents.find().sort("created_at", -1)
    return dumps(incidents), 200


# 📄 SINGLE INCIDENT DETAILS
@admin_bp.route("/incident/<incident_id>", methods=["GET"])
@jwt_required()
def get_incident_detail(incident_id):
    if not staff_required():
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

    try:
        incident = db.incidents.find_one({"_id": ObjectId(incident_id)})
    except:
        return jsonify({"msg": AdminMessages.INVALID_ID}), 400

    if not incident:
        return jsonify({"msg": AdminMessages.NOT_FOUND}), 404

    return dumps(incident), 200


#▶ START REVIEW
@admin_bp.route("/incident/<incident_id>/start-review", methods=["PUT"])
@jwt_required()
def start_review(incident_id):
    if not staff_required():
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

    actor = get_jwt_identity()

    db.incidents.update_one(
        {"_id": ObjectId(incident_id)},
        {"$set": {
            "status": "under_review",
            "review_started_at": datetime.utcnow()
        }}
    )

    add_history(incident_id, "Review started", actor)

    return jsonify({"msg": AdminMessages.REVIEW_STARTED}), 200



#🧠 REVIEW & FINALIZE INCIDENT (ANALYST ACTION)
@admin_bp.route("/incident/<incident_id>/review", methods=["PUT"])
@jwt_required()
def review_incident(incident_id):
    if not staff_required():
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

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

    return jsonify({"msg": AdminMessages.REVIEW_SUCCESS}), 200


#🔄 UPDATE STATUS
@admin_bp.route("/incident/<incident_id>/status", methods=["PUT"])
@jwt_required()
def update_incident_status(incident_id):
    if not staff_required():
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

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

    return jsonify({"msg": AdminMessages.STATUS_UPDATED}), 200


#🧾 VIEW INCIDENT HISTORY
@admin_bp.route("/incident/<incident_id>/history", methods=["GET"])
@jwt_required()
def get_history(incident_id):
    if not staff_required():
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

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

    return jsonify({"msg": AdminMessages.INCIDENT_CREATED}), 201


#❌ DELETE INCIDENT
@admin_bp.route("/incident/<incident_id>", methods=["DELETE"])
@jwt_required()
def delete_incident(incident_id):
    if not admin_required():
        return jsonify({"msg": "Admins only"}), 403

    result = db.incidents.delete_one({"_id": ObjectId(incident_id)})

    if result.deleted_count == 0:
        return jsonify({"msg": "Not found"}), 404

    return jsonify({"msg": AdminMessages.INCIDENT_DELETED}), 200
# stats
@admin_bp.route("/stats", methods=["GET"])
@jwt_required()
def get_admin_stats():
    if not staff_required():
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

    total_incidents = db.incidents.count_documents({})
    open_incidents = db.incidents.count_documents({"status": "open"})
    resolved_incidents = db.incidents.count_documents({"status": "resolved"})
    high_risk = db.incidents.count_documents({"risk_level": "HIGH"})

    stats = [
        {"id": 1, "label": "TOTAL INCIDENTS", "value": str(total_incidents), "trend": "+12%", "trendType": "up"},
        {"id": 2, "label": "OPEN CASES", "value": str(open_incidents), "trend": "-5%", "trendType": "down"},
        {"id": 3, "label": "RESOLVED", "value": str(resolved_incidents), "trend": "+8%", "trendType": "up"},
        {"id": 4, "label": "HIGH RISK AI", "value": str(high_risk), "trend": "+2%", "trendType": "up"},
    ]

    return jsonify(stats), 200

# escalations
@admin_bp.route("/escalations", methods=["GET"])
@jwt_required()
def get_escalations():
    if not staff_required():
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

    incidents = db.incidents.find({
        "risk_level": "HIGH"
    }).sort("created_at", -1).limit(5)

    escalations = []
    for inc in incidents:
        escalations.append({
            "id": str(inc["_id"]),
            "title": inc.get("title") or f"Incident on {inc.get('platform', 'Unknown')}",
            "severity": inc.get("risk_level", "LOW"),
            "status": inc.get("status", "open"),
            "cert": "CERT-AI-1",
            "date": inc.get("created_at").strftime("%Y-%m-%d") if inc.get("created_at") else "N/A"
        })

    return jsonify(escalations), 200

# users
@admin_bp.route("/users", methods=["GET"])
@jwt_required()
def get_admin_users():
    if not admin_required():
        return jsonify({"msg": "Admins only"}), 403

    users_cursor = db.users.find({}, {"password": 0})
    users_list = []
    for user in users_cursor:
        users_list.append({
            "id": str(user["_id"]),
            "name": user.get("username"),
            "email": f"{user.get('username')}@internal.gov",
            "role": user.get("role", "user").capitalize(),
            "status": "Active",
            "lastLogin": "2026-02-22"
        })

    return jsonify(users_list), 200

# audit-logs
@admin_bp.route("/audit-logs", methods=["GET"])
@jwt_required()
def get_audit_logs():
    if not admin_required():
        return jsonify({"msg": "Admins only"}), 403
    return jsonify([]), 200

# system-health
@admin_bp.route("/system-health", methods=["GET"])
@jwt_required()
def get_system_health():
    if not admin_required():
        return jsonify({"msg": "Admins only"}), 403

    health_data = {
        "cards": [
            {"label": "CPU USAGE", "value": "12%", "status": "normal"},
            {"label": "MEMORY", "value": "4.2GB", "status": "normal"},
            {"label": "DB LATENCY", "value": "14ms", "status": "normal"},
            {"label": "API UPTIME", "value": "99.9%", "status": "normal"},
        ],
        "metrics": []
    }
    return jsonify(health_data), 200

# threat-intel
@admin_bp.route("/threat-intel", methods=["GET"])
@jwt_required()
def get_threat_intel():
    if not staff_required():
        return jsonify({"msg": AdminMessages.STAFF_ONLY}), 403

    intel = {
        "blockedDomains": [],
        "watchlist": []
    }
    return jsonify(intel), 200
