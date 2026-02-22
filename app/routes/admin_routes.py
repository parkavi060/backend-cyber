from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from bson.objectid import ObjectId
from datetime import datetime
from bson.json_util import dumps
from app.constants.incident_constants import AdminMessages
from app.constants.auth_constants import AuthRoles
from app.utils.security import generate_evidence_hashes, build_evidence_string
from app.helpers.rbac_helpers import role_required
from app.services.audit_service import log_activity, get_audit_logs
from app.constants.audit_constants import AuditEvents
from app.services.monitoring_service import get_system_metrics

admin_bp = Blueprint("admin", __name__)


#🧾 HISTORY LOGGER (Incident Internal Timeline)
def add_history(incident_id, action, actor):
    db = current_app.db
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
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def get_pending_incidents():

    db = current_app.db
    incidents = db.incidents.find(
        {"analyst_reviewed": False}
    ).sort("created_at", -1)

    return dumps(incidents), 200


# 🚨 HIGH-RISK ALERT QUEUE
@admin_bp.route("/incidents/high-risk", methods=["GET"])
@jwt_required()
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def get_high_risk_incidents():

    db = current_app.db
    incidents = db.incidents.find({
        "risk_level": "HIGH",
        "analyst_reviewed": False
    }).sort("created_at", -1)

    return dumps(incidents), 200


#  📄 VIEW ALL INCIDENTS (ADMIN/ANALYST DASHBOARD)
@admin_bp.route("/incidents/all", methods=["GET"])
@jwt_required()
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def get_all_incidents():

    db = current_app.db
    incidents = db.incidents.find().sort("created_at", -1)
    return dumps(incidents), 200


# 📄 SINGLE INCIDENT DETAILS
@admin_bp.route("/incident/<incident_id>", methods=["GET"])
@jwt_required()
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def get_incident_detail(incident_id):

    db = current_app.db
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
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def start_review(incident_id):

    actor = get_jwt_identity()
    db = current_app.db
    db.incidents.update_one(
        {"_id": ObjectId(incident_id)},
        {"$set": {
            "status": "under_review",
            "review_started_at": datetime.utcnow()
        }}
    )

    add_history(incident_id, "Review started", actor)
    
    log_activity(
        actor=actor,
        event_type=AuditEvents.REVIEW_STARTED,
        details={"incident_id": incident_id},
        role=get_jwt().get("role")
    )

    return jsonify({"msg": AdminMessages.REVIEW_STARTED}), 200



#🧠 REVIEW & FINALIZE INCIDENT (ANALYST ACTION)
@admin_bp.route("/incident/<incident_id>/review", methods=["PUT"])
@jwt_required()
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def review_incident(incident_id):

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

    db = current_app.db
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

    log_activity(
        actor=analyst,
        event_type=AuditEvents.REVIEW_COMPLETED,
        details={
            "incident_id": incident_id,
            "status": update_fields["status"],
            "threat_type": update_fields["threat_type"]
        },
        role=get_jwt().get("role")
    )

    return jsonify({"msg": AdminMessages.REVIEW_SUCCESS}), 200


#🔄 UPDATE STATUS
@admin_bp.route("/incident/<incident_id>/status", methods=["PUT"])
@jwt_required()
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def update_incident_status(incident_id):

    status = request.json.get("status")
    actor = get_jwt_identity()

    if not status:
        return jsonify({"msg": "Status required"}), 400

    db = current_app.db
    db.incidents.update_one(
        {"_id": ObjectId(incident_id)},
        {"$set": {
            "status": status,
            "updated_at": datetime.utcnow()
        }}
    )

    add_history(incident_id, f"Status changed to {status}", actor)

    log_activity(
        actor=actor,
        event_type=AuditEvents.STATUS_CHANGED,
        details={"incident_id": incident_id, "new_status": status},
        role=get_jwt().get("role")
    )

    return jsonify({"msg": AdminMessages.STATUS_UPDATED}), 200


#🧾 VIEW INCIDENT HISTORY
@admin_bp.route("/incident/<incident_id>/history", methods=["GET"])
@jwt_required()
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def get_history(incident_id):

    db = current_app.db
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
@role_required(AuthRoles.ADMIN)
def create_incident_admin():

    data = request.json
    actor = get_jwt_identity()

    # 🔐 Evidence integrity hash (Hybrid: SHA-256 + MD5)
    combined_data = build_evidence_string(
        data.get("platform", ""),
        data.get("incident_date", ""),
        data.get("description", ""),
        data.get("ioc_indicators", "")
    )
    hashes = generate_evidence_hashes(combined_data)

    incident = {
        "title": data.get("title"),
        "description": data.get("description"),
        "platform": data.get("platform"),
        "incident_date": data.get("incident_date"),
        "ioc_indicators": data.get("ioc_indicators", ""),
        "reported_by": "ADMIN",
        "created_at": datetime.utcnow(),
        "status": "open",
        "analyst_reviewed": False,
        "evidence_hash": hashes["sha256"],
        "evidence_hash_md5": hashes["md5"],
        "history": [{
            "action": "Incident created by admin",
            "by": actor,
            "time": datetime.utcnow()
        }]
    }

    db = current_app.db
    db.incidents.insert_one(incident)

    log_activity(
        actor=actor,
        event_type=AuditEvents.INCIDENT_CREATED,
        details={"title": data.get("title")},
        role=AuthRoles.ADMIN
    )

    return jsonify({"msg": AdminMessages.INCIDENT_CREATED}), 201


#❌ DELETE INCIDENT
@admin_bp.route("/incident/<incident_id>", methods=["DELETE"])
@jwt_required()
@role_required(AuthRoles.ADMIN)
def delete_incident(incident_id):

    db = current_app.db
    result = db.incidents.delete_one({"_id": ObjectId(incident_id)})

    if result.deleted_count == 0:
        return jsonify({"msg": "Not found"}), 404

    log_activity(
        actor=get_jwt_identity(),
        event_type=AuditEvents.INCIDENT_DELETED,
        details={"incident_id": incident_id},
        role=AuthRoles.ADMIN
    )

    return jsonify({"msg": AdminMessages.INCIDENT_DELETED}), 200
# stats
@admin_bp.route("/stats", methods=["GET"])
@jwt_required()
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def get_admin_stats():

    db = current_app.db
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
@role_required(AuthRoles.ADMIN, AuthRoles.CERT_ANALYST)
def get_escalations():

    db = current_app.db
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
@role_required(AuthRoles.ADMIN)
def get_admin_users():

    db = current_app.db
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
@role_required(AuthRoles.ADMIN)
def get_admin_audit_logs():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    event_type = request.args.get("event_type")
    
    filters = {}
    if event_type:
        filters["event_type"] = event_type
        
    result = get_audit_logs(page=page, limit=limit, filters=filters)
    
    # Track the view action itself
    log_activity(
        actor=get_jwt_identity(),
        event_type=AuditEvents.AUDIT_LOG_VIEWED,
        details={"page": page},
        role=AuthRoles.ADMIN
    )
    
    return dumps(result), 200

# system-health
@admin_bp.route("/system-health", methods=["GET"])
@jwt_required()
@role_required(AuthRoles.ADMIN)
def get_system_health_metrics():
    metrics = get_system_metrics()
    return jsonify(metrics), 200

# threat-intel
@admin_bp.route("/threat-intel", methods=["GET"])
@jwt_required()
@role_required(AuthRoles.ADMIN, AuthRoles.ANALYST, AuthRoles.CERT_ANALYST)
def get_threat_intel():

    intel = {
        "blockedDomains": [],
        "watchlist": []
    }
    return jsonify(intel), 200
