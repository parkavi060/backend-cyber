from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from bson import ObjectId
from app.utils.risk_engine import calculate_risk_score, detect_threat_type
from app.utils.response_playbook import PLAYBOOK
from app.utils.security import generate_sha256

incident_bp = Blueprint("incident", __name__)


#✅ REPORT INCIDENT (UPDATED FOR NEW FORM)
@incident_bp.route("/report", methods=["POST"])
@jwt_required()
def report_incident():

    db = current_app.db
    current_user = get_jwt_identity()
    data = request.get_json()

    if not data:
        return jsonify({"msg": "Invalid request body"}), 400

    # 📥 Extract fields from new form
    platform = data.get("platform")
    incident_date = data.get("incident_date")
    relationship = data.get("relationship")
    ioc_indicators = data.get("ioc_indicators", "")
    narrative = data.get("narrative", "")
    confirmation = data.get("confirmation", False)

    # ✅ Validate required fields
    if not platform or not incident_date or not narrative:
        return jsonify({"msg": "Required fields missing"}), 400

    if not confirmation:
        return jsonify({"msg": "You must confirm the report"}), 400

    # 🔎 Combine text for analysis
    combined_text = narrative + " " + ioc_indicators

    # 🤖 Risk scoring
    risk_score, risk_level, risk_reasons = calculate_risk_score(
        combined_text, narrative, ioc_indicators
    )

    # 🌐 Detect URL presence
    malicious_url_found = "http" in ioc_indicators.lower()

    # urgency detection
    urgency_score = 15 if any(word in narrative.lower() for word in ["urgent", "immediately", "now"]) else 0

    # 🧠 Threat type detection
    threat_type = detect_threat_type(combined_text, malicious_url_found, urgency_score)

    # 📘 Safety guidance
    guidance = PLAYBOOK.get(threat_type, PLAYBOOK["Suspicious Message"])

    # 🔐 Evidence integrity hash
    combined_data = platform + incident_date + narrative + ioc_indicators
    evidence_hash = generate_sha256(combined_data)

    incident = {
        # metadata
        "platform": platform,
        "incident_date": incident_date,
        "relationship": relationship,

        # narrative & IOC
        "ioc_indicators": ioc_indicators,
        "narrative": narrative,

        # reporter info
        "reported_by": current_user,
        "created_at": datetime.utcnow(),

        # AI analysis
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "flagged": risk_level.lower() == "high",

        # AI threat classification
        "threat_type_suggested": threat_type,
        "immediate_actions": guidance["immediate"],
        "preventive_advice": guidance["preventive"],

        # workflow
        "status": "open",
        "analyst_reviewed": False,

        # integrity
        "evidence_hash": evidence_hash,

        # analyst review fields
        "analyst_name": None,
        "threat_type": None,
        "analyst_notes": None,
        "final_verdict": None,
        "response_actions": [],
        "reviewed_at": None,

        # history
        "history": [
            {
                "action": "Incident reported",
                "by": current_user,
                "time": datetime.utcnow()
            }
        ]
    }

    db.incidents.insert_one(incident)

    return jsonify({
        "msg": "Incident reported successfully",
        "risk_level": risk_level,
        "threat_type": threat_type,
        "immediate_actions": guidance["immediate"],
        "preventive_advice": guidance["preventive"],
        "note": "Automated safety guidance provided. Final verification will follow analyst review."
    }), 201


#✅ FETCH USER INCIDENTS
@incident_bp.route("/my-incidents", methods=["GET"])
@jwt_required()
def get_my_incidents():
    db = current_app.db
    current_user = get_jwt_identity()

    incidents = list(db.incidents.find({"reported_by": current_user}))

    for incident in incidents:
        incident["_id"] = str(incident["_id"])

    return jsonify(incidents), 200


#✅ FETCH INCIDENT ANALYSIS
@incident_bp.route("/analysis/<incident_id>", methods=["GET"])
@jwt_required()
def get_incident_analysis(incident_id):
    db = current_app.db
    current_user = get_jwt_identity()

    try:
        incident = db.incidents.find_one({"_id": ObjectId(incident_id)})
    except:
        return jsonify({"msg": "Invalid incident ID"}), 400

    if not incident:
        return jsonify({"msg": "Incident not found"}), 404

    if incident.get("reported_by") != current_user:
        return jsonify({"msg": "Unauthorized access"}), 403

    analysis = {
        "riskScore": incident.get("risk_score", 0),
        "riskLevel": incident.get("risk_level", "UNKNOWN"),
        "status": incident.get("status", "pending"),
        "analystReviewed": incident.get("analyst_reviewed", False),
        "platform": incident.get("platform"),
        "incident_date": incident.get("incident_date"),
        "created_at": incident.get("created_at"),
    }

    if incident.get("analyst_reviewed"):
        analysis.update({
            "threatType": incident.get("threat_type"),
            "analystNotes": incident.get("analyst_notes"),
            "finalVerdict": incident.get("final_verdict"),
            "responseActions": incident.get("response_actions", []),
            "preventiveAdvice": incident.get("preventive_advice", [])
        })
    else:
        analysis.update({
            "threatType": incident.get("threat_type_suggested"),
            "insights": incident.get("risk_reasons", []),
            "immediateActions": incident.get("immediate_actions", []),
            "preventiveAdvice": incident.get("preventive_advice", [])
        })

    return jsonify(analysis), 200


#✅ VERIFY INTEGRITY (UPDATED)
@incident_bp.route("/verify/<incident_id>", methods=["GET"])
@jwt_required()
def verify_incident(incident_id):
    db = current_app.db

    try:
        incident = db.incidents.find_one({"_id": ObjectId(incident_id)})
    except:
        return jsonify({"msg": "Invalid incident ID"}), 400

    if not incident:
        return jsonify({"msg": "Incident not found"}), 404

    combined_data = (
        incident.get("platform", "") +
        incident.get("incident_date", "") +
        incident.get("narrative", "") +
        incident.get("ioc_indicators", "")
    )

    new_hash = generate_sha256(combined_data)

    integrity_status = "valid" if new_hash == incident.get("evidence_hash") else "tampered"

    return jsonify({
        "incident_id": incident_id,
        "integrity": integrity_status
    }), 200