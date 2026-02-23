from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from bson import ObjectId
from app.services.risk_engine import calculate_risk_score, detect_threat_type
from app.constants.incident_constants import PLAYBOOK, IncidentMessages, SUPPORTED_PLATFORMS
from app.utils.security import generate_evidence_hashes, build_evidence_string, verify_evidence_integrity
from app.services.audit_service import log_activity
from app.constants.audit_constants import AuditEvents
from app.services.ocr_service import extract_text_from_images

incident_bp = Blueprint("incident", __name__)


#✅ REPORT INCIDENT (UPDATED FOR NEW FORM)
@incident_bp.route("/report", methods=["POST"])
@jwt_required()
def report_incident():

    db = current_app.db
    current_user = get_jwt_identity()
    data = request.form if request.form else request.get_json()
    files = request.files.getlist("files")

    if not data:
        return jsonify({"msg": IncidentMessages.INVALID_REQUEST}), 400

    # 📥 Extract fields from new form
    platform = data.get("platform")
    incident_date = data.get("incident_date")
    relationship = data.get("relationship")
    custom_platform = data.get("custom_platform")
    ioc_indicators = data.get("ioc_indicators", "")
    narrative = data.get("narrative", "")
    confirmation = data.get("confirmation", False)

    # ✅ Validate required fields
    if not platform or not incident_date or not narrative:
        return jsonify({"msg": IncidentMessages.REQUIRED_FIELDS_MISSING}), 400

    if not confirmation:
        return jsonify({"msg": IncidentMessages.CONFIRMATION_REQUIRED}), 400

    # 🔄 Handle "Other" platform
    final_platform = platform
    if platform == "Other" and custom_platform:
        final_platform = custom_platform

    # 🔍 OCR: Extract text from uploaded images
    ocr_text = ""
    ocr_results = []
    if files:
        ocr_text, ocr_results = extract_text_from_images(files)
        current_app.logger.info(f"OCR extracted {len(ocr_text)} chars from {len(files)} file(s)")

    # 🔎 Combine text for analysis (narrative + IOC + OCR extracted text)
    combined_text = narrative + " " + ioc_indicators
    if ocr_text:
        combined_text += " " + ocr_text

    # 🤖 Risk scoring (now includes OCR text)
    risk_score, risk_level, risk_reasons = calculate_risk_score(
        combined_text, narrative, ioc_indicators + " " + ocr_text
    )

    # 🌐 Detect URL presence
    malicious_url_found = "http" in ioc_indicators.lower()

    # urgency detection
    urgency_score = 15 if any(word in narrative.lower() for word in ["urgent", "immediately", "now"]) else 0

    # 🧠 Threat type detection
    threat_type = detect_threat_type(combined_text, malicious_url_found, urgency_score)

    # 📘 Safety guidance
    guidance = PLAYBOOK.get(threat_type, PLAYBOOK["Suspicious Message"])

    # 🔐 Evidence integrity hash (Hybrid: SHA-256 + MD5)
    combined_data = build_evidence_string(platform, incident_date, narrative, ioc_indicators)
    hashes = generate_evidence_hashes(combined_data)

    incident = {
        # metadata
        "platform": final_platform,
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
        "evidence_hash": hashes["sha256"],
        "evidence_hash_md5": hashes["md5"],

        # analyst review fields
        "analyst_name": None,
        "threat_type": None,
        "analyst_notes": None,
        "final_verdict": None,
        "response_actions": [],
        "reviewed_at": None,

        # OCR data
        "ocr_extracted_text": ocr_text if ocr_text else None,
        "ocr_results": ocr_results,

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

    log_activity(
        actor=current_user,
        event_type=AuditEvents.INCIDENT_REPORTED,
        details={"platform": final_platform, "risk_level": risk_level}
    )

    return jsonify({
        "msg": IncidentMessages.REPORT_SUCCESS,
        "risk_level": risk_level,
        "threat_type": threat_type,
        "immediate_actions": guidance["immediate"],
        "preventive_advice": guidance["preventive"],
        "ocr_extracted_text": ocr_text if ocr_text else None,
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
        return jsonify({"msg": IncidentMessages.INVALID_ID}), 400

    if not incident:
        return jsonify({"msg": IncidentMessages.NOT_FOUND}), 404

    if incident.get("reported_by") != current_user:
        return jsonify({"msg": IncidentMessages.UNAUTHORIZED}), 403

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


#✅ VERIFY INTEGRITY (Hybrid: SHA-256 + MD5)
@incident_bp.route("/verify/<incident_id>", methods=["GET"])
@jwt_required()
def verify_incident(incident_id):
    db = current_app.db

    try:
        incident = db.incidents.find_one({"_id": ObjectId(incident_id)})
    except:
        return jsonify({"msg": IncidentMessages.INVALID_ID}), 400

    if not incident:
        return jsonify({"msg": IncidentMessages.NOT_FOUND}), 404

    result = verify_evidence_integrity(incident)

    return jsonify({
        "incident_id": incident_id,
        **result
    }), 200

#✅ FETCH SUPPORTED PLATFORMS
@incident_bp.route("/platforms", methods=["GET"])
def get_supported_platforms():
    return jsonify({
        "platforms": SUPPORTED_PLATFORMS
    }), 200