from datetime import datetime
from flask import current_app, request
from bson.json_util import dumps

def log_activity(actor, event_type, details=None, ip_address=None, role=None):
    """
    Logs an activity to the audit_logs collection.
    """
    db = current_app.db
    
    if not ip_address:
        ip_address = request.remote_addr if request else "0.0.0.0"

    log_entry = {
        "actor": actor,
        "event_type": event_type,
        "details": details or {},
        "ip_address": ip_address,
        "role": role,
        "timestamp": datetime.utcnow()
    }
    
    try:
        db.audit_logs.insert_one(log_entry)
        current_app.logger.info(f"AUDIT LOG: {actor} - {event_type} - {ip_address}")
    except Exception as e:
        current_app.logger.error(f"Failed to write audit log: {e}")

def get_audit_logs(page=1, limit=50, filters=None):
    """
    Retrieves audit logs from the database.
    """
    db = current_app.db
    query = filters if filters else {}
    
    skip = (page - 1) * limit
    
    logs = db.audit_logs.find(query).sort("timestamp", -1).skip(skip).limit(limit)
    total = db.audit_logs.count_documents(query)
    
    return {
        "logs": list(logs),
        "total": total,
        "page": page,
        "limit": limit
    }
