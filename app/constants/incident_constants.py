class IncidentMessages:
    INVALID_REQUEST = "Invalid request body"
    REQUIRED_FIELDS_MISSING = "Required fields missing"
    CONFIRMATION_REQUIRED = "You must confirm the report"
    REPORT_SUCCESS = "Incident reported successfully"
    INVALID_ID = "Invalid incident ID"
    NOT_FOUND = "Incident not found"
    UNAUTHORIZED = "Unauthorized access"
    INTEGRITY_VALID = "Evidence integrity verified (SHA-256 + MD5)"
    INTEGRITY_TAMPERED = "Evidence integrity FAILED — tampering detected"

class AdminMessages:
    STAFF_ONLY = "Staff only"
    ADMIN_ONLY = "Admins only"
    CERT_OR_ADMIN_ONLY = "CERT Analysts or Admins only"
    INSUFFICIENT_PERMISSIONS = "Insufficient permissions"
    NOT_FOUND = "Not found"
    INVALID_ID = "Invalid ID"
    STATUS_REQUIRED = "Status required"
    REVIEW_STARTED = "Review started"
    REVIEW_SUCCESS = "Incident reviewed successfully"
    STATUS_UPDATED = "Status updated"
    INCIDENT_CREATED = "Incident created"
    INCIDENT_DELETED = "Incident deleted"

PLAYBOOK = {
    "Malicious Link": {
        "immediate": [
            "Do NOT click the link again",
            "Disconnect internet if device behaves suspiciously",
            "Run antivirus scan immediately"
        ],
        "preventive": [
            "Avoid clicking unknown links",
            "Verify URLs before visiting",
            "Keep antivirus updated"
        ]
    },
    "Credential Theft": {
        "immediate": [
            "Change all passwords immediately",
            "Enable two-factor authentication",
            "Log out from all devices"
        ],
        "preventive": [
            "Never share OTP or passwords",
            "Use a password manager",
            "Avoid logging into unknown sites"
        ]
    },
    "Social Engineering": {
        "immediate": [
            "Do not respond to the sender",
            "Block and report the account",
            "Avoid sharing personal information"
        ],
        "preventive": [
            "Be cautious of urgent requests",
            "Verify identity before sharing information"
        ]
    },
    "Suspicious Message": {
        "immediate": [
            "Do not interact with the message",
            "Verify sender authenticity"
        ],
        "preventive": [
            "Stay cautious of unknown communications"
        ]
    }
}
