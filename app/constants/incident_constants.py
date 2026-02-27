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

SUPPORTED_PLATFORMS = [
    "WhatsApp",
    "Facebook",
    "Instagram",
    "Twitter (X)",
    "LinkedIn",
    "Telegram",
    "TikTok",
    "Snapchat",
    "Email",
    "SMS",
    "Other"
]

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
    },
    "Phishing": {
        "immediate": [
            "Do not enter any credentials",
            "Change passwords if already entered",
            "Report as phishing to the platform"
        ],
        "preventive": [
            "Check sender email/URL carefully",
            "Enable MFA",
            "Use browser protection"
        ]
    },
    "Malware": {
        "immediate": [
            "Disconnect from network",
            "Run full system scan",
            "Do not open any attachments"
        ],
        "preventive": [
            "Keep software updated",
            "Don't download from untrusted sources",
            "Use reliable antivirus"
        ]
    }
}

class ThreatTypes:
    PHISHING = "Phishing"
    MALWARE = "Malware"
    MALICIOUS_LINK = "Malicious Link"
    CREDENTIAL_THEFT = "Credential Theft"
    SOCIAL_ENGINEERING = "Social Engineering"
    SUSPICIOUS_MESSAGE = "Suspicious Message"

THREAT_TYPES_LIST = [
    ThreatTypes.PHISHING,
    ThreatTypes.MALWARE,
    ThreatTypes.MALICIOUS_LINK,
    ThreatTypes.CREDENTIAL_THEFT,
    ThreatTypes.SOCIAL_ENGINEERING,
    ThreatTypes.SUSPICIOUS_MESSAGE
]
