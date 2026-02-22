"""
Incident Model Definition
"""

class IncidentModel:
    """
    Schema for Incident document in MongoDB
    - platform: Platform where incident occurred
    - incident_date: Date of incident
    - relationship: User relationship to platform
    - ioc_indicators: Indicators of compromise
    - narrative: Description of the incident
    - reported_by: Username of reporter
    - created_at: Timestamp
    - risk_score: AI calculated risk score
    - risk_level: low | medium | high
    - threat_type: Classified threat type
    - evidence_hash: SHA256 integrity hash
    - evidence_hash_md5: MD5 integrity hash (hybrid verification)
    - status: open | in_progress | closed
    """
    COLLECTION = "incidents"
