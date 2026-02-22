"""
Security Utilities — Evidence Integrity Hashing
Provides MD5 + SHA-256 hybrid hashing for forensic evidence chain.
"""
import hashlib


def generate_sha256(data: str) -> str:
    """Generate SHA-256 hex digest from string data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def generate_md5(data: str) -> str:
    """Generate MD5 hex digest from string data."""
    return hashlib.md5(data.encode('utf-8')).hexdigest()


def generate_evidence_hashes(data: str) -> dict:
    """
    Generate hybrid hash (SHA-256 + MD5) for evidence integrity.
    Returns dict with both hashes for dual-algorithm verification.
    """
    return {
        "sha256": generate_sha256(data),
        "md5": generate_md5(data)
    }


def build_evidence_string(platform: str, incident_date: str, narrative: str, ioc_indicators: str) -> str:
    """
    Build the canonical evidence string from incident fields.
    Centralizes the hash-input construction to avoid duplication.
    """
    return (platform or "") + (incident_date or "") + (narrative or "") + (ioc_indicators or "")


def verify_evidence_integrity(incident: dict) -> dict:
    """
    Verify stored hashes against recalculated hashes from incident data.
    Returns per-algorithm verification result.
    """
    combined_data = build_evidence_string(
        incident.get("platform", ""),
        incident.get("incident_date", ""),
        incident.get("narrative", ""),
        incident.get("ioc_indicators", "")
    )

    recalculated = generate_evidence_hashes(combined_data)

    stored_sha256 = incident.get("evidence_hash", "")
    stored_md5 = incident.get("evidence_hash_md5", "")

    sha256_valid = recalculated["sha256"] == stored_sha256
    md5_valid = recalculated["md5"] == stored_md5

    overall = "valid" if (sha256_valid and md5_valid) else "tampered"

    return {
        "integrity": overall,
        "sha256": {
            "status": "valid" if sha256_valid else "tampered",
            "hash": recalculated["sha256"]
        },
        "md5": {
            "status": "valid" if md5_valid else "tampered",
            "hash": recalculated["md5"]
        }
    }
