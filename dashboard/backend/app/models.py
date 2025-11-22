"""Data models matching Supabase schema"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class VulnerabilityLog(BaseModel):
    """Model for vulnerability_logs table"""
    id: str
    base_url: str
    vulnerability_type: str
    technique_id: str
    timestamp: datetime
    attacker_id: str
    session_id: str
    is_synthetic: Optional[bool] = None
    success: Optional[bool] = None
    
    class Config:
        from_attributes = True


class Attack(BaseModel):
    """Attack representation for internal use"""
    id: str
    timestamp: datetime
    website_url: str  # Maps to base_url
    vulnerability_type: str
    attack_vector: Optional[str] = None  # Derived from vulnerability_type
    technique_id: str
    success: bool  # Derived: correct API key = success
    payload: Optional[str] = None
    source_ip: str  # Maps to attacker_id
    user_agent: Optional[str] = None
    response_code: Optional[int] = None
    session_id: str
    
    @classmethod
    def from_vulnerability_log(cls, log: dict):
        """Convert vulnerability_log to Attack"""
        # Use success column from database, fallback to vulnerability_type inference if NULL
        success_db = log.get("success")
        if success_db is not None:
            success = bool(success_db)
        else:
            # Fallback: infer from vulnerability_type (for backward compatibility)
            success = "correct" in log.get("vulnerability_type", "").lower()
        
        # Determine attack vector from vulnerability type
        vuln_type = log.get("vulnerability_type", "")
        if "api-key" in vuln_type:
            attack_vector = f"API Key Access - {vuln_type}"
        else:
            attack_vector = vuln_type
        
        # Parse timestamp - handle both string and datetime objects
        from datetime import timezone
        timestamp_str = log.get("timestamp", "")
        if isinstance(timestamp_str, str):
            # Replace Z with +00:00 for ISO format
            if timestamp_str.endswith("Z"):
                timestamp_str = timestamp_str.replace("Z", "+00:00")
            timestamp = datetime.fromisoformat(timestamp_str)
            # Ensure timezone-aware
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            # If it's already a datetime object
            timestamp = timestamp_str
            # Ensure timezone-aware
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        
        return cls(
            id=log["id"],
            timestamp=timestamp,
            website_url=log["base_url"],
            vulnerability_type=vuln_type,
            attack_vector=attack_vector,
            technique_id=log.get("technique_id", ""),
            success=success,
            source_ip=log.get("attacker_id", ""),
            session_id=log.get("session_id", ""),
        )

