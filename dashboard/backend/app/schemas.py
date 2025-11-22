"""Pydantic schemas for API requests/responses"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class AgentIndicators(BaseModel):
    speed_score: float
    pattern_score: float
    coordination_score: float
    overall_agent_probability: float
    indicators: List[str]


class AttackResponse(BaseModel):
    id: str
    timestamp: datetime
    website_url: str
    vulnerability_type: str
    attack_vector: Optional[str] = None
    technique_id: str
    success: bool
    payload: Optional[str] = None
    source_ip: str
    user_agent: Optional[str] = None
    response_code: Optional[int] = None
    session_id: str
    agent_indicators: Optional[AgentIndicators] = None  # Disabled for now


class StatsResponse(BaseModel):
    total_attacks: int
    attacks_24h: int
    attacks_7d: int
    attacks_30d: int
    successful_attacks: int
    failed_attacks: int
    websites_attacked: int
    successful_vulnerabilities: List[str]
    failed_vulnerabilities: List[str]
    attack_vectors: List[Dict[str, Any]]
    website_stats: List[Dict[str, Any]]
    vulnerability_stats: List[Dict[str, Any]]
    time_series: List[Dict[str, Any]]
    technique_stats: List[Dict[str, Any]]


class RiskForecast(BaseModel):
    current_risk_score: float
    risk_trajectory: List[Dict[str, Any]]
    forecast_24h: Dict[str, Any]
    forecast_7d: Dict[str, Any]
    forecast_30d: Dict[str, Any]
    attack_probability: float
    vulnerability_exposure_score: float
    threat_level: str  # low, medium, high, critical
    confidence: float

