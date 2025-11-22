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


# MITRE Risk Portfolio Schemas
class MitreTechniqueRiskResponse(BaseModel):
    technique_id: str
    technique_name: str
    risk_score: float
    attack_count: int
    successful_count: int
    success_rate: float
    recent_activity: int
    trend: str
    tactics: List[str]
    severity_multiplier: float = 1.0


class MitreTacticRiskResponse(BaseModel):
    tactic_id: str
    tactic_name: str
    risk_score: float
    attack_count: int
    successful_count: int
    unique_techniques: int
    exposure_score: float
    trend: str
    trend_score: float
    techniques: List[Dict[str, Any]]


class RiskPortfolioResponse(BaseModel):
    tactics: List[MitreTacticRiskResponse]
    overall_risk_score: float
    high_risk_tactics: List[str]
    moderate_risk_tactics: List[str]
    low_risk_tactics: List[str]
    risk_distribution: Dict[str, float]


class RiskProjectionResponse(BaseModel):
    time_horizon: str
    predicted_attacks: int
    predicted_techniques: int
    predicted_tactics: int
    high_risk_tactics: List[str]
    high_risk_techniques: List[str]
    confidence: float
    risk_trajectory: List[Dict[str, Any]]
    tactic_projections: Dict[str, Dict[str, Any]]


# Advanced Risk Forecast Schemas
class RiskScoreBreakdown(BaseModel):
    """Detailed breakdown of risk score calculation"""
    attack_frequency: Dict[str, Any]
    success_rate: Dict[str, Any]
    vulnerability_diversity: Dict[str, Any]
    trend_momentum: Dict[str, Any]
    methodology: Dict[str, Any]
    data_quality: Dict[str, Any]


class AdvancedRiskForecastResponse(BaseModel):
    """Advanced risk forecast with full transparency"""
    risk_score: float
    risk_score_breakdown: RiskScoreBreakdown
    projection_24h: Dict[str, Any]
    projection_7d: Dict[str, Any]
    projection_30d: Dict[str, Any]
    methodology: Dict[str, Any]
    statistical_analysis: Dict[str, Any]
    data_quality_assessment: Dict[str, Any]
