"""Pydantic schemas for Agent Trajectory Analysis API"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime


# ============================================
# Honeypot Event Schemas
# ============================================

class HoneypotEventSchema(BaseModel):
    id: str
    timestamp: datetime
    trajectory_id: str

    # HTTP request
    method: Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
    path: str
    query_params: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    body: Optional[str] = None

    # Response
    response_code: int
    response_time_ms: float

    # Payload analysis
    detected_payload_type: Optional[str] = None
    payload_content: Optional[str] = None

    # Timing
    time_since_last_event_ms: Optional[float] = None

    # Inferred technique
    inferred_technique_id: Optional[str] = None


# ============================================
# Agent Step Schemas (Red Team)
# ============================================

class AgentStepSchema(BaseModel):
    step_number: int
    timestamp: datetime

    # Chain of thought
    reasoning: str

    # Tool usage
    tool_name: str
    tool_input: Dict[str, Any]
    tool_output: str

    # TTP classification
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    procedure: Optional[str] = None


# ============================================
# TTP Schemas
# ============================================

class TTPTacticSchema(BaseModel):
    id: str
    name: str
    order: int


class TTPTechniqueSchema(BaseModel):
    id: str
    name: str
    tactic_id: str
    confidence: float


class TTPSummarySchema(BaseModel):
    tactics: List[TTPTacticSchema]
    techniques: List[TTPTechniqueSchema]
    procedures: List[str]


# ============================================
# Classifier Output Schemas
# ============================================

class FeatureContributionSchema(BaseModel):
    feature: str
    value: float
    contribution: float


class AgentDetectionResultSchema(BaseModel):
    is_agent: bool
    confidence: float
    confidence_level: Literal['low', 'medium', 'high']
    indicators: List[str]
    feature_contributions: List[FeatureContributionSchema]


class TTPPredictionSchema(BaseModel):
    technique_id: str
    technique_name: str
    tactic_id: str
    probability: float
    evidence: List[str]


class StageClassificationSchema(BaseModel):
    current_stage: Literal[
        'reconnaissance', 'weaponization', 'delivery',
        'exploitation', 'installation', 'command_control', 'actions'
    ]
    stage_confidence: float
    stages_completed: List[str]
    next_likely_stage: str
    progress_percentage: float


class VelocityAnalysisSchema(BaseModel):
    automation_score: float
    avg_time_between_actions_ms: float
    time_to_next_action_predicted_ms: float
    burst_detected: bool
    timing_pattern: Literal['human', 'scripted', 'ml_agent', 'unknown']


class DivergencePointSchema(BaseModel):
    step: int
    expected_action: str
    actual_action: str


class ThreatPatternMatchSchema(BaseModel):
    similarity_to_red_team: float
    matched_pattern_id: Optional[str] = None
    matched_pattern_name: Optional[str] = None
    divergence_points: List[DivergencePointSchema]


class EarlyWarningSchema(BaseModel):
    alert_level: Literal['none', 'watch', 'warning', 'critical']
    alert_reasons: List[str]
    predicted_target: str
    predicted_technique: str
    time_to_action_seconds: float
    recommended_intervention: str
    confidence: float


class TrajectoryPredictionsSchema(BaseModel):
    agent_detection: AgentDetectionResultSchema
    ttp_predictions: List[TTPPredictionSchema]
    stage_classification: StageClassificationSchema
    velocity_analysis: VelocityAnalysisSchema
    threat_match: ThreatPatternMatchSchema

    overall_threat_score: float
    threat_level: Literal['low', 'medium', 'high', 'critical']

    early_warning: EarlyWarningSchema


# ============================================
# Trajectory Schemas
# ============================================

class BaseTrajectorySchema(BaseModel):
    id: str
    vulnerability_id: str
    vulnerability_type: str
    target_endpoint: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    success: bool
    events: List[HoneypotEventSchema]


class RedTeamTrajectorySchema(BaseTrajectorySchema):
    type: Literal['red_team'] = 'red_team'
    agent_steps: List[AgentStepSchema]
    ttps: TTPSummarySchema


class ExternalTrajectorySchema(BaseTrajectorySchema):
    type: Literal['external'] = 'external'
    session_id: str
    source_ip: str
    user_agent: str
    predictions: Optional[TrajectoryPredictionsSchema] = None


# ============================================
# Comparison Schemas
# ============================================

class TimelineAlignmentSchema(BaseModel):
    timestamp: datetime
    red_team_action: Optional[str] = None
    external_action: Optional[str] = None
    alignment_score: float


class TTPCoverageSchema(BaseModel):
    shared_techniques: List[str]
    red_team_only: List[str]
    external_only: List[str]
    coverage_percentage: float


class TrajectoryComparisonSchema(BaseModel):
    red_team_trajectory_id: str
    external_trajectory_id: str

    timeline_alignment: List[TimelineAlignmentSchema]
    ttp_coverage: TTPCoverageSchema

    similarity_score: float
    time_difference_seconds: float
    divergence_points: int

    key_differences: List[str]
    behavioral_insights: List[str]


# ============================================
# Recommendation Schemas
# ============================================

class DetectionRuleSchema(BaseModel):
    id: str
    title: str
    description: str
    related_techniques: List[str]
    priority: Literal['low', 'medium', 'high', 'critical']


class EarlyWarningPatternSchema(BaseModel):
    pattern: str
    description: str
    typical_step: int
    detection_window_seconds: float


class MitigationSchema(BaseModel):
    title: str
    description: str
    blocks_techniques: List[str]
    implementation_effort: Literal['low', 'medium', 'high']


class VulnerabilityRecommendationsSchema(BaseModel):
    vulnerability_id: str
    vulnerability_type: str
    detection_rules: List[DetectionRuleSchema]
    early_warning_patterns: List[EarlyWarningPatternSchema]
    mitigations: List[MitigationSchema]


# ============================================
# Honeypot Vulnerability Schemas
# ============================================

class VulnerabilityStatsSchema(BaseModel):
    total_attempts: int
    successful_attempts: int
    red_team_trajectories: int
    external_trajectories: int
    avg_steps_to_exploit: float
    avg_time_to_exploit_seconds: float


class HoneypotVulnerabilitySchema(BaseModel):
    id: str
    name: str
    type: str
    endpoint: str
    description: str
    expected_ttps: List[str]
    stats: VulnerabilityStatsSchema
    risk_level: Literal['low', 'medium', 'high', 'critical']
    recommendations: VulnerabilityRecommendationsSchema


# ============================================
# Classifier Model Info Schemas
# ============================================

class TrainingDataStatsSchema(BaseModel):
    red_team_trajectories: int
    external_trajectories: int
    total_events: int


class ModelPerformanceSchema(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float


class FeatureImportanceSchema(BaseModel):
    feature_name: str
    importance: float


class ClassifierModelInfoSchema(BaseModel):
    name: str
    version: str
    trained_at: datetime
    training_data: TrainingDataStatsSchema
    performance: ModelPerformanceSchema
    feature_importance: List[FeatureImportanceSchema]


# ============================================
# API Request/Response Schemas
# ============================================

class ClassifyTrajectoryRequest(BaseModel):
    """Request to classify an external trajectory"""
    events: List[HoneypotEventSchema]
    vulnerability_type: Optional[str] = None


class ClassifyTrajectoryResponse(BaseModel):
    """Full classification result"""
    predictions: TrajectoryPredictionsSchema
    model_info: ClassifierModelInfoSchema


class VulnerabilityListResponse(BaseModel):
    """List of honeypot vulnerabilities"""
    vulnerabilities: List[HoneypotVulnerabilitySchema]
    total: int


class TrajectoryListResponse(BaseModel):
    """List of trajectories for a vulnerability"""
    red_team: List[RedTeamTrajectorySchema]
    external: List[ExternalTrajectorySchema]
    total_red_team: int
    total_external: int
