export interface Attack {
  id: string
  timestamp: string
  website_url: string
  vulnerability_type: string
  attack_vector?: string
  technique_id: string
  success: boolean
  payload?: string
  source_ip: string
  user_agent?: string
  response_code?: number
  session_id: string
  agent_indicators?: {
    speed_score: number
    pattern_score: number
    coordination_score: number
    overall_agent_probability: number
    indicators: string[]
  }
}

export interface Stats {
  total_attacks: number
  attacks_24h: number
  attacks_7d: number
  attacks_30d: number
  successful_attacks: number
  failed_attacks: number
  websites_attacked: number
  successful_vulnerabilities: string[]
  failed_vulnerabilities: string[]
  attack_vectors: Array<{ vector: string; count: number }>
  website_stats: Array<{ url: string; total: number; successful: number }>
  vulnerability_stats: Array<{ type: string; total: number; successful: number }>
  time_series: Array<{ timestamp: string; count: number }>
  technique_stats: Array<{ technique_id: string; total: number; successful: number }>
}

export interface RiskForecast {
  current_risk_score: number
  risk_trajectory: Array<{
    date: string
    risk_score: number
    attacks: number
    successful: number
  }>
  forecast_24h: {
    predicted_attacks: number
    predicted_successful: number
    confidence: number
    risk_score: number
  }
  forecast_7d: {
    predicted_attacks: number
    predicted_successful: number
    confidence: number
    risk_score: number
  }
  forecast_30d: {
    predicted_attacks: number
    predicted_successful: number
    confidence: number
    risk_score: number
  }
  attack_probability: number
  vulnerability_exposure_score: number
  threat_level: 'low' | 'medium' | 'high' | 'critical'
  confidence: number
}

// ============================================
// Agent Trajectory Analysis Types
// ============================================

// Honeypot event captured from web traffic
export interface HoneypotEvent {
  id: string
  timestamp: string
  trajectory_id: string

  // HTTP request data
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD'
  path: string
  query_params: Record<string, string>
  headers: Record<string, string>
  body?: string

  // Response data
  response_code: number
  response_time_ms: number

  // Payload analysis
  detected_payload_type?: string  // sql_injection, xss, path_traversal, etc.
  payload_content?: string

  // Timing features (computed)
  time_since_last_event_ms?: number

  // Inferred technique (if detected)
  inferred_technique_id?: string
}

// Red team agent's internal step (full observability)
export interface AgentStep {
  step_number: number
  timestamp: string

  // Chain of thought from the agent
  reasoning: string

  // Tool usage (LangChain tool calls)
  tool_name: string
  tool_input: Record<string, unknown>
  tool_output: string

  // TTP classification (LLM-derived)
  tactic_id?: string       // e.g., TA0043
  tactic_name?: string     // e.g., Reconnaissance
  technique_id?: string    // e.g., T1595
  technique_name?: string  // e.g., Active Scanning
  procedure?: string       // e.g., "Port scanning with nmap"
}

// Base trajectory (shared between red team and external)
export interface BaseTrajectory {
  id: string
  vulnerability_id: string
  vulnerability_type: string
  target_endpoint: string
  started_at: string
  ended_at?: string
  success: boolean

  // Captured events from honeypot
  events: HoneypotEvent[]
}

// Red team trajectory (full observability)
export interface RedTeamTrajectory extends BaseTrajectory {
  type: 'red_team'

  // Agent internals we have access to
  agent_steps: AgentStep[]

  // Derived TTP summary
  ttps: TTPSummary
}

// External trajectory (event data only)
export interface ExternalTrajectory extends BaseTrajectory {
  type: 'external'
  session_id: string
  source_ip: string
  user_agent: string

  // Classifier predictions (computed)
  predictions?: TrajectoryPredictions
}

export type Trajectory = RedTeamTrajectory | ExternalTrajectory

// TTP summary derived from trajectory
export interface TTPSummary {
  tactics: Array<{
    id: string
    name: string
    order: number
  }>
  techniques: Array<{
    id: string
    name: string
    tactic_id: string
    confidence: number
  }>
  procedures: string[]
}

// ============================================
// Classifier Types
// ============================================

// Agent detection classifier output
export interface AgentDetectionResult {
  is_agent: boolean
  confidence: number  // 0-1
  confidence_level: 'low' | 'medium' | 'high'
  indicators: string[]
  feature_contributions: Array<{
    feature: string
    value: number
    contribution: number
  }>
}

// TTP prediction classifier output
export interface TTPPrediction {
  technique_id: string
  technique_name: string
  tactic_id: string
  probability: number  // 0-1
  evidence: string[]
}

// Stage classifier output (kill chain position)
export interface StageClassification {
  current_stage: 'reconnaissance' | 'weaponization' | 'delivery' | 'exploitation' | 'installation' | 'command_control' | 'actions'
  stage_confidence: number
  stages_completed: string[]
  next_likely_stage: string
  progress_percentage: number
}

// Velocity/timing analysis
export interface VelocityAnalysis {
  automation_score: number  // 0-1 (1 = definitely automated)
  avg_time_between_actions_ms: number
  time_to_next_action_predicted_ms: number
  burst_detected: boolean
  timing_pattern: 'human' | 'scripted' | 'ml_agent' | 'unknown'
}

// Red team pattern matching
export interface ThreatPatternMatch {
  similarity_to_red_team: number  // 0-1
  matched_pattern_id?: string
  matched_pattern_name?: string
  divergence_points: Array<{
    step: number
    expected_action: string
    actual_action: string
  }>
}

// Combined predictions for external trajectory
export interface TrajectoryPredictions {
  // Core classifiers
  agent_detection: AgentDetectionResult
  ttp_predictions: TTPPrediction[]
  stage_classification: StageClassification
  velocity_analysis: VelocityAnalysis
  threat_match: ThreatPatternMatch

  // Aggregate scores
  overall_threat_score: number  // 0-100
  threat_level: 'low' | 'medium' | 'high' | 'critical'

  // Early warning
  early_warning: EarlyWarning
}

// Early warning system output
export interface EarlyWarning {
  alert_level: 'none' | 'watch' | 'warning' | 'critical'
  alert_reasons: string[]
  predicted_target: string
  predicted_technique: string
  time_to_action_seconds: number
  recommended_intervention: string
  confidence: number
}

// ============================================
// Comparison Types
// ============================================

export interface TrajectoryComparison {
  red_team_trajectory_id: string
  external_trajectory_id: string

  // Timeline comparison
  timeline_alignment: Array<{
    timestamp: string
    red_team_action?: string
    external_action?: string
    alignment_score: number
  }>

  // TTP coverage comparison
  ttp_coverage: {
    shared_techniques: string[]
    red_team_only: string[]
    external_only: string[]
    coverage_percentage: number
  }

  // Key metrics
  similarity_score: number  // 0-1
  time_difference_seconds: number
  divergence_points: number

  // Analysis
  key_differences: string[]
  behavioral_insights: string[]
}

// ============================================
// Recommendation Types
// ============================================

export interface VulnerabilityRecommendations {
  vulnerability_id: string
  vulnerability_type: string

  // Detection rules
  detection_rules: Array<{
    id: string
    title: string
    description: string
    related_techniques: string[]
    priority: 'low' | 'medium' | 'high' | 'critical'
  }>

  // Early warning patterns
  early_warning_patterns: Array<{
    pattern: string
    description: string
    typical_step: number
    detection_window_seconds: number
  }>

  // Mitigation strategies
  mitigations: Array<{
    title: string
    description: string
    blocks_techniques: string[]
    implementation_effort: 'low' | 'medium' | 'high'
  }>
}

// ============================================
// Honeypot Vulnerability Reference
// ============================================

export interface HoneypotVulnerability {
  id: string
  name: string
  type: string  // sql_injection, xss, path_traversal, rce, etc.
  endpoint: string
  description: string

  // Expected attack patterns (from red team)
  expected_ttps: string[]

  // Statistics
  stats: {
    total_attempts: number
    successful_attempts: number
    red_team_trajectories: number
    external_trajectories: number
    avg_steps_to_exploit: number
    avg_time_to_exploit_seconds: number
  }

  // Risk assessment
  risk_level: 'low' | 'medium' | 'high' | 'critical'

  // Recommendations
  recommendations: VulnerabilityRecommendations
}

// ============================================
// Classifier Model Metadata
// ============================================

export interface ClassifierModelInfo {
  name: string
  version: string
  trained_at: string

  // Training stats
  training_data: {
    red_team_trajectories: number
    external_trajectories: number
    total_events: number
  }

  // Performance metrics
  performance: {
    accuracy: number
    precision: number
    recall: number
    f1_score: number
  }

  // Feature importance
  feature_importance: Array<{
    feature_name: string
    importance: number
  }>
}

