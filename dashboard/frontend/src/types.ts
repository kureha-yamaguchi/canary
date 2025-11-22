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

