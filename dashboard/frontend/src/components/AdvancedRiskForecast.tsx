import { useState, useEffect } from 'react'
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, AreaChart, Area } from 'recharts'
import { format } from 'date-fns'
import { SyntheticDataToggle } from './SyntheticDataToggle'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

interface RiskScoreBreakdown {
  attack_frequency: {
    value: number
    normalized: number
    weight: number
    contribution: number
  }
  success_rate: {
    value: number
    normalized: number
    weight: number
    contribution: number
    successful: number
    total: number
  }
  vulnerability_diversity: {
    value: number
    normalized: number
    weight: number
    contribution: number
    unique_websites: number
  }
  trend_momentum: {
    value: number
    normalized: number
    weight: number
    contribution: number
    direction: string
    recent_3d: number
    prev_4d: number
  }
  methodology: any
  data_quality: any
}

interface Projection {
  predicted_attacks: number
  predicted_successful: number
  prediction_range: { lower: number; upper: number }
  confidence: number
  methodology: any
  statistics: any
  data_quality: any
}

interface AdvancedRiskForecast {
  risk_score: number
  risk_score_breakdown: RiskScoreBreakdown
  projection_24h: Projection
  projection_7d: Projection
  projection_30d: Projection
  methodology: any
  statistical_analysis: any
  data_quality_assessment: any
}

export function AdvancedRiskForecast() {
  const [forecast, setForecast] = useState<AdvancedRiskForecast | null>(null)
  const [loading, setLoading] = useState(true)
  const [includeSynthetic, setIncludeSynthetic] = useState(false)
  const [showMethodology, setShowMethodology] = useState(false)

  useEffect(() => {
    fetchForecast()
    const interval = setInterval(() => {
      fetchForecast()
    }, 60000) // Refresh every minute
    return () => clearInterval(interval)
  }, [includeSynthetic])

  const fetchForecast = async () => {
    try {
      setLoading(true)
      const response = await fetch(`${API_BASE}/api/advanced-risk-forecast?include_synthetic=${includeSynthetic}`)
      const data = await response.json()
      setForecast(data)
    } catch (error) {
      console.error('Error fetching advanced risk forecast:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading advanced risk forecast...</div>
      </div>
    )
  }

  if (!forecast) {
    return (
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <p className="text-slate-400">Advanced risk forecast not available yet.</p>
      </div>
    )
  }

  const { risk_score_breakdown, projection_24h, projection_7d, projection_30d, statistical_analysis } = forecast

  // Risk trajectory data
  const trajectoryData = [
    { time: '24h', predicted: projection_24h.predicted_attacks, lower: projection_24h.prediction_range.lower, upper: projection_24h.prediction_range.upper },
    { time: '7d', predicted: projection_7d.predicted_attacks, lower: projection_7d.prediction_range.lower, upper: projection_7d.prediction_range.upper },
    { time: '30d', predicted: projection_30d.predicted_attacks, lower: projection_30d.prediction_range.lower, upper: projection_30d.prediction_range.upper }
  ]

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-red-400'
    if (score >= 40) return 'text-yellow-400'
    return 'text-green-400'
  }

  const getRiskBgColor = (score: number) => {
    if (score >= 70) return 'bg-red-500'
    if (score >= 40) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  return (
    <div className="space-y-6">
      {/* Header with Toggle */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Advanced Risk Analysis</h2>
          <p className="text-slate-400 text-sm mt-1">
            Statistical forecasting with full transparency on calculations
          </p>
        </div>
        <SyntheticDataToggle 
          includeSynthetic={includeSynthetic}
          onToggle={setIncludeSynthetic}
        />
      </div>

      {/* Current Risk Score with Breakdown */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold text-white">Current Risk Score</h3>
          <span className={`text-4xl font-bold ${getRiskColor(forecast.risk_score)}`}>
            {forecast.risk_score.toFixed(1)}
          </span>
        </div>

        {/* Risk Score Progress Bar */}
        <div className="mb-6">
          <div className="w-full bg-slate-700 rounded-full h-4 mb-2">
            <div
              className={`h-4 rounded-full ${getRiskBgColor(forecast.risk_score)}`}
              style={{ width: `${Math.min(forecast.risk_score, 100)}%` }}
            ></div>
          </div>
        </div>

        {/* Risk Score Breakdown */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {risk_score_breakdown && (
            <>
              <FactorCard
                title="Attack Frequency"
                value={risk_score_breakdown.attack_frequency.value}
                contribution={risk_score_breakdown.attack_frequency.contribution.toFixed(1)}
                weight={`${(risk_score_breakdown.attack_frequency.weight * 100).toFixed(0)}%`}
                color="text-blue-400"
              />
              <FactorCard
                title="Success Rate"
                value={`${(risk_score_breakdown.success_rate.value * 100).toFixed(1)}%`}
                contribution={risk_score_breakdown.success_rate.contribution.toFixed(1)}
                weight={`${(risk_score_breakdown.success_rate.weight * 100).toFixed(0)}%`}
                subtitle={`${risk_score_breakdown.success_rate.successful}/${risk_score_breakdown.success_rate.total}`}
                color="text-red-400"
              />
              <FactorCard
                title="Vulnerability Diversity"
                value={risk_score_breakdown.vulnerability_diversity.value}
                contribution={risk_score_breakdown.vulnerability_diversity.contribution.toFixed(1)}
                weight={`${(risk_score_breakdown.vulnerability_diversity.weight * 100).toFixed(0)}%`}
                color="text-purple-400"
              />
              <FactorCard
                title="Trend Momentum"
                value={risk_score_breakdown.trend_momentum.direction}
                contribution={risk_score_breakdown.trend_momentum.contribution.toFixed(1)}
                weight={`${(risk_score_breakdown.trend_momentum.weight * 100).toFixed(0)}%`}
                subtitle={`${risk_score_breakdown.trend_momentum.recent_3d} recent vs ${risk_score_breakdown.trend_momentum.prev_4d} previous`}
                color="text-yellow-400"
              />
            </>
          )}
        </div>

        {/* Methodology Toggle */}
        <button
          onClick={() => setShowMethodology(!showMethodology)}
          className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
        >
          {showMethodology ? '▼ Hide' : '▶ Show'} Calculation Methodology
        </button>

        {showMethodology && risk_score_breakdown?.methodology && (
          <div className="mt-4 p-4 bg-slate-900 rounded-lg border border-slate-700">
            <h4 className="text-sm font-semibold text-white mb-3">Risk Score Calculation Method</h4>
            <div className="text-xs text-slate-400 space-y-2">
              <p><strong className="text-slate-300">Method:</strong> {risk_score_breakdown.methodology.method}</p>
              <div>
                <strong className="text-slate-300">Factors:</strong>
                <ul className="ml-4 mt-1 space-y-1">
                  {Object.entries(risk_score_breakdown.methodology.factors || {}).map(([key, factor]: [string, any]) => (
                    <li key={key}>
                      • <strong>{key.replace('_', ' ').toUpperCase()}</strong> ({factor.weight * 100}%): {factor.description}
                    </li>
                  ))}
                </ul>
              </div>
              <p><strong className="text-slate-300">Normalization:</strong> {risk_score_breakdown.methodology.normalization}</p>
            </div>
          </div>
        )}
      </div>

      {/* Projections */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <ProjectionCard
          title="24 Hours"
          projection={projection_24h}
          color="text-blue-400"
          bgColor="bg-blue-500/10 border-blue-500/20"
        />
        <ProjectionCard
          title="7 Days"
          projection={projection_7d}
          color="text-yellow-400"
          bgColor="bg-yellow-500/10 border-yellow-500/20"
        />
        <ProjectionCard
          title="30 Days"
          projection={projection_30d}
          color="text-orange-400"
          bgColor="bg-orange-500/10 border-orange-500/20"
        />
      </div>

      {/* Statistical Analysis */}
      {statistical_analysis && Object.keys(statistical_analysis).length > 0 && (
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Statistical Analysis</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <StatItem label="Mean Attacks/Day" value={statistical_analysis.mean_attacks_per_day?.toFixed(1) || '0'} />
            <StatItem label="Std Dev/Day" value={statistical_analysis.std_attacks_per_day?.toFixed(1) || '0'} />
            <StatItem label="Success Rate" value={`${(statistical_analysis.success_rate * 100).toFixed(1)}%`} />
            <StatItem label="Unique Techniques" value={statistical_analysis.unique_techniques || '0'} />
            <StatItem label="Time Span" value={`${statistical_analysis.time_span_days?.toFixed(0) || '0'} days`} />
            <StatItem label="Data Points" value={statistical_analysis.total_attacks || '0'} />
          </div>
        </div>
      )}

      {/* Projection Chart */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h3 className="text-xl font-bold text-white mb-4">Attack Projections</h3>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={trajectoryData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
            <XAxis dataKey="time" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" />
            <Tooltip
              contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
              labelStyle={{ color: '#e2e8f0' }}
            />
            <Area
              type="monotone"
              dataKey="upper"
              stackId="1"
              stroke="#8884d8"
              fill="#8884d8"
              fillOpacity={0.2}
              name="Upper Bound"
            />
            <Area
              type="monotone"
              dataKey="predicted"
              stackId="2"
              stroke="#ef4444"
              fill="#ef4444"
              fillOpacity={0.6}
              name="Predicted"
            />
            <Area
              type="monotone"
              dataKey="lower"
              stackId="3"
              stroke="#8884d8"
              fill="#3b82f6"
              fillOpacity={0.4}
              name="Lower Bound"
            />
            <Legend />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

function FactorCard({ title, value, contribution, weight, subtitle, color }: {
  title: string
  value: string | number
  contribution: string
  weight: string
  subtitle?: string
  color: string
}) {
  return (
    <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
      <div className="text-xs text-slate-400 mb-1">{title}</div>
      <div className={`text-2xl font-bold ${color} mb-1`}>{value}</div>
      {subtitle && <div className="text-xs text-slate-500 mb-2">{subtitle}</div>}
      <div className="flex justify-between text-xs">
        <span className="text-slate-400">Contribution:</span>
        <span className="text-white font-semibold">{contribution}</span>
      </div>
      <div className="flex justify-between text-xs mt-1">
        <span className="text-slate-400">Weight:</span>
        <span className="text-slate-300">{weight}</span>
      </div>
    </div>
  )
}

function ProjectionCard({ title, projection, color, bgColor }: {
  title: string
  projection: Projection
  color: string
  bgColor: string
}) {
  return (
    <div className={`bg-slate-800 rounded-lg shadow-lg p-6 border ${bgColor}`}>
      <h4 className="text-lg font-bold text-white mb-4">{title}</h4>
      <div className="space-y-3">
        <div>
          <div className="text-sm text-slate-400 mb-1">Predicted Attacks</div>
          <div className={`text-3xl font-bold ${color}`}>{projection.predicted_attacks}</div>
          <div className="text-xs text-slate-500 mt-1">
            Range: {projection.prediction_range.lower} - {projection.prediction_range.upper}
          </div>
        </div>
        <div>
          <div className="text-sm text-slate-400 mb-1">Confidence</div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full"
              style={{ width: `${projection.confidence * 100}%` }}
            ></div>
          </div>
          <div className="text-xs text-slate-500 mt-1">
            {(projection.confidence * 100).toFixed(0)}%
          </div>
        </div>
        {projection.statistics && (
          <div className="pt-3 border-t border-slate-700 text-xs text-slate-400">
            <div>Historical Mean: {projection.statistics.historical_mean?.toFixed(1) || 'N/A'}</div>
            {projection.statistics.trend_slope && (
              <div>Trend: {projection.statistics.trend_slope > 0 ? '↑' : '↓'} {Math.abs(projection.statistics.trend_slope).toFixed(2)}/hr</div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function StatItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-slate-400 mb-1">{label}</div>
      <div className="text-lg font-semibold text-white">{value}</div>
    </div>
  )
}

