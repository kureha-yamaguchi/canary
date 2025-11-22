import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts'
import { format } from 'date-fns'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

interface MitreTacticRisk {
  tactic_id: string
  tactic_name: string
  risk_score: number
  attack_count: number
  successful_count: number
  unique_techniques: number
  exposure_score: number
  trend: string
  trend_score: number
  techniques: Array<{
    technique_id: string
    technique_name: string
    attack_count: number
    successful_count: number
    success_rate: number
  }>
}

interface RiskPortfolio {
  tactics: MitreTacticRisk[]
  overall_risk_score: number
  high_risk_tactics: string[]
  moderate_risk_tactics: string[]
  low_risk_tactics: string[]
  risk_distribution: Record<string, number>
}

export function MitreRiskPortfolio() {
  const [portfolio, setPortfolio] = useState<RiskPortfolio | null>(null)
  const [projection, setProjection] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [timeHorizon, setTimeHorizon] = useState<'24h' | '7d' | '30d'>('7d')

  useEffect(() => {
    fetchPortfolio()
    fetchProjection()
    
    const interval = setInterval(() => {
      fetchPortfolio()
      fetchProjection()
    }, 60000) // Refresh every minute
    
    return () => clearInterval(interval)
  }, [timeHorizon])

  const fetchPortfolio = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/mitre-risk-portfolio`)
      const data = await response.json()
      setPortfolio(data)
    } catch (error) {
      console.error('Error fetching risk portfolio:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchProjection = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/mitre-risk-projection?time_horizon=${timeHorizon}`)
      const data = await response.json()
      setProjection(data)
    } catch (error) {
      console.error('Error fetching risk projection:', error)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading risk portfolio...</div>
      </div>
    )
  }

  if (!portfolio || portfolio.tactics.length === 0) {
    return (
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <p className="text-slate-400">No risk portfolio data available yet.</p>
      </div>
    )
  }

  const tacticData = portfolio.tactics
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10)
    .map(t => ({
      name: t.tactic_name,
      risk: t.risk_score,
      attacks: t.attack_count,
      successful: t.successful_count,
      techniques: t.unique_techniques
    }))

  const riskDistribution = portfolio.tactics.map(t => ({
    name: t.tactic_name,
    value: t.risk_score
  }))

  const COLORS = ['#ef4444', '#f59e0b', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316']

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
      {/* Overall Risk Score */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold text-white">MITRE ATT&CK Risk Portfolio</h2>
          <div className="text-sm text-slate-400">
            Overall Risk: <span className={`text-lg font-bold ${getRiskColor(portfolio.overall_risk_score)}`}>
              {portfolio.overall_risk_score.toFixed(1)}
            </span>
          </div>
        </div>

        {/* Risk Summary */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="bg-red-900/20 border border-red-500/20 rounded-lg p-4">
            <div className="text-sm text-slate-400 mb-1">High Risk Tactics</div>
            <div className="text-2xl font-bold text-red-400">{portfolio.high_risk_tactics.length}</div>
          </div>
          <div className="bg-yellow-900/20 border border-yellow-500/20 rounded-lg p-4">
            <div className="text-sm text-slate-400 mb-1">Moderate Risk</div>
            <div className="text-2xl font-bold text-yellow-400">{portfolio.moderate_risk_tactics.length}</div>
          </div>
          <div className="bg-green-900/20 border border-green-500/20 rounded-lg p-4">
            <div className="text-sm text-slate-400 mb-1">Low Risk</div>
            <div className="text-2xl font-bold text-green-400">{portfolio.low_risk_tactics.length}</div>
          </div>
        </div>
      </div>

      {/* Tactic Risk Chart */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h3 className="text-xl font-bold text-white mb-4">Tactic Risk Scores</h3>
        <ResponsiveContainer width="100%" height={400}>
          <BarChart data={tacticData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
            <XAxis 
              dataKey="name" 
              stroke="#94a3b8" 
              angle={-45} 
              textAnchor="end" 
              height={120}
              tick={{ fontSize: 12 }}
            />
            <YAxis stroke="#94a3b8" domain={[0, 100]} />
            <Tooltip
              contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
              labelStyle={{ color: '#e2e8f0' }}
            />
            <Legend />
            <Bar dataKey="risk" fill="#ef4444" name="Risk Score" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Tactic Details Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {portfolio.tactics.slice(0, 9).map((tactic) => (
          <div key={tactic.tactic_id} className="bg-slate-800 rounded-lg shadow-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-lg font-bold text-white">{tactic.tactic_name}</h4>
              <span className={`text-sm font-semibold ${getRiskColor(tactic.risk_score)}`}>
                {tactic.risk_score.toFixed(0)}
              </span>
            </div>
            
            <div className="mb-3">
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div
                  className={`h-2 rounded-full ${getRiskBgColor(tactic.risk_score)}`}
                  style={{ width: `${tactic.risk_score}%` }}
                ></div>
              </div>
            </div>

            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Attacks:</span>
                <span className="text-white">{tactic.attack_count}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Successful:</span>
                <span className="text-red-400">{tactic.successful_count}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Techniques:</span>
                <span className="text-white">{tactic.unique_techniques}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Trend:</span>
                <span className={`${
                  tactic.trend === 'increasing' ? 'text-red-400' :
                  tactic.trend === 'decreasing' ? 'text-green-400' :
                  'text-slate-400'
                }`}>
                  {tactic.trend === 'increasing' ? '↑ Increasing' :
                   tactic.trend === 'decreasing' ? '↓ Decreasing' :
                   '→ Stable'}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Risk Projection */}
      {projection && (
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-white">Risk Projection</h3>
            <div className="flex gap-2">
              {(['24h', '7d', '30d'] as const).map((horizon) => (
                <button
                  key={horizon}
                  onClick={() => setTimeHorizon(horizon)}
                  className={`px-3 py-1 rounded text-sm transition-colors ${
                    timeHorizon === horizon
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  {horizon}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div>
              <div className="text-sm text-slate-400 mb-1">Predicted Attacks</div>
              <div className="text-2xl font-bold text-white">{projection.predicted_attacks}</div>
            </div>
            <div>
              <div className="text-sm text-slate-400 mb-1">Predicted Techniques</div>
              <div className="text-2xl font-bold text-blue-400">{projection.predicted_techniques}</div>
            </div>
            <div>
              <div className="text-sm text-slate-400 mb-1">Predicted Tactics</div>
              <div className="text-2xl font-bold text-purple-400">{projection.predicted_tactics}</div>
            </div>
            <div>
              <div className="text-sm text-slate-400 mb-1">Confidence</div>
              <div className="text-2xl font-bold text-yellow-400">
                {(projection.confidence * 100).toFixed(0)}%
              </div>
            </div>
          </div>

          {projection.high_risk_tactics.length > 0 && (
            <div className="mb-4">
              <div className="text-sm text-slate-400 mb-2">High-Risk Tactics:</div>
              <div className="flex flex-wrap gap-2">
                {projection.high_risk_tactics.map((tactic: string) => (
                  <span key={tactic} className="px-2 py-1 bg-red-900/30 text-red-300 rounded text-sm">
                    {tactic}
                  </span>
                ))}
              </div>
            </div>
          )}

          {projection.risk_trajectory && projection.risk_trajectory.length > 0 && (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={projection.risk_trajectory}>
                <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
                <XAxis 
                  dataKey="timestamp" 
                  stroke="#94a3b8"
                  tickFormatter={(value) => format(new Date(value), 'MMM dd HH:mm')}
                />
                <YAxis stroke="#94a3b8" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                  labelStyle={{ color: '#e2e8f0' }}
                />
                <Line
                  type="monotone"
                  dataKey="predicted_attacks"
                  stroke="#ef4444"
                  strokeWidth={2}
                  name="Predicted Attacks"
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      )}
    </div>
  )
}

