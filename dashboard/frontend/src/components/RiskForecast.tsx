import { RiskForecast as RiskForecastType } from '../types'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { format } from 'date-fns'

interface RiskForecastProps {
  forecast: RiskForecastType
}

const threatLevelColors = {
  low: 'text-green-400',
  medium: 'text-yellow-400',
  high: 'text-orange-400',
  critical: 'text-red-400'
}

const threatLevelBgColors = {
  low: 'bg-green-500/20 border-green-500',
  medium: 'bg-yellow-500/20 border-yellow-500',
  high: 'bg-orange-500/20 border-orange-500',
  critical: 'bg-red-500/20 border-red-500'
}

export function RiskForecast({ forecast }: RiskForecastProps) {
  const trajectoryData = forecast.risk_trajectory.map(item => ({
    date: format(new Date(item.date), 'MMM dd'),
    risk: item.risk_score,
    attacks: item.attacks
  }))

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-400'
    if (score >= 50) return 'text-orange-400'
    if (score >= 25) return 'text-yellow-400'
    return 'text-green-400'
  }

  const getRiskBarColor = (score: number) => {
    if (score >= 75) return 'bg-red-500'
    if (score >= 50) return 'bg-orange-500'
    if (score >= 25) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  return (
    <div className="space-y-6">
      {/* Current Risk Score */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold text-white mb-4">Risk Assessment</h2>
        
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-slate-400">Current Risk Score</span>
            <span className={`text-2xl font-bold ${getRiskColor(forecast.current_risk_score)}`}>
              {forecast.current_risk_score.toFixed(1)}
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-4">
            <div
              className={`h-4 rounded-full ${getRiskBarColor(forecast.current_risk_score)}`}
              style={{ width: `${forecast.current_risk_score}%` }}
            ></div>
          </div>
        </div>

        <div className={`p-4 rounded-lg border-2 ${threatLevelBgColors[forecast.threat_level]}`}>
          <div className="flex items-center justify-between">
            <span className="text-sm text-slate-300">Threat Level</span>
            <span className={`text-lg font-bold ${threatLevelColors[forecast.threat_level]}`}>
              {forecast.threat_level.toUpperCase()}
            </span>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-4">
          <div>
            <div className="text-xs text-slate-400 mb-1">Attack Probability</div>
            <div className="text-lg font-semibold text-yellow-400">
              {(forecast.attack_probability * 100).toFixed(1)}%
            </div>
          </div>
          <div>
            <div className="text-xs text-slate-400 mb-1">Exposure Score</div>
            <div className="text-lg font-semibold text-orange-400">
              {forecast.vulnerability_exposure_score.toFixed(1)}
            </div>
          </div>
        </div>

        <div className="mt-4">
          <div className="text-xs text-slate-400 mb-1">Forecast Confidence</div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full"
              style={{ width: `${forecast.confidence * 100}%` }}
            ></div>
          </div>
          <div className="text-xs text-slate-500 mt-1">
            {(forecast.confidence * 100).toFixed(0)}% confidence
          </div>
        </div>
      </div>

      {/* Risk Trajectory */}
      {trajectoryData.length > 0 && (
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Risk Trajectory</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trajectoryData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
              <XAxis dataKey="date" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" domain={[0, 100]} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Line
                type="monotone"
                dataKey="risk"
                stroke="#ef4444"
                strokeWidth={2}
                name="Risk Score"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Forecasts */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h3 className="text-xl font-bold text-white mb-4">Attack Forecasts</h3>
        <div className="space-y-4">
          <ForecastItem
            label="24 Hours"
            forecast={forecast.forecast_24h}
            color="text-blue-400"
          />
          <ForecastItem
            label="7 Days"
            forecast={forecast.forecast_7d}
            color="text-yellow-400"
          />
          <ForecastItem
            label="30 Days"
            forecast={forecast.forecast_30d}
            color="text-orange-400"
          />
        </div>
      </div>
    </div>
  )
}

function ForecastItem({ label, forecast, color }: {
  label: string
  forecast: any
  color: string
}) {
  return (
    <div className="p-4 bg-slate-700/50 rounded-lg">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-semibold text-slate-300">{label}</span>
        <span className={`text-sm ${color}`}>
          {(forecast.confidence * 100).toFixed(0)}% confidence
        </span>
      </div>
      <div className="grid grid-cols-3 gap-2 text-xs">
        <div>
          <div className="text-slate-400">Predicted</div>
          <div className="text-white font-semibold">{forecast.predicted_attacks}</div>
        </div>
        <div>
          <div className="text-slate-400">Successful</div>
          <div className="text-red-400 font-semibold">{forecast.predicted_successful}</div>
        </div>
        <div>
          <div className="text-slate-400">Risk Score</div>
          <div className="text-yellow-400 font-semibold">{forecast.risk_score.toFixed(1)}</div>
        </div>
      </div>
    </div>
  )
}

