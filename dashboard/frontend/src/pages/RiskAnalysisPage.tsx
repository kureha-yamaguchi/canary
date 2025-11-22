import { useState, useEffect } from 'react'
import { RiskForecast } from '../components/RiskForecast'
import { RiskForecast as RiskForecastType } from '../types'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export function RiskAnalysisPage() {
  const [forecast, setForecast] = useState<RiskForecastType | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchForecast = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/risk-forecast`)
      const data = await response.json()
      setForecast(data)
    } catch (error) {
      console.error('Error fetching forecast:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchForecast()
    const interval = setInterval(() => {
      fetchForecast()
    }, 60000) // Refresh every minute
    return () => clearInterval(interval)
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading risk analysis...</div>
      </div>
    )
  }

  if (!forecast) {
    return (
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold text-white mb-4">Risk Analysis</h2>
        <p className="text-slate-400">
          Risk forecasting will be available soon. We're working on advanced analytics.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="bg-slate-800 rounded-lg shadow-lg p-6 mb-6">
        <h2 className="text-2xl font-bold text-white mb-2">Risk Analysis & Forecasting</h2>
        <p className="text-slate-400">
          Advanced threat intelligence and predictive analytics for cyber attack monitoring.
        </p>
      </div>

      {forecast && <RiskForecast forecast={forecast} />}
    </div>
  )
}

