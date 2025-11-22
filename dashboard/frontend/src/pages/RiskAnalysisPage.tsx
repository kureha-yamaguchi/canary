import { useState } from 'react'
import { RiskForecast } from '../components/RiskForecast'
import { MitreRiskPortfolio } from '../components/MitreRiskPortfolio'
import { AdvancedRiskForecast } from '../components/AdvancedRiskForecast'
import { RiskForecast as RiskForecastType } from '../types'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export function RiskAnalysisPage() {
  const [activeTab, setActiveTab] = useState<'portfolio' | 'advanced-forecast' | 'forecast'>('portfolio')

  return (
    <div className="space-y-6">
      <div className="bg-slate-800 rounded-lg shadow-lg p-6 mb-6">
        <h2 className="text-2xl font-bold text-white mb-2">Risk Analysis & Forecasting</h2>
        <p className="text-slate-400 mb-4">
          MITRE ATT&CK-based risk classification and projection for cyber attack monitoring.
        </p>
        
        {/* Tab Navigation */}
        <div className="flex gap-4 border-b border-slate-700">
          <button
            onClick={() => setActiveTab('portfolio')}
            className={`px-4 py-2 font-semibold transition-colors ${
              activeTab === 'portfolio'
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            MITRE Risk Portfolio
          </button>
          <button
            onClick={() => setActiveTab('advanced-forecast')}
            className={`px-4 py-2 font-semibold transition-colors ${
              activeTab === 'advanced-forecast'
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Advanced Forecast
          </button>
          <button
            onClick={() => setActiveTab('forecast')}
            className={`px-4 py-2 font-semibold transition-colors ${
              activeTab === 'forecast'
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Classic Forecast
          </button>
        </div>
      </div>

      {activeTab === 'portfolio' && <MitreRiskPortfolio />}
      {activeTab === 'advanced-forecast' && <AdvancedRiskForecast />}
      {activeTab === 'forecast' && (
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <p className="text-slate-400">
            Traditional risk forecasting view - coming soon with enhanced MITRE integration.
          </p>
        </div>
      )}
    </div>
  )
}

