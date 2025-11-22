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
      <div className="bg-white rounded-lg shadow-sm p-6 mb-6 border border-gray-200">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Risk Analysis & Forecasting</h2>
        <p className="text-gray-600 mb-4">
          MITRE ATT&CK-based risk classification and projection for cyber attack monitoring.
        </p>
        
        {/* Tab Navigation */}
        <div className="flex gap-4 border-b border-gray-200">
          <button
            onClick={() => setActiveTab('portfolio')}
            className={`px-4 py-2 font-semibold transition-colors ${
              activeTab === 'portfolio'
                ? 'text-blue-600 border-b-2 border-blue-600'
                : 'text-gray-600 hover:text-blue-600'
            }`}
          >
            MITRE Risk Portfolio
          </button>
          <button
            onClick={() => setActiveTab('advanced-forecast')}
            className={`px-4 py-2 font-semibold transition-colors ${
              activeTab === 'advanced-forecast'
                ? 'text-blue-600 border-b-2 border-blue-600'
                : 'text-gray-600 hover:text-blue-600'
            }`}
          >
            Advanced Forecast
          </button>
          <button
            onClick={() => setActiveTab('forecast')}
            className={`px-4 py-2 font-semibold transition-colors ${
              activeTab === 'forecast'
                ? 'text-blue-600 border-b-2 border-blue-600'
                : 'text-gray-600 hover:text-blue-600'
            }`}
          >
            Classic Forecast
          </button>
        </div>
      </div>

      {activeTab === 'portfolio' && <MitreRiskPortfolio />}
      {activeTab === 'advanced-forecast' && <AdvancedRiskForecast />}
      {activeTab === 'forecast' && (
        <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
          <p className="text-gray-600">
            Traditional risk forecasting view - coming soon with enhanced MITRE integration.
          </p>
        </div>
      )}
    </div>
  )
}

