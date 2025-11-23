import { VulnerabilityRecommendations } from '../../types'

interface RecommendationsSectionProps {
  recommendations: VulnerabilityRecommendations
}

export function RecommendationsSection({ recommendations }: RecommendationsSectionProps) {
  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-300'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-300'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-300'
      case 'low': return 'bg-green-100 text-green-800 border-green-300'
      default: return 'bg-gray-100 text-gray-800 border-gray-300'
    }
  }

  const getEffortColor = (effort: string) => {
    switch (effort) {
      case 'low': return 'text-green-600'
      case 'medium': return 'text-yellow-600'
      case 'high': return 'text-red-600'
      default: return 'text-gray-600'
    }
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      {/* Header */}
      <div className="bg-green-50 border-b border-green-200 p-4">
        <div className="flex items-center gap-2">
          <span className="text-xl">🛡️</span>
          <h2 className="text-lg font-semibold text-green-900">Recommendations</h2>
        </div>
        <p className="text-sm text-green-700 mt-1">
          Based on TTPs for {recommendations.vulnerability_type.replace(/_/g, ' ')} vulnerability
        </p>
      </div>

      <div className="p-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Detection Rules */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-3 flex items-center gap-2">
              <span className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 text-xs">1</span>
              Detection Rules
            </h3>
            <div className="space-y-3">
              {recommendations.detection_rules.map((rule) => (
                <div
                  key={rule.id}
                  className="bg-gray-50 rounded-lg p-3 border border-gray-200"
                >
                  <div className="flex items-start justify-between gap-2">
                    <h4 className="text-sm font-medium text-gray-900">{rule.title}</h4>
                    <span className={`px-2 py-0.5 text-xs font-medium rounded border ${getPriorityColor(rule.priority)}`}>
                      {rule.priority}
                    </span>
                  </div>
                  <p className="text-xs text-gray-600 mt-1">{rule.description}</p>
                  <div className="flex gap-1 mt-2 flex-wrap">
                    {rule.related_techniques.map((tech) => (
                      <span
                        key={tech}
                        className="px-1.5 py-0.5 bg-blue-50 text-blue-700 text-xs rounded font-mono"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Early Warning Patterns */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-3 flex items-center gap-2">
              <span className="w-6 h-6 bg-yellow-100 rounded-full flex items-center justify-center text-yellow-600 text-xs">2</span>
              Early Warning Signs
            </h3>
            <div className="space-y-3">
              {recommendations.early_warning_patterns.map((pattern, i) => (
                <div
                  key={i}
                  className="bg-yellow-50 rounded-lg p-3 border border-yellow-200"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-yellow-500">⚠️</span>
                    <h4 className="text-sm font-medium text-yellow-900">{pattern.pattern}</h4>
                  </div>
                  <p className="text-xs text-yellow-800 mt-1">{pattern.description}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-yellow-700">
                    <span>Typical step: #{pattern.typical_step}</span>
                    <span>Window: {pattern.detection_window_seconds}s</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Mitigation Strategies */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-3 flex items-center gap-2">
              <span className="w-6 h-6 bg-green-100 rounded-full flex items-center justify-center text-green-600 text-xs">3</span>
              Mitigation Strategies
            </h3>
            <div className="space-y-3">
              {recommendations.mitigations.map((mitigation, i) => (
                <div
                  key={i}
                  className="bg-green-50 rounded-lg p-3 border border-green-200"
                >
                  <div className="flex items-start justify-between gap-2">
                    <h4 className="text-sm font-medium text-green-900">{mitigation.title}</h4>
                    <span className={`text-xs ${getEffortColor(mitigation.implementation_effort)}`}>
                      {mitigation.implementation_effort} effort
                    </span>
                  </div>
                  <p className="text-xs text-green-800 mt-1">{mitigation.description}</p>
                  <div className="flex gap-1 mt-2 flex-wrap">
                    <span className="text-xs text-green-700">Blocks:</span>
                    {mitigation.blocks_techniques.map((tech) => (
                      <span
                        key={tech}
                        className="px-1.5 py-0.5 bg-green-100 text-green-800 text-xs rounded font-mono"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
