import { TrajectoryPredictions } from '../../types'

interface ClassifierInsightsProps {
  predictions: TrajectoryPredictions
}

export function ClassifierInsights({ predictions }: ClassifierInsightsProps) {
  // Feature importance data (would come from API in production)
  const featureImportance = [
    { name: 'Request Timing Patterns', importance: 0.35 },
    { name: 'Payload Sophistication', importance: 0.28 },
    { name: 'Error Handling Behavior', importance: 0.22 },
    { name: 'Endpoint Coverage Order', importance: 0.15 }
  ]

  // Calculate capability predictions based on classifier outputs
  const sophisticationScore = (
    predictions.agent_detection.confidence * 4 +
    predictions.threat_match.similarity_to_red_team * 3 +
    predictions.velocity_analysis.automation_score * 3
  ).toFixed(1)

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      {/* Header */}
      <div className="bg-slate-800 p-4">
        <div className="flex items-center gap-2">
          <span className="text-xl">🤖</span>
          <h2 className="text-lg font-semibold text-white">Classifier Insights</h2>
        </div>
        <p className="text-sm text-slate-300 mt-1">
          Model: TrajectoryClassifier v1.0-mvp | Training: 50 red team + 500 external trajectories
        </p>
      </div>

      <div className="p-4 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Feature Importance */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-3">Feature Importance</h3>
            <div className="space-y-3">
              {featureImportance.map((feature) => (
                <div key={feature.name}>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="text-gray-700">{feature.name}</span>
                    <span className="text-gray-500">{(feature.importance * 100).toFixed(0)}%</span>
                  </div>
                  <div className="bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-gradient-to-r from-blue-500 to-purple-500 h-2 rounded-full"
                      style={{ width: `${feature.importance * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Capability Predictions */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-3">Capability Predictions</h3>
            <div className="bg-slate-50 rounded-lg p-4 border border-slate-200 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Sophistication Level:</span>
                <div className="flex items-center gap-2">
                  <span className="text-lg font-bold text-slate-800">{sophisticationScore}/10</span>
                  <span className={`px-2 py-0.5 text-xs font-medium rounded ${
                    parseFloat(sophisticationScore) > 7 ? 'bg-red-100 text-red-800' :
                    parseFloat(sophisticationScore) > 4 ? 'bg-yellow-100 text-yellow-800' :
                    'bg-green-100 text-green-800'
                  }`}>
                    {parseFloat(sophisticationScore) > 7 ? 'Advanced' :
                     parseFloat(sophisticationScore) > 4 ? 'Intermediate' : 'Basic'}
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Automation Level:</span>
                <div className="flex items-center gap-2">
                  <div className="w-24 bg-gray-200 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${
                        predictions.velocity_analysis.automation_score > 0.7 ? 'bg-red-500' :
                        predictions.velocity_analysis.automation_score > 0.4 ? 'bg-yellow-500' :
                        'bg-green-500'
                      }`}
                      style={{ width: `${predictions.velocity_analysis.automation_score * 100}%` }}
                    />
                  </div>
                  <span className="text-sm font-medium text-gray-700">
                    {(predictions.velocity_analysis.automation_score * 100).toFixed(0)}%
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Prior Knowledge:</span>
                <span className={`px-2 py-0.5 text-xs font-medium rounded ${
                  predictions.stage_classification.progress_percentage > 50
                    ? 'bg-orange-100 text-orange-800'
                    : 'bg-blue-100 text-blue-800'
                }`}>
                  {predictions.stage_classification.progress_percentage > 50 ? 'High' : 'Medium'}
                  <span className="text-gray-500 ml-1">(some endpoint pre-knowledge)</span>
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Tool Fingerprint:</span>
                <span className="text-sm text-gray-700">
                  {predictions.velocity_analysis.timing_pattern === 'ml_agent'
                    ? 'Similar to LLM-based agents'
                    : predictions.velocity_analysis.timing_pattern === 'scripted'
                    ? 'Similar to SQLMap/Nuclei'
                    : 'Manual or unknown tooling'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Overall Assessment */}
        <div className={`rounded-lg p-4 border ${
          predictions.threat_level === 'critical' ? 'bg-red-50 border-red-300' :
          predictions.threat_level === 'high' ? 'bg-orange-50 border-orange-300' :
          predictions.threat_level === 'medium' ? 'bg-yellow-50 border-yellow-300' :
          'bg-green-50 border-green-300'
        }`}>
          <div className="flex items-center justify-between">
            <div>
              <h4 className="font-medium text-gray-900">Overall Threat Assessment</h4>
              <p className="text-sm text-gray-600 mt-1">
                Based on combined classifier outputs and behavioral analysis
              </p>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold text-gray-900">
                {predictions.overall_threat_score.toFixed(0)}
              </div>
              <div className={`text-sm font-medium uppercase ${
                predictions.threat_level === 'critical' ? 'text-red-700' :
                predictions.threat_level === 'high' ? 'text-orange-700' :
                predictions.threat_level === 'medium' ? 'text-yellow-700' :
                'text-green-700'
              }`}>
                {predictions.threat_level} threat
              </div>
            </div>
          </div>

          {/* Contributing Factors */}
          <div className="mt-4 pt-4 border-t border-gray-200">
            <h5 className="text-xs font-medium text-gray-500 mb-2">Contributing Factors:</h5>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
              <div>
                <span className="text-gray-500">Agent Detection:</span>
                <span className="ml-1 font-medium">{(predictions.agent_detection.confidence * 25).toFixed(1)} pts</span>
              </div>
              <div>
                <span className="text-gray-500">Pattern Match:</span>
                <span className="ml-1 font-medium">{(predictions.threat_match.similarity_to_red_team * 35).toFixed(1)} pts</span>
              </div>
              <div>
                <span className="text-gray-500">Stage Progress:</span>
                <span className="ml-1 font-medium">{(predictions.stage_classification.progress_percentage * 0.25).toFixed(1)} pts</span>
              </div>
              <div>
                <span className="text-gray-500">Automation:</span>
                <span className="ml-1 font-medium">{(predictions.velocity_analysis.automation_score * 15).toFixed(1)} pts</span>
              </div>
            </div>
          </div>
        </div>

        {/* TTP Predictions */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-3">Predicted Next TTPs</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {predictions.ttp_predictions.slice(0, 4).map((ttp, i) => (
              <div
                key={i}
                className="bg-gray-50 rounded-lg p-3 border border-gray-200"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-sm font-medium text-blue-600">{ttp.technique_id}</span>
                  <span className={`text-xs font-medium ${
                    ttp.probability > 0.7 ? 'text-red-600' :
                    ttp.probability > 0.4 ? 'text-yellow-600' : 'text-gray-600'
                  }`}>
                    {(ttp.probability * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="text-xs text-gray-600 truncate" title={ttp.technique_name}>
                  {ttp.technique_name}
                </div>
                <div className="mt-2 bg-gray-200 rounded-full h-1">
                  <div
                    className={`h-1 rounded-full ${
                      ttp.probability > 0.7 ? 'bg-red-500' :
                      ttp.probability > 0.4 ? 'bg-yellow-500' : 'bg-gray-400'
                    }`}
                    style={{ width: `${ttp.probability * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
