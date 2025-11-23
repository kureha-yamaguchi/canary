import { ExternalTrajectory } from '../../types'
import { TrajectoryTimeline } from './TrajectoryTimeline'
import { EventsTable } from './EventsTable'
import { EarlyWarningBanner } from './EarlyWarningBanner'

interface ExternalAgentSectionProps {
  trajectory: ExternalTrajectory | null
}

export function ExternalAgentSection({ trajectory }: ExternalAgentSectionProps) {
  if (!trajectory) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-4">
          <span className="w-3 h-3 bg-blue-500 rounded-full"></span>
          <h2 className="text-lg font-semibold text-gray-900">External Agent</h2>
        </div>
        <p className="text-gray-500 text-center py-8">No external trajectory available</p>
      </div>
    )
  }

  const predictions = trajectory.predictions

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      {/* Header */}
      <div className="bg-blue-50 border-b border-blue-200 p-4">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 bg-blue-500 rounded-full"></span>
          <h2 className="text-lg font-semibold text-blue-900">External Agent (Event Data Only)</h2>
        </div>
        <p className="text-sm text-blue-700 mt-1">
          Limited visibility - Honeypot events with classifier predictions
        </p>
      </div>

      <div className="p-4 space-y-4">
        {/* Early Warning Banner */}
        {predictions?.early_warning && predictions.early_warning.alert_level !== 'none' && (
          <EarlyWarningBanner warning={predictions.early_warning} />
        )}

        {/* Inferred Trajectory Timeline */}
        {predictions?.ttp_predictions && predictions.ttp_predictions.length > 0 && (
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-2">Inferred Trajectory</h3>
            <TrajectoryTimeline
              steps={predictions.ttp_predictions.map((ttp) => ({
                label: ttp.technique_name,
                techniqueId: ttp.technique_id,
                timestamp: `${(ttp.probability * 100).toFixed(0)}% conf`,
                isComplete: ttp.probability > 0.7,
                isInferred: true
              }))}
              variant="blue"
            />
          </div>
        )}

        {/* Event Data */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-2">Honeypot Event Data</h3>
          <EventsTable events={trajectory.events} maxHeight="200px" />
        </div>

        {/* Classifier Predictions Summary */}
        {predictions && (
          <div className="space-y-3">
            {/* Agent Detection */}
            <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-medium text-gray-700">Agent Detection</h4>
                <span className={`px-2 py-1 text-xs font-medium rounded ${
                  predictions.agent_detection.is_agent
                    ? 'bg-red-100 text-red-800'
                    : 'bg-green-100 text-green-800'
                }`}>
                  {predictions.agent_detection.is_agent ? 'AI AGENT' : 'LIKELY HUMAN'}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex-1 bg-gray-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      predictions.agent_detection.confidence > 0.7 ? 'bg-red-500' :
                      predictions.agent_detection.confidence > 0.4 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${predictions.agent_detection.confidence * 100}%` }}
                  />
                </div>
                <span className="text-sm font-medium text-gray-700">
                  {(predictions.agent_detection.confidence * 100).toFixed(0)}%
                </span>
              </div>
              {predictions.agent_detection.indicators.length > 0 && (
                <ul className="mt-2 text-xs text-gray-600">
                  {predictions.agent_detection.indicators.map((ind, i) => (
                    <li key={i} className="flex items-center gap-1">
                      <span className="text-yellow-500">!</span> {ind}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Stage Classification */}
            <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
              <h4 className="text-sm font-medium text-gray-700 mb-2">Kill Chain Stage</h4>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-600">Current Stage:</span>
                <span className="px-2 py-1 bg-purple-100 text-purple-800 text-xs font-medium rounded capitalize">
                  {predictions.stage_classification.current_stage}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex-1 bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-purple-500 h-2 rounded-full transition-all"
                    style={{ width: `${predictions.stage_classification.progress_percentage}%` }}
                  />
                </div>
                <span className="text-xs text-gray-500">
                  {predictions.stage_classification.progress_percentage.toFixed(0)}%
                </span>
              </div>
              <p className="text-xs text-gray-500 mt-2">
                Next likely stage: <span className="font-medium">{predictions.stage_classification.next_likely_stage}</span>
              </p>
            </div>

            {/* Velocity Analysis */}
            <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
              <h4 className="text-sm font-medium text-gray-700 mb-2">Velocity Analysis</h4>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-gray-500">Automation Score:</span>
                  <span className={`ml-2 font-medium ${
                    predictions.velocity_analysis.automation_score > 0.7 ? 'text-red-600' : 'text-gray-900'
                  }`}>
                    {(predictions.velocity_analysis.automation_score * 100).toFixed(0)}%
                  </span>
                </div>
                <div>
                  <span className="text-gray-500">Pattern:</span>
                  <span className="ml-2 font-medium text-gray-900 capitalize">
                    {predictions.velocity_analysis.timing_pattern}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500">Avg Time:</span>
                  <span className="ml-2 font-medium text-gray-900">
                    {(predictions.velocity_analysis.avg_time_between_actions_ms / 1000).toFixed(1)}s
                  </span>
                </div>
                <div>
                  <span className="text-gray-500">Burst Detected:</span>
                  <span className={`ml-2 font-medium ${
                    predictions.velocity_analysis.burst_detected ? 'text-red-600' : 'text-gray-900'
                  }`}>
                    {predictions.velocity_analysis.burst_detected ? 'Yes' : 'No'}
                  </span>
                </div>
              </div>
            </div>

            {/* Threat Match */}
            <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
              <h4 className="text-sm font-medium text-gray-700 mb-2">Red Team Pattern Match</h4>
              <div className="flex items-center gap-2 mb-2">
                <div className="flex-1 bg-gray-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      predictions.threat_match.similarity_to_red_team > 0.7 ? 'bg-red-500' :
                      predictions.threat_match.similarity_to_red_team > 0.4 ? 'bg-yellow-500' : 'bg-blue-500'
                    }`}
                    style={{ width: `${predictions.threat_match.similarity_to_red_team * 100}%` }}
                  />
                </div>
                <span className="text-sm font-medium text-gray-700">
                  {(predictions.threat_match.similarity_to_red_team * 100).toFixed(0)}% similar
                </span>
              </div>
              {predictions.threat_match.matched_pattern_name && (
                <p className="text-xs text-gray-600">
                  Matches: <span className="font-medium">{predictions.threat_match.matched_pattern_name}</span>
                </p>
              )}
            </div>
          </div>
        )}

        {/* Source Info */}
        <div className="text-xs text-gray-500 flex items-center gap-4 pt-2 border-t border-gray-200">
          <span>IP: {trajectory.source_ip}</span>
          <span>Session: {trajectory.session_id}</span>
        </div>
      </div>
    </div>
  )
}
