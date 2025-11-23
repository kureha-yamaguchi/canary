import { TrajectoryComparison, RedTeamTrajectory, ExternalTrajectory } from '../../types'

interface ComparisonSectionProps {
  comparison: TrajectoryComparison
  redTeam: RedTeamTrajectory
  external: ExternalTrajectory
}

export function ComparisonSection({ comparison, redTeam, external }: ComparisonSectionProps) {
  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      {/* Header */}
      <div className="bg-purple-50 border-b border-purple-200 p-4">
        <div className="flex items-center gap-2">
          <span className="text-xl">📊</span>
          <h2 className="text-lg font-semibold text-purple-900">Comparison & Analysis</h2>
        </div>
      </div>

      <div className="p-4 space-y-6">
        {/* Key Metrics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-gray-50 rounded-lg p-4 text-center border border-gray-200">
            <div className="text-3xl font-bold text-purple-600">
              {(comparison.similarity_score * 100).toFixed(0)}%
            </div>
            <div className="text-sm text-gray-500">Similarity Score</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-4 text-center border border-gray-200">
            <div className="text-3xl font-bold text-gray-900">
              {comparison.divergence_points}
            </div>
            <div className="text-sm text-gray-500">Divergence Points</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-4 text-center border border-gray-200">
            <div className="text-3xl font-bold text-gray-900">
              {comparison.time_difference_seconds.toFixed(0)}s
            </div>
            <div className="text-sm text-gray-500">Time Difference</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-4 text-center border border-gray-200">
            <div className="text-3xl font-bold text-green-600">
              {(comparison.ttp_coverage.coverage_percentage * 100).toFixed(0)}%
            </div>
            <div className="text-sm text-gray-500">TTP Coverage</div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Timeline Comparison */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-3">Timeline Comparison</h3>
            <div className="space-y-2">
              {/* Red Team Bar */}
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-500 w-20">Red Team:</span>
                <div className="flex-1 bg-red-100 rounded h-6 relative overflow-hidden">
                  <div
                    className="bg-red-500 h-full"
                    style={{ width: '100%' }}
                  />
                  <span className="absolute inset-0 flex items-center justify-end pr-2 text-xs text-white font-medium">
                    {redTeam.events.length} events
                  </span>
                </div>
              </div>
              {/* External Bar */}
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-500 w-20">External:</span>
                <div className="flex-1 bg-blue-100 rounded h-6 relative overflow-hidden">
                  <div
                    className="bg-blue-500 h-full"
                    style={{ width: `${(external.events.length / redTeam.events.length) * 100}%` }}
                  />
                  <span className="absolute inset-0 flex items-center justify-end pr-2 text-xs text-blue-900 font-medium">
                    {external.events.length} events
                  </span>
                </div>
              </div>
            </div>

            {/* Timeline alignment details */}
            <div className="mt-4 space-y-2">
              {comparison.timeline_alignment.map((align, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <div className={`w-2 h-2 rounded-full ${
                    align.alignment_score > 0.9 ? 'bg-green-500' :
                    align.alignment_score > 0.7 ? 'bg-yellow-500' : 'bg-red-500'
                  }`} />
                  <span className="text-gray-500">{new Date(align.timestamp).toLocaleTimeString()}</span>
                  <span className="text-red-600">{align.red_team_action}</span>
                  <span className="text-gray-400">vs</span>
                  <span className="text-blue-600">{align.external_action}</span>
                  <span className="text-gray-400">({(align.alignment_score * 100).toFixed(0)}%)</span>
                </div>
              ))}
            </div>
          </div>

          {/* TTP Coverage Matrix */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-3">TTP Coverage Matrix</h3>
            <div className="bg-gray-50 rounded-lg border border-gray-200 overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-gray-100">
                  <tr>
                    <th className="px-3 py-2 text-left text-gray-600">Technique</th>
                    <th className="px-3 py-2 text-center text-red-600">Red Team</th>
                    <th className="px-3 py-2 text-center text-blue-600">External</th>
                  </tr>
                </thead>
                <tbody>
                  {/* Shared techniques */}
                  {comparison.ttp_coverage.shared_techniques.map((tech) => (
                    <tr key={tech} className="border-t border-gray-200">
                      <td className="px-3 py-2 font-mono">{tech}</td>
                      <td className="px-3 py-2 text-center text-green-600">✓</td>
                      <td className="px-3 py-2 text-center text-green-600">✓</td>
                    </tr>
                  ))}
                  {/* Red team only */}
                  {comparison.ttp_coverage.red_team_only.map((tech) => (
                    <tr key={tech} className="border-t border-gray-200 bg-red-50">
                      <td className="px-3 py-2 font-mono">{tech}</td>
                      <td className="px-3 py-2 text-center text-green-600">✓</td>
                      <td className="px-3 py-2 text-center text-gray-400">✗</td>
                    </tr>
                  ))}
                  {/* External only */}
                  {comparison.ttp_coverage.external_only.map((tech) => (
                    <tr key={tech} className="border-t border-gray-200 bg-blue-50">
                      <td className="px-3 py-2 font-mono">{tech}</td>
                      <td className="px-3 py-2 text-center text-gray-400">✗</td>
                      <td className="px-3 py-2 text-center text-green-600">✓</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Key Differences */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-3">Key Differences</h3>
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <ul className="space-y-2">
              {comparison.key_differences.map((diff, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-yellow-800">
                  <span className="text-yellow-600 mt-0.5">•</span>
                  {diff}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Behavioral Insights */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-3">Behavioral Insights</h3>
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <ul className="space-y-2">
              {comparison.behavioral_insights.map((insight, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-blue-800">
                  <span className="text-blue-600 mt-0.5">💡</span>
                  {insight}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
