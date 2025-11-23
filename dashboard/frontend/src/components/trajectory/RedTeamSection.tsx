import { RedTeamTrajectory } from '../../types'
import { TrajectoryTimeline } from './TrajectoryTimeline'
import { EventsTable } from './EventsTable'

interface RedTeamSectionProps {
  trajectory: RedTeamTrajectory | null
}

export function RedTeamSection({ trajectory }: RedTeamSectionProps) {
  if (!trajectory) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-4">
          <span className="w-3 h-3 bg-red-500 rounded-full"></span>
          <h2 className="text-lg font-semibold text-gray-900">Red Team Agent</h2>
        </div>
        <p className="text-gray-500 text-center py-8">No red team trajectory available</p>
      </div>
    )
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      {/* Header */}
      <div className="bg-red-50 border-b border-red-200 p-4">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 bg-red-500 rounded-full animate-pulse"></span>
          <h2 className="text-lg font-semibold text-red-900">Red Team Agent (Internal Baseline)</h2>
        </div>
        <p className="text-sm text-red-700 mt-1">
          Full observability - Chain of thought, tool calls, and TTP classification
        </p>
      </div>

      <div className="p-4 space-y-4">
        {/* Trajectory Timeline */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-2">Attack Trajectory</h3>
          <TrajectoryTimeline
            steps={trajectory.agent_steps.map((step) => ({
              label: step.tactic_name || 'Unknown',
              techniqueId: step.technique_id || 'N/A',
              timestamp: new Date(step.timestamp).toLocaleTimeString(),
              isComplete: true
            }))}
            variant="red"
          />
        </div>

        {/* Agent Reasoning & Tool Calls */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-2">Agent Reasoning & Tool Calls</h3>
          <div className="space-y-3 max-h-64 overflow-y-auto">
            {trajectory.agent_steps.map((step, index) => (
              <div key={index} className="bg-gray-50 rounded-lg p-3 border border-gray-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-gray-500">Step {step.step_number}</span>
                  <span className="text-xs text-gray-400">
                    {new Date(step.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-sm text-gray-700 mb-2 italic">"{step.reasoning}"</p>
                <div className="flex items-center gap-2 text-xs">
                  <span className="px-2 py-1 bg-purple-100 text-purple-800 rounded font-mono">
                    {step.tool_name}
                  </span>
                  <span className="text-gray-400">→</span>
                  <span className="text-gray-600 truncate">{step.tool_output.substring(0, 50)}...</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* TTP Classification */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-2">TTP Classification</h3>
          <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
            <div className="mb-3">
              <span className="text-xs text-gray-500">Tactics:</span>
              <div className="flex gap-2 mt-1">
                {trajectory.ttps.tactics.map((tactic) => (
                  <span
                    key={tactic.id}
                    className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded"
                  >
                    {tactic.name}
                  </span>
                ))}
              </div>
            </div>
            <div className="mb-3">
              <span className="text-xs text-gray-500">Techniques:</span>
              <div className="flex gap-2 mt-1 flex-wrap">
                {trajectory.ttps.techniques.map((technique) => (
                  <span
                    key={technique.id}
                    className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded font-mono"
                  >
                    {technique.id}: {technique.name}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <span className="text-xs text-gray-500">Procedures:</span>
              <ul className="mt-1 text-xs text-gray-600 list-disc list-inside">
                {trajectory.ttps.procedures.map((proc, i) => (
                  <li key={i}>{proc}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Event Data */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-2">Honeypot Event Data</h3>
          <EventsTable events={trajectory.events} maxHeight="200px" />
        </div>
      </div>
    </div>
  )
}
