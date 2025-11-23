interface TimelineStep {
  label: string
  techniqueId: string
  timestamp: string
  isComplete: boolean
  isInferred?: boolean
}

interface TrajectoryTimelineProps {
  steps: TimelineStep[]
  variant: 'red' | 'blue'
}

export function TrajectoryTimeline({ steps, variant }: TrajectoryTimelineProps) {
  const colors = {
    red: {
      line: 'bg-red-300',
      dot: 'bg-red-500',
      dotBorder: 'border-red-200',
      text: 'text-red-700',
      bg: 'bg-red-50',
      border: 'border-red-200'
    },
    blue: {
      line: 'bg-blue-300',
      dot: 'bg-blue-500',
      dotBorder: 'border-blue-200',
      text: 'text-blue-700',
      bg: 'bg-blue-50',
      border: 'border-blue-200'
    }
  }

  const c = colors[variant]

  if (steps.length === 0) {
    return (
      <div className={`${c.bg} rounded-lg p-4 text-center ${c.text}`}>
        No trajectory steps available
      </div>
    )
  }

  return (
    <div className={`${c.bg} rounded-lg p-4 border ${c.border} overflow-x-auto`}>
      <div className="flex items-center min-w-max">
        {steps.map((step, index) => (
          <div key={index} className="flex items-center">
            {/* Step */}
            <div className="flex flex-col items-center">
              {/* Dot */}
              <div
                className={`w-4 h-4 rounded-full ${
                  step.isComplete ? c.dot : `border-2 ${c.dotBorder} bg-white`
                } ${step.isInferred ? 'border-dashed' : ''}`}
              />

              {/* Label */}
              <div className="mt-2 text-center max-w-24">
                <div className={`text-xs font-medium ${c.text}`}>
                  {step.label}
                </div>
                <div className="text-xs text-gray-500 font-mono">
                  {step.techniqueId}
                </div>
                <div className="text-xs text-gray-400">
                  {step.timestamp}
                </div>
              </div>
            </div>

            {/* Connector */}
            {index < steps.length - 1 && (
              <div className={`w-12 h-0.5 ${c.line} mx-2 mt-[-2rem]`} />
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
