import { EarlyWarning } from '../../types'

interface EarlyWarningBannerProps {
  warning: EarlyWarning
}

export function EarlyWarningBanner({ warning }: EarlyWarningBannerProps) {
  const getBannerStyle = (level: string) => {
    switch (level) {
      case 'critical':
        return {
          bg: 'bg-red-50',
          border: 'border-red-400',
          icon: 'bg-red-500',
          title: 'text-red-800',
          text: 'text-red-700'
        }
      case 'warning':
        return {
          bg: 'bg-orange-50',
          border: 'border-orange-400',
          icon: 'bg-orange-500',
          title: 'text-orange-800',
          text: 'text-orange-700'
        }
      case 'watch':
        return {
          bg: 'bg-yellow-50',
          border: 'border-yellow-400',
          icon: 'bg-yellow-500',
          title: 'text-yellow-800',
          text: 'text-yellow-700'
        }
      default:
        return {
          bg: 'bg-gray-50',
          border: 'border-gray-400',
          icon: 'bg-gray-500',
          title: 'text-gray-800',
          text: 'text-gray-700'
        }
    }
  }

  const style = getBannerStyle(warning.alert_level)

  return (
    <div className={`${style.bg} border-l-4 ${style.border} p-4 rounded-r-lg`}>
      <div className="flex items-start gap-3">
        {/* Alert Icon */}
        <div className={`${style.icon} rounded-full p-1 mt-0.5`}>
          <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>

        <div className="flex-1">
          {/* Header */}
          <div className="flex items-center justify-between">
            <h4 className={`font-semibold ${style.title}`}>
              {warning.alert_level.toUpperCase()} ALERT
            </h4>
            <span className={`text-xs ${style.text}`}>
              Confidence: {(warning.confidence * 100).toFixed(0)}%
            </span>
          </div>

          {/* Alert Reasons */}
          <ul className={`mt-2 text-sm ${style.text} space-y-1`}>
            {warning.alert_reasons.map((reason, i) => (
              <li key={i} className="flex items-center gap-2">
                <span>•</span>
                {reason}
              </li>
            ))}
          </ul>

          {/* Predictions */}
          <div className="mt-3 grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className={`text-xs ${style.text} opacity-75`}>Predicted Next Action:</span>
              <div className={`font-medium ${style.title}`}>
                {warning.predicted_technique}: {warning.predicted_target}
              </div>
            </div>
            <div>
              <span className={`text-xs ${style.text} opacity-75`}>Time to Action:</span>
              <div className={`font-medium ${style.title}`}>
                ~{warning.time_to_action_seconds.toFixed(0)} seconds
              </div>
            </div>
          </div>

          {/* Intervention */}
          <div className={`mt-3 p-2 bg-white bg-opacity-50 rounded text-sm ${style.text}`}>
            <span className="font-medium">Recommended Action:</span> {warning.recommended_intervention}
          </div>
        </div>
      </div>
    </div>
  )
}
