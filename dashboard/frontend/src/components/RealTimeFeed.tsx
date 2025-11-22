import { Attack } from '../types'
import { format } from 'date-fns'
import { Link } from 'react-router-dom'
import { TruncateText, formatUrl, formatVulnerabilityType, formatIp } from '../utils/stringUtils'

// Note: Link import is already there

interface RealTimeFeedProps {
  attacks: Attack[]
  connectionStatus: number
}

export function RealTimeFeed({ attacks, connectionStatus }: RealTimeFeedProps) {
  const getStatusColor = () => {
    if (connectionStatus === WebSocket.OPEN) return 'bg-green-500'
    if (connectionStatus === WebSocket.CONNECTING) return 'bg-yellow-500'
    return 'bg-red-500'
  }

  const getStatusText = () => {
    if (connectionStatus === WebSocket.OPEN) return 'Connected'
    if (connectionStatus === WebSocket.CONNECTING) return 'Connecting...'
    return 'Disconnected'
  }

  return (
    <div className="bg-slate-800 rounded-lg shadow-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold text-white">Real-Time Attack Feed</h2>
        <div className="flex items-center gap-2">
          <div className={`w-3 h-3 rounded-full ${getStatusColor()}`}></div>
          <span className="text-sm text-slate-400">{getStatusText()}</span>
        </div>
      </div>

      <div className="space-y-3 max-h-[600px] overflow-y-auto">
        {attacks.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            No attacks detected yet. Waiting for data...
          </div>
        ) : (
          attacks.map((attack) => (
            <Link
              key={attack.id}
              to={`/attack/${attack.id}`}
              className={`block p-4 rounded-lg border-l-4 transition-colors hover:brightness-110 ${
                attack.success
                  ? 'bg-red-900/20 border-red-500 hover:bg-red-900/30'
                  : 'bg-yellow-900/20 border-yellow-500 hover:bg-yellow-900/30'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span
                      className={`px-2 py-1 rounded text-xs font-semibold ${
                        attack.success
                          ? 'bg-red-500 text-white'
                          : 'bg-yellow-500 text-black'
                      }`}
                    >
                      {attack.success ? 'SUCCESS' : 'FAILED'}
                    </span>
                    <span className="text-xs text-slate-400">
                      {format(new Date(attack.timestamp), 'HH:mm:ss')}
                    </span>
                    <span className="text-xs px-2 py-1 bg-slate-700 rounded text-slate-300">
                      {attack.technique_id}
                    </span>
                  </div>
                  
                  <div className="text-sm text-white font-medium mb-1 break-words">
                    <TruncateText text={attack.website_url} maxLength={60} className="font-medium" />
                  </div>
                  
                  <div className="text-xs text-slate-300 space-y-1">
                    <div>
                      <span className="text-slate-500">Vulnerability:</span>{' '}
                      <span className="font-medium">
                        <TruncateText text={formatVulnerabilityType(attack.vulnerability_type)} maxLength={35} />
                      </span>
                    </div>
                    {attack.attack_vector && (
                      <div>
                        <span className="text-slate-500">Vector:</span>{' '}
                        <TruncateText text={attack.attack_vector} maxLength={40} />
                      </div>
                    )}
                    {attack.source_ip && (
                      <div>
                        <span className="text-slate-500">Source IP:</span>{' '}
                        <span className="font-mono text-xs">{formatIp(attack.source_ip)}</span>
                      </div>
                    )}
                    <div className="mt-2 pt-2 border-t border-slate-700">
                      <Link
                        to={`/session/${attack.session_id}`}
                        className="text-xs text-blue-400 hover:text-blue-300"
                        onClick={(e) => e.stopPropagation()}
                      >
                        View Full Session →
                      </Link>
                    </div>
                    
                    {attack.agent_indicators && (
                      <div className="mt-2 pt-2 border-t border-slate-700">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-slate-500">Agent Probability:</span>
                          <div className="flex-1 bg-slate-700 rounded-full h-2">
                            <div
                              className="bg-blue-500 h-2 rounded-full"
                              style={{
                                width: `${attack.agent_indicators.overall_agent_probability * 100}%`
                              }}
                            ></div>
                          </div>
                          <span className="text-xs">
                            {(attack.agent_indicators.overall_agent_probability * 100).toFixed(0)}%
                          </span>
                        </div>
                        {attack.agent_indicators.indicators.length > 0 && (
                          <div className="text-xs text-slate-400">
                            {attack.agent_indicators.indicators[0]}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  )
}

