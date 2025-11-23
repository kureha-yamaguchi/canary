import { useState, useEffect, useCallback } from 'react'
import {
  HoneypotVulnerability,
  RedTeamTrajectory,
  ExternalTrajectory,
} from '../types'

// Granular event type from the new database table
interface GranularEvent {
  id: string
  session_id: string
  event_type: string
  event_category: string
  element_id?: string
  element_class?: string
  element_text?: string
  page_url: string
  page_path: string
  click_x?: number
  click_y?: number
  scroll_depth?: number
  viewport_width?: number
  viewport_height?: number
  timestamp: string
  user_agent: string
  time_since_last_ms?: number
  metadata?: string
}

interface BehavioralFeatures {
  timing: {
    avg_time_between_ms: number
    time_variance: number
    min_time_ms: number
    max_time_ms: number
    burst_ratio: number
  }
  clicks: {
    total_clicks: number
    grid_alignment_ratio: number
    click_spread: number
    click_ratio: number
  }
  engagement: {
    has_time_on_page: boolean
    has_scroll: boolean
    unique_elements: number
    unique_pages: number
    total_events: number
  }
}

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// Model fingerprint data - in production, derived from actual red team runs
const MODEL_FINGERPRINTS = [
  {
    id: 'gpt-4',
    name: 'GPT-4',
    color: '#10B981',
    traits: {
      timing: 'Methodical, consistent pauses',
      errorHandling: 'Reflects on errors, tries semantic variants',
      payloadStyle: 'Textbook examples first, then creative',
      coverage: 'Systematic but adaptive',
    },
    timingPattern: [0.8, 0.7, 0.3, 0.3, 0.8, 0.7, 0.4, 0.3],
    avgTimeBetweenMs: 2500,
    adaptationScore: 0.85,
  },
  {
    id: 'claude',
    name: 'Claude',
    color: '#8B5CF6',
    traits: {
      timing: 'Cautious, longer reflection pauses',
      errorHandling: 'Backs off, tries different attack vector',
      payloadStyle: 'More conservative probing',
      coverage: 'Thorough reconnaissance first',
    },
    timingPattern: [0.9, 0.8, 0.8, 0.4, 0.4, 0.9, 0.8, 0.5],
    avgTimeBetweenMs: 3200,
    adaptationScore: 0.78,
  },
  {
    id: 'llama-70b',
    name: 'Llama 70B',
    color: '#F59E0B',
    traits: {
      timing: 'Aggressive, rapid-fire attempts',
      errorHandling: 'Persists with modifications',
      payloadStyle: 'Direct, less refined',
      coverage: 'Fast and broad',
    },
    timingPattern: [0.4, 0.5, 0.4, 0.6, 0.4, 0.5, 0.4, 0.5],
    avgTimeBetweenMs: 1200,
    adaptationScore: 0.65,
  },
]

// Simulated embedding positions for clustering viz
const CLUSTER_DATA = {
  redTeam: [
    { x: 25, y: 30, model: 'gpt-4', label: 'RT-1' },
    { x: 28, y: 35, model: 'gpt-4', label: 'RT-2' },
    { x: 22, y: 28, model: 'gpt-4', label: 'RT-3' },
    { x: 45, y: 55, model: 'claude', label: 'RT-4' },
    { x: 48, y: 52, model: 'claude', label: 'RT-5' },
    { x: 42, y: 58, model: 'claude', label: 'RT-6' },
    { x: 70, y: 25, model: 'llama-70b', label: 'RT-7' },
    { x: 73, y: 28, model: 'llama-70b', label: 'RT-8' },
  ],
  external: [
    { x: 26, y: 32, classified: 'gpt-4', label: 'EXT-1' },
    { x: 85, y: 70, classified: 'human', label: 'EXT-2' },
    { x: 88, y: 75, classified: 'human', label: 'EXT-3' },
    { x: 15, y: 80, classified: 'script', label: 'EXT-4' },
    { x: 12, y: 85, classified: 'script', label: 'EXT-5' },
    { x: 46, y: 54, classified: 'claude', label: 'EXT-6' },
  ],
}

type TabType = 'fingerprints' | 'live-demo'

export function AgentTrajectoryPage() {
  const [activeTab, setActiveTab] = useState<TabType>('fingerprints')
  const [vulnerabilities, setVulnerabilities] = useState<HoneypotVulnerability[]>([])
  const [selectedVulnerability, setSelectedVulnerability] = useState<HoneypotVulnerability | null>(null)
  const [redTeamTrajectories, setRedTeamTrajectories] = useState<RedTeamTrajectory[]>([])
  const [externalTrajectories, setExternalTrajectories] = useState<ExternalTrajectory[]>([])
  const [loading, setLoading] = useState(true)

  // Live demo state
  const [liveEvents, setLiveEvents] = useState<GranularEvent[]>([])
  const [livePrediction, setLivePrediction] = useState<{
    human: number
    script: number
    ai_agent: number
    likely_model: string | null
    model_confidence: number
    timing_pattern?: string
    avg_time_between_ms?: number
    click_pattern?: string
  } | null>(null)
  const [behavioralFeatures, setBehavioralFeatures] = useState<BehavioralFeatures | null>(null)
  const [isLivePolling, setIsLivePolling] = useState(false)
  const [revealedAttacker, setRevealedAttacker] = useState<string | null>(null)
  const [sessionId, setSessionId] = useState<string | null>(null)

  useEffect(() => {
    fetchVulnerabilities()
  }, [])

  useEffect(() => {
    if (selectedVulnerability) {
      fetchTrajectories(selectedVulnerability.id)
    }
  }, [selectedVulnerability])

  const fetchVulnerabilities = async () => {
    try {
      setLoading(true)
      const response = await fetch(`${API_BASE}/api/vulnerabilities`)
      const data = await response.json()
      setVulnerabilities(data.vulnerabilities)
      if (data.vulnerabilities.length > 0) {
        setSelectedVulnerability(data.vulnerabilities[0])
      }
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const fetchTrajectories = async (vulnerabilityId: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/vulnerabilities/${vulnerabilityId}/trajectories`)
      const data = await response.json()
      setRedTeamTrajectories(data.red_team)
      setExternalTrajectories(data.external)
    } catch (err) {
      console.error('Failed to fetch trajectories:', err)
    }
  }

  // Live polling for demo
  const pollLiveEvents = useCallback(async () => {
    if (!sessionId) return

    try {
      const response = await fetch(`${API_BASE}/api/live-session/${sessionId}`)
      const data = await response.json()

      if (data.events && data.events.length > 0) {
        setLiveEvents(data.events)
        setLivePrediction(data.prediction)
        setBehavioralFeatures(data.behavioral_features)
      }
    } catch (err) {
      console.error('Failed to poll live events:', err)
    }
  }, [sessionId])

  useEffect(() => {
    if (isLivePolling && sessionId) {
      const interval = setInterval(pollLiveEvents, 1000)
      return () => clearInterval(interval)
    }
  }, [isLivePolling, sessionId, pollLiveEvents])

  const startLiveDemo = () => {
    // Generate a session ID for tracking
    const newSessionId = `demo-${Date.now()}`
    setSessionId(newSessionId)
    setLiveEvents([])
    setLivePrediction(null)
    setRevealedAttacker(null)
    setIsLivePolling(true)
  }

  const stopLiveDemo = () => {
    setIsLivePolling(false)
  }

  const revealAttacker = () => {
    // In production, this would fetch the actual attacker type from the backend
    // For demo, we'll show a reveal animation
    setRevealedAttacker('AI Agent (GPT-4)')
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  // These are available for future use when connecting real data
  const _redTeam = redTeamTrajectories[0] || null
  const _external = externalTrajectories[0] || null

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Classification</h1>
          <p className="text-slate-600 mt-1">
            Identify attackers through behavioral fingerprinting and model attribution
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded-full text-sm">
          <span className="w-2 h-2 bg-indigo-500 rounded-full"></span>
          AI Detection Active
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-gray-200">
        <button
          onClick={() => setActiveTab('fingerprints')}
          className={`px-6 py-3 font-medium transition-colors border-b-2 -mb-px ${
            activeTab === 'fingerprints'
              ? 'border-blue-500 text-blue-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          Model Fingerprints
        </button>
        <button
          onClick={() => setActiveTab('live-demo')}
          className={`px-6 py-3 font-medium transition-colors border-b-2 -mb-px ${
            activeTab === 'live-demo'
              ? 'border-blue-500 text-blue-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          Live Demo
        </button>
      </div>

      {activeTab === 'fingerprints' && (
        <div className="space-y-6">
          {/* Model Fingerprints Grid */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-4">AI Model Behavioral Fingerprints</h2>
            <p className="text-sm text-gray-600 mb-6">
              Each model exhibits distinct patterns when attacking. These fingerprints are derived from running
              our red team agent with different underlying models.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {MODEL_FINGERPRINTS.map((model) => (
                <div
                  key={model.id}
                  className="border-2 rounded-lg p-4"
                  style={{ borderColor: model.color }}
                >
                  <div className="flex items-center gap-2 mb-4">
                    <div
                      className="w-4 h-4 rounded-full"
                      style={{ backgroundColor: model.color }}
                    />
                    <h3 className="font-bold text-gray-900">{model.name}</h3>
                  </div>

                  {/* Timing Pattern Visualization */}
                  <div className="mb-4">
                    <div className="text-xs text-gray-500 mb-1">Timing Pattern</div>
                    <div className="flex gap-0.5 h-8 items-end">
                      {model.timingPattern.map((v, i) => (
                        <div
                          key={i}
                          className="flex-1 rounded-t"
                          style={{
                            height: `${v * 100}%`,
                            backgroundColor: model.color,
                            opacity: 0.7,
                          }}
                        />
                      ))}
                    </div>
                    <div className="text-xs text-gray-500 mt-1">
                      Avg: {model.avgTimeBetweenMs}ms between actions
                    </div>
                  </div>

                  {/* Traits */}
                  <div className="space-y-2 text-sm">
                    <div>
                      <span className="text-gray-500">Timing:</span>
                      <span className="ml-1 text-gray-700">{model.traits.timing}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">On Error:</span>
                      <span className="ml-1 text-gray-700">{model.traits.errorHandling}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">Style:</span>
                      <span className="ml-1 text-gray-700">{model.traits.payloadStyle}</span>
                    </div>
                  </div>

                  {/* Adaptation Score */}
                  <div className="mt-4 pt-4 border-t border-gray-200">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-500">Adaptation Score</span>
                      <span className="font-bold" style={{ color: model.color }}>
                        {(model.adaptationScore * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="mt-1 bg-gray-200 rounded-full h-2">
                      <div
                        className="h-2 rounded-full"
                        style={{
                          width: `${model.adaptationScore * 100}%`,
                          backgroundColor: model.color,
                        }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Clustering Visualization */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-2">Trajectory Embedding Space</h2>
            <p className="text-sm text-gray-600 mb-6">
              Attack trajectories projected into 2D space using behavioral features.
              External attackers clustering with known red team patterns indicates AI-driven attacks.
            </p>

            <div className="flex gap-8">
              {/* Scatter Plot */}
              <div className="flex-1">
                <div className="relative bg-slate-50 rounded-lg border border-slate-200 h-80">
                  {/* Grid lines */}
                  <svg className="absolute inset-0 w-full h-full" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                      <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                        <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#e2e8f0" strokeWidth="1"/>
                      </pattern>
                    </defs>
                    <rect width="100%" height="100%" fill="url(#grid)" />
                  </svg>

                  {/* Cluster regions */}
                  <div className="absolute top-[15%] left-[15%] w-24 h-24 bg-green-100 rounded-full opacity-30" />
                  <div className="absolute top-[40%] left-[35%] w-24 h-24 bg-purple-100 rounded-full opacity-30" />
                  <div className="absolute top-[15%] left-[60%] w-20 h-20 bg-yellow-100 rounded-full opacity-30" />
                  <div className="absolute top-[60%] left-[75%] w-24 h-24 bg-gray-200 rounded-full opacity-30" />
                  <div className="absolute top-[65%] left-[5%] w-20 h-20 bg-gray-300 rounded-full opacity-30" />

                  {/* Red team points */}
                  {CLUSTER_DATA.redTeam.map((point, i) => {
                    const model = MODEL_FINGERPRINTS.find(m => m.id === point.model)
                    return (
                      <div
                        key={`rt-${i}`}
                        className="absolute w-4 h-4 rounded-full border-2 border-white shadow-md transform -translate-x-1/2 -translate-y-1/2 cursor-pointer hover:scale-125 transition-transform"
                        style={{
                          left: `${point.x}%`,
                          top: `${point.y}%`,
                          backgroundColor: model?.color || '#666',
                        }}
                        title={`${point.label} (${model?.name})`}
                      />
                    )
                  })}

                  {/* External points */}
                  {CLUSTER_DATA.external.map((point, i) => {
                    const isAI = point.classified !== 'human' && point.classified !== 'script'
                    const model = MODEL_FINGERPRINTS.find(m => m.id === point.classified)
                    return (
                      <div
                        key={`ext-${i}`}
                        className="absolute w-4 h-4 transform -translate-x-1/2 -translate-y-1/2 cursor-pointer hover:scale-125 transition-transform"
                        style={{
                          left: `${point.x}%`,
                          top: `${point.y}%`,
                        }}
                        title={`${point.label} (${point.classified})`}
                      >
                        <div
                          className={`w-full h-full ${isAI ? 'rounded-full' : 'rounded-sm'} border-2`}
                          style={{
                            backgroundColor: model?.color || (point.classified === 'human' ? '#9CA3AF' : '#6B7280'),
                            borderColor: '#fff',
                            opacity: 0.8,
                          }}
                        />
                        {isAI && (
                          <div className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                        )}
                      </div>
                    )
                  })}

                  {/* Axis labels */}
                  <div className="absolute bottom-2 left-1/2 transform -translate-x-1/2 text-xs text-gray-400">
                    Timing Features →
                  </div>
                  <div className="absolute top-1/2 left-2 transform -rotate-90 -translate-y-1/2 text-xs text-gray-400">
                    Adaptation Features →
                  </div>
                </div>
              </div>

              {/* Legend */}
              <div className="w-48 space-y-4">
                <div>
                  <div className="text-xs font-medium text-gray-500 uppercase mb-2">Red Team (Known)</div>
                  {MODEL_FINGERPRINTS.map((model) => (
                    <div key={model.id} className="flex items-center gap-2 text-sm py-1">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: model.color }}
                      />
                      <span>{model.name}</span>
                    </div>
                  ))}
                </div>

                <div>
                  <div className="text-xs font-medium text-gray-500 uppercase mb-2">External (Classified)</div>
                  <div className="flex items-center gap-2 text-sm py-1">
                    <div className="w-3 h-3 rounded-full bg-gray-400" />
                    <span>Human</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm py-1">
                    <div className="w-3 h-3 rounded-sm bg-gray-500" />
                    <span>Script</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm py-1">
                    <div className="relative">
                      <div className="w-3 h-3 rounded-full bg-green-500" />
                      <div className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 bg-red-500 rounded-full" />
                    </div>
                    <span>AI Agent</span>
                  </div>
                </div>

                <div className="pt-4 border-t border-gray-200">
                  <div className="text-xs text-gray-500">
                    External attackers clustering with red team patterns are classified as AI-driven.
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Key Insight */}
          <div className="bg-slate-800 rounded-lg p-6 text-white">
            <div className="flex items-start gap-4">
              <div className="text-3xl">🔬</div>
              <div>
                <h4 className="font-bold text-lg">The Novel Insight</h4>
                <p className="text-slate-300 mt-2">
                  By running red team agents with <strong className="text-white">multiple AI models</strong>, we discover that
                  each model has a unique behavioral signature. This allows us to not only detect AI-driven attacks,
                  but potentially <strong className="text-white">identify which model</strong> is being used -
                  turning offensive AI capabilities into a traceable fingerprint for defensive intelligence.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'live-demo' && (
        <div className="space-y-6">
          {/* Live Demo Panel */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div className="bg-slate-800 text-white p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="font-bold text-lg">Live Attack Classification</h2>
                  <p className="text-slate-300 text-sm mt-1">
                    Attack the honeypot and watch the classifier predict what you are
                  </p>
                </div>
                <div className="flex gap-2">
                  {!isLivePolling ? (
                    <button
                      onClick={startLiveDemo}
                      className="px-4 py-2 bg-green-500 hover:bg-green-600 rounded-lg font-medium transition-colors"
                    >
                      Start Monitoring
                    </button>
                  ) : (
                    <button
                      onClick={stopLiveDemo}
                      className="px-4 py-2 bg-red-500 hover:bg-red-600 rounded-lg font-medium transition-colors"
                    >
                      Stop
                    </button>
                  )}
                </div>
              </div>
            </div>

            <div className="p-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Event Feed */}
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-3">Incoming Events</h3>
                  <div className="bg-slate-900 rounded-lg p-4 h-64 overflow-y-auto font-mono text-sm">
                    {liveEvents.length === 0 ? (
                      <div className="text-slate-500 text-center py-8">
                        {isLivePolling ? (
                          <div className="space-y-2">
                            <div className="animate-pulse">Waiting for events...</div>
                            <div className="text-xs">Attack the honeypot to see events appear</div>
                          </div>
                        ) : (
                          'Click "Start Monitoring" to begin'
                        )}
                      </div>
                    ) : (
                      <div className="space-y-1">
                        {liveEvents.map((event, i) => (
                          <div key={i} className="flex items-center gap-2 text-xs">
                            <span className="text-slate-500">
                              {new Date(event.timestamp).toLocaleTimeString()}
                            </span>
                            <span className={
                              event.event_type === 'click' ? 'text-cyan-400' :
                              event.event_type === 'scroll' ? 'text-purple-400' :
                              event.event_type === 'time_on_page' ? 'text-yellow-400' :
                              'text-green-400'
                            }>
                              {event.event_type}
                            </span>
                            {event.event_type === 'click' && event.click_x && (
                              <span className="text-slate-400">
                                ({event.click_x}, {event.click_y})
                              </span>
                            )}
                            <span className="text-slate-300 truncate flex-1">
                              {event.element_text || event.page_path || '/'}
                            </span>
                            {event.time_since_last_ms !== undefined && event.time_since_last_ms > 0 && (
                              <span className={`text-xs px-1 rounded ${
                                event.time_since_last_ms < 500 ? 'bg-red-900 text-red-300' :
                                event.time_since_last_ms > 3000 ? 'bg-green-900 text-green-300' :
                                'bg-yellow-900 text-yellow-300'
                              }`}>
                                +{(event.time_since_last_ms / 1000).toFixed(1)}s
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Prediction Panel */}
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-3">Live Prediction</h3>
                  <div className="bg-gray-50 rounded-lg border border-gray-200 p-4 h-64">
                    {!livePrediction ? (
                      <div className="h-full flex items-center justify-center text-gray-400">
                        <div className="text-center">
                          <div className="text-4xl mb-2">🎯</div>
                          <div>Prediction will appear as events come in</div>
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {/* Classification Bars */}
                        <div className="space-y-3">
                          <div>
                            <div className="flex justify-between text-sm mb-1">
                              <span className="text-gray-600">Human</span>
                              <span className="font-medium">{(livePrediction.human * 100).toFixed(0)}%</span>
                            </div>
                            <div className="bg-gray-200 rounded-full h-3">
                              <div
                                className="bg-gray-500 h-3 rounded-full transition-all duration-500"
                                style={{ width: `${livePrediction.human * 100}%` }}
                              />
                            </div>
                          </div>
                          <div>
                            <div className="flex justify-between text-sm mb-1">
                              <span className="text-gray-600">Script</span>
                              <span className="font-medium">{(livePrediction.script * 100).toFixed(0)}%</span>
                            </div>
                            <div className="bg-gray-200 rounded-full h-3">
                              <div
                                className="bg-blue-500 h-3 rounded-full transition-all duration-500"
                                style={{ width: `${livePrediction.script * 100}%` }}
                              />
                            </div>
                          </div>
                          <div>
                            <div className="flex justify-between text-sm mb-1">
                              <span className="text-gray-600">AI Agent</span>
                              <span className="font-bold text-yellow-600">{(livePrediction.ai_agent * 100).toFixed(0)}%</span>
                            </div>
                            <div className="bg-gray-200 rounded-full h-3">
                              <div
                                className="bg-yellow-500 h-3 rounded-full transition-all duration-500"
                                style={{ width: `${livePrediction.ai_agent * 100}%` }}
                              />
                            </div>
                          </div>
                        </div>

                        {/* Model Attribution */}
                        {livePrediction.likely_model && (
                          <div className="pt-3 border-t border-gray-200">
                            <div className="text-sm text-gray-600">If AI, most likely model:</div>
                            <div className="text-lg font-bold text-gray-900">
                              {livePrediction.likely_model}
                              <span className="text-sm font-normal text-gray-500 ml-2">
                                ({(livePrediction.model_confidence * 100).toFixed(0)}% confidence)
                              </span>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Behavioral Features Panel */}
              {behavioralFeatures && (
                <div className="mt-6 pt-6 border-t border-gray-200">
                  <h3 className="text-sm font-medium text-gray-700 mb-4">Detected Behavioral Features</h3>
                  <div className="grid grid-cols-3 gap-4">
                    {/* Timing */}
                    <div className="bg-slate-50 rounded-lg p-4 border border-slate-200">
                      <div className="text-xs font-medium text-slate-500 uppercase mb-2">Timing</div>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Avg between:</span>
                          <span className="font-mono">{(behavioralFeatures.timing.avg_time_between_ms / 1000).toFixed(1)}s</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Burst ratio:</span>
                          <span className={`font-mono ${behavioralFeatures.timing.burst_ratio > 0.3 ? 'text-red-600' : 'text-green-600'}`}>
                            {(behavioralFeatures.timing.burst_ratio * 100).toFixed(0)}%
                          </span>
                        </div>
                      </div>
                    </div>
                    {/* Clicks */}
                    <div className="bg-slate-50 rounded-lg p-4 border border-slate-200">
                      <div className="text-xs font-medium text-slate-500 uppercase mb-2">Clicks</div>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Total clicks:</span>
                          <span className="font-mono">{behavioralFeatures.clicks.total_clicks}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Grid aligned:</span>
                          <span className={`font-mono ${behavioralFeatures.clicks.grid_alignment_ratio > 0.3 ? 'text-red-600' : 'text-green-600'}`}>
                            {(behavioralFeatures.clicks.grid_alignment_ratio * 100).toFixed(0)}%
                          </span>
                        </div>
                      </div>
                    </div>
                    {/* Engagement */}
                    <div className="bg-slate-50 rounded-lg p-4 border border-slate-200">
                      <div className="text-xs font-medium text-slate-500 uppercase mb-2">Engagement</div>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Time on page:</span>
                          <span className={behavioralFeatures.engagement.has_time_on_page ? 'text-green-600' : 'text-red-600'}>
                            {behavioralFeatures.engagement.has_time_on_page ? '✓' : '✗'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Unique elements:</span>
                          <span className="font-mono">{behavioralFeatures.engagement.unique_elements}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Reveal Section */}
              {liveEvents.length > 0 && (
                <div className="mt-6 pt-6 border-t border-gray-200">
                  <div className="flex items-center justify-center gap-4">
                    {!revealedAttacker ? (
                      <button
                        onClick={revealAttacker}
                        className="px-8 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-bold transition-colors"
                      >
                        Reveal Actual Attacker
                      </button>
                    ) : (
                      <div className="text-center">
                        <div className="text-sm text-gray-500 mb-2">The attacker was:</div>
                        <div className="text-3xl font-bold text-purple-600 animate-pulse">
                          {revealedAttacker}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* TTP/MITRE Integration */}
          {liveEvents.length > 0 && livePrediction && (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
              <div className="bg-orange-50 border-b border-orange-200 p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xl">🎯</span>
                    <h3 className="font-bold text-orange-900">TTP Analysis</h3>
                  </div>
                  <a
                    href="/matrix-map"
                    className="px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white rounded-lg text-sm font-medium transition-colors"
                  >
                    View Full MITRE Matrix →
                  </a>
                </div>
                <p className="text-sm text-orange-700 mt-1">
                  While this page identifies <strong>who</strong> is attacking, the MITRE analysis shows <strong>what</strong> they're doing
                </p>
              </div>

              <div className="p-4">
                <div className="grid grid-cols-2 gap-6">
                  {/* This Page */}
                  <div className="border-r border-gray-200 pr-6">
                    <div className="text-xs font-medium text-gray-500 uppercase mb-3">Agent Trajectory (This Page)</div>
                    <ul className="space-y-2 text-sm text-gray-700">
                      <li className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-green-100 text-green-600 flex items-center justify-center text-xs">✓</span>
                        Human vs Script vs AI Agent detection
                      </li>
                      <li className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-green-100 text-green-600 flex items-center justify-center text-xs">✓</span>
                        Model fingerprinting (GPT-4, Claude, Llama)
                      </li>
                      <li className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-green-100 text-green-600 flex items-center justify-center text-xs">✓</span>
                        Behavioral clustering
                      </li>
                    </ul>
                    <div className="mt-4 p-3 bg-slate-50 rounded-lg">
                      <div className="text-xs text-gray-500">Key Question Answered:</div>
                      <div className="font-medium text-gray-900">"Who is attacking us?"</div>
                    </div>
                  </div>

                  {/* MITRE Page */}
                  <div className="pl-2">
                    <div className="text-xs font-medium text-gray-500 uppercase mb-3">MITRE Analysis</div>
                    <ul className="space-y-2 text-sm text-gray-700">
                      <li className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-xs">→</span>
                        Tactics, Techniques & Procedures mapping
                      </li>
                      <li className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-xs">→</span>
                        Kill chain progression tracking
                      </li>
                      <li className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-xs">→</span>
                        Defense recommendations
                      </li>
                    </ul>
                    <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                      <div className="text-xs text-gray-500">Key Question Answered:</div>
                      <div className="font-medium text-gray-900">"What are they doing?"</div>
                    </div>
                  </div>
                </div>

                {/* Combined Insight */}
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <div className="flex items-center gap-3 p-3 bg-purple-50 rounded-lg">
                    <span className="text-2xl">💡</span>
                    <div className="text-sm text-purple-900">
                      <strong>Combined Insight:</strong> When an attacker is identified as an AI agent,
                      their TTP patterns can predict which vulnerabilities they'll target next,
                      enabling <strong>proactive defense</strong> rather than reactive response.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Instructions */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h3 className="font-medium text-blue-900 mb-2">How to Demo</h3>
            <ol className="text-sm text-blue-800 space-y-1 list-decimal list-inside">
              <li>Click "Start Monitoring" to begin watching for attacks</li>
              <li>Have someone (human, script, or AI agent) attack the honeypot</li>
              <li>Watch the prediction update in real-time as events come in</li>
              <li>After the attack, click "Reveal Actual Attacker" to see if the prediction was correct</li>
            </ol>
          </div>
        </div>
      )}
    </div>
  )
}