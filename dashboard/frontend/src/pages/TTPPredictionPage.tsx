import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

// @ts-expect-error Vite env
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// TTP prediction based on observed events
interface TTPPrediction {
  technique_id: string
  technique_name: string
  tactic: string
  probability: number
  evidence: string[]
  next_likely_technique?: string
}

// Mitigation recommendation
interface Mitigation {
  id: string
  title: string
  description: string
  blocks_techniques: string[]
  implementation_effort: 'low' | 'medium' | 'high'
  priority: 'low' | 'medium' | 'high' | 'critical'
}

// Observed event from trajectory
interface TrajectoryEvent {
  timestamp: string
  event_type: string
  element_text?: string
  page_path: string
  inferred_technique?: string
}

// Known TTP patterns from red team
const RED_TEAM_PATTERNS = [
  {
    id: 'recon_pattern_1',
    name: 'Automated Reconnaissance',
    techniques: ['T1595', 'T1592', 'T1589'],
    indicators: ['rapid page navigation', 'form enumeration', 'hidden field discovery'],
  },
  {
    id: 'exploit_pattern_1',
    name: 'Injection Attack Chain',
    techniques: ['T1190', 'T1059', 'T1055'],
    indicators: ['input field focus', 'special character injection', 'form submission'],
  },
  {
    id: 'exfil_pattern_1',
    name: 'Data Exfiltration',
    techniques: ['T1005', 'T1041', 'T1567'],
    indicators: ['data element selection', 'copy actions', 'external navigation'],
  },
]

// TTP database (subset for demo)
const TTP_DATABASE: Record<string, { name: string; tactic: string; description: string }> = {
  'T1595': { name: 'Active Scanning', tactic: 'Reconnaissance', description: 'Scanning for vulnerabilities in target systems' },
  'T1592': { name: 'Gather Victim Host Information', tactic: 'Reconnaissance', description: 'Collecting host details for targeting' },
  'T1589': { name: 'Gather Victim Identity Information', tactic: 'Reconnaissance', description: 'Collecting identity details for targeting' },
  'T1190': { name: 'Exploit Public-Facing Application', tactic: 'Initial Access', description: 'Exploiting vulnerabilities in web applications' },
  'T1059': { name: 'Command and Scripting Interpreter', tactic: 'Execution', description: 'Using scripts or commands to execute actions' },
  'T1055': { name: 'Process Injection', tactic: 'Defense Evasion', description: 'Injecting code into running processes' },
  'T1005': { name: 'Data from Local System', tactic: 'Collection', description: 'Collecting data from the local system' },
  'T1041': { name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', description: 'Exfiltrating data over command and control' },
  'T1567': { name: 'Exfiltration Over Web Service', tactic: 'Exfiltration', description: 'Exfiltrating data to web services' },
  'T1071': { name: 'Application Layer Protocol', tactic: 'Command and Control', description: 'Using application protocols for C2' },
  'T1082': { name: 'System Information Discovery', tactic: 'Discovery', description: 'Gathering system configuration info' },
  'T1087': { name: 'Account Discovery', tactic: 'Discovery', description: 'Attempting to discover user accounts' },
}

// Mitigations database
const MITIGATIONS_DATABASE: Mitigation[] = [
  {
    id: 'M1030',
    title: 'Network Segmentation',
    description: 'Isolate sensitive systems and limit lateral movement potential',
    blocks_techniques: ['T1055', 'T1041', 'T1071'],
    implementation_effort: 'high',
    priority: 'high',
  },
  {
    id: 'M1031',
    title: 'Network Intrusion Prevention',
    description: 'Deploy IDS/IPS to detect and block malicious traffic patterns',
    blocks_techniques: ['T1190', 'T1059', 'T1071'],
    implementation_effort: 'medium',
    priority: 'critical',
  },
  {
    id: 'M1050',
    title: 'Exploit Protection',
    description: 'Enable exploit protection features to prevent common attack techniques',
    blocks_techniques: ['T1190', 'T1055'],
    implementation_effort: 'low',
    priority: 'critical',
  },
  {
    id: 'M1056',
    title: 'Input Validation',
    description: 'Validate and sanitize all user inputs to prevent injection attacks',
    blocks_techniques: ['T1059', 'T1190'],
    implementation_effort: 'medium',
    priority: 'critical',
  },
  {
    id: 'M1057',
    title: 'Data Loss Prevention',
    description: 'Implement DLP controls to detect and prevent data exfiltration',
    blocks_techniques: ['T1005', 'T1041', 'T1567'],
    implementation_effort: 'high',
    priority: 'high',
  },
  {
    id: 'M1037',
    title: 'Filter Network Traffic',
    description: 'Filter outbound traffic to prevent unauthorized data transfers',
    blocks_techniques: ['T1041', 'T1567', 'T1071'],
    implementation_effort: 'medium',
    priority: 'high',
  },
]

// Analyze events to predict TTPs
function predictTTPs(events: TrajectoryEvent[]): TTPPrediction[] {
  const predictions: TTPPrediction[] = []

  if (events.length === 0) return predictions

  // Analyze event patterns
  const eventTypes = events.map(e => e.event_type)
  const pagePaths = events.map(e => e.page_path)
  const hasRapidNavigation = events.filter((_, i) => i > 0).length > 5
  const hasFormInteraction = eventTypes.includes('click') && events.some(e =>
    e.element_text?.toLowerCase().includes('submit') ||
    e.element_text?.toLowerCase().includes('login') ||
    e.element_text?.toLowerCase().includes('search')
  )
  const uniquePages = new Set(pagePaths).size

  // Reconnaissance indicators
  if (uniquePages > 3 || hasRapidNavigation) {
    predictions.push({
      technique_id: 'T1595',
      technique_name: 'Active Scanning',
      tactic: 'Reconnaissance',
      probability: Math.min(0.85, 0.5 + (uniquePages * 0.1)),
      evidence: [
        `Visited ${uniquePages} unique pages`,
        hasRapidNavigation ? 'Rapid navigation pattern detected' : 'Systematic page exploration',
      ],
      next_likely_technique: 'T1592',
    })
  }

  // Form interaction → potential exploitation
  if (hasFormInteraction) {
    predictions.push({
      technique_id: 'T1190',
      technique_name: 'Exploit Public-Facing Application',
      tactic: 'Initial Access',
      probability: 0.72,
      evidence: [
        'Form interaction detected',
        'Input field engagement observed',
      ],
      next_likely_technique: 'T1059',
    })
  }

  // Click patterns → discovery
  const clickCount = eventTypes.filter(t => t === 'click').length
  if (clickCount > 3) {
    predictions.push({
      technique_id: 'T1082',
      technique_name: 'System Information Discovery',
      tactic: 'Discovery',
      probability: 0.65,
      evidence: [
        `${clickCount} click interactions recorded`,
        'Element inspection behavior',
      ],
      next_likely_technique: 'T1087',
    })
  }

  // Scroll behavior → collection
  if (eventTypes.includes('scroll')) {
    predictions.push({
      technique_id: 'T1005',
      technique_name: 'Data from Local System',
      tactic: 'Collection',
      probability: 0.58,
      evidence: [
        'Page scrolling indicates content review',
        'Potential data identification',
      ],
      next_likely_technique: 'T1041',
    })
  }

  // Sort by probability
  return predictions.sort((a, b) => b.probability - a.probability)
}

// Get relevant mitigations for predicted TTPs
function getRelevantMitigations(predictions: TTPPrediction[]): Mitigation[] {
  const techniqueIds = new Set(predictions.map(p => p.technique_id))
  const nextTechniques = new Set(predictions.map(p => p.next_likely_technique).filter(Boolean))

  // Also consider next likely techniques
  const allRelevantTechniques = new Set([...techniqueIds, ...nextTechniques])

  // Find mitigations that block these techniques
  const relevantMitigations = MITIGATIONS_DATABASE.filter(m =>
    m.blocks_techniques.some(t => allRelevantTechniques.has(t))
  )

  // Sort by priority and how many relevant techniques they block
  return relevantMitigations.sort((a, b) => {
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
    if (priorityOrder[a.priority] !== priorityOrder[b.priority]) {
      return priorityOrder[a.priority] - priorityOrder[b.priority]
    }
    const aBlocks = a.blocks_techniques.filter(t => allRelevantTechniques.has(t)).length
    const bBlocks = b.blocks_techniques.filter(t => allRelevantTechniques.has(t)).length
    return bBlocks - aBlocks
  })
}

export function TTPPredictionPage() {
  const [events, setEvents] = useState<TrajectoryEvent[]>([])
  const [predictions, setPredictions] = useState<TTPPrediction[]>([])
  const [mitigations, setMitigations] = useState<Mitigation[]>([])
  const [loading, setLoading] = useState(false)
  const [sessionId] = useState<string>('latest')
  const [isPolling, setIsPolling] = useState(false)
  const [matchedPattern, setMatchedPattern] = useState<typeof RED_TEAM_PATTERNS[0] | null>(null)

  // Fetch live events
  const fetchEvents = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/live-session/${sessionId}`)
      const data = await response.json()

      if (data.events && data.events.length > 0) {
        const trajectoryEvents: TrajectoryEvent[] = data.events.map((e: any) => ({
          timestamp: e.timestamp,
          event_type: e.event_type,
          element_text: e.element_text,
          page_path: e.page_path,
        }))

        setEvents(trajectoryEvents)

        // Predict TTPs
        const ttps = predictTTPs(trajectoryEvents)
        setPredictions(ttps)

        // Get mitigations
        const mits = getRelevantMitigations(ttps)
        setMitigations(mits)

        // Check for pattern matches
        const matchedTechniques = new Set(ttps.map(p => p.technique_id))
        for (const pattern of RED_TEAM_PATTERNS) {
          const overlap = pattern.techniques.filter(t => matchedTechniques.has(t))
          if (overlap.length >= 2) {
            setMatchedPattern(pattern)
            break
          }
        }
      }
    } catch (err) {
      console.error('Failed to fetch events:', err)
    }
  }

  // Start/stop polling
  useEffect(() => {
    let interval: ReturnType<typeof setInterval> | null = null

    if (isPolling) {
      fetchEvents()
      interval = setInterval(fetchEvents, 2000)
    }

    return () => {
      if (interval) clearInterval(interval)
    }
  }, [isPolling, sessionId])

  // Demo mode - generate synthetic events
  const startDemo = () => {
    setLoading(true)

    // Simulate a trajectory
    const demoEvents: TrajectoryEvent[] = [
      { timestamp: new Date(Date.now() - 10000).toISOString(), event_type: 'pageview', page_path: '/' },
      { timestamp: new Date(Date.now() - 8000).toISOString(), event_type: 'click', element_text: 'Products', page_path: '/' },
      { timestamp: new Date(Date.now() - 6000).toISOString(), event_type: 'pageview', page_path: '/products' },
      { timestamp: new Date(Date.now() - 5000).toISOString(), event_type: 'scroll', page_path: '/products' },
      { timestamp: new Date(Date.now() - 4000).toISOString(), event_type: 'click', element_text: 'Login', page_path: '/products' },
      { timestamp: new Date(Date.now() - 3000).toISOString(), event_type: 'pageview', page_path: '/login' },
      { timestamp: new Date(Date.now() - 2000).toISOString(), event_type: 'click', element_text: 'Submit', page_path: '/login' },
      { timestamp: new Date(Date.now() - 1000).toISOString(), event_type: 'pageview', page_path: '/admin' },
    ]

    setTimeout(() => {
      setEvents(demoEvents)
      const ttps = predictTTPs(demoEvents)
      setPredictions(ttps)
      const mits = getRelevantMitigations(ttps)
      setMitigations(mits)
      setMatchedPattern(RED_TEAM_PATTERNS[0])
      setLoading(false)
    }, 1500)
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-300'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-300'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-300'
      default: return 'bg-gray-100 text-gray-800 border-gray-300'
    }
  }

  const getEffortBadge = (effort: string) => {
    switch (effort) {
      case 'low': return 'bg-green-100 text-green-700'
      case 'medium': return 'bg-yellow-100 text-yellow-700'
      case 'high': return 'bg-red-100 text-red-700'
      default: return 'bg-gray-100 text-gray-700'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Prediction</h1>
          <p className="text-slate-600 mt-1">
            Predict attack trajectories and recommend mitigations before attacks complete
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={startDemo}
            disabled={loading}
            className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-sm font-medium transition-colors"
          >
            {loading ? 'Loading...' : 'Run Demo'}
          </button>
          <button
            onClick={() => setIsPolling(!isPolling)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              isPolling
                ? 'bg-red-500 hover:bg-red-600 text-white'
                : 'bg-indigo-600 hover:bg-indigo-700 text-white'
            }`}
          >
            {isPolling ? 'Stop Live' : 'Start Live'}
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-12 gap-6">
        {/* Left: Trajectory Events */}
        <div className="col-span-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div className="bg-slate-800 text-white p-4">
              <h2 className="font-bold flex items-center gap-2">
                <span>📍</span> Attack Trajectory
              </h2>
              <p className="text-slate-400 text-xs mt-1">
                {events.length} events captured
              </p>
            </div>

            <div className="p-4 max-h-96 overflow-y-auto">
              {events.length === 0 ? (
                <div className="text-center text-gray-500 py-8">
                  <p className="text-sm">No events yet</p>
                  <p className="text-xs mt-1">Click "Run Demo" or "Start Live" to begin</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {events.map((event, i) => (
                    <div key={i} className="flex items-start gap-2 text-sm">
                      <div className="w-6 h-6 rounded-full bg-slate-100 flex items-center justify-center text-xs font-bold text-slate-600">
                        {i + 1}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            event.event_type === 'click' ? 'bg-cyan-100 text-cyan-700' :
                            event.event_type === 'scroll' ? 'bg-purple-100 text-purple-700' :
                            event.event_type === 'pageview' ? 'bg-green-100 text-green-700' :
                            'bg-gray-100 text-gray-700'
                          }`}>
                            {event.event_type}
                          </span>
                          <span className="text-gray-500 text-xs">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <div className="text-gray-700 mt-1">
                          {event.element_text || event.page_path}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Pattern Match */}
          {matchedPattern && (
            <div className="mt-4 bg-amber-50 border border-amber-200 rounded-xl p-4">
              <div className="flex items-center gap-2 text-amber-800 font-bold">
                <span>⚠️</span>
                Pattern Match Detected
              </div>
              <div className="mt-2">
                <div className="text-sm font-medium text-amber-900">
                  {matchedPattern.name}
                </div>
                <div className="text-xs text-amber-700 mt-1">
                  Matches red-team pattern with {matchedPattern.techniques.length} known techniques
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {matchedPattern.indicators.map((indicator, i) => (
                    <span key={i} className="text-xs px-2 py-1 bg-amber-100 rounded text-amber-800">
                      {indicator}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Middle: TTP Predictions */}
        <div className="col-span-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div className="bg-orange-500 text-white p-4">
              <h2 className="font-bold flex items-center gap-2">
                <span>🔮</span> Predicted TTPs
              </h2>
              <p className="text-orange-200 text-xs mt-1">
                Based on trajectory similarity to red-team patterns
              </p>
            </div>

            <div className="p-4 max-h-[500px] overflow-y-auto">
              {predictions.length === 0 ? (
                <div className="text-center text-gray-500 py-8">
                  <p className="text-sm">No predictions yet</p>
                  <p className="text-xs mt-1">Events needed to generate predictions</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {predictions.map((pred, i) => (
                    <div key={i} className="border border-gray-200 rounded-lg p-3">
                      <div className="flex items-center justify-between">
                        <a
                          href={`https://attack.mitre.org/techniques/${pred.technique_id}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-medium text-orange-600 hover:text-orange-800 hover:underline"
                        >
                          {pred.technique_id}
                        </a>
                        <div className="flex items-center gap-1">
                          <div className="w-20 h-2 bg-gray-200 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-orange-500"
                              style={{ width: `${pred.probability * 100}%` }}
                            />
                          </div>
                          <span className="text-xs text-gray-600">
                            {Math.round(pred.probability * 100)}%
                          </span>
                        </div>
                      </div>
                      <div className="text-sm font-medium text-gray-900 mt-1">
                        {pred.technique_name}
                      </div>
                      <div className="text-xs text-gray-500 mt-0.5">
                        {pred.tactic}
                      </div>

                      {/* Evidence */}
                      <div className="mt-2 space-y-1">
                        {pred.evidence.map((e, j) => (
                          <div key={j} className="text-xs text-gray-600 flex items-center gap-1">
                            <span className="text-green-500">✓</span>
                            {e}
                          </div>
                        ))}
                      </div>

                      {/* Next prediction */}
                      {pred.next_likely_technique && TTP_DATABASE[pred.next_likely_technique] && (
                        <div className="mt-2 pt-2 border-t border-gray-100">
                          <div className="text-xs text-gray-500">
                            Next likely: <span className="font-medium text-gray-700">
                              {pred.next_likely_technique} - {TTP_DATABASE[pred.next_likely_technique].name}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {predictions.length > 0 && (
              <div className="border-t border-gray-200 p-3 bg-gray-50">
                <Link
                  to="/matrix-map"
                  className="text-sm text-orange-600 hover:text-orange-800 font-medium flex items-center justify-center gap-1"
                >
                  View Full MITRE Matrix →
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Right: Mitigations */}
        <div className="col-span-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div className="bg-green-600 text-white p-4">
              <h2 className="font-bold flex items-center gap-2">
                <span>🛡️</span> Recommended Mitigations
              </h2>
              <p className="text-green-200 text-xs mt-1">
                Prioritized defenses for predicted attack chain
              </p>
            </div>

            <div className="p-4 max-h-[500px] overflow-y-auto">
              {mitigations.length === 0 ? (
                <div className="text-center text-gray-500 py-8">
                  <p className="text-sm">No mitigations yet</p>
                  <p className="text-xs mt-1">TTPs needed to recommend mitigations</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {mitigations.map((mit, i) => (
                    <div
                      key={i}
                      className={`border rounded-lg p-3 ${getPriorityColor(mit.priority)}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="font-medium text-sm">
                          {mit.title}
                        </div>
                        <span className={`text-xs px-2 py-0.5 rounded ${getEffortBadge(mit.implementation_effort)}`}>
                          {mit.implementation_effort} effort
                        </span>
                      </div>
                      <div className="text-xs mt-1 opacity-80">
                        {mit.description}
                      </div>
                      <div className="flex flex-wrap gap-1 mt-2">
                        {mit.blocks_techniques.map((t, j) => (
                          <span
                            key={j}
                            className="text-xs px-1.5 py-0.5 bg-white/50 rounded font-mono"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {mitigations.length > 0 && (
              <div className="border-t border-gray-200 p-4 bg-gray-50">
                <div className="text-xs text-gray-600 text-center">
                  {mitigations.filter(m => m.priority === 'critical').length} critical, {' '}
                  {mitigations.filter(m => m.priority === 'high').length} high priority mitigations
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Explanation */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
        <h3 className="font-bold text-blue-900 flex items-center gap-2">
          <span>💡</span> How This Works
        </h3>
        <div className="grid grid-cols-3 gap-6 mt-3">
          <div>
            <div className="text-sm font-medium text-blue-800">1. Trajectory Analysis</div>
            <div className="text-xs text-blue-700 mt-1">
              We capture behavioral events (clicks, navigation, timing) from attackers interacting with honeypots
            </div>
          </div>
          <div>
            <div className="text-sm font-medium text-blue-800">2. TTP Prediction</div>
            <div className="text-xs text-blue-700 mt-1">
              Events are matched against known red-team patterns to predict which MITRE ATT&CK techniques will be used next
            </div>
          </div>
          <div>
            <div className="text-sm font-medium text-blue-800">3. Proactive Defense</div>
            <div className="text-xs text-blue-700 mt-1">
              Based on predicted TTPs, we recommend prioritized mitigations to deploy before the attack progresses
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
