import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { Attack } from '../types'
import { format } from 'date-fns'
import { TruncateText, formatUrl, formatVulnerabilityType, formatIp } from '../utils/stringUtils'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export function SessionViewPage() {
  const { sessionId } = useParams<{ sessionId: string }>()
  const navigate = useNavigate()
  const [sessionAttacks, setSessionAttacks] = useState<Attack[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedAttack, setSelectedAttack] = useState<Attack | null>(null)

  useEffect(() => {
    const fetchSessionAttacks = async () => {
      if (!sessionId) return

      try {
        // Fetch all attacks
        const response = await fetch(`${API_BASE}/api/attacks?limit=1000`)
        const attacks: Attack[] = await response.json()
        
        // Filter attacks by session ID
        const session = attacks
          .filter(a => a.session_id === sessionId)
          .sort((a, b) => 
            new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
          )

        if (session.length === 0) {
          setLoading(false)
          return
        }

        setSessionAttacks(session)
        setSelectedAttack(session[0]) // Select first attack by default

      } catch (error) {
        console.error('Error fetching session attacks:', error)
      } finally {
        setLoading(false)
      }
    }

    fetchSessionAttacks()
  }, [sessionId])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading session...</div>
      </div>
    )
  }

  if (sessionAttacks.length === 0) {
    return (
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold text-white mb-4">Session Not Found</h2>
        <p className="text-slate-400 mb-4">No attacks found for session ID: {sessionId}</p>
        <Link to="/" className="text-blue-400 hover:text-blue-300">
          ← Back to Live Attacks
        </Link>
      </div>
    )
  }

  const firstAttack = sessionAttacks[0]
  const lastAttack = sessionAttacks[sessionAttacks.length - 1]
  const sessionDuration = new Date(lastAttack.timestamp).getTime() - new Date(firstAttack.timestamp).getTime()
  const durationMinutes = Math.round(sessionDuration / 60000)
  const durationSeconds = Math.round((sessionDuration % 60000) / 1000)

  const successfulCount = sessionAttacks.filter(a => a.success).length
  const failedCount = sessionAttacks.filter(a => !a.success).length

  const uniqueWebsites = Array.from(new Set(sessionAttacks.map(a => a.website_url)))
  const uniqueTechniques = Array.from(new Set(sessionAttacks.map(a => a.technique_id)))
  const uniqueVulnerabilities = Array.from(new Set(sessionAttacks.map(a => a.vulnerability_type)))

  return (
    <div className="space-y-6">
      {/* Breadcrumb Navigation */}
      <nav className="flex items-center gap-2 text-sm text-slate-400">
        <Link to="/" className="hover:text-white transition-colors">Live Attacks</Link>
        <span>→</span>
        <span className="text-white">Session View</span>
      </nav>

      {/* Session Overview */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-2xl font-bold text-white mb-2">Session Overview</h2>
            <p className="text-slate-400 text-sm font-mono break-all">{sessionId}</p>
          </div>
          <Link
            to="/"
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
          >
            ← Back to Live Attacks
          </Link>
        </div>

        {/* Session Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-slate-700/50 rounded-lg p-4">
            <div className="text-sm text-slate-400 mb-1">Total Attacks</div>
            <div className="text-2xl font-bold text-white">{sessionAttacks.length}</div>
          </div>
          <div className="bg-red-900/20 rounded-lg p-4 border border-red-500/20">
            <div className="text-sm text-slate-400 mb-1">Successful</div>
            <div className="text-2xl font-bold text-red-400">{successfulCount}</div>
          </div>
          <div className="bg-yellow-900/20 rounded-lg p-4 border border-yellow-500/20">
            <div className="text-sm text-slate-400 mb-1">Failed</div>
            <div className="text-2xl font-bold text-yellow-400">{failedCount}</div>
          </div>
          <div className="bg-slate-700/50 rounded-lg p-4">
            <div className="text-sm text-slate-400 mb-1">Duration</div>
            <div className="text-xl font-bold text-white">
              {durationMinutes > 0 ? `${durationMinutes}m ` : ''}{durationSeconds}s
            </div>
          </div>
        </div>

        {/* Session Metadata */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div>
            <span className="text-slate-400">Source IP:</span>
            <span className="ml-2 text-white font-mono">{formatIp(firstAttack.source_ip)}</span>
          </div>
          <div>
            <span className="text-slate-400">Start Time:</span>
            <span className="ml-2 text-white">{format(new Date(firstAttack.timestamp), 'PPpp')}</span>
          </div>
          <div>
            <span className="text-slate-400">End Time:</span>
            <span className="ml-2 text-white">{format(new Date(lastAttack.timestamp), 'PPpp')}</span>
          </div>
          <div>
            <span className="text-slate-400">Websites Targeted:</span>
            <span className="ml-2 text-white">{uniqueWebsites.length}</span>
          </div>
          <div>
            <span className="text-slate-400">MITRE Techniques:</span>
            <span className="ml-2 text-white">{uniqueTechniques.join(', ')}</span>
          </div>
          <div>
            <span className="text-slate-400">Vulnerability Types:</span>
            <span className="ml-2 text-white">{uniqueVulnerabilities.length}</span>
          </div>
        </div>
      </div>

      {/* Timeline View */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h3 className="text-xl font-bold text-white mb-4">
          Attack Timeline ({sessionAttacks.length} attacks)
        </h3>
        
        <div className="space-y-2 max-h-[600px] overflow-y-auto">
          {sessionAttacks.map((attack, index) => (
            <div
              key={attack.id}
              className={`p-4 rounded-lg border-l-4 transition-colors cursor-pointer ${
                selectedAttack?.id === attack.id
                  ? 'bg-slate-700 border-blue-500'
                  : attack.success
                  ? 'bg-red-900/20 border-red-500 hover:bg-red-900/30'
                  : 'bg-yellow-900/20 border-yellow-500 hover:bg-yellow-900/30'
              }`}
              onClick={() => setSelectedAttack(attack)}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <span className="text-xs text-slate-400 font-mono">#{index + 1}</span>
                    <span
                      className={`px-2 py-1 rounded text-xs font-semibold ${
                        attack.success
                          ? 'bg-red-500 text-white'
                          : 'bg-yellow-500 text-black'
                      }`}
                    >
                      {attack.success ? 'SUCCESS' : 'FAILED'}
                    </span>
                    <span className="text-xs px-2 py-1 bg-slate-700 rounded text-slate-300">
                      {attack.technique_id}
                    </span>
                    <span className="text-xs text-slate-400">
                      {format(new Date(attack.timestamp), 'HH:mm:ss.SSS')}
                    </span>
                  </div>
                  
                  <div className="text-sm text-white font-medium mb-1">
                    <TruncateText text={attack.website_url} maxLength={60} />
                  </div>
                  
                  <div className="text-xs text-slate-300">
                    <TruncateText text={formatVulnerabilityType(attack.vulnerability_type)} maxLength={50} />
                  </div>
                </div>
                
                <Link
                  to={`/attack/${attack.id}`}
                  className="ml-4 px-3 py-1 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors"
                  onClick={(e) => e.stopPropagation()}
                >
                  View Details
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected Attack Details Sidebar */}
      {selectedAttack && (
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Selected Attack Details</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm text-slate-400">Attack ID</label>
              <div className="mt-1 text-white font-mono text-sm break-all">{selectedAttack.id}</div>
            </div>
            <div>
              <label className="text-sm text-slate-400">Status</label>
              <div className="mt-1">
                <span
                  className={`px-3 py-1 rounded text-sm font-semibold ${
                    selectedAttack.success
                      ? 'bg-red-500 text-white'
                      : 'bg-yellow-500 text-black'
                  }`}
                >
                  {selectedAttack.success ? 'SUCCESS' : 'FAILED'}
                </span>
              </div>
            </div>
            <div>
              <label className="text-sm text-slate-400">Website URL</label>
              <div className="mt-1 text-white break-words" title={selectedAttack.website_url}>
                {formatUrl(selectedAttack.website_url, 50)}
              </div>
            </div>
            <div>
              <label className="text-sm text-slate-400">Vulnerability Type</label>
              <div className="mt-1 text-white">
                {formatVulnerabilityType(selectedAttack.vulnerability_type, 40)}
              </div>
            </div>
            <div>
              <label className="text-sm text-slate-400">MITRE Technique</label>
              <div className="mt-1 text-white font-mono">{selectedAttack.technique_id}</div>
            </div>
            <div>
              <label className="text-sm text-slate-400">Timestamp</label>
              <div className="mt-1 text-white font-mono text-sm">
                {format(new Date(selectedAttack.timestamp), 'PPpp')}
              </div>
            </div>
            {selectedAttack.user_agent && (
              <div className="md:col-span-2">
                <label className="text-sm text-slate-400">User Agent</label>
                <div className="mt-1 text-white text-sm break-words">{selectedAttack.user_agent}</div>
              </div>
            )}
          </div>
          <div className="mt-4 pt-4 border-t border-slate-700">
            <Link
              to={`/attack/${selectedAttack.id}`}
              className="inline-block px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              View Full Attack Details →
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}

