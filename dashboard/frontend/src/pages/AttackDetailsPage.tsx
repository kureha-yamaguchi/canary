import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { Attack } from '../types'
import { format } from 'date-fns'
import { TruncateText, formatUrl, formatVulnerabilityType, formatIp } from '../utils/stringUtils'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export function AttackDetailsPage() {
  const { attackId } = useParams<{ attackId: string }>()
  const navigate = useNavigate()
  const [attack, setAttack] = useState<Attack | null>(null)
  const [relatedAttacks, setRelatedAttacks] = useState<Attack[]>([])
  const [sessionAttacks, setSessionAttacks] = useState<Attack[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchAttackDetails = async () => {
      if (!attackId) return

      try {
        // Fetch the specific attack
        const response = await fetch(`${API_BASE}/api/attacks?limit=1000`)
        const attacks: Attack[] = await response.json()
        
        const foundAttack = attacks.find(a => a.id === attackId)
        if (!foundAttack) {
          setLoading(false)
          return
        }

        setAttack(foundAttack)

        // Find related attacks (same IP or same session)
        const related = attacks.filter(a => 
          a.id !== attackId && (
            a.source_ip === foundAttack.source_ip || 
            a.session_id === foundAttack.session_id
          )
        ).slice(0, 20)

        setRelatedAttacks(related)

        // Find all attacks in same session
        const session = attacks.filter(a => 
          a.session_id === foundAttack.session_id
        ).sort((a, b) => 
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
        )

        setSessionAttacks(session)

      } catch (error) {
        console.error('Error fetching attack details:', error)
      } finally {
        setLoading(false)
      }
    }

    fetchAttackDetails()
  }, [attackId])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading attack details...</div>
      </div>
    )
  }

  if (!attack) {
    return (
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold text-white mb-4">Attack Not Found</h2>
        <Link to="/" className="text-blue-400 hover:text-blue-300">
          ← Back to Live Attacks
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Breadcrumb Navigation */}
      <nav className="flex items-center gap-2 text-sm text-slate-400">
        <Link to="/" className="hover:text-white transition-colors">Live Attacks</Link>
        <span>→</span>
        <span className="text-white">Attack Details</span>
      </nav>

      {/* Attack Details */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold text-white">Attack Details</h2>
          <Link
            to="/"
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
          >
            ← Back
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Basic Info */}
          <div className="space-y-4">
            <div>
              <label className="text-sm text-slate-400">Status</label>
              <div className="mt-1">
                <span
                  className={`px-3 py-1 rounded text-sm font-semibold ${
                    attack.success
                      ? 'bg-red-500 text-white'
                      : 'bg-yellow-500 text-black'
                  }`}
                >
                  {attack.success ? 'SUCCESS' : 'FAILED'}
                </span>
              </div>
            </div>

            <div>
              <label className="text-sm text-slate-400">Timestamp</label>
              <div className="mt-1 text-white font-mono text-sm">
                {format(new Date(attack.timestamp), 'PPpp')}
              </div>
            </div>

            <div>
              <label className="text-sm text-slate-400">Attack ID</label>
              <div className="mt-1 text-white font-mono text-sm break-all">{attack.id}</div>
            </div>

            <div>
              <label className="text-sm text-slate-400">Session ID</label>
              <div className="mt-1 text-white font-mono text-sm break-all">{attack.session_id}</div>
            </div>
          </div>

          {/* Attack Info */}
          <div className="space-y-4">
            <div>
              <label className="text-sm text-slate-400">Website URL</label>
              <div className="mt-1 text-white break-words" title={attack.website_url}>
                {formatUrl(attack.website_url, 60)}
              </div>
            </div>

            <div>
              <label className="text-sm text-slate-400">Vulnerability Type</label>
              <div className="mt-1 text-white">
                {formatVulnerabilityType(attack.vulnerability_type, 50)}
              </div>
            </div>

            <div>
              <label className="text-sm text-slate-400">MITRE Technique</label>
              <div className="mt-1 text-white font-mono">{attack.technique_id}</div>
            </div>

            <div>
              <label className="text-sm text-slate-400">Source IP</label>
              <div className="mt-1 text-white font-mono">{formatIp(attack.source_ip)}</div>
            </div>
          </div>

          {/* Additional Info */}
          {attack.attack_vector && (
            <div>
              <label className="text-sm text-slate-400">Attack Vector</label>
              <div className="mt-1 text-white break-words">{attack.attack_vector}</div>
            </div>
          )}

          {attack.user_agent && (
            <div>
              <label className="text-sm text-slate-400">User Agent</label>
              <div className="mt-1 text-white text-sm break-words">{attack.user_agent}</div>
            </div>
          )}

          {attack.response_code && (
            <div>
              <label className="text-sm text-slate-400">Response Code</label>
              <div className="mt-1 text-white">{attack.response_code}</div>
            </div>
          )}

          {attack.payload && (
            <div className="md:col-span-2">
              <label className="text-sm text-slate-400">Payload</label>
              <div className="mt-1 p-3 bg-slate-900 rounded text-white font-mono text-sm break-all">
                {attack.payload}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Session Timeline */}
      {sessionAttacks.length > 1 && (
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-white">
              Session Timeline ({sessionAttacks.length} attacks in this session)
            </h3>
            <Link
              to={`/session/${attack.session_id}`}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-sm"
            >
              View Full Session →
            </Link>
          </div>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {sessionAttacks.map((a) => (
              <Link
                key={a.id}
                to={`/attack/${a.id}`}
                className={`block p-3 rounded border-l-4 ${
                  a.id === attack.id
                    ? 'bg-slate-700 border-blue-500'
                    : a.success
                    ? 'bg-red-900/20 border-red-500 hover:bg-red-900/30'
                    : 'bg-yellow-900/20 border-yellow-500 hover:bg-yellow-900/30'
                } transition-colors`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`text-xs px-2 py-1 rounded ${
                      a.success ? 'bg-red-500 text-white' : 'bg-yellow-500 text-black'
                    }`}>
                      {a.success ? 'SUCCESS' : 'FAILED'}
                    </span>
                    <span className="text-white text-sm">{formatVulnerabilityType(a.vulnerability_type)}</span>
                  </div>
                  <span className="text-slate-400 text-xs">
                    {format(new Date(a.timestamp), 'HH:mm:ss')}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Related Attacks */}
      {relatedAttacks.length > 0 && (
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">
            Related Attacks ({relatedAttacks.length} attacks from same IP)
          </h3>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {relatedAttacks.map((a) => (
              <Link
                key={a.id}
                to={`/attack/${a.id}`}
                className={`block p-3 rounded border-l-4 ${
                  a.success
                    ? 'bg-red-900/20 border-red-500 hover:bg-red-900/30'
                    : 'bg-yellow-900/20 border-yellow-500 hover:bg-yellow-900/30'
                } transition-colors`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`text-xs px-2 py-1 rounded ${
                      a.success ? 'bg-red-500 text-white' : 'bg-yellow-500 text-black'
                    }`}>
                      {a.success ? 'SUCCESS' : 'FAILED'}
                    </span>
                    <TruncateText 
                      text={formatUrl(a.website_url, 40)} 
                      maxLength={40}
                      className="text-white text-sm"
                    />
                  </div>
                  <span className="text-slate-400 text-xs">
                    {format(new Date(a.timestamp), 'PPp')}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

