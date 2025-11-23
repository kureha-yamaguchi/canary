'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { AttackHistogramChart } from '../components/AttackHistogramChart';
import { LiveAttacksFeed } from '../components/LiveAttacksFeed';

interface Website {
  url: string;
  name: string;
  description: string;
}

interface Technique {
  technique_id: string;
  name: string;
  description?: string;
  url?: string;
  domain?: string;
  tactic?: string;
}

interface TacticsData {
  tactics: Record<string, Technique[]>;
  techniques: Technique[];
}

interface HistogramDataPoint {
  time_bucket: string;
  tactic: string;
  tactic_name: string;
  attack_count: number;
}

// MITRE ATT&CK Tactics with colors
const TACTIC_COLORS: Record<string, string> = {
  'Reconnaissance': '#00E5CC',
  'Resource Development': '#7B68EE',
  'Initial Access': '#FFB627',
  'Execution': '#DC143C',
  'Persistence': '#FF3B30',
  'Privilege Escalation': '#9B9B9B',
  'Defense Evasion': '#00E5CC',
  'Credential Access': '#7B68EE',
  'Discovery': '#FFB627',
  'Lateral Movement': '#DC143C',
  'Collection': '#FF3B30',
  'Command and Control': '#9B9B9B',
  'Exfiltration': '#00E5CC',
  'Impact': '#FFB627',
};

const websites: Website[] = [
  {
    url: 'https://honeypot-nine.vercel.app',
    name: 'Honeypot API',
    description: 'Exposed API key'
  },
  {
    url: 'https://very-secure-website.vercel.app',
    name: 'Very Secure Website',
    description: 'Actually secure, but logs all attack attempts'
  },
  {
    url: 'https://honeypot-jwt-alg-confusion.vercel.app',
    name: 'JWT Honeypot',
    description: 'Vulnerable to JWT injection attacks'
  },
  {
    url: 'https://neuralmarket.vercel.app',
    name: 'Neural Market',
    description: 'User ID manipulation allows viewing other users\' credentials'
  },
  {
    url: 'https://sqli-demo-shop.vercel.app',
    name: 'Demo Shopping Portal',
    description: 'SQL injection in product search and login forms'
  },
  {
    url: 'https://xss-guestbook.vercel.app',
    name: 'XSS Guestbook',
    description: 'Stored XSS in comment fields, no input sanitization'
  },
  {
    url: 'https://file-traversal-docs.vercel.app',
    name: 'Document Viewer',
    description: 'Path traversal vulnerability in file download endpoint'
  },
  {
    url: 'https://csrf-bank-demo.vercel.app',
    name: 'Banking Demo',
    description: 'Missing CSRF tokens on money transfer forms'
  },
  {
    url: 'https://xxe-parser-api.vercel.app',
    name: 'XML Parser API',
    description: 'XXE vulnerability in XML upload endpoint'
  },
  {
    url: 'https://ssrf-image-proxy.vercel.app',
    name: 'Image Proxy Service',
    description: 'SSRF via unvalidated URL parameter in image fetcher'
  },
  {
    url: 'https://open-redirect-ads.vercel.app',
    name: 'Ad Network Redirector',
    description: 'Open redirect vulnerability in click tracking'
  },
  {
    url: 'https://nosql-injection-blog.vercel.app',
    name: 'Tech Blog Platform',
    description: 'NoSQL injection in MongoDB search queries'
  },
  {
    url: 'https://insecure-upload.vercel.app',
    name: 'File Upload Service',
    description: 'Unrestricted file upload with code execution'
  },
  {
    url: 'https://broken-auth-admin.vercel.app',
    name: 'Admin Dashboard',
    description: 'Broken authentication allows session fixation'
  },
  {
    url: 'https://hardcoded-secrets.vercel.app',
    name: 'Legacy API Gateway',
    description: 'Hardcoded credentials in client-side JavaScript'
  },
  {
    url: 'https://cors-misconfigured.vercel.app',
    name: 'Data Analytics API',
    description: 'Overly permissive CORS allows credential theft'
  },
  {
    url: 'https://xml-bomb-parser.vercel.app',
    name: 'XML Processing Service',
    description: 'Vulnerable to XML bomb DoS attacks'
  },
  {
    url: 'https://graphql-introspection.vercel.app',
    name: 'GraphQL API',
    description: 'Introspection enabled, exposes full schema and mutations'
  },
  {
    url: 'https://race-condition-wallet.vercel.app',
    name: 'Digital Wallet',
    description: 'Race condition in balance updates allows double-spending'
  }
];

interface Stats {
  total_attacks: number;
  successful_attacks: number;
  unique_targets: number;
  unique_techniques: number;
}

const TIME_RANGES = [
  { label: 'Last 5 mins', minutes: 5 },
  { label: 'Last 10 mins', minutes: 10 },
  { label: 'Last 30 mins', minutes: 30 },
  { label: 'Last 1 hr', minutes: 60 },
  { label: 'Last 2 hrs', minutes: 120 },
  { label: 'Last 12 hrs', minutes: 720 },
  { label: 'Last 24 hrs', minutes: 1440 },
  { label: 'Last week', minutes: 10080 },
  { label: 'Last month', minutes: 43200 },
  { label: 'Last 6 months', minutes: 259200 },
];

export default function DemoPage() {
  const [selectedWebsite, setSelectedWebsite] = useState<Website | null>(null);
  const [mode, setMode] = useState<'defensive' | 'offensive'>('defensive');

  // Time filter state
  const [timeFrom, setTimeFrom] = useState<Date>(new Date(Date.now() - 1440 * 60000)); // 24 hours ago
  const [useCustomTimeFrom, setUseCustomTimeFrom] = useState(false);

  // Stats and histogram data
  const [histogramData, setHistogramData] = useState<HistogramDataPoint[]>([]);
  const [stats, setStats] = useState<Stats>({
    total_attacks: 0,
    successful_attacks: 0,
    unique_targets: 0,
    unique_techniques: 0
  });
  const [attacksData, setAttacksData] = useState<any[]>([]);

  // Offensive mode state
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [selectedSubcategory, setSelectedSubcategory] = useState<string>('');
  const [tacticsData, setTacticsData] = useState<TacticsData | null>(null);
  const [loading, setLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(false);

  // Fetch tactics and techniques data
  useEffect(() => {
    if (mode === 'offensive') {
      fetchTacticsData();
    }
  }, [mode]);

  // Fetch stats when filters change
  useEffect(() => {
    fetchStats();
    fetchAttacksData();
  }, [timeFrom, mode, selectedWebsite, selectedCategory, selectedSubcategory]);

  const fetchTacticsData = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/tactics');
      if (response.ok) {
        const data = await response.json();
        setTacticsData(data);
      }
    } catch (error) {
      console.error('Error fetching tactics data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    setStatsLoading(true);
    try {
      // Calculate time range in minutes from timeFrom to NOW
      // (Backend API fetches from NOW backwards by X minutes)
      const now = Date.now();
      const timeRangeMinutes = Math.floor((now - timeFrom.getTime()) / 60000);

      const params = new URLSearchParams({
        timeRange: timeRangeMinutes.toString(),
        bucketMinutes: '60',
        includeSynthetic: 'true',
      });

      // Add filters based on mode
      if (mode === 'defensive' && selectedWebsite) {
        // Include both with and without trailing slash
        const urlWithoutSlash = selectedWebsite.url.replace(/\/$/, '');
        const urlWithSlash = urlWithoutSlash + '/';
        params.append('websites', `${urlWithoutSlash},${urlWithSlash}`);
      } else if (mode === 'offensive') {
        if (selectedSubcategory && selectedSubcategory !== 'ALL') {
          // Specific technique selected
          params.append('techniques', selectedSubcategory);
        } else if (selectedCategory && selectedCategory !== 'ALL' && tacticsData) {
          // Category selected with "All Techniques" - filter by all techniques in this category
          const categoryTechniques = tacticsData.tactics[selectedCategory]?.map(t => t.technique_id) || [];
          if (categoryTechniques.length > 0) {
            params.append('techniques', categoryTechniques.join(','));
          }
        }
      }

      const response = await fetch(`/api/attacks?${params.toString()}`);
      if (response.ok) {
        const data = await response.json();
        setHistogramData(data.histogram || []);
        setStats(data.stats || {
          total_attacks: 0,
          successful_attacks: 0,
          unique_targets: 0,
          unique_techniques: 0
        });
      }
    } catch (error) {
      console.error('Error fetching stats:', error);
    } finally {
      setStatsLoading(false);
    }
  };

  const fetchAttacksData = async () => {
    try {
      const now = Date.now();
      const timeRangeMinutes = Math.floor((now - timeFrom.getTime()) / 60000);

      const params = new URLSearchParams({
        timeRange: timeRangeMinutes.toString(),
        includeSynthetic: 'true',
      });

      // Add filters based on mode
      if (mode === 'defensive' && selectedWebsite) {
        const urlWithoutSlash = selectedWebsite.url.replace(/\/$/, '');
        const urlWithSlash = urlWithoutSlash + '/';
        params.append('websites', `${urlWithoutSlash},${urlWithSlash}`);
      } else if (mode === 'offensive') {
        if (selectedSubcategory && selectedSubcategory !== 'ALL') {
          params.append('techniques', selectedSubcategory);
        } else if (selectedCategory && selectedCategory !== 'ALL' && tacticsData) {
          const categoryTechniques = tacticsData.tactics[selectedCategory]?.map(t => t.technique_id) || [];
          if (categoryTechniques.length > 0) {
            params.append('techniques', categoryTechniques.join(','));
          }
        }
      }

      const response = await fetch(`/api/attacks-data?${params.toString()}`);
      if (response.ok) {
        const data = await response.json();
        setAttacksData(data);
      }
    } catch (error) {
      console.error('Error fetching attacks data:', error);
    }
  };

  const downloadCSV = () => {
    if (attacksData.length === 0) return;

    // Create CSV header
    const headers = [
      'Timestamp',
      'Target URL',
      'Vulnerability Type',
      'Technique ID',
      'Source IP',
      'Session ID',
      'Success',
      'Synthetic',
      'Attack ID'
    ];

    // Create CSV rows
    const rows = attacksData.map(attack => {
      const fullUrl = attack.url_path ? `${attack.base_url}${attack.url_path}` : attack.base_url;
      return [
        attack.timestamp,
        `"${fullUrl}"`,
        attack.vulnerability_type,
        attack.technique_id,
        attack.attacker_id,
        attack.session_id || '',
        attack.success ? 'true' : 'false',
        attack.is_synthetic ? 'true' : 'false',
        attack.id
      ];
    });

    // Combine headers and rows
    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n');

    // Create download link
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);

    link.setAttribute('href', url);
    link.setAttribute('download', `attack_data_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Get available subcategories based on selected category
  const availableSubcategories = selectedCategory && selectedCategory !== 'ALL' && tacticsData
    ? tacticsData.tactics[selectedCategory] || []
    : [];

  // Handle category change
  const handleCategoryChange = (category: string) => {
    setSelectedCategory(category);
    // Set to "ALL" by default when selecting a specific category
    setSelectedSubcategory(category && category !== 'ALL' ? 'ALL' : '');
  };

  // Handle quick time range selection
  const setQuickTimeRange = (minutes: number) => {
    setTimeFrom(new Date(Date.now() - minutes * 60000));
    setUseCustomTimeFrom(false);
  };

  // Format date for input
  const formatDateForInput = (date: Date) => {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${year}-${month}-${day}T${hours}:${minutes}`;
  };

  return (
    <div className="min-h-screen relative bg-[#F5F5F7] dark:bg-charcoal">
      {/* Header */}
      <div className="border-b border-charcoal dark:border-cream bg-white dark:bg-charcoal">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                ATTACK_DASHBOARD
              </h1>
              <div className="text-xs text-ghost">/system/dashboard</div>
            </div>
            <Link
              href="/dashboard_old"
              className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-4 py-2 text-sm font-mono hover:bg-cyan hover:text-charcoal transition-colors"
            >
              [OLD_DASHBOARD →]
            </Link>
          </div>
        </div>
      </div>

      <div className="px-6 py-6 h-[calc(100vh-80px)]">
        <div className="grid grid-cols-12 gap-6 h-full">
          {/* Left Column - Filters */}
          <div className="col-span-4 space-y-4 overflow-y-auto">
            {/* Mode Toggle */}
            <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
              <div className="flex items-center gap-3">
                <span className="text-xs text-ghost font-mono">MODE:</span>
                <div className="flex border border-charcoal dark:border-cream">
                  <button
                    onClick={() => setMode('defensive')}
                    className={`px-4 py-1.5 text-xs font-mono transition-colors ${
                      mode === 'defensive'
                        ? 'bg-cyan text-charcoal'
                        : 'bg-white dark:bg-charcoal text-charcoal dark:text-cream hover:bg-cyan/10'
                    }`}
                  >
                    [DEFENSIVE]
                  </button>
                  <button
                    onClick={() => setMode('offensive')}
                    className={`px-4 py-1.5 text-xs font-mono border-l border-charcoal dark:border-cream transition-colors ${
                      mode === 'offensive'
                        ? 'bg-cyan text-charcoal'
                        : 'bg-white dark:bg-charcoal text-charcoal dark:text-cream hover:bg-cyan/10'
                    }`}
                  >
                    [OFFENSIVE]
                  </button>
                </div>
              </div>
            </div>

            {/* Selection UI based on mode */}
            {mode === 'defensive' ? (
              <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4 flex flex-col">
                <div className="mb-3">
                  <h2 className="text-sm font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                    TARGET_SELECTION
                  </h2>
                  {selectedWebsite && (
                    <div className="text-[10px] text-cyan font-mono mt-1">
                      {selectedWebsite.name}
                    </div>
                  )}
                </div>

                <div className="space-y-2 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 500px)' }}>
                  {websites.map((website, index) => (
                    <div
                      key={index}
                      onClick={() => setSelectedWebsite(website)}
                      className={`border p-3 cursor-pointer transition-all ${
                        selectedWebsite?.url === website.url
                          ? 'border-cyan bg-cyan/10'
                          : 'border-charcoal/20 dark:border-cream/20 hover:bg-cyan/5'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <h3 className="text-xs font-bold font-mono mb-1 truncate">
                            {website.name}
                          </h3>
                          <p className="text-[10px] text-ghost font-mono line-clamp-2">
                            {website.description}
                          </p>
                        </div>
                        <a
                          href={website.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="border border-charcoal dark:border-cream bg-cyan text-charcoal px-2 py-1 text-[10px] font-mono hover:bg-amber transition-colors whitespace-nowrap flex-shrink-0"
                        >
                          [OPEN →]
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              /* Offensive Mode - Category/Subcategory Selection */
              <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
                <div className="mb-4">
                  <h2 className="text-sm font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                    ATTACK_CONFIGURATION
                  </h2>
                  <div className="text-[10px] text-ghost mt-1">
                    Select tactic and technique
                  </div>
                </div>

                {loading ? (
                  <div className="text-center py-8 text-ghost text-xs">[LOADING_DATA...]</div>
                ) : !tacticsData ? (
                  <div className="text-center py-8 text-ghost text-xs">[NO_DATA_AVAILABLE]</div>
                ) : (
                  <>
                    {/* Category Dropdown */}
                    <div className="mb-4">
                      <label className="block text-[10px] text-ghost font-mono mb-2">CATEGORY (TACTIC)</label>
                      <select
                        value={selectedCategory}
                        onChange={(e) => handleCategoryChange(e.target.value)}
                        className="w-full border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-cyan"
                      >
                        <option value="">Select a tactic...</option>
                        <option value="ALL">All Categories</option>
                        {Object.keys(tacticsData.tactics).sort().map((tactic) => (
                          <option key={tactic} value={tactic}>
                            {tactic} ({tacticsData.tactics[tactic].length})
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Subcategory Dropdown - only show if not "All Categories" */}
                    {selectedCategory && selectedCategory !== 'ALL' && (
                      <div className="mb-4">
                        <label className="block text-[10px] text-ghost font-mono mb-2">SUBCATEGORY (TECHNIQUE)</label>
                        <select
                          value={selectedSubcategory}
                          onChange={(e) => setSelectedSubcategory(e.target.value)}
                          className="w-full border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-cyan"
                        >
                          <option value="ALL">All Techniques</option>
                          {availableSubcategories.map((technique) => (
                            <option key={technique.technique_id} value={technique.technique_id}>
                              {technique.technique_id} - {technique.name}
                            </option>
                          ))}
                        </select>
                      </div>
                    )}

                    {/* Selected Details - only show when a specific technique is selected */}
                    {selectedSubcategory && selectedSubcategory !== 'ALL' && (
                      <div className="border-t border-charcoal/20 dark:border-cream/20 pt-4 mt-4">
                        {(() => {
                          const selectedTechnique = availableSubcategories.find(t => t.technique_id === selectedSubcategory);
                          if (!selectedTechnique) return null;

                          return (
                            <div>
                              <div className="mb-3">
                                <div className="flex items-center gap-2 mb-2 flex-wrap">
                                  <span
                                    className="px-2 py-0.5 text-[10px] font-mono"
                                    style={{ backgroundColor: TACTIC_COLORS[selectedCategory], color: '#1A1A1D' }}
                                  >
                                    {selectedCategory}
                                  </span>
                                  <span className="text-ghost text-xs">→</span>
                                  <span className="px-2 py-0.5 bg-charcoal dark:bg-cream text-cream dark:text-charcoal text-[10px] font-mono">
                                    {selectedTechnique.technique_id}
                                  </span>
                                </div>
                                <div className="text-xs font-mono">{selectedTechnique.name}</div>
                              </div>

                              {selectedTechnique.description && (
                                <div>
                                  <h4 className="text-[10px] text-ghost font-mono mb-1">DESCRIPTION</h4>
                                  <div className="text-[10px] font-mono text-charcoal dark:text-cream leading-relaxed">
                                    {selectedTechnique.description}
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })()}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Time Range Filter */}
            <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
              <div className="mb-3">
                <span className="text-[10px] text-ghost font-mono">TIME_FROM (to NOW)</span>
              </div>

              {!useCustomTimeFrom ? (
                <div className="space-y-1.5">
                  <div className="grid grid-cols-2 gap-1.5">
                    {TIME_RANGES.slice(0, 6).map((range) => (
                      <button
                        key={range.minutes}
                        onClick={() => setQuickTimeRange(range.minutes)}
                        className="px-2 py-1 text-[10px] font-mono border border-charcoal/20 dark:border-cream/20 hover:bg-cyan/10 transition-colors"
                      >
                        {range.label}
                      </button>
                    ))}
                  </div>
                  <div className="grid grid-cols-2 gap-1.5">
                    {TIME_RANGES.slice(6).map((range) => (
                      <button
                        key={range.minutes}
                        onClick={() => setQuickTimeRange(range.minutes)}
                        className="px-2 py-1 text-[10px] font-mono border border-charcoal/20 dark:border-cream/20 hover:bg-cyan/10 transition-colors"
                      >
                        {range.label}
                      </button>
                    ))}
                  </div>
                  <button
                    onClick={() => setUseCustomTimeFrom(true)}
                    className="w-full px-2 py-1 text-[10px] font-mono border border-charcoal dark:border-cream bg-white dark:bg-charcoal hover:bg-cyan/10 transition-colors"
                  >
                    [CUSTOM_DATE →]
                  </button>
                </div>
              ) : (
                <div className="space-y-1.5">
                  <input
                    type="datetime-local"
                    value={formatDateForInput(timeFrom)}
                    onChange={(e) => setTimeFrom(new Date(e.target.value))}
                    className="w-full border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-2 py-1 text-[10px] font-mono focus:outline-none focus:ring-1 focus:ring-cyan"
                  />
                  <button
                    onClick={() => setUseCustomTimeFrom(false)}
                    className="w-full px-2 py-1 text-[10px] font-mono border border-charcoal dark:border-cream bg-white dark:bg-charcoal hover:bg-cyan/10 transition-colors"
                  >
                    [← QUICK_SELECT]
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Right Column - Observability */}
          <div className="col-span-8 space-y-4 overflow-y-auto">
            {/* Stats Cards and Download */}
            <div className="flex gap-3">
              <div className="flex-1 grid grid-cols-4 gap-3">
                <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-3">
                  <div className="text-[10px] text-ghost font-mono mb-1">TOTAL</div>
                  <div className="text-xl font-bold font-mono">
                    {statsLoading ? '...' : stats.total_attacks.toLocaleString()}
                  </div>
                </div>
                <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-3">
                  <div className="text-[10px] text-ghost font-mono mb-1">SUCCESS</div>
                  <div className="text-xl font-bold font-mono text-crimson">
                    {statsLoading ? '...' : stats.successful_attacks.toLocaleString()}
                  </div>
                </div>
                <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-3">
                  <div className="text-[10px] text-ghost font-mono mb-1">TARGETS</div>
                  <div className="text-xl font-bold font-mono">
                    {statsLoading ? '...' : stats.unique_targets}
                  </div>
                </div>
                <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-3">
                  <div className="text-[10px] text-ghost font-mono mb-1">TECHS</div>
                  <div className="text-xl font-bold font-mono">
                    {statsLoading ? '...' : stats.unique_techniques}
                  </div>
                </div>
              </div>
              <button
                onClick={downloadCSV}
                disabled={attacksData.length === 0}
                className="border border-charcoal dark:border-cream bg-cyan text-charcoal px-4 py-3 text-xs font-mono hover:bg-amber transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap h-full"
              >
                [DOWNLOAD_CSV]<br />
                <span className="text-[10px]">
                  {attacksData.length.toLocaleString()} records
                </span>
              </button>
            </div>

            {/* Attack Histogram */}
            <div>
              <AttackHistogramChart histogramData={histogramData} loading={statsLoading} />
            </div>

            {/* Live Attacks Feed */}
            <div>
              <LiveAttacksFeed
                includeSynthetic={true}
                filterWebsite={
                  mode === 'defensive' && selectedWebsite
                    ? (() => {
                        const urlWithoutSlash = selectedWebsite.url.replace(/\/$/, '');
                        const urlWithSlash = urlWithoutSlash + '/';
                        return `${urlWithoutSlash},${urlWithSlash}`;
                      })()
                    : undefined
                }
                filterTechnique={
                  mode === 'offensive'
                    ? selectedSubcategory && selectedSubcategory !== 'ALL'
                      ? selectedSubcategory
                      : selectedCategory && selectedCategory !== 'ALL' && tacticsData
                      ? tacticsData.tactics[selectedCategory]?.map(t => t.technique_id).join(',')
                      : undefined
                    : undefined
                }
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
