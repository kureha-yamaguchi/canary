'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

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
    url: 'https://honeypot-nine.vercel.app/',
    name: 'Honeypot API',
    description: 'Exposed API key'
  },
  {
    url: 'https://very-secure-website.vercel.app/',
    name: 'Very Secure Website',
    description: 'Actually secure, but logs all attack attempts'
  },
  {
    url: 'https://honeypot-jwt-alg-confusion.vercel.app/',
    name: 'JWT Honeypot',
    description: 'Vulnerable to JWT injection attacks'
  },
  {
    url: 'https://neuralmarket.vercel.app/',
    name: 'Neural Market',
    description: 'User ID manipulation allows viewing other users\' credentials'
  },
  {
    url: 'https://sqli-demo-shop.vercel.app/',
    name: 'Demo Shopping Portal',
    description: 'SQL injection in product search and login forms'
  },
  {
    url: 'https://xss-guestbook.vercel.app/',
    name: 'XSS Guestbook',
    description: 'Stored XSS in comment fields, no input sanitization'
  },
  {
    url: 'https://file-traversal-docs.vercel.app/',
    name: 'Document Viewer',
    description: 'Path traversal vulnerability in file download endpoint'
  },
  {
    url: 'https://csrf-bank-demo.vercel.app/',
    name: 'Banking Demo',
    description: 'Missing CSRF tokens on money transfer forms'
  },
  {
    url: 'https://xxe-parser-api.vercel.app/',
    name: 'XML Parser API',
    description: 'XXE vulnerability in XML upload endpoint'
  },
  {
    url: 'https://ssrf-image-proxy.vercel.app/',
    name: 'Image Proxy Service',
    description: 'SSRF via unvalidated URL parameter in image fetcher'
  },
  {
    url: 'https://open-redirect-ads.vercel.app/',
    name: 'Ad Network Redirector',
    description: 'Open redirect vulnerability in click tracking'
  },
  {
    url: 'https://nosql-injection-blog.vercel.app/',
    name: 'Tech Blog Platform',
    description: 'NoSQL injection in MongoDB search queries'
  },
  {
    url: 'https://insecure-upload.vercel.app/',
    name: 'File Upload Service',
    description: 'Unrestricted file upload with code execution'
  },
  {
    url: 'https://broken-auth-admin.vercel.app/',
    name: 'Admin Dashboard',
    description: 'Broken authentication allows session fixation'
  },
  {
    url: 'https://hardcoded-secrets.vercel.app/',
    name: 'Legacy API Gateway',
    description: 'Hardcoded credentials in client-side JavaScript'
  },
  {
    url: 'https://cors-misconfigured.vercel.app/',
    name: 'Data Analytics API',
    description: 'Overly permissive CORS allows credential theft'
  },
  {
    url: 'https://xml-bomb-parser.vercel.app/',
    name: 'XML Processing Service',
    description: 'Vulnerable to XML bomb DoS attacks'
  },
  {
    url: 'https://graphql-introspection.vercel.app/',
    name: 'GraphQL API',
    description: 'Introspection enabled, exposes full schema and mutations'
  },
  {
    url: 'https://race-condition-wallet.vercel.app/',
    name: 'Digital Wallet',
    description: 'Race condition in balance updates allows double-spending'
  }
];

export default function DemoPage() {
  const [selectedWebsite, setSelectedWebsite] = useState<Website | null>(null);
  const [mode, setMode] = useState<'defensive' | 'offensive'>('defensive');

  // Offensive mode state
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [selectedSubcategory, setSelectedSubcategory] = useState<string>('');
  const [tacticsData, setTacticsData] = useState<TacticsData | null>(null);
  const [loading, setLoading] = useState(false);

  // Fetch tactics and techniques data
  useEffect(() => {
    if (mode === 'offensive') {
      fetchTacticsData();
    }
  }, [mode]);

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

  return (
    <div className="min-h-screen relative bg-[#F5F5F7] dark:bg-charcoal">
      {/* Header */}
      <div className="border-b border-charcoal dark:border-cream bg-white dark:bg-charcoal">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                DEMO_ENVIRONMENT
              </h1>
              <div className="text-xs text-ghost">/system/demo/targets</div>
            </div>
            <Link
              href="/dashboard"
              className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-4 py-2 text-sm font-mono hover:bg-cyan hover:text-charcoal transition-colors"
            >
              [← BACK_TO_DASHBOARD]
            </Link>
          </div>
        </div>
      </div>

      <div className="px-6 py-6 space-y-6">
        {/* Mode Toggle */}
        <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
          <div className="flex items-center gap-4">
            <span className="text-xs text-ghost font-mono">MODE:</span>
            <div className="flex border border-charcoal dark:border-cream">
              <button
                onClick={() => setMode('defensive')}
                className={`px-6 py-2 text-sm font-mono transition-colors ${
                  mode === 'defensive'
                    ? 'bg-cyan text-charcoal'
                    : 'bg-white dark:bg-charcoal text-charcoal dark:text-cream hover:bg-cyan/10'
                }`}
              >
                [DEFENSIVE]
              </button>
              <button
                onClick={() => setMode('offensive')}
                className={`px-6 py-2 text-sm font-mono border-l border-charcoal dark:border-cream transition-colors ${
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
        {mode === 'defensive' ? (
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
            {/* Minimal Currently Selected Indicator */}
            {selectedWebsite && (
              <div className="mb-4 pb-4 border-b border-charcoal/20 dark:border-cream/20">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-ghost font-mono">SELECTED:</span>
                  <span className="text-xs font-mono font-bold">{selectedWebsite.name}</span>
                  <span className="text-xs text-ghost font-mono">•</span>
                  <span className="text-xs text-cyan font-mono">{selectedWebsite.url}</span>
                </div>
              </div>
            )}

            <div className="space-y-4">
              {websites.map((website, index) => (
                <div
                  key={index}
                  onClick={() => setSelectedWebsite(website)}
                  className={`border p-4 cursor-pointer transition-all ${
                    selectedWebsite?.url === website.url
                      ? 'border-cyan bg-cyan/10 shadow-[0_0_0_2px_#00E5CC]'
                      : 'border-charcoal/20 dark:border-cream/20 hover:bg-cyan/5'
                  }`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <h3 className="text-sm font-bold font-mono mb-2">
                        {website.name}
                      </h3>
                      <p className="text-xs text-ghost font-mono mb-3">
                        {website.description}
                      </p>
                      <div className="text-xs font-mono text-cyan break-all">
                        {website.url}
                      </div>
                    </div>
                    <a
                      href={website.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="border border-charcoal dark:border-cream bg-cyan text-charcoal px-4 py-2 text-xs font-mono hover:bg-amber transition-colors whitespace-nowrap"
                    >
                      [OPEN_TARGET →]
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          /* Offensive Mode - Category/Subcategory Selection */
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
            <div className="mb-6">
              <h2 className="text-xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                ATTACK_CONFIGURATION
              </h2>
              <div className="text-xs text-ghost mt-1">
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
                <div className="mb-6">
                  <label className="block text-xs text-ghost font-mono mb-2">CATEGORY (TACTIC)</label>
                  <select
                    value={selectedCategory}
                    onChange={(e) => handleCategoryChange(e.target.value)}
                    className="w-full border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-4 py-3 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-cyan"
                  >
                    <option value="">Select a tactic...</option>
                    <option value="ALL">All Categories</option>
                    {Object.keys(tacticsData.tactics).sort().map((tactic) => (
                      <option key={tactic} value={tactic}>
                        {tactic} ({tacticsData.tactics[tactic].length} technique{tacticsData.tactics[tactic].length !== 1 ? 's' : ''})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Subcategory Dropdown - only show if not "All Categories" */}
                {selectedCategory && selectedCategory !== 'ALL' && (
                  <div className="mb-6">
                    <label className="block text-xs text-ghost font-mono mb-2">SUBCATEGORY (TECHNIQUE)</label>
                    <select
                      value={selectedSubcategory}
                      onChange={(e) => setSelectedSubcategory(e.target.value)}
                      className="w-full border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-4 py-3 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-cyan"
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
                  <div className="border-t border-charcoal/20 dark:border-cream/20 pt-6">
                    {(() => {
                      const selectedTechnique = availableSubcategories.find(t => t.technique_id === selectedSubcategory);
                      if (!selectedTechnique) return null;

                      return (
                        <div>
                          <div className="mb-4">
                            <h3 className="text-sm font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)] mb-2">
                              SELECTED_CONFIGURATION
                            </h3>
                            <div className="flex items-center gap-2 mb-3">
                              <span
                                className="px-3 py-1 text-xs font-mono"
                                style={{ backgroundColor: TACTIC_COLORS[selectedCategory], color: '#1A1A1D' }}
                              >
                                {selectedCategory}
                              </span>
                              <span className="text-ghost">→</span>
                              <span className="px-3 py-1 bg-charcoal dark:bg-cream text-cream dark:text-charcoal text-xs font-mono">
                                {selectedTechnique.technique_id}
                              </span>
                              <span className="text-xs font-mono">{selectedTechnique.name}</span>
                            </div>
                          </div>

                          {selectedTechnique.description && (
                            <div className="mb-4">
                              <h4 className="text-xs text-ghost font-mono mb-2">DESCRIPTION</h4>
                              <div className="text-xs font-mono text-charcoal dark:text-cream">
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
      </div>
    </div>
  );
}
