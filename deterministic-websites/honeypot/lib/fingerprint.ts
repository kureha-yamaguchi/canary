/**
 * Fingerprinting module to detect if a request is from a human, automation, or AI agent
 */

export type EntityType = 'human' | 'automation' | 'ai_agent' | 'unknown';

export interface FingerprintResult {
  entityType: EntityType;
  confidence: number; // 0-100
  signals: FingerprintSignal[];
  userAgent: string | null;
  rawHeaders: Record<string, string>;
}

export interface FingerprintSignal {
  name: string;
  value: string | boolean | number;
  weight: number; // positive = human, negative = bot/AI
  category: 'user_agent' | 'headers' | 'behavior' | 'ai_signature';
}

// Known AI agent user agent patterns
const AI_AGENT_PATTERNS = [
  // Claude/Anthropic patterns
  /claude/i,
  /anthropic/i,
  /claude-code/i,

  // OpenAI patterns
  /chatgpt/i,
  /gpt-?4/i,
  /openai/i,
  /gpt-?3\.?5/i,

  // Other AI agents
  /copilot/i,
  /github.?copilot/i,
  /cursor/i,
  /codeium/i,
  /tabnine/i,
  /amazon-?q/i,
  /gemini/i,
  /bard/i,
  /perplexity/i,
  /phind/i,
  /sourcegraph/i,
  /cody/i,

  // Generic AI agent patterns
  /ai-?agent/i,
  /llm-?agent/i,
  /auto-?gpt/i,
  /agent-?gpt/i,
  /langchain/i,
  /llamaindex/i,
];

// Known automation/bot user agent patterns
const AUTOMATION_PATTERNS = [
  // HTTP clients
  /curl/i,
  /wget/i,
  /httpie/i,
  /postman/i,
  /insomnia/i,
  /paw/i,

  // Programming language HTTP libraries
  /python-requests/i,
  /python-urllib/i,
  /aiohttp/i,
  /httpx/i,
  /axios/i,
  /node-fetch/i,
  /got\//i,
  /superagent/i,
  /request\//i,
  /java\//i,
  /okhttp/i,
  /apache-httpclient/i,
  /go-http-client/i,
  /ruby/i,
  /perl/i,
  /php/i,
  /libwww/i,

  // Web scraping tools
  /scrapy/i,
  /selenium/i,
  /puppeteer/i,
  /playwright/i,
  /headless/i,
  /phantomjs/i,
  /cheerio/i,
  /beautifulsoup/i,
  /mechanize/i,

  // Search engine bots
  /googlebot/i,
  /bingbot/i,
  /yandexbot/i,
  /baiduspider/i,
  /duckduckbot/i,
  /slurp/i,
  /msnbot/i,

  // Other bots
  /bot\b/i,
  /crawler/i,
  /spider/i,
  /scraper/i,
  /fetch/i,
  /scan/i,
];

// Headers typically present in real browsers
const BROWSER_HEADERS = [
  'accept',
  'accept-language',
  'accept-encoding',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
];

// Headers that indicate AI agent activity
const AI_AGENT_HEADERS = [
  'x-claude-',
  'x-openai-',
  'x-anthropic-',
  'x-ai-agent',
  'x-llm-',
  'x-copilot-',
  'authorization', // Often used by AI agents with Bearer tokens
];

/**
 * Analyze a request to determine if it's from a human, automation, or AI agent
 */
export function analyzeFingerprint(request: Request): FingerprintResult {
  const headers = request.headers;
  const userAgent = headers.get('user-agent');
  const signals: FingerprintSignal[] = [];

  // Collect raw headers for logging
  const rawHeaders: Record<string, string> = {};
  for (const [key, value] of headers.entries()) {
    rawHeaders[key] = value;
  }

  // 1. Analyze User-Agent
  if (userAgent) {
    // Check for AI agent patterns
    for (const pattern of AI_AGENT_PATTERNS) {
      if (pattern.test(userAgent)) {
        signals.push({
          name: 'ai_agent_user_agent',
          value: pattern.toString(),
          weight: -50,
          category: 'ai_signature',
        });
        break;
      }
    }

    // Check for automation patterns
    for (const pattern of AUTOMATION_PATTERNS) {
      if (pattern.test(userAgent)) {
        signals.push({
          name: 'automation_user_agent',
          value: pattern.toString(),
          weight: -30,
          category: 'user_agent',
        });
        break;
      }
    }

    // Check for browser-like user agent
    if (/mozilla/i.test(userAgent) && /chrome|firefox|safari|edge/i.test(userAgent)) {
      signals.push({
        name: 'browser_user_agent',
        value: true,
        weight: 20,
        category: 'user_agent',
      });
    }
  } else {
    // No user agent is suspicious
    signals.push({
      name: 'missing_user_agent',
      value: true,
      weight: -25,
      category: 'user_agent',
    });
  }

  // 2. Analyze browser-specific headers
  let browserHeaderCount = 0;
  for (const header of BROWSER_HEADERS) {
    if (headers.get(header)) {
      browserHeaderCount++;
    }
  }

  if (browserHeaderCount >= 5) {
    signals.push({
      name: 'browser_headers_present',
      value: browserHeaderCount,
      weight: 25,
      category: 'headers',
    });
  } else if (browserHeaderCount <= 2) {
    signals.push({
      name: 'minimal_headers',
      value: browserHeaderCount,
      weight: -20,
      category: 'headers',
    });
  }

  // 3. Check for AI-specific headers
  for (const [key] of headers.entries()) {
    const lowerKey = key.toLowerCase();
    for (const aiHeader of AI_AGENT_HEADERS) {
      if (lowerKey.startsWith(aiHeader) || lowerKey.includes(aiHeader)) {
        signals.push({
          name: 'ai_specific_header',
          value: key,
          weight: -40,
          category: 'ai_signature',
        });
        break;
      }
    }
  }

  // 4. Check for referer (humans usually have one when clicking links)
  const referer = headers.get('referer');
  if (referer) {
    signals.push({
      name: 'has_referer',
      value: referer,
      weight: 15,
      category: 'headers',
    });
  }

  // 5. Check for cookies (indicates session/previous visit)
  const cookies = headers.get('cookie');
  if (cookies) {
    signals.push({
      name: 'has_cookies',
      value: true,
      weight: 10,
      category: 'headers',
    });
  }

  // 6. Check Accept header patterns
  const accept = headers.get('accept');
  if (accept) {
    if (accept.includes('text/html')) {
      signals.push({
        name: 'accepts_html',
        value: true,
        weight: 10,
        category: 'headers',
      });
    }
    if (accept === 'application/json' || accept === '*/*') {
      signals.push({
        name: 'api_accept_header',
        value: accept,
        weight: -10,
        category: 'headers',
      });
    }
  }

  // 7. Check for connection upgrade headers (WebSocket - usually browser)
  const upgrade = headers.get('upgrade');
  if (upgrade) {
    signals.push({
      name: 'connection_upgrade',
      value: upgrade,
      weight: 15,
      category: 'headers',
    });
  }

  // 8. Check for DNT (Do Not Track) - typically set by browsers
  const dnt = headers.get('dnt');
  if (dnt) {
    signals.push({
      name: 'dnt_header',
      value: dnt,
      weight: 10,
      category: 'headers',
    });
  }

  // Calculate final score and determine entity type
  const totalWeight = signals.reduce((sum, signal) => sum + signal.weight, 0);

  let entityType: EntityType;
  let confidence: number;

  // Check for strong AI agent signals
  const hasAiSignal = signals.some(
    s => s.category === 'ai_signature' && s.weight < -30
  );

  // Check for strong automation signals
  const hasAutomationSignal = signals.some(
    s => s.name === 'automation_user_agent' || s.name === 'missing_user_agent'
  );

  if (hasAiSignal) {
    entityType = 'ai_agent';
    confidence = Math.min(95, 70 + Math.abs(totalWeight));
  } else if (totalWeight < -20 || hasAutomationSignal) {
    entityType = 'automation';
    confidence = Math.min(90, 50 + Math.abs(totalWeight));
  } else if (totalWeight > 30) {
    entityType = 'human';
    confidence = Math.min(85, 50 + totalWeight);
  } else {
    entityType = 'unknown';
    confidence = 30;
  }

  return {
    entityType,
    confidence,
    signals,
    userAgent,
    rawHeaders,
  };
}

/**
 * Get a summary string for the fingerprint result
 */
export function getFingerprintSummary(result: FingerprintResult): string {
  const topSignals = result.signals
    .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
    .slice(0, 3)
    .map(s => s.name)
    .join(', ');

  return `${result.entityType} (${result.confidence}% confidence) - Key signals: ${topSignals || 'none'}`;
}
