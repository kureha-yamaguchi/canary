# Canary

To defend against agents of prey, our solution is to deploy red herrings (adversary traps) and canaries (early warning signals) at scale, while collecting threat intelligence.

Cybersecurity has a massive data problem. There is a lack of threat intelligence sharing and cybersecurity datasets, leaving cybersecurity experts in the dark and leaving organisations vulnerable in the new wave of agentic hackers. By deliberately planting vulnerabilities at scale in our client websites, our impact is 3 pronged: 

1. Red herrings: lure adversaries towards our traps, away from critical assets.
2. Threat intelligence at scale: by deploying our internal red team agents at scale, we are able to uncover information on the adversary attack vector and can map TTPS onto the industry standard MITRE ATT&CK matrix.
3. Behavioural fingerprinting: By analysing behavioural patterns of our benign agent vs our malicious agent, we hope to forecast malicious/benign intent from breadcrumbs left by agents in the wild, providing early warning signals/ canaries. 

In the landscape where offensive AI capabilities can spread in seconds, scalable solutions are key! This is why our pipeline has been designed to scale through our (i) automated website generator and. (ii) automated red-team agent. 


## Project Overview

Canary enables systematic security assessment through a complete testing pipeline:

```
Vulnerable Websites → Red-Team Agent → Auditor → Dashboard Visualization
```

The platform deploys autonomous agents to discover vulnerabilities, verifies findings against known exploits, and provides real-time monitoring with MITRE ATT&CK integration.

## About our code base
```
Vulnerable Websites → Red-Team Agent  → Dashboard Visualization
```

### Vulnerable Websites

#### Deterministic Websites (`deterministic-websites/`)
Pre-built Next.js applications with known vulnerabilities for consistent testing.

- **Port**: 8000
- **Vulnerabilities**: SQL injection, XSS (reflected/stored), API key exposure, IDOR, CSRF
- **Structure**: Each vulnerability is a standalone Next.js app with mapping documentation

#### Multi-Website Builder (`multi-website-builder/`)
LLM-driven generator for rapid creation of vulnerable test environments.

- **Tech**: Node.js + Python
- **Features**: Configurable vulnerability types, Supabase logging
- **Outputs**: Generated Next.js applications

### Red-Team Agent (`red-team-agent/`)
LangChain-based autonomous testing agent powered by multiple LLM providers via OpenRouter.

- **Models**: GPT-4o, Claude 3.5/4.5 Sonnet, Qwen, Llama 3.3, Gemini
- **Tools**: Website scanner, SQL injection tester, XSS detector, endpoint checker
- **Tech**: Python, LangChain, Playwright, browser-use
- **Outputs**: JSON logs and markdown reports in `logs/run_<id>/`

#### Auditor (`auditor/`)
Validates whether red-team agents successfully identified target vulnerabilities.

- **Function**: Compares agent findings against known vulnerabilities using intelligent keyword matching
- **Input**: Red-team agent reports and vulnerability definitions
- **Output**: YES/NO audit determination with detailed analysis
- **Integration**: MITRE ATT&CK technique mapping

#### Orchestrator (`orchestrator/`)
Executes red-team agent and auditor sequentially as a complete test pipeline.

- **Features**: Automatic run coordination, exit codes, summary reporting
- **Usage**: `python orchestrator/activate.py --model <model> --website <url>`

### Monitoring & Analytics

#### Dashboard (`dashboard/`)
Real-time attack monitoring with AI-powered threat detection.

**Frontend** (React + TypeScript)
- **Port**: 3000
- **Features**: Live attack feed, statistics, time-series visualization, risk forecasting
- **Tech**: React 18, Vite, Recharts, Tailwind CSS

**Backend** (FastAPI)
- **Port**: 8001
- **Endpoints**:
  - `GET /api/attacks` - Recent attacks with pagination
  - `GET /api/stats` - Comprehensive statistics
  - `GET /api/risk-forecast` - 24h/7d/30d predictions
  - `WebSocket /ws` - Real-time attack feed
- **Features**:
  - Autonomous agent detection (pattern analysis, speed, coordination)
  - Risk forecasting with ML (scikit-learn)
  - MITRE ATT&CK integration
- **Tech**: FastAPI, Supabase, pandas, numpy

#### MITRE Dashboard (`mitre-dashboard/`)
MITRE ATT&CK framework integration with threat level assessment.

- **Tech**: Next.js with Supabase
- **Features**: Real-time 24h stats, success rate tracking

## Quick Start

### Prerequisites

```bash
# Required environment variables in .env
DATABASE_URL=postgresql://...          # Supabase connection
OPENROUTER_API_KEY=sk-or-v1-...       # OpenRouter API key
DEFAULT_MODEL=openai/gpt-4o           # Default LLM model
```

### Run All Services

```bash
docker-compose up
```

### Run Specific Services

```bash
docker-compose up dashboard              # Frontend + Backend
docker-compose up deterministic-websites # Vulnerable websites
docker-compose up multi-website-builder  # Website generator
```

### Manual Execution

#### Single Test
```bash
# Red-team agent only
python red-team-agent/activate.py --model openai/gpt-4o --website https://example.com

# Complete pipeline (agent + auditor)
python orchestrator/activate.py --model openai/gpt-4o --website https://example.com
```

#### Batch Testing
```bash
# Test multiple URLs with specified models (configured in data/runs-plan.json)
python run_batch.py --model anthropic/claude-3.5-sonnet
```

## Workflow Example

1. **Setup**: Configure models and URLs in [data/runs-plan.json](data/runs-plan.json)
2. **Execute**: Run batch testing across all targets
3. **Agent Testing**: Each URL is probed by the red-team agent
4. **Audit**: Auditor verifies if target vulnerability was discovered
5. **Monitor**: Dashboard displays real-time results and statistics
6. **Analyze**: Review success rates, timing, and vulnerability coverage

## Database Schema

### `vulnerability_logs` (Primary attack tracking)
```sql
id (UUID)
base_url (TEXT)
vulnerability_type (TEXT)
technique_id (TEXT)
timestamp (TIMESTAMPTZ)
attacker_id (TEXT)
session_id (TEXT)
success (BOOLEAN)
```

### `multi_website_builder_runs`
```sql
timestamp, model, vulnerability_id, website_prompt_id
building_success, supabase_connection_success
```

## Technology Stack

**Backend**: Python 3.11+, LangChain, FastAPI, Playwright, scikit-learn, pandas
**Frontend**: React 18, Next.js, TypeScript, Vite, Recharts, Tailwind CSS
**Database**: Supabase (PostgreSQL)
**Infrastructure**: Docker, WebSockets
**LLM Access**: OpenRouter API (multi-model support)

## Key Features

- **Multi-Model Testing**: Support for 6+ LLM providers via OpenRouter
- **Autonomous Detection**: AI-powered identification of automated attack patterns
- **Risk Forecasting**: ML-based prediction of attack trends (24h/7d/30d)
- **MITRE Integration**: ATT&CK technique mapping and visualization
- **Real-Time Monitoring**: WebSocket-based live attack feed
- **Automated Auditing**: Intelligent verification of vulnerability discovery
- **Batch Testing**: Parallel-safe execution across multiple targets
- **Comprehensive Logging**: Chain-of-thought reasoning and detailed reports

## Service Ports

| Service | Port |
|---------|------|
| Dashboard Frontend | 3000 |
| Dashboard Backend | 8001 |
| Deterministic Websites | 8000 |

## Contributing

The platform is modular and extensible. Key extension points:

- **Tools**: Add new security testing tools in [red-team-agent/tools.py](red-team-agent/tools.py)
- **Vulnerabilities**: Define new types in [data/vulnarabilities.json](data/vulnarabilities.json)
- **Websites**: Create new deterministic sites in [deterministic-websites/](deterministic-websites/)
- **Analytics**: Extend dashboard backend in [dashboard/backend/](dashboard/backend/)

## Acknowledgements

Our project is the output of the def/acc hackathon organised by BlueDot Impact and Apart Research, and sponsored by Halcyon Futures. We're grateful to their support in facilitating this collaboration.
