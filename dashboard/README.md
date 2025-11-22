# Dashboard for Canary App

A monitoring dashboard that tracks and visualizes security attack data from canary deployments with real-time updates, autonomous agent detection, and risk forecasting.

## Features

### Core Monitoring
- **Real-time Attack Feed**: Live stream of attacks as they occur via WebSocket
- **Attack Statistics**: Comprehensive metrics including:
  - Total attacks (all time, 24h, 7d, 30d)
  - Success vs failure rates
  - Websites targeted
  - Vulnerabilities exploited
  - MITRE ATT&CK technique tracking
  - Attack vectors used

### Advanced Analytics
- **Autonomous Agent Detection**: Identifies potential AI-powered attacks through:
  - Speed analysis (rapid attack sequences)
  - Pattern analysis (systematic exploration)
  - Coordination analysis (multi-source patterns)
  
- **Risk Forecasting**: Intelligent prediction system including:
  - Current risk score (0-100)
  - Risk trajectory over time
  - 24h, 7d, and 30d attack forecasts
  - Attack probability calculations
  - Vulnerability exposure scoring
  - Threat level assessment (low/medium/high/critical)

### Visualizations
- Real-time attack feed with agent indicators
- Time-series charts for attack trends
- Vulnerability and website statistics
- Attack vector distribution
- MITRE ATT&CK technique breakdown
- Risk trajectory graphs
- Forecast visualizations

## Architecture

The dashboard consists of two services:

1. **Backend (FastAPI)**: Python API server that:
   - Connects to Supabase to query attack data
   - Provides REST API endpoints
   - WebSocket server for real-time updates
   - Python-based analytics and forecasting

2. **Frontend (React + TypeScript)**: Modern dashboard UI with:
   - Real-time WebSocket connections
   - Interactive charts and visualizations
   - Responsive design

## Tech Stack

- **Backend**: FastAPI (Python) with Supabase client
- **Frontend**: React + TypeScript + Vite
- **Charts**: Recharts
- **Styling**: Tailwind CSS
- **Real-time**: WebSockets
- **Forecasting**: scikit-learn, pandas, numpy
- **Database**: Supabase (PostgreSQL)

## Setup

### Prerequisites

1. Supabase project with `vulnerability_logs` table (see schema below)
2. Environment variables configured

### Environment Variables

#### Backend (.env in dashboard/backend/)

```bash
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
# OR use service role key to bypass RLS:
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
```

#### Frontend (.env in dashboard/frontend/)

```bash
VITE_API_URL=http://localhost:8001
```

### Running with Docker Compose (Recommended)

1. Set environment variables in your shell or `.env` file:
   ```bash
   export SUPABASE_URL=https://your-project.supabase.co
   export SUPABASE_ANON_KEY=your-anon-key
   ```

2. Start the services:
   ```bash
   docker-compose up dashboard-backend dashboard
   ```

3. Access the dashboard:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8001
   - API Docs: http://localhost:8001/docs

### Manual Setup

#### Backend

```bash
cd dashboard/backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8001
```

#### Frontend

```bash
cd dashboard/frontend
npm install
npm run dev
```

## Database Schema

The dashboard expects a Supabase table `vulnerability_logs` with the following schema:

```sql
CREATE TABLE vulnerability_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    base_url TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attacker_id TEXT NOT NULL,
    session_id TEXT NOT NULL
);
```

## API Endpoints

### GET `/api/attacks`
Get recent attacks (supports `limit` and `offset` query params).

### GET `/api/stats`
Get comprehensive statistics including:
- Attack counts by time window
- Success/failure rates
- Website and vulnerability breakdowns
- MITRE technique statistics
- Time series data

### GET `/api/risk-forecast`
Get risk trajectory and forecasting data.

### WebSocket `/ws`
Real-time attack feed. Messages are sent as:
```json
{
  "type": "new_attack",
  "data": {
    "id": "...",
    "timestamp": "...",
    "website_url": "...",
    "vulnerability_type": "...",
    "technique_id": "...",
    "success": true/false,
    "source_ip": "...",
    "agent_indicators": {
      "overall_agent_probability": 0.75,
      "indicators": ["..."],
      ...
    }
  }
}
```

## Autonomous Agent Detection

The system analyzes attacks for indicators of autonomous AI agents:

1. **Speed Score**: Detects rapid successive attacks (< 1s apart = high score)
2. **Pattern Score**: Identifies systematic vulnerability exploration
3. **Coordination Score**: Detects similar patterns from multiple sources
4. **Overall Probability**: Weighted combination of all indicators

## Risk Forecasting

The forecasting system uses:
- **Linear regression** for attack trend prediction
- **Time-series analysis** for risk trajectory
- **Multi-factor scoring** for current risk assessment
- **Confidence intervals** based on data quality

Risk factors include:
- Attack frequency
- Success rate
- Vulnerability diversity
- Recent trends
- Website exposure

## Project Structure

```
dashboard/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── database.py          # Supabase connection
│   │   ├── models.py            # Data models
│   │   ├── schemas.py           # Pydantic schemas
│   │   ├── agent_detection.py   # AI agent detection
│   │   └── forecasting.py       # Risk forecasting
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── components/          # React components
    │   │   ├── RealTimeFeed.tsx
    │   │   ├── StatsOverview.tsx
    │   │   └── RiskForecast.tsx
    │   ├── hooks/
    │   │   └── useWebSocket.ts
    │   ├── types.ts
    │   └── App.tsx
    └── package.json
```

## Development

### Adding New Features

1. **New Metrics**: Add to `StatsResponse` schema and `/api/stats` endpoint
2. **New Forecasts**: Extend `RiskForecaster` class
3. **New Agent Indicators**: Add to `AgentDetector` class
4. **New Visualizations**: Create React components in `frontend/src/components/`

## License

MIT
