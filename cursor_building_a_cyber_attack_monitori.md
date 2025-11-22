# Building a cyber attack monitoring dashboard
_Exported on 21/11/2025 at 22:44:00 GMT from Cursor (2.0.77)_

---

**User**

I am building a project at a defensive acceleration hackathon. Our threat model is AI cyber attacks and the lack of knowledge about real AI capabilities. We want a way to monitor attacks and predict cyber risk at any point in time. 

We are building a number of internet-facing honeypots to detect autonomous AI agent cyber attacks and provide a tracking and monitoring dashboard. My task is to create the dashboard. 



I want the dashboard to take in our attacks across our websites with the vulnerabilities. We will want to track:

1. the number of attacks

2. the websites which are attacked

3. the vulnerabilities which are successfully attacked

4. the vulnerabilities which are attacked but failed



First brainstorm what would a good dashboard will look like and what else would be good to track. 

Ask any questions that need clarifying about the project. 



I really want to develop a clever intelligent risk trajectory and projection of cyber attack risk bringing in all information from above - moving into the forecasting realm. 



I think AI safety forecasting is really interesting but needs real data to back it up

---

**Cursor**


Exploring the codebase to understand the current structure, then brainstorming the dashboard design and risk forecasting.



Starting fresh. Brainstorming the dashboard design and risk forecasting approach, then asking clarifying questions.

## Dashboard Design Brainstorm

### Core metrics to track
1. Attack volume and trends
   - Total attacks (all time, last 24h, 7d, 30d)
   - Attack rate (attacks/hour, attacks/day)
   - Time-series chart of attack frequency
   - Peak attack times

2. Website targeting
   - Attacks per website
   - Most targeted websites
   - Geographic distribution (if available)
   - Website health/status

3. Vulnerability analysis
   - Success vs failure rates per vulnerability
   - Most exploited vulnerabilities
   - Attack patterns by vulnerability type
   - Vulnerability severity scoring

4. Attack characteristics
   - Attack vectors (SQL injection, XSS, etc.)
   - Attack sophistication level
   - Autonomous agent indicators (speed, patterns, coordination)
   - Attack duration and persistence

### Advanced metrics for risk forecasting
5. Temporal patterns
   - Attack frequency trends
   - Seasonal/time-of-day patterns
   - Attack escalation indicators
   - Coordinated attack detection

6. Risk indicators
   - Vulnerability exposure score
   - Attack success rate trends
   - New attack pattern detection
   - Threat level progression

7. Predictive analytics
   - Risk trajectory projection
   - Attack probability forecasting
   - Vulnerability exploitation likelihood
   - Time-to-exploitation estimates

### Dashboard layout ideas
- Real-time attack feed
- Risk score gauge/indicator
- Interactive timeline
- Geographic heatmap (if applicable)
- Vulnerability matrix
- Attack pattern visualization
- Forecast charts with confidence intervals

## Clarifying questions
1. Data source: What format will attack data arrive in? (REST API, webhooks, database, log files, etc.)
2. Real-time vs batch: Real-time updates or periodic batch processing?
3. Technology stack: Any preferences? (React/Vue, Python/Node.js, specific libraries)
4. Data schema: What fields are available per attack? (timestamp, source IP, target URL, vulnerability type, success/failure, payload, etc.)
5. Authentication: Do you need user auth, or is this internal-only?
6. Deployment: Where will this run? (local dev, cloud, containerized)
7. Historical data: Do you have existing data, or starting from scratch?
8. AI agent detection: How do you identify autonomous AI agents vs human attackers? (specific indicators/metrics?)

Once I have these details, I can build the dashboard with risk forecasting. Should I proceed with a modern stack (React + TypeScript + a charting library) and a mock data structure, or wait for your answers?

---

**User**

I really like all the core metrics. I think the autonomous agent indicators is really interesting. 

The advanced metrics are also good. 

I think for our demo a real-time attack feed would be useful with the other views possible on other pages. 

The data will probably arrive from REST API or webhooks. 

Use a modern stack with some python for more advanced analysis

No authentication needed. 

This will run on a docker image in local dev. We will be starting from scratch. 

I do not yet know how to identify autonomous AI agents vs human attackers and I don't think it really matters

---

**Cursor**


Building a modern dashboard with real-time attack feed and risk forecasting. Setting up the project structure.



Creating the project structure and initializing the backend and frontend:


```pip-requirements
fastapi==0.104.1
uvicorn[standard]==0.24.0
websockets==12.0
pydantic==2.5.0
sqlalchemy==2.0.23
python-multipart==0.0.6
numpy==1.26.2
pandas==2.1.3
scikit-learn==1.3.2
python-dateutil==2.8.2
pytz==2023.3

```

```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
from typing import List, Dict, Any
import json
from datetime import datetime, timedelta

from app.database import init_db, get_db
from app.models import Attack, Vulnerability, Website
from app.schemas import AttackCreate, AttackResponse, StatsResponse, RiskForecast
from app.forecasting import RiskForecaster
from app.agent_detection import AgentDetector

# Global connections manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()
forecaster = RiskForecaster()
agent_detector = AgentDetector()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    yield
    # Shutdown
    pass

app = FastAPI(
    title="AI Cyber Attack Monitoring Dashboard",
    description="Real-time monitoring and risk forecasting for AI cyber attacks",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "AI Cyber Attack Monitoring API"}

@app.post("/api/attacks", response_model=AttackResponse)
async def create_attack(attack: AttackCreate):
    """Receive attack data from honeypots via REST API or webhook"""
    db = next(get_db())
    
    # Create attack record
    db_attack = Attack(
        timestamp=attack.timestamp or datetime.utcnow(),
        website_url=attack.website_url,
        vulnerability_type=attack.vulnerability_type,
        attack_vector=attack.attack_vector,
        success=attack.success,
        payload=attack.payload,
        source_ip=attack.source_ip,
        user_agent=attack.user_agent,
        response_code=attack.response_code
    )
    
    db.add(db_attack)
    db.commit()
    db.refresh(db_attack)
    
    # Analyze for autonomous agent indicators
    agent_indicators = agent_detector.analyze_attack(db_attack)
    
    # Broadcast to WebSocket clients
    attack_data = {
        "id": db_attack.id,
        "timestamp": db_attack.timestamp.isoformat(),
        "website_url": db_attack.website_url,
        "vulnerability_type": db_attack.vulnerability_type,
        "attack_vector": db_attack.attack_vector,
        "success": db_attack.success,
        "source_ip": db_attack.source_ip,
        "agent_indicators": agent_indicators
    }
    await manager.broadcast({"type": "new_attack", "data": attack_data})
    
    return AttackResponse(
        id=db_attack.id,
        timestamp=db_attack.timestamp,
        website_url=db_attack.website_url,
        vulnerability_type=db_attack.vulnerability_type,
        attack_vector=db_attack.attack_vector,
        success=db_attack.success,
        payload=db_attack.payload,
        source_ip=db_attack.source_ip,
        user_agent=db_attack.user_agent,
        response_code=db_attack.response_code,
        agent_indicators=agent_indicators
    )

@app.get("/api/attacks", response_model=List[AttackResponse])
async def get_attacks(limit: int = 100, offset: int = 0):
    """Get recent attacks"""
    db = next(get_db())
    attacks = db.query(Attack).order_by(Attack.timestamp.desc()).offset(offset).limit(limit).all()
    return attacks

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get comprehensive statistics"""
    db = next(get_db())
    
    # Total attacks
    total_attacks = db.query(Attack).count()
    
    # Attacks in different time windows
    now = datetime.utcnow()
    attacks_24h = db.query(Attack).filter(Attack.timestamp >= now - timedelta(hours=24)).count()
    attacks_7d = db.query(Attack).filter(Attack.timestamp >= now - timedelta(days=7)).count()
    attacks_30d = db.query(Attack).filter(Attack.timestamp >= now - timedelta(days=30)).count()
    
    # Successful vs failed attacks
    successful_attacks = db.query(Attack).filter(Attack.success == True).count()
    failed_attacks = total_attacks - successful_attacks
    
    # Websites attacked
    websites_attacked = db.query(Attack.website_url).distinct().count()
    
    # Vulnerabilities successfully attacked
    successful_vulns = db.query(Attack.vulnerability_type).filter(
        Attack.success == True
    ).distinct().all()
    successful_vulns = [v[0] for v in successful_vulns]
    
    # Vulnerabilities attacked but failed
    failed_vulns = db.query(Attack.vulnerability_type).filter(
        Attack.success == False
    ).distinct().all()
    failed_vulns = [v[0] for v in failed_vulns]
    
    # Attack vectors
    attack_vectors = db.query(Attack.attack_vector, db.func.count(Attack.id)).group_by(
        Attack.attack_vector
    ).all()
    
    # Attacks per website
    website_stats = db.query(
        Attack.website_url,
        db.func.count(Attack.id).label('count'),
        db.func.sum(db.cast(Attack.success, db.Integer)).label('successful')
    ).group_by(Attack.website_url).all()
    
    # Vulnerability success rates
    vuln_stats = db.query(
        Attack.vulnerability_type,
        db.func.count(Attack.id).label('total'),
        db.func.sum(db.cast(Attack.success, db.Integer)).label('successful')
    ).group_by(Attack.vulnerability_type).all()
    
    # Time series data (last 24 hours, hourly buckets)
    time_series = []
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        count = db.query(Attack).filter(
            Attack.timestamp >= hour_start,
            Attack.timestamp < hour_end
        ).count()
        time_series.append({
            "timestamp": hour_start.isoformat(),
            "count": count
        })
    time_series.reverse()
    
    return StatsResponse(
        total_attacks=total_attacks,
        attacks_24h=attacks_24h,
        attacks_7d=attacks_7d,
        attacks_30d=attacks_30d,
        successful_attacks=successful_attacks,
        failed_attacks=failed_attacks,
        websites_attacked=websites_attacked,
        successful_vulnerabilities=successful_vulns,
        failed_vulnerabilities=failed_vulns,
        attack_vectors=[{"vector": v[0], "count": v[1]} for v in attack_vectors],
        website_stats=[{"url": w[0], "total": w[1], "successful": w[2]} for w in website_stats],
        vulnerability_stats=[{"type": v[0], "total": v[1], "successful": v[2]} for v in vuln_stats],
        time_series=time_series
    )

@app.get("/api/risk-forecast", response_model=RiskForecast)
async def get_risk_forecast():
    """Get risk trajectory and forecasting"""
    db = next(get_db())
    attacks = db.query(Attack).order_by(Attack.timestamp.asc()).all()
    
    forecast = forecaster.generate_forecast(attacks)
    return forecast

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle any client messages
            data = await websocket.receive_text()
            # Echo back or handle commands
            await websocket.send_json({"type": "pong", "data": json.loads(data) if data else {}})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

```

```python
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# SQLite database for simplicity
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./attacks.db")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Database dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

```

```python
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base

class Attack(Base):
    __tablename__ = "attacks"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=func.now(), index=True)
    website_url = Column(String, index=True)
    vulnerability_type = Column(String, index=True)
    attack_vector = Column(String)
    success = Column(Boolean, default=False, index=True)
    payload = Column(Text, nullable=True)
    source_ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    response_code = Column(Integer, nullable=True)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(Text)
    severity = Column(String)  # low, medium, high, critical
    website_url = Column(String, index=True)

class Website(Base):
    __tablename__ = "websites"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    status = Column(String)  # active, inactive, compromised
    last_checked = Column(DateTime, nullable=True)

```

```python
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class AttackCreate(BaseModel):
    timestamp: Optional[datetime] = None
    website_url: str
    vulnerability_type: str
    attack_vector: str
    success: bool
    payload: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    response_code: Optional[int] = None

class AgentIndicators(BaseModel):
    speed_score: float
    pattern_score: float
    coordination_score: float
    overall_agent_probability: float
    indicators: List[str]

class AttackResponse(BaseModel):
    id: int
    timestamp: datetime
    website_url: str
    vulnerability_type: str
    attack_vector: str
    success: bool
    payload: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    response_code: Optional[int] = None
    agent_indicators: Optional[AgentIndicators] = None
    
    class Config:
        from_attributes = True

class StatsResponse(BaseModel):
    total_attacks: int
    attacks_24h: int
    attacks_7d: int
    attacks_30d: int
    successful_attacks: int
    failed_attacks: int
    websites_attacked: int
    successful_vulnerabilities: List[str]
    failed_vulnerabilities: List[str]
    attack_vectors: List[Dict[str, Any]]
    website_stats: List[Dict[str, Any]]
    vulnerability_stats: List[Dict[str, Any]]
    time_series: List[Dict[str, Any]]

class RiskForecast(BaseModel):
    current_risk_score: float
    risk_trajectory: List[Dict[str, Any]]
    forecast_24h: Dict[str, Any]
    forecast_7d: Dict[str, Any]
    forecast_30d: Dict[str, Any]
    attack_probability: float
    vulnerability_exposure_score: float
    threat_level: str  # low, medium, high, critical
    confidence: float

```

```python
from app.models import Attack
from app.schemas import AgentIndicators
from sqlalchemy.orm import Session
from app.database import SessionLocal
from datetime import datetime, timedelta
from typing import List
import statistics

class AgentDetector:
    """Detect autonomous AI agent indicators in attacks"""
    
    def analyze_attack(self, attack: Attack) -> AgentIndicators:
        """Analyze a single attack for autonomous agent indicators"""
        db = SessionLocal()
        indicators = []
        
        try:
            # Get recent attacks from same source
            recent_window = datetime.utcnow() - timedelta(minutes=5)
            recent_attacks = db.query(Attack).filter(
                Attack.source_ip == attack.source_ip,
                Attack.timestamp >= recent_window,
                Attack.timestamp <= attack.timestamp
            ).order_by(Attack.timestamp.asc()).all()
            
            # Speed analysis: rapid successive attacks
            speed_score = 0.0
            if len(recent_attacks) > 1:
                time_diffs = []
                for i in range(1, len(recent_attacks)):
                    diff = (recent_attacks[i].timestamp - recent_attacks[i-1].timestamp).total_seconds()
                    time_diffs.append(diff)
                
                if time_diffs:
                    avg_time = statistics.mean(time_diffs)
                    # Very fast attacks (< 1 second) suggest automation
                    if avg_time < 1.0:
                        speed_score = 1.0
                        indicators.append("Extremely rapid attack sequence")
                    elif avg_time < 5.0:
                        speed_score = 0.7
                        indicators.append("Rapid attack sequence")
                    elif avg_time < 30.0:
                        speed_score = 0.4
                        indicators.append("Fast attack sequence")
            
            # Pattern analysis: systematic exploration
            pattern_score = 0.0
            if len(recent_attacks) > 2:
                # Check for systematic vulnerability testing
                vuln_types = [a.vulnerability_type for a in recent_attacks]
                unique_vulns = len(set(vuln_types))
                total_attacks = len(vuln_types)
                
                # High diversity in short time suggests systematic scanning
                if unique_vulns / total_attacks > 0.7 and total_attacks > 3:
                    pattern_score = 0.8
                    indicators.append("Systematic vulnerability exploration")
                
                # Check for methodical website targeting
                websites = [a.website_url for a in recent_attacks]
                if len(set(websites)) > 1:
                    pattern_score = max(pattern_score, 0.6)
                    indicators.append("Multi-target systematic approach")
            
            # Coordination analysis: multiple IPs, similar patterns
            coordination_score = 0.0
            # Check for similar attack patterns from different IPs in short time
            similar_attacks = db.query(Attack).filter(
                Attack.vulnerability_type == attack.vulnerability_type,
                Attack.attack_vector == attack.attack_vector,
                Attack.timestamp >= recent_window
            ).all()
            
            unique_ips = len(set([a.source_ip for a in similar_attacks if a.source_ip]))
            if unique_ips > 3:
                coordination_score = 0.7
                indicators.append("Coordinated multi-source attack pattern")
            elif unique_ips > 1:
                coordination_score = 0.4
                indicators.append("Multiple sources with similar patterns")
            
            # User agent analysis
            if attack.user_agent:
                ua_lower = attack.user_agent.lower()
                if any(bot in ua_lower for bot in ['bot', 'crawler', 'spider', 'scraper']):
                    indicators.append("Bot-like user agent")
                    pattern_score = max(pattern_score, 0.5)
            
            # Payload analysis: sophisticated or generic
            if attack.payload:
                # Check for generic/common attack patterns
                generic_patterns = ['union select', 'script>', 'eval(', 'base64']
                if any(pattern in attack.payload.lower() for pattern in generic_patterns):
                    pattern_score = max(pattern_score, 0.3)
                    indicators.append("Generic attack payload pattern")
            
            # Overall probability (weighted combination)
            overall = (speed_score * 0.3 + pattern_score * 0.4 + coordination_score * 0.3)
            
            if overall > 0.7:
                indicators.append("High probability of autonomous agent")
            elif overall > 0.4:
                indicators.append("Moderate probability of autonomous agent")
            
            return AgentIndicators(
                speed_score=speed_score,
                pattern_score=pattern_score,
                coordination_score=coordination_score,
                overall_agent_probability=overall,
                indicators=indicators if indicators else ["No strong agent indicators"]
            )
            
        finally:
            db.close()

```

```python
from app.models import Attack
from app.schemas import RiskForecast
from datetime import datetime, timedelta
from typing import List, Dict, Any
import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures
import statistics

class RiskForecaster:
    """Generate risk forecasts and trajectories"""
    
    def generate_forecast(self, attacks: List[Attack]) -> RiskForecast:
        """Generate comprehensive risk forecast"""
        if not attacks:
            return self._empty_forecast()
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame([{
            'timestamp': a.timestamp,
            'success': 1 if a.success else 0,
            'vulnerability': a.vulnerability_type
        } for a in attacks])
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # Calculate current risk score
        current_risk = self._calculate_risk_score(attacks)
        
        # Generate risk trajectory (last 30 days)
        trajectory = self._generate_trajectory(df)
        
        # Generate forecasts
        forecast_24h = self._forecast_attacks(df, hours=24)
        forecast_7d = self._forecast_attacks(df, hours=168)
        forecast_30d = self._forecast_attacks(df, hours=720)
        
        # Calculate attack probability
        attack_probability = self._calculate_attack_probability(df)
        
        # Vulnerability exposure score
        exposure_score = self._calculate_exposure_score(attacks)
        
        # Threat level
        threat_level = self._determine_threat_level(current_risk, attack_probability)
        
        # Confidence (based on data volume and recency)
        confidence = self._calculate_confidence(attacks)
        
        return RiskForecast(
            current_risk_score=current_risk,
            risk_trajectory=trajectory,
            forecast_24h=forecast_24h,
            forecast_7d=forecast_7d,
            forecast_30d=forecast_30d,
            attack_probability=attack_probability,
            vulnerability_exposure_score=exposure_score,
            threat_level=threat_level,
            confidence=confidence
        )
    
    def _calculate_risk_score(self, attacks: List[Attack]) -> float:
        """Calculate current risk score (0-100)"""
        if not attacks:
            return 0.0
        
        recent_attacks = [a for a in attacks if (datetime.utcnow() - a.timestamp).days <= 7]
        
        if not recent_attacks:
            return 0.0
        
        # Factors:
        # 1. Attack frequency (40%)
        # 2. Success rate (30%)
        # 3. Vulnerability diversity (20%)
        # 4. Recent trend (10%)
        
        total_recent = len(recent_attacks)
        successful = sum(1 for a in recent_attacks if a.success)
        success_rate = successful / total_recent if total_recent > 0 else 0
        
        unique_vulns = len(set(a.vulnerability_type for a in recent_attacks))
        unique_websites = len(set(a.website_url for a in recent_attacks))
        
        # Normalize factors
        frequency_score = min(total_recent / 100.0, 1.0)  # Cap at 100 attacks/week
        diversity_score = min(unique_vulns / 10.0, 1.0)  # Cap at 10 unique vulns
        
        # Trend: compare last 3 days to previous 4 days
        now = datetime.utcnow()
        last_3d = [a for a in recent_attacks if (now - a.timestamp).days <= 3]
        prev_4d = [a for a in recent_attacks if 3 < (now - a.timestamp).days <= 7]
        
        trend_score = 0.5  # Neutral by default
        if len(prev_4d) > 0:
            recent_rate = len(last_3d) / 3.0
            prev_rate = len(prev_4d) / 4.0
            if prev_rate > 0:
                trend_ratio = recent_rate / prev_rate
                if trend_ratio > 1.5:
                    trend_score = 1.0  # Escalating
                elif trend_ratio > 1.1:
                    trend_score = 0.75
                elif trend_ratio < 0.7:
                    trend_score = 0.25  # Decreasing
        
        risk = (
            frequency_score * 0.4 +
            success_rate * 0.3 +
            diversity_score * 0.2 +
            trend_score * 0.1
        ) * 100
        
        return min(risk, 100.0)
    
    def _generate_trajectory(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Generate risk trajectory over time"""
        if df.empty:
            return []
        
        # Group by day
        df['date'] = df['timestamp'].dt.date
        daily = df.groupby('date').agg({
            'success': ['count', 'sum']
        }).reset_index()
        
        daily.columns = ['date', 'total', 'successful']
        daily['risk'] = daily.apply(
            lambda row: (row['total'] / 10.0 * 0.4 + row['successful'] / row['total'] * 0.6) * 100 
            if row['total'] > 0 else 0,
            axis=1
        )
        
        trajectory = []
        for _, row in daily.tail(30).iterrows():  # Last 30 days
            trajectory.append({
                "date": row['date'].isoformat(),
                "risk_score": min(row['risk'], 100.0),
                "attacks": int(row['total']),
                "successful": int(row['successful'])
            })
        
        return trajectory
    
    def _forecast_attacks(self, df: pd.DataFrame, hours: int) -> Dict[str, Any]:
        """Forecast attacks for given time horizon"""
        if len(df) < 3:
            return {
                "predicted_attacks": 0,
                "predicted_successful": 0,
                "confidence": 0.0,
                "risk_score": 0.0
            }
        
        # Resample to hourly
        df['hour'] = df['timestamp'].dt.floor('H')
        hourly = df.groupby('hour').size().reset_index(name='count')
        
        if len(hourly) < 3:
            # Not enough data for forecasting
            avg = df.shape[0] / max((df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600, 1)
            predicted = int(avg * hours)
            return {
                "predicted_attacks": predicted,
                "predicted_successful": int(predicted * df['success'].mean()),
                "confidence": 0.3,
                "risk_score": min(predicted / 10.0 * 100, 100.0)
            }
        
        # Simple linear regression for trend
        hourly['hours_since_start'] = (hourly['hour'] - hourly['hour'].min()).dt.total_seconds() / 3600
        
        X = hourly['hours_since_start'].values.reshape(-1, 1)
        y = hourly['count'].values
        
        try:
            model = LinearRegression()
            model.fit(X, y)
            
            # Predict for next period
            last_hour = hourly['hours_since_start'].max()
            future_hours = np.arange(last_hour + 1, last_hour + hours + 1).reshape(-1, 1)
            predictions = model.predict(future_hours)
            predictions = np.maximum(predictions, 0)  # No negative predictions
            
            predicted_total = int(np.sum(predictions))
            success_rate = df['success'].mean()
            predicted_successful = int(predicted_total * success_rate)
            
            # Confidence based on R² and data volume
            r2 = model.score(X, y)
            confidence = min(r2 * 0.8 + (len(hourly) / 100.0) * 0.2, 1.0)
            
            risk_score = min(predicted_total / (hours / 24.0) / 10.0 * 100, 100.0)
            
            return {
                "predicted_attacks": predicted_total,
                "predicted_successful": predicted_successful,
                "confidence": confidence,
                "risk_score": risk_score
            }
        except:
            # Fallback to simple average
            avg = hourly['count'].mean()
            predicted = int(avg * hours)
            return {
                "predicted_attacks": predicted,
                "predicted_successful": int(predicted * success_rate),
                "confidence": 0.5,
                "risk_score": min(predicted / 10.0 * 100, 100.0)
            }
    
    def _calculate_attack_probability(self, df: pd.DataFrame) -> float:
        """Calculate probability of attack in next hour"""
        if df.empty:
            return 0.0
        
        # Recent attack rate
        recent = df[df['timestamp'] >= (datetime.utcnow() - timedelta(hours=24))]
        if len(recent) == 0:
            return 0.0
        
        # Attacks per hour in last 24h
        hours_covered = max((recent['timestamp'].max() - recent['timestamp'].min()).total_seconds() / 3600, 1)
        attacks_per_hour = len(recent) / hours_covered
        
        # Convert to probability (cap at 1.0)
        probability = min(attacks_per_hour, 1.0)
        
        return probability
    
    def _calculate_exposure_score(self, attacks: List[Attack]) -> float:
        """Calculate vulnerability exposure score"""
        if not attacks:
            return 0.0
        
        recent = [a for a in attacks if (datetime.utcnow() - a.timestamp).days <= 7]
        
        if not recent:
            return 0.0
        
        # Factors:
        # - Number of unique vulnerabilities
        # - Success rate
        # - Number of affected websites
        
        unique_vulns = len(set(a.vulnerability_type for a in recent))
        unique_websites = len(set(a.website_url for a in recent))
        success_rate = sum(1 for a in recent if a.success) / len(recent)
        
        exposure = (
            min(unique_vulns / 10.0, 1.0) * 0.4 +
            success_rate * 0.4 +
            min(unique_websites / 5.0, 1.0) * 0.2
        ) * 100
        
        return min(exposure, 100.0)
    
    def _determine_threat_level(self, risk_score: float, attack_probability: float) -> str:
        """Determine overall threat level"""
        combined = (risk_score / 100.0 * 0.7 + attack_probability * 0.3)
        
        if combined >= 0.75:
            return "critical"
        elif combined >= 0.5:
            return "high"
        elif combined >= 0.25:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence(self, attacks: List[Attack]) -> float:
        """Calculate forecast confidence based on data quality"""
        if not attacks:
            return 0.0
        
        # Factors:
        # - Data volume
        # - Data recency
        # - Time span covered
        
        total = len(attacks)
        volume_score = min(total / 100.0, 1.0)
        
        if attacks:
            newest = max(a.timestamp for a in attacks)
            oldest = min(a.timestamp for a in attacks)
            recency = 1.0 if (datetime.utcnow() - newest).hours < 1 else 0.7
            span = min((newest - oldest).days / 30.0, 1.0)
        else:
            recency = 0.0
            span = 0.0
        
        confidence = volume_score * 0.5 + recency * 0.3 + span * 0.2
        return min(confidence, 1.0)
    
    def _empty_forecast(self) -> RiskForecast:
        """Return empty forecast when no data"""
        return RiskForecast(
            current_risk_score=0.0,
            risk_trajectory=[],
            forecast_24h={"predicted_attacks": 0, "predicted_successful": 0, "confidence": 0.0, "risk_score": 0.0},
            forecast_7d={"predicted_attacks": 0, "predicted_successful": 0, "confidence": 0.0, "risk_score": 0.0},
            forecast_30d={"predicted_attacks": 0, "predicted_successful": 0, "confidence": 0.0, "risk_score": 0.0},
            attack_probability=0.0,
            vulnerability_exposure_score=0.0,
            threat_level="low",
            confidence=0.0
        )

```


Creating the frontend React dashboard:


```json
{
  "name": "cyber-attack-dashboard",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "recharts": "^2.10.3",
    "axios": "^1.6.2",
    "date-fns": "^2.30.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.43",
    "@types/react-dom": "^18.2.17",
    "@vitejs/plugin-react": "^4.2.1",
    "typescript": "^5.3.3",
    "vite": "^5.0.8",
    "tailwindcss": "^3.3.6",
    "postcss": "^8.4.32",
    "autoprefixer": "^10.4.16"
  }
}

```

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true
  }
})

```

```jsonc
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}

```

```jsonc
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}

```

```javascript
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        danger: {
          50: '#fef2f2',
          100: '#fee2e2',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
        },
        warning: {
          50: '#fffbeb',
          100: '#fef3c7',
          500: '#f59e0b',
          600: '#d97706',
        },
        success: {
          50: '#f0fdf4',
          100: '#dcfce7',
          500: '#22c55e',
          600: '#16a34a',
        }
      }
    },
  },
  plugins: [],
}

```

```javascript
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}

```

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>AI Cyber Attack Monitoring Dashboard</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>

```

```typescriptreact
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

```

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background-color: #0f172a;
  color: #e2e8f0;
}

code {
  font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New',
    monospace;
}

```

```typescriptreact
import { useState, useEffect } from 'react'
import { RealTimeFeed } from './components/RealTimeFeed'
import { StatsOverview } from './components/StatsOverview'
import { RiskForecast } from './components/RiskForecast'
import { useWebSocket } from './hooks/useWebSocket'
import { Attack } from './types'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function App() {
  const [attacks, setAttacks] = useState<Attack[]>([])
  const [stats, setStats] = useState<any>(null)
  const [forecast, setForecast] = useState<any>(null)
  const { lastMessage, readyState } = useWebSocket(`${API_BASE.replace('http', 'ws')}/ws`)

  // Handle new attack from WebSocket
  useEffect(() => {
    if (lastMessage?.type === 'new_attack') {
      setAttacks(prev => [lastMessage.data, ...prev].slice(0, 100)) // Keep last 100
    }
  }, [lastMessage])

  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [attacksRes, statsRes, forecastRes] = await Promise.all([
          fetch(`${API_BASE}/api/attacks?limit=50`),
          fetch(`${API_BASE}/api/stats`),
          fetch(`${API_BASE}/api/risk-forecast`)
        ])
        
        const attacksData = await attacksRes.json()
        const statsData = await statsRes.json()
        const forecastData = await forecastRes.json()
        
        setAttacks(attacksData)
        setStats(statsData)
        setForecast(forecastData)
      } catch (error) {
        console.error('Error fetching data:', error)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="min-h-screen bg-slate-900">
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <h1 className="text-3xl font-bold text-white">
            AI Cyber Attack Monitoring Dashboard
          </h1>
          <p className="text-slate-400 mt-1">
            Real-time threat detection and risk forecasting
          </p>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <div className="lg:col-span-2">
            <RealTimeFeed attacks={attacks} connectionStatus={readyState} />
          </div>
          <div>
            {forecast && <RiskForecast forecast={forecast} />}
          </div>
        </div>

        {stats && <StatsOverview stats={stats} />}
      </main>
    </div>
  )
}

export default App

```

```typescript
export interface Attack {
  id: number
  timestamp: string
  website_url: string
  vulnerability_type: string
  attack_vector: string
  success: boolean
  payload?: string
  source_ip?: string
  user_agent?: string
  response_code?: number
  agent_indicators?: {
    speed_score: number
    pattern_score: number
    coordination_score: number
    overall_agent_probability: number
    indicators: string[]
  }
}

export interface Stats {
  total_attacks: number
  attacks_24h: number
  attacks_7d: number
  attacks_30d: number
  successful_attacks: number
  failed_attacks: number
  websites_attacked: number
  successful_vulnerabilities: string[]
  failed_vulnerabilities: string[]
  attack_vectors: Array<{ vector: string; count: number }>
  website_stats: Array<{ url: string; total: number; successful: number }>
  vulnerability_stats: Array<{ type: string; total: number; successful: number }>
  time_series: Array<{ timestamp: string; count: number }>
}

export interface RiskForecast {
  current_risk_score: number
  risk_trajectory: Array<{
    date: string
    risk_score: number
    attacks: number
    successful: number
  }>
  forecast_24h: {
    predicted_attacks: number
    predicted_successful: number
    confidence: number
    risk_score: number
  }
  forecast_7d: {
    predicted_attacks: number
    predicted_successful: number
    confidence: number
    risk_score: number
  }
  forecast_30d: {
    predicted_attacks: number
    predicted_successful: number
    confidence: number
    risk_score: number
  }
  attack_probability: number
  vulnerability_exposure_score: number
  threat_level: 'low' | 'medium' | 'high' | 'critical'
  confidence: number
}

```

```typescript
import { useEffect, useRef, useState } from 'react'

interface WebSocketMessage {
  type: string
  data: any
}

export function useWebSocket(url: string) {
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [readyState, setReadyState] = useState<number>(WebSocket.CONNECTING)
  const ws = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!url) return

    ws.current = new WebSocket(url)

    ws.current.onopen = () => {
      setReadyState(WebSocket.OPEN)
    }

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setLastMessage(data)
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }

    ws.current.onerror = () => {
      setReadyState(WebSocket.CLOSED)
    }

    ws.current.onclose = () => {
      setReadyState(WebSocket.CLOSED)
      // Attempt to reconnect after 3 seconds
      setTimeout(() => {
        if (ws.current?.readyState === WebSocket.CLOSED) {
          setReadyState(WebSocket.CONNECTING)
        }
      }, 3000)
    }

    return () => {
      ws.current?.close()
    }
  }, [url])

  return { lastMessage, readyState }
}

```

```typescriptreact
import { Attack } from '../types'
import { format } from 'date-fns'

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
            <div
              key={attack.id}
              className={`p-4 rounded-lg border-l-4 ${
                attack.success
                  ? 'bg-red-900/20 border-red-500'
                  : 'bg-yellow-900/20 border-yellow-500'
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
                  </div>
                  
                  <div className="text-sm text-white font-medium mb-1">
                    {attack.website_url}
                  </div>
                  
                  <div className="text-xs text-slate-300 space-y-1">
                    <div>
                      <span className="text-slate-500">Vulnerability:</span>{' '}
                      <span className="font-medium">{attack.vulnerability_type}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Vector:</span>{' '}
                      {attack.attack_vector}
                    </div>
                    {attack.source_ip && (
                      <div>
                        <span className="text-slate-500">Source IP:</span>{' '}
                        {attack.source_ip}
                      </div>
                    )}
                    
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
            </div>
          ))
        )}
      </div>
    </div>
  )
}

```

```typescriptreact
import { Stats } from '../types'
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { format } from 'date-fns'

interface StatsOverviewProps {
  stats: Stats
}

const COLORS = ['#ef4444', '#f59e0b', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899']

export function StatsOverview({ stats }: StatsOverviewProps) {
  const timeSeriesData = stats.time_series.map(item => ({
    time: format(new Date(item.timestamp), 'HH:mm'),
    attacks: item.count
  }))

  const vulnerabilityData = stats.vulnerability_stats
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
    .map(v => ({
      name: v.type.length > 20 ? v.type.substring(0, 20) + '...' : v.type,
      total: v.total,
      successful: v.successful,
      failed: v.total - v.successful
    }))

  const websiteData = stats.website_stats
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
    .map(w => ({
      name: w.url.length > 30 ? w.url.substring(0, 30) + '...' : w.url,
      total: w.total,
      successful: w.successful
    }))

  const attackVectorData = stats.attack_vectors.map(v => ({
    name: v.vector,
    value: v.count
  }))

  return (
    <div className="space-y-6">
      {/* Key Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard
          title="Total Attacks"
          value={stats.total_attacks.toLocaleString()}
          subtitle="All time"
          color="text-blue-400"
        />
        <MetricCard
          title="24h Attacks"
          value={stats.attacks_24h.toLocaleString()}
          subtitle="Last 24 hours"
          color="text-yellow-400"
        />
        <MetricCard
          title="Successful"
          value={stats.successful_attacks.toLocaleString()}
          subtitle={`${stats.total_attacks > 0 ? ((stats.successful_attacks / stats.total_attacks) * 100).toFixed(1) : 0}% success rate`}
          color="text-red-400"
        />
        <MetricCard
          title="Websites Targeted"
          value={stats.websites_attacked.toLocaleString()}
          subtitle="Unique targets"
          color="text-green-400"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attack Timeline */}
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Attack Timeline (24h)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Legend />
              <Line
                type="monotone"
                dataKey="attacks"
                stroke="#ef4444"
                strokeWidth={2}
                name="Attacks"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Vectors */}
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Attack Vectors</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={attackVectorData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {attackVectorData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Top Vulnerabilities */}
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Top Vulnerabilities</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={vulnerabilityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
              <XAxis dataKey="name" stroke="#94a3b8" angle={-45} textAnchor="end" height={100} />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Legend />
              <Bar dataKey="successful" stackId="a" fill="#ef4444" name="Successful" />
              <Bar dataKey="failed" stackId="a" fill="#f59e0b" name="Failed" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top Websites */}
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Most Targeted Websites</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={websiteData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
              <XAxis dataKey="name" stroke="#94a3b8" angle={-45} textAnchor="end" height={100} />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Legend />
              <Bar dataKey="total" fill="#3b82f6" name="Total Attacks" />
              <Bar dataKey="successful" fill="#ef4444" name="Successful" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Vulnerability Lists */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Successfully Exploited</h3>
          <div className="space-y-2">
            {stats.successful_vulnerabilities.length === 0 ? (
              <p className="text-slate-400">None</p>
            ) : (
              stats.successful_vulnerabilities.map((vuln, idx) => (
                <div key={idx} className="p-2 bg-red-900/20 rounded text-sm text-red-300">
                  {vuln}
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Failed Exploitation Attempts</h3>
          <div className="space-y-2">
            {stats.failed_vulnerabilities.length === 0 ? (
              <p className="text-slate-400">None</p>
            ) : (
              stats.failed_vulnerabilities.map((vuln, idx) => (
                <div key={idx} className="p-2 bg-yellow-900/20 rounded text-sm text-yellow-300">
                  {vuln}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function MetricCard({ title, value, subtitle, color }: {
  title: string
  value: string
  subtitle: string
  color: string
}) {
  return (
    <div className="bg-slate-800 rounded-lg shadow-lg p-6">
      <div className="text-sm text-slate-400 mb-1">{title}</div>
      <div className={`text-3xl font-bold ${color} mb-1`}>{value}</div>
      <div className="text-xs text-slate-500">{subtitle}</div>
    </div>
  )
}

```

```typescriptreact
import { RiskForecast as RiskForecastType } from '../types'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { format } from 'date-fns'

interface RiskForecastProps {
  forecast: RiskForecastType
}

const threatLevelColors = {
  low: 'text-green-400',
  medium: 'text-yellow-400',
  high: 'text-orange-400',
  critical: 'text-red-400'
}

const threatLevelBgColors = {
  low: 'bg-green-500/20 border-green-500',
  medium: 'bg-yellow-500/20 border-yellow-500',
  high: 'bg-orange-500/20 border-orange-500',
  critical: 'bg-red-500/20 border-red-500'
}

export function RiskForecast({ forecast }: RiskForecastProps) {
  const trajectoryData = forecast.risk_trajectory.map(item => ({
    date: format(new Date(item.date), 'MMM dd'),
    risk: item.risk_score,
    attacks: item.attacks
  }))

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-400'
    if (score >= 50) return 'text-orange-400'
    if (score >= 25) return 'text-yellow-400'
    return 'text-green-400'
  }

  const getRiskBarColor = (score: number) => {
    if (score >= 75) return 'bg-red-500'
    if (score >= 50) return 'bg-orange-500'
    if (score >= 25) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  return (
    <div className="space-y-6">
      {/* Current Risk Score */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold text-white mb-4">Risk Assessment</h2>
        
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-slate-400">Current Risk Score</span>
            <span className={`text-2xl font-bold ${getRiskColor(forecast.current_risk_score)}`}>
              {forecast.current_risk_score.toFixed(1)}
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-4">
            <div
              className={`h-4 rounded-full ${getRiskBarColor(forecast.current_risk_score)}`}
              style={{ width: `${forecast.current_risk_score}%` }}
            ></div>
          </div>
        </div>

        <div className={`p-4 rounded-lg border-2 ${threatLevelBgColors[forecast.threat_level]}`}>
          <div className="flex items-center justify-between">
            <span className="text-sm text-slate-300">Threat Level</span>
            <span className={`text-lg font-bold ${threatLevelColors[forecast.threat_level]}`}>
              {forecast.threat_level.toUpperCase()}
            </span>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-4">
          <div>
            <div className="text-xs text-slate-400 mb-1">Attack Probability</div>
            <div className="text-lg font-semibold text-yellow-400">
              {(forecast.attack_probability * 100).toFixed(1)}%
            </div>
          </div>
          <div>
            <div className="text-xs text-slate-400 mb-1">Exposure Score</div>
            <div className="text-lg font-semibold text-orange-400">
              {forecast.vulnerability_exposure_score.toFixed(1)}
            </div>
          </div>
        </div>

        <div className="mt-4">
          <div className="text-xs text-slate-400 mb-1">Forecast Confidence</div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full"
              style={{ width: `${forecast.confidence * 100}%` }}
            ></div>
          </div>
          <div className="text-xs text-slate-500 mt-1">
            {(forecast.confidence * 100).toFixed(0)}% confidence
          </div>
        </div>
      </div>

      {/* Risk Trajectory */}
      {trajectoryData.length > 0 && (
        <div className="bg-slate-800 rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Risk Trajectory</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trajectoryData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
              <XAxis dataKey="date" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" domain={[0, 100]} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Line
                type="monotone"
                dataKey="risk"
                stroke="#ef4444"
                strokeWidth={2}
                name="Risk Score"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Forecasts */}
      <div className="bg-slate-800 rounded-lg shadow-lg p-6">
        <h3 className="text-xl font-bold text-white mb-4">Attack Forecasts</h3>
        <div className="space-y-4">
          <ForecastItem
            label="24 Hours"
            forecast={forecast.forecast_24h}
            color="text-blue-400"
          />
          <ForecastItem
            label="7 Days"
            forecast={forecast.forecast_7d}
            color="text-yellow-400"
          />
          <ForecastItem
            label="30 Days"
            forecast={forecast.forecast_30d}
            color="text-orange-400"
          />
        </div>
      </div>
    </div>
  )
}

function ForecastItem({ label, forecast, color }: {
  label: string
  forecast: any
  color: string
}) {
  return (
    <div className="p-4 bg-slate-700/50 rounded-lg">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-semibold text-slate-300">{label}</span>
        <span className={`text-sm ${color}`}>
          {(forecast.confidence * 100).toFixed(0)}% confidence
        </span>
      </div>
      <div className="grid grid-cols-3 gap-2 text-xs">
        <div>
          <div className="text-slate-400">Predicted</div>
          <div className="text-white font-semibold">{forecast.predicted_attacks}</div>
        </div>
        <div>
          <div className="text-slate-400">Successful</div>
          <div className="text-red-400 font-semibold">{forecast.predicted_successful}</div>
        </div>
        <div>
          <div className="text-slate-400">Risk Score</div>
          <div className="text-yellow-400 font-semibold">{forecast.risk_score.toFixed(1)}</div>
        </div>
      </div>
    </div>
  )
}

```


Creating Docker configuration and fixing a few issues:


```dockerfile
# Multi-stage build for frontend and backend
FROM node:18-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ ./backend/

# Copy frontend build
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Expose port
EXPOSE 8000

# Run backend (which can serve static files if needed, or use nginx)
CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

```

```dockercompose
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app/backend
      - ./attacks.db:/app/attacks.db
    environment:
      - DATABASE_URL=sqlite:///./attacks.db
    command: python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    ports:
      - "3000:3000"
    volumes:
      - ./frontend:/app/frontend
      - /app/frontend/node_modules
    environment:
      - VITE_API_URL=http://localhost:8000
    command: npm run dev

```

```dockerfile
FROM node:18-alpine
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host"]

```

```python
"""
Script to generate test attack data for the dashboard
Run this to populate the database with sample attacks for demo purposes
"""
import requests
import random
import time
from datetime import datetime, timedelta

API_URL = "http://localhost:8000/api/attacks"

WEBSITES = [
    "https://honeypot1.example.com",
    "https://honeypot2.example.com",
    "https://honeypot3.example.com",
    "https://api-test.example.com",
    "https://admin-panel.example.com",
]

VULNERABILITIES = [
    "SQL Injection",
    "XSS (Cross-Site Scripting)",
    "CSRF (Cross-Site Request Forgery)",
    "Path Traversal",
    "Command Injection",
    "SSRF (Server-Side Request Forgery)",
    "XXE (XML External Entity)",
    "Insecure Deserialization",
    "Broken Authentication",
    "Sensitive Data Exposure",
]

ATTACK_VECTORS = [
    "POST /api/login",
    "GET /api/users?id=",
    "POST /upload",
    "GET /admin",
    "POST /api/execute",
    "GET /files/",
    "POST /api/query",
]

def generate_attack():
    """Generate a random attack"""
    base_time = datetime.utcnow() - timedelta(hours=random.randint(0, 24))
    
    attack = {
        "timestamp": (base_time - timedelta(seconds=random.randint(0, 3600))).isoformat(),
        "website_url": random.choice(WEBSITES),
        "vulnerability_type": random.choice(VULNERABILITIES),
        "attack_vector": random.choice(ATTACK_VECTORS),
        "success": random.random() < 0.3,  # 30% success rate
        "payload": f"<script>alert('test')</script>" if random.random() < 0.5 else None,
        "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "user_agent": random.choice([
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "python-requests/2.28.1",
            "curl/7.68.0",
            None
        ]),
        "response_code": random.choice([200, 403, 404, 500, 302])
    }
    
    return attack

def send_attacks(count=50):
    """Send multiple attacks to the API"""
    print(f"Sending {count} test attacks...")
    
    for i in range(count):
        attack = generate_attack()
        try:
            response = requests.post(API_URL, json=attack)
            if response.status_code == 200:
                print(f"✓ Attack {i+1}/{count} sent")
            else:
                print(f"✗ Attack {i+1}/{count} failed: {response.status_code}")
        except Exception as e:
            print(f"✗ Error sending attack {i+1}: {e}")
        
        # Small delay to simulate real-time
        time.sleep(0.1)
    
    print(f"\n✓ Sent {count} attacks successfully!")

if __name__ == "__main__":
    import sys
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    send_attacks(count)

```

```typescript
import { useEffect, useRef, useState } from 'react'

interface WebSocketMessage {
  type: string
  data: any
}

export function useWebSocket(url: string) {
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [readyState, setReadyState] = useState<number>(WebSocket.CONNECTING)
  const ws = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!url) return

    ws.current = new WebSocket(url)

    ws.current.onopen = () => {
      setReadyState(WebSocket.OPEN)
    }

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setLastMessage(data)
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }

    ws.current.onerror = () => {
      setReadyState(WebSocket.CLOSED)
    }

    ws.current.onclose = () => {
      setReadyState(WebSocket.CLOSED)
    }

    return () => {
      ws.current?.close()
    }
  }, [url])

  return { lastMessage, readyState }
}


```

```typescript
import { useEffect, useRef, useState } from 'react'

interface WebSocketMessage {
  type: string
  data: any
}

export function useWebSocket(url: string) {
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [readyState, setReadyState] = useState<number>(WebSocket.CONNECTING)
  const ws = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!url) return

    const connect = () => {
      ws.current = new WebSocket(url)

    ws.current.onopen = () => {
      setReadyState(WebSocket.OPEN)
    }

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setLastMessage(data)
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }

    ws.current.onerror = () => {
      setReadyState(WebSocket.CLOSED)
    }

    ws.current.onclose = () => {
      setReadyState(WebSocket.CLOSED)
    }

    return () => {
      ws.current?.close()
    }
  }, [url])

  return { lastMessage, readyState }
}


```

```typescript
import { useEffect, useRef, useState } from 'react'

interface WebSocketMessage {
  type: string
  data: any
}

export function useWebSocket(url: string) {
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [readyState, setReadyState] = useState<number>(WebSocket.CONNECTING)
  const ws = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!url) return

    const connect = () => {
      ws.current = new WebSocket(url)

    ws.current.onopen = () => {
      setReadyState(WebSocket.OPEN)
    }

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setLastMessage(data)
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }

    ws.current.onerror = () => {
      setReadyState(WebSocket.CLOSED)
    }

    ws.current.onclose = () => {
      setReadyState(WebSocket.CLOSED)
      // Attempt to reconnect after 3 seconds
      setTimeout(() => {
        if (!ws.current || ws.current.readyState === WebSocket.CLOSED) {
          connect()
        }
      }, 3000)
    }

    return () => {
      ws.current?.close()
    }
    }

    connect()
  }, [url])

  return { lastMessage, readyState }
}


```


Fixing the WebSocket hook:


```typescript
import { useEffect, useRef, useState } from 'react'

interface WebSocketMessage {
  type: string
  data: any
}

export function useWebSocket(url: string) {
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [readyState, setReadyState] = useState<number>(WebSocket.CONNECTING)
  const ws = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!url) return

    const connect = () => {
      ws.current = new WebSocket(url)

      ws.current.onopen = () => {
        setReadyState(WebSocket.OPEN)
      }

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          setLastMessage(data)
        } catch (error) {
          console.error('Error parsing WebSocket message:', error)
        }
      }

      ws.current.onerror = () => {
        setReadyState(WebSocket.CLOSED)
      }

      ws.current.onclose = () => {
        setReadyState(WebSocket.CLOSED)
        // Attempt to reconnect after 3 seconds
        setTimeout(() => {
          if (!ws.current || ws.current.readyState === WebSocket.CLOSED) {
            connect()
          }
        }, 3000)
      }
    }

    connect()

    return () => {
      ws.current?.close()
    }
  }, [url])

  return { lastMessage, readyState }
}

```

```python
from app.models import Attack
from app.schemas import AgentIndicators
from sqlalchemy.orm import Session
from app.database import SessionLocal
from datetime import datetime, timedelta
from typing import List
import statistics

class AgentDetector:
    """Detect autonomous AI agent indicators in attacks"""
    
    def analyze_attack(self, attack: Attack) -> AgentIndicators:
        """Analyze a single attack for autonomous agent indicators"""
        db = SessionLocal()
        indicators = []
        
        try:
            # Get recent attacks from same source
            recent_window = attack.timestamp - timedelta(minutes=5)
            recent_attacks = db.query(Attack).filter(
                Attack.source_ip == attack.source_ip,
                Attack.timestamp >= recent_window,
                Attack.timestamp <= attack.timestamp
            ).order_by(Attack.timestamp.asc()).all()
            
            # Speed analysis: rapid successive attacks
            speed_score = 0.0
            if len(recent_attacks) > 1:
                time_diffs = []
                for i in range(1, len(recent_attacks)):
                    diff = (recent_attacks[i].timestamp - recent_attacks[i-1].timestamp).total_seconds()
                    time_diffs.append(diff)
                
                if time_diffs:
                    avg_time = statistics.mean(time_diffs)
                    # Very fast attacks (< 1 second) suggest automation
                    if avg_time < 1.0:
                        speed_score = 1.0
                        indicators.append("Extremely rapid attack sequence")
                    elif avg_time < 5.0:
                        speed_score = 0.7
                        indicators.append("Rapid attack sequence")
                    elif avg_time < 30.0:
                        speed_score = 0.4
                        indicators.append("Fast attack sequence")
            
            # Pattern analysis: systematic exploration
            pattern_score = 0.0
            if len(recent_attacks) > 2:
                # Check for systematic vulnerability testing
                vuln_types = [a.vulnerability_type for a in recent_attacks]
                unique_vulns = len(set(vuln_types))
                total_attacks = len(vuln_types)
                
                # High diversity in short time suggests systematic scanning
                if unique_vulns / total_attacks > 0.7 and total_attacks > 3:
                    pattern_score = 0.8
                    indicators.append("Systematic vulnerability exploration")
                
                # Check for methodical website targeting
                websites = [a.website_url for a in recent_attacks]
                if len(set(websites)) > 1:
                    pattern_score = max(pattern_score, 0.6)
                    indicators.append("Multi-target systematic approach")
            
            # Coordination analysis: multiple IPs, similar patterns
            coordination_score = 0.0
            # Check for similar attack patterns from different IPs in short time
            similar_attacks = db.query(Attack).filter(
                Attack.vulnerability_type == attack.vulnerability_type,
                Attack.attack_vector == attack.attack_vector,
                Attack.timestamp >= recent_window
            ).all()
            
            unique_ips = len(set([a.source_ip for a in similar_attacks if a.source_ip]))
            if unique_ips > 3:
                coordination_score = 0.7
                indicators.append("Coordinated multi-source attack pattern")
            elif unique_ips > 1:
                coordination_score = 0.4
                indicators.append("Multiple sources with similar patterns")
            
            # User agent analysis
            if attack.user_agent:
                ua_lower = attack.user_agent.lower()
                if any(bot in ua_lower for bot in ['bot', 'crawler', 'spider', 'scraper']):
                    indicators.append("Bot-like user agent")
                    pattern_score = max(pattern_score, 0.5)
            
            # Payload analysis: sophisticated or generic
            if attack.payload:
                # Check for generic/common attack patterns
                generic_patterns = ['union select', 'script>', 'eval(', 'base64']
                if any(pattern in attack.payload.lower() for pattern in generic_patterns):
                    pattern_score = max(pattern_score, 0.3)
                    indicators.append("Generic attack payload pattern")
            
            # Overall probability (weighted combination)
            overall = (speed_score * 0.3 + pattern_score * 0.4 + coordination_score * 0.3)
            
            if overall > 0.7:
                indicators.append("High probability of autonomous agent")
            elif overall > 0.4:
                indicators.append("Moderate probability of autonomous agent")
            
            return AgentIndicators(
                speed_score=speed_score,
                pattern_score=pattern_score,
                coordination_score=coordination_score,
                overall_agent_probability=overall,
                indicators=indicators if indicators else ["No strong agent indicators"]
            )
            
        finally:
            db.close()


```

```python
from app.models import Attack
from app.schemas import AgentIndicators
from sqlalchemy.orm import Session
from app.database import SessionLocal
from datetime import datetime, timedelta
from typing import List
import statistics

class AgentDetector:
    """Detect autonomous AI agent indicators in attacks"""
    
    def analyze_attack(self, attack: Attack) -> AgentIndicators:
        """Analyze a single attack for autonomous agent indicators"""
        db = SessionLocal()
        indicators = []
        
        try:
            # Get recent attacks from same source
            recent_window = attack.timestamp - timedelta(minutes=5)
            recent_attacks = db.query(Attack).filter(
                Attack.source_ip == attack.source_ip,
                Attack.timestamp >= recent_window,
                Attack.timestamp <= attack.timestamp
            ).order_by(Attack.timestamp.asc()).all()
            
            # Speed analysis: rapid successive attacks
            speed_score = 0.0
            if len(recent_attacks) > 1:
                time_diffs = []
                for i in range(1, len(recent_attacks)):
                    diff = (recent_attacks[i].timestamp - recent_attacks[i-1].timestamp).total_seconds()
                    time_diffs.append(diff)
                
                if time_diffs:
                    avg_time = statistics.mean(time_diffs)
                    # Very fast attacks (< 1 second) suggest automation
                    if avg_time < 1.0:
                        speed_score = 1.0
                        indicators.append("Extremely rapid attack sequence")
                    elif avg_time < 5.0:
                        speed_score = 0.7
                        indicators.append("Rapid attack sequence")
                    elif avg_time < 30.0:
                        speed_score = 0.4
                        indicators.append("Fast attack sequence")
            
            # Pattern analysis: systematic exploration
            pattern_score = 0.0
            if len(recent_attacks) > 2:
                # Check for systematic vulnerability testing
                vuln_types = [a.vulnerability_type for a in recent_attacks]
                unique_vulns = len(set(vuln_types))
                total_attacks = len(vuln_types)
                
                # High diversity in short time suggests systematic scanning
                if unique_vulns / total_attacks > 0.7 and total_attacks > 3:
                    pattern_score = 0.8
                    indicators.append("Systematic vulnerability exploration")
                
                # Check for methodical website targeting
                websites = [a.website_url for a in recent_attacks]
                if len(set(websites)) > 1:
                    pattern_score = max(pattern_score, 0.6)
                    indicators.append("Multi-target systematic approach")
            
            # Coordination analysis: multiple IPs, similar patterns
            coordination_score = 0.0
            # Check for similar attack patterns from different IPs in short time
            similar_attacks = db.query(Attack).filter(
                Attack.vulnerability_type == attack.vulnerability_type,
                Attack.attack_vector == attack.attack_vector,
                Attack.timestamp >= recent_window,
                Attack.timestamp <= attack.timestamp
            ).all()
            
            unique_ips = len(set([a.source_ip for a in similar_attacks if a.source_ip]))
            if unique_ips > 3:
                coordination_score = 0.7
                indicators.append("Coordinated multi-source attack pattern")
            elif unique_ips > 1:
                coordination_score = 0.4
                indicators.append("Multiple sources with similar patterns")
            
            # User agent analysis
            if attack.user_agent:
                ua_lower = attack.user_agent.lower()
                if any(bot in ua_lower for bot in ['bot', 'crawler', 'spider', 'scraper']):
                    indicators.append("Bot-like user agent")
                    pattern_score = max(pattern_score, 0.5)
            
            # Payload analysis: sophisticated or generic
            if attack.payload:
                # Check for generic/common attack patterns
                generic_patterns = ['union select', 'script>', 'eval(', 'base64']
                if any(pattern in attack.payload.lower() for pattern in generic_patterns):
                    pattern_score = max(pattern_score, 0.3)
                    indicators.append("Generic attack payload pattern")
            
            # Overall probability (weighted combination)
            overall = (speed_score * 0.3 + pattern_score * 0.4 + coordination_score * 0.3)
            
            if overall > 0.7:
                indicators.append("High probability of autonomous agent")
            elif overall > 0.4:
                indicators.append("Moderate probability of autonomous agent")
            
            return AgentIndicators(
                speed_score=speed_score,
                pattern_score=pattern_score,
                coordination_score=coordination_score,
                overall_agent_probability=overall,
                indicators=indicators if indicators else ["No strong agent indicators"]
            )
            
        finally:
            db.close()


```


Fixing a bug in the forecasting code:


```python
from app.models import Attack
from app.schemas import RiskForecast
from datetime import datetime, timedelta
from typing import List, Dict, Any
import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures
import statistics

class RiskForecaster:
    """Generate risk forecasts and trajectories"""
    
    def generate_forecast(self, attacks: List[Attack]) -> RiskForecast:
        """Generate comprehensive risk forecast"""
        if not attacks:
            return self._empty_forecast()
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame([{
            'timestamp': a.timestamp,
            'success': 1 if a.success else 0,
            'vulnerability': a.vulnerability_type
        } for a in attacks])
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # Calculate current risk score
        current_risk = self._calculate_risk_score(attacks)
        
        # Generate risk trajectory (last 30 days)
        trajectory = self._generate_trajectory(df)
        
        # Generate forecasts
        forecast_24h = self._forecast_attacks(df, hours=24)
        forecast_7d = self._forecast_attacks(df, hours=168)
        forecast_30d = self._forecast_attacks(df, hours=720)
        
        # Calculate attack probability
        attack_probability = self._calculate_attack_probability(df)
        
        # Vulnerability exposure score
        exposure_score = self._calculate_exposure_score(attacks)
        
        # Threat level
        threat_level = self._determine_threat_level(current_risk, attack_probability)
        
        # Confidence (based on data volume and recency)
        confidence = self._calculate_confidence(attacks)
        
        return RiskForecast(
            current_risk_score=current_risk,
            risk_trajectory=trajectory,
            forecast_24h=forecast_24h,
            forecast_7d=forecast_7d,
            forecast_30d=forecast_30d,
            attack_probability=attack_probability,
            vulnerability_exposure_score=exposure_score,
            threat_level=threat_level,
            confidence=confidence
        )
    
    def _calculate_risk_score(self, attacks: List[Attack]) -> float:
        """Calculate current risk score (0-100)"""
        if not attacks:
            return 0.0
        
        recent_attacks = [a for a in attacks if (datetime.utcnow() - a.timestamp).days <= 7]
        
        if not recent_attacks:
            return 0.0
        
        # Factors:
        # 1. Attack frequency (40%)
        # 2. Success rate (30%)
        # 3. Vulnerability diversity (20%)
        # 4. Recent trend (10%)
        
        total_recent = len(recent_attacks)
        successful = sum(1 for a in recent_attacks if a.success)
        success_rate = successful / total_recent if total_recent > 0 else 0
        
        unique_vulns = len(set(a.vulnerability_type for a in recent_attacks))
        unique_websites = len(set(a.website_url for a in recent_attacks))
        
        # Normalize factors
        frequency_score = min(total_recent / 100.0, 1.0)  # Cap at 100 attacks/week
        diversity_score = min(unique_vulns / 10.0, 1.0)  # Cap at 10 unique vulns
        
        # Trend: compare last 3 days to previous 4 days
        now = datetime.utcnow()
        last_3d = [a for a in recent_attacks if (now - a.timestamp).days <= 3]
        prev_4d = [a for a in recent_attacks if 3 < (now - a.timestamp).days <= 7]
        
        trend_score = 0.5  # Neutral by default
        if len(prev_4d) > 0:
            recent_rate = len(last_3d) / 3.0
            prev_rate = len(prev_4d) / 4.0
            if prev_rate > 0:
                trend_ratio = recent_rate / prev_rate
                if trend_ratio > 1.5:
                    trend_score = 1.0  # Escalating
                elif trend_ratio > 1.1:
                    trend_score = 0.75
                elif trend_ratio < 0.7:
                    trend_score = 0.25  # Decreasing
        
        risk = (
            frequency_score * 0.4 +
            success_rate * 0.3 +
            diversity_score * 0.2 +
            trend_score * 0.1
        ) * 100
        
        return min(risk, 100.0)
    
    def _generate_trajectory(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Generate risk trajectory over time"""
        if df.empty:
            return []
        
        # Group by day
        df['date'] = df['timestamp'].dt.date
        daily = df.groupby('date').agg({
            'success': ['count', 'sum']
        }).reset_index()
        
        daily.columns = ['date', 'total', 'successful']
        daily['risk'] = daily.apply(
            lambda row: (row['total'] / 10.0 * 0.4 + row['successful'] / row['total'] * 0.6) * 100 
            if row['total'] > 0 else 0,
            axis=1
        )
        
        trajectory = []
        for _, row in daily.tail(30).iterrows():  # Last 30 days
            trajectory.append({
                "date": row['date'].isoformat(),
                "risk_score": min(row['risk'], 100.0),
                "attacks": int(row['total']),
                "successful": int(row['successful'])
            })
        
        return trajectory
    
    def _forecast_attacks(self, df: pd.DataFrame, hours: int) -> Dict[str, Any]:
        """Forecast attacks for given time horizon"""
        if len(df) < 3:
            return {
                "predicted_attacks": 0,
                "predicted_successful": 0,
                "confidence": 0.0,
                "risk_score": 0.0
            }
        
        # Resample to hourly
        df['hour'] = df['timestamp'].dt.floor('H')
        hourly = df.groupby('hour').size().reset_index(name='count')
        
        if len(hourly) < 3:
            # Not enough data for forecasting
            avg = df.shape[0] / max((df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600, 1)
            predicted = int(avg * hours)
            return {
                "predicted_attacks": predicted,
                "predicted_successful": int(predicted * df['success'].mean()),
                "confidence": 0.3,
                "risk_score": min(predicted / 10.0 * 100, 100.0)
            }
        
        # Simple linear regression for trend
        hourly['hours_since_start'] = (hourly['hour'] - hourly['hour'].min()).dt.total_seconds() / 3600
        
        X = hourly['hours_since_start'].values.reshape(-1, 1)
        y = hourly['count'].values
        
        try:
            model = LinearRegression()
            model.fit(X, y)
            
            # Predict for next period
            last_hour = hourly['hours_since_start'].max()
            future_hours = np.arange(last_hour + 1, last_hour + hours + 1).reshape(-1, 1)
            predictions = model.predict(future_hours)
            predictions = np.maximum(predictions, 0)  # No negative predictions
            
            predicted_total = int(np.sum(predictions))
            success_rate = df['success'].mean()
            predicted_successful = int(predicted_total * success_rate)
            
            # Confidence based on R² and data volume
            r2 = model.score(X, y)
            confidence = min(r2 * 0.8 + (len(hourly) / 100.0) * 0.2, 1.0)
            
            risk_score = min(predicted_total / (hours / 24.0) / 10.0 * 100, 100.0)
            
            return {
                "predicted_attacks": predicted_total,
                "predicted_successful": predicted_successful,
                "confidence": confidence,
                "risk_score": risk_score
            }
        except:
            # Fallback to simple average
            avg = hourly['count'].mean()
            predicted = int(avg * hours)
            return {
                "predicted_attacks": predicted,
                "predicted_successful": int(predicted * success_rate),
                "confidence": 0.5,
                "risk_score": min(predicted / 10.0 * 100, 100.0)
            }
    
    def _calculate_attack_probability(self, df: pd.DataFrame) -> float:
        """Calculate probability of attack in next hour"""
        if df.empty:
            return 0.0
        
        # Recent attack rate
        recent = df[df['timestamp'] >= (datetime.utcnow() - timedelta(hours=24))]
        if len(recent) == 0:
            return 0.0
        
        # Attacks per hour in last 24h
        hours_covered = max((recent['timestamp'].max() - recent['timestamp'].min()).total_seconds() / 3600, 1)
        attacks_per_hour = len(recent) / hours_covered
        
        # Convert to probability (cap at 1.0)
        probability = min(attacks_per_hour, 1.0)
        
        return probability
    
    def _calculate_exposure_score(self, attacks: List[Attack]) -> float:
        """Calculate vulnerability exposure score"""
        if not attacks:
            return 0.0
        
        recent = [a for a in attacks if (datetime.utcnow() - a.timestamp).days <= 7]
        
        if not recent:
            return 0.0
        
        # Factors:
        # - Number of unique vulnerabilities
        # - Success rate
        # - Number of affected websites
        
        unique_vulns = len(set(a.vulnerability_type for a in recent))
        unique_websites = len(set(a.website_url for a in recent))
        success_rate = sum(1 for a in recent if a.success) / len(recent)
        
        exposure = (
            min(unique_vulns / 10.0, 1.0) * 0.4 +
            success_rate * 0.4 +
            min(unique_websites / 5.0, 1.0) * 0.2
        ) * 100
        
        return min(exposure, 100.0)
    
    def _determine_threat_level(self, risk_score: float, attack_probability: float) -> str:
        """Determine overall threat level"""
        combined = (risk_score / 100.0 * 0.7 + attack_probability * 0.3)
        
        if combined >= 0.75:
            return "critical"
        elif combined >= 0.5:
            return "high"
        elif combined >= 0.25:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence(self, attacks: List[Attack]) -> float:
        """Calculate forecast confidence based on data quality"""
        if not attacks:
            return 0.0
        
        # Factors:
        # - Data volume
        # - Data recency
        # - Time span covered
        
        total = len(attacks)
        volume_score = min(total / 100.0, 1.0)
        
        if attacks:
            newest = max(a.timestamp for a in attacks)
            oldest = min(a.timestamp for a in attacks)
            hours_ago = (datetime.utcnow() - newest).total_seconds() / 3600
            recency = 1.0 if hours_ago < 1 else 0.7
            span = min((newest - oldest).days / 30.0, 1.0)
        else:
            recency = 0.0
            span = 0.0
        
        confidence = volume_score * 0.5 + recency * 0.3 + span * 0.2
        return min(confidence, 1.0)
    
    def _empty_forecast(self) -> RiskForecast:
        """Return empty forecast when no data"""
        return RiskForecast(
            current_risk_score=0.0,
            risk_trajectory=[],
            forecast_24h={"predicted_attacks": 0, "predicted_successful": 0, "confidence": 0.0, "risk_score": 0.0},
            forecast_7d={"predicted_attacks": 0, "predicted_successful": 0, "confidence": 0.0, "risk_score": 0.0},
            forecast_30d={"predicted_attacks": 0, "predicted_successful": 0, "confidence": 0.0, "risk_score": 0.0},
            attack_probability=0.0,
            vulnerability_exposure_score=0.0,
            threat_level="low",
            confidence=0.0
        )


```

```markdown
# AI Cyber Attack Monitoring Dashboard

A real-time monitoring and risk forecasting dashboard for detecting and analyzing AI-powered cyber attacks through honeypot systems.

## Features

### Core Monitoring
- **Real-time Attack Feed**: Live stream of attacks as they occur
- **Attack Statistics**: Comprehensive metrics including:
  - Total attacks (all time, 24h, 7d, 30d)
  - Success vs failure rates
  - Websites targeted
  - Vulnerabilities exploited
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
- Risk trajectory graphs
- Forecast visualizations

## Tech Stack

- **Backend**: FastAPI (Python) with SQLAlchemy
- **Frontend**: React + TypeScript + Vite
- **Charts**: Recharts
- **Styling**: Tailwind CSS
- **Real-time**: WebSockets
- **Forecasting**: scikit-learn, pandas, numpy

## Quick Start

### Using Docker (Recommended)

1. **Start the services**:
   ```bash
   docker-compose up --build
   ```

2. **Access the dashboard**:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

3. **Generate test data** (optional):
   ```bash
   # Install requests if needed
   pip install requests
   
   # Generate 50 test attacks
   python backend/test_data.py 50
   ```

### Manual Setup

#### Backend

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

#### Frontend

```bash
cd frontend
npm install
npm run dev
```

## API Endpoints

### POST `/api/attacks`
Receive attack data from honeypots.

**Request Body**:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "website_url": "https://honeypot.example.com",
  "vulnerability_type": "SQL Injection",
  "attack_vector": "POST /api/login",
  "success": false,
  "payload": "<script>alert('test')</script>",
  "source_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "response_code": 403
}
```

### GET `/api/attacks`
Get recent attacks (supports `limit` and `offset` query params).

### GET `/api/stats`
Get comprehensive statistics.

### GET `/api/risk-forecast`
Get risk trajectory and forecasting data.

### WebSocket `/ws`
Real-time attack feed. Messages are sent as:
```json
{
  "type": "new_attack",
  "data": { ...attack data... }
}
```

## Data Model

### Attack
- `id`: Unique identifier
- `timestamp`: When the attack occurred
- `website_url`: Target website
- `vulnerability_type`: Type of vulnerability targeted
- `attack_vector`: Specific attack method
- `success`: Whether the attack succeeded
- `payload`: Attack payload (optional)
- `source_ip`: Attacker IP (optional)
- `user_agent`: User agent string (optional)
- `response_code`: HTTP response code (optional)

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

## Development

### Project Structure

```
hackathon/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI application
│   │   ├── database.py      # Database setup
│   │   ├── models.py        # SQLAlchemy models
│   │   ├── schemas.py       # Pydantic schemas
│   │   ├── agent_detection.py  # Agent detection logic
│   │   └── forecasting.py   # Risk forecasting
│   ├── requirements.txt
│   └── test_data.py         # Test data generator
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── hooks/           # Custom hooks
│   │   ├── types.ts         # TypeScript types
│   │   └── App.tsx
│   └── package.json
├── docker-compose.yml
└── README.md
```

### Adding New Features

1. **New Metrics**: Add to `StatsResponse` schema and `/api/stats` endpoint
2. **New Forecasts**: Extend `RiskForecaster` class
3. **New Agent Indicators**: Add to `AgentDetector` class
4. **New Visualizations**: Create React components in `frontend/src/components/`

## License

MIT

## Contributing

This is a hackathon project. Feel free to fork and extend!

```


Adding a `.gitignore` and fixing a small issue:


```ignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
*.db
*.sqlite
*.sqlite3

# Node
node_modules/
dist/
build/
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Environment
.env
.env.local

# Database
attacks.db
*.db-journal

```

```typescriptreact
import { useState, useEffect } from 'react'
import { RealTimeFeed } from './components/RealTimeFeed'
import { StatsOverview } from './components/StatsOverview'
import { RiskForecast } from './components/RiskForecast'
import { useWebSocket } from './hooks/useWebSocket'
import { Attack } from './types'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function App() {
  const [attacks, setAttacks] = useState<Attack[]>([])
  const [stats, setStats] = useState<any>(null)
  const [forecast, setForecast] = useState<any>(null)
  const wsUrl = API_BASE.replace(/^http/, 'ws')
  const { lastMessage, readyState } = useWebSocket(`${wsUrl}/ws`)

  // Handle new attack from WebSocket
  useEffect(() => {
    if (lastMessage?.type === 'new_attack') {
      setAttacks(prev => [lastMessage.data, ...prev].slice(0, 100)) // Keep last 100
    }
  }, [lastMessage])

  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [attacksRes, statsRes, forecastRes] = await Promise.all([
          fetch(`${API_BASE}/api/attacks?limit=50`),
          fetch(`${API_BASE}/api/stats`),
          fetch(`${API_BASE}/api/risk-forecast`)
        ])
        
        const attacksData = await attacksRes.json()
        const statsData = await statsRes.json()
        const forecastData = await forecastRes.json()
        
        setAttacks(attacksData)
        setStats(statsData)
        setForecast(forecastData)
      } catch (error) {
        console.error('Error fetching data:', error)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="min-h-screen bg-slate-900">
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <h1 className="text-3xl font-bold text-white">
            AI Cyber Attack Monitoring Dashboard
          </h1>
          <p className="text-slate-400 mt-1">
            Real-time threat detection and risk forecasting
          </p>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <div className="lg:col-span-2">
            <RealTimeFeed attacks={attacks} connectionStatus={readyState} />
          </div>
          <div>
            {forecast && <RiskForecast forecast={forecast} />}
          </div>
        </div>

        {stats && <StatsOverview stats={stats} />}
      </main>
    </div>
  )
}

export default App


```


Adding a development helper script and fixing a small issue in the main.py file:



Creating a simple startup script and verifying everything works:


```shellscript
#!/bin/bash

# Start script for the AI Cyber Attack Monitoring Dashboard

echo "🚀 Starting AI Cyber Attack Monitoring Dashboard..."
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Start services
echo "📦 Starting Docker containers..."
docker-compose up --build -d

echo ""
echo "✅ Services started!"
echo ""
echo "📍 Access points:"
echo "   - Frontend Dashboard: http://localhost:3000"
echo "   - Backend API: http://localhost:8000"
echo "   - API Documentation: http://localhost:8000/docs"
echo ""
echo "💡 To generate test data, run:"
echo "   python backend/test_data.py 50"
echo ""
echo "🛑 To stop services, run:"
echo "   docker-compose down"

```


Fixing the docker-compose configuration so the frontend can connect to the backend:


```dockercompose
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app/backend
      - ./attacks.db:/app/attacks.db
    environment:
      - DATABASE_URL=sqlite:///./attacks.db
    command: python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    ports:
      - "3000:3000"
    volumes:
      - ./frontend:/app/frontend
      - /app/frontend/node_modules
    environment:
      - VITE_API_URL=http://backend:8000
    depends_on:
      - backend
    command: npm run dev


```


Reverting the change. The browser connects to localhost, not the Docker service name:


```dockercompose
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app/backend
      - ./attacks.db:/app/attacks.db
    environment:
      - DATABASE_URL=sqlite:///./attacks.db
    command: python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    ports:
      - "3000:3000"
    volumes:
      - ./frontend:/app/frontend
      - /app/frontend/node_modules
      - VITE_API_URL=http://localhost:8000
    depends_on:
      - backend
    command: npm run dev


```


## Dashboard features

### Real-time monitoring
- Live attack feed with WebSocket updates
- Attack statistics (total, 24h, 7d, 30d)
- Website targeting analysis
- Vulnerability tracking (successful and failed)
- Attack vector distribution

### Autonomous agent detection
- Speed analysis (rapid attack sequences)
- Pattern analysis (systematic exploration)
- Coordination analysis (multi-source patterns)
- Overall agent probability scoring

### Risk forecasting
- Current risk score (0-100)
- Risk trajectory over time
- 24h, 7d, and 30d attack forecasts
- Attack probability calculations
- Vulnerability exposure scoring
- Threat level assessment

## Project structure

```
hackathon/
├── backend/          # FastAPI Python backend
│   ├── app/
│   │   ├── main.py              # API endpoints
│   │   ├── agent_detection.py  # AI agent detection
│   │   ├── forecasting.py      # Risk forecasting models
│   │   └── ...
│   └── test_data.py            # Test data generator
├── frontend/        # React + TypeScript frontend
│   └── src/
│       ├── components/         # Dashboard components
│       └── ...
├── docker-compose.yml
└── README.md
```

## Quick start

1. Start the services:
   ```bash
   ./start.sh
   # or
   docker-compose up --build
   ```

2. Access the dashboard:
   - Frontend: http://localhost:3000
   - API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

3. Generate test data (optional):
   ```bash
   pip install requests
   python backend/test_data.py 50
   ```

## API integration

Your honeypots can send attack data via POST to `/api/attacks`:

```json
{
  "website_url": "https://honeypot.example.com",
  "vulnerability_type": "SQL Injection",
  "attack_vector": "POST /api/login",
  "success": false,
  "source_ip": "192.168.1.100"
}
```

The dashboard will:
- Store the attack
- Analyze for agent indicators
- Update statistics in real time
- Broadcast via WebSocket to connected clients
- Update risk forecasts

## Highlights

1. Real-time updates via WebSockets
2. Agent detection using speed, pattern, and coordination analysis
3. Risk forecasting with scikit-learn for trend prediction
4. Visualizations with Recharts
5. Docker setup for easy deployment

The dashboard is ready for your hackathon demo. You can integrate it with your honeypots by sending POST requests to the `/api/attacks` endpoint, and the dashboard will update in real time.

Need any adjustments or additional features?

```plaintext
hackathon/
├── backend/          # FastAPI Python backend
│   ├── app/
│   │   ├── main.py              # API endpoints
│   │   ├── agent_detection.py  # AI agent detection
│   │   ├── forecasting.py      # Risk forecasting models
│   │   └── ...
│   └── test_data.py            # Test data generator
├── frontend/        # React + TypeScript frontend
│   └── src/
│       ├── components/         # Dashboard components
│       └── ...
├── docker-compose.yml
└── README.md
```

```shellscript
   ./start.sh
   # or
   docker-compose up --build
```

```shellscript
   pip install requests
   python backend/test_data.py 50
```

```json
{
  "website_url": "https://honeypot.example.com",
  "vulnerability_type": "SQL Injection",
  "attack_vector": "POST /api/login",
  "success": false,
  "source_ip": "192.168.1.100"
}
```

