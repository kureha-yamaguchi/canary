"""FastAPI main application"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
from typing import List, Dict, Any
import json
from datetime import datetime, timedelta
import asyncio

from app.database import supabase
from app.models import Attack
from app.schemas import AttackResponse, StatsResponse, RiskForecast
from app.forecasting import RiskForecaster
# Temporarily disable agent detection to focus on basic views
# from app.agent_detection import AgentDetector

# Global connections manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"Error broadcasting to connection: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected connections
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()
forecaster = RiskForecaster()
# agent_detector = AgentDetector()  # Disabled for now

# Background task for polling Supabase and broadcasting updates
polling_task = None

async def poll_and_broadcast():
    """Poll Supabase for new attacks and broadcast via WebSocket"""
    # Simplified: Just sleep for now, will re-enable polling once basic queries work
    while True:
        try:
            await asyncio.sleep(10)  # Sleep - polling disabled temporarily
        except Exception as e:
            print(f"Error in polling task: {e}")
            await asyncio.sleep(5)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global polling_task
    polling_task = asyncio.create_task(poll_and_broadcast())
    yield
    # Shutdown
    if polling_task:
        polling_task.cancel()
        try:
            await polling_task
        except asyncio.CancelledError:
            pass

app = FastAPI(
    title="AI Cyber Attack Monitoring Dashboard API",
    description="Real-time monitoring and risk forecasting for AI cyber attacks",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "AI Cyber Attack Monitoring API"}

@app.get("/api/attacks", response_model=List[AttackResponse])
async def get_attacks(limit: int = 100, offset: int = 0):
    """Get recent attacks"""
    try:
        response = supabase.table("vulnerability_logs")\
            .select("*")\
            .order("timestamp", desc=True)\
            .range(offset, offset + limit - 1)\
            .execute()
        
        if not response.data:
            return []
        
        attacks = []
        for log_data in response.data:
            try:
                attack = Attack.from_vulnerability_log(log_data)
                # Skip agent detection for now - just return basic data
                # agent_indicators = agent_detector.analyze_attack(attack)
                agent_indicators = None
                
                attacks.append(AttackResponse(
                    id=attack.id,
                    timestamp=attack.timestamp,
                    website_url=attack.website_url,
                    vulnerability_type=attack.vulnerability_type,
                    attack_vector=attack.attack_vector,
                    technique_id=attack.technique_id,
                    success=attack.success,
                    payload=attack.payload,
                    source_ip=attack.source_ip,
                    user_agent=attack.user_agent,
                    response_code=attack.response_code,
                    session_id=attack.session_id,
                    agent_indicators=agent_indicators
                ))
            except Exception as e:
                print(f"Error converting log to attack response: {e}")
                continue
        
        return attacks
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get comprehensive statistics"""
    try:
        from datetime import timezone
        now = datetime.now(timezone.utc)
        
        # Get all attacks
        all_response = supabase.table("vulnerability_logs")\
            .select("*")\
            .execute()
        
        if not all_response.data:
            return StatsResponse(
                total_attacks=0,
                attacks_24h=0,
                attacks_7d=0,
                attacks_30d=0,
                successful_attacks=0,
                failed_attacks=0,
                websites_attacked=0,
                successful_vulnerabilities=[],
                failed_vulnerabilities=[],
                attack_vectors=[],
                website_stats=[],
                vulnerability_stats=[],
                time_series=[],
                technique_stats=[]
            )
        
        # Convert to Attack objects
        all_attacks = []
        for log_data in all_response.data:
            try:
                attack = Attack.from_vulnerability_log(log_data)
                # Ensure timestamp is timezone-aware
                if attack.timestamp.tzinfo is None:
                    attack.timestamp = attack.timestamp.replace(tzinfo=timezone.utc)
                all_attacks.append(attack)
            except Exception as e:
                print(f"Error converting log: {e}")
                continue
        
        # Time windows - normalize timestamps for comparison
        def normalize_datetime(dt):
            """Ensure datetime is timezone-aware"""
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        
        time_24h_ago = now - timedelta(hours=24)
        time_7d_ago = now - timedelta(days=7)
        time_30d_ago = now - timedelta(days=30)
        
        attacks_24h = [a for a in all_attacks if normalize_datetime(a.timestamp) >= time_24h_ago]
        attacks_7d = [a for a in all_attacks if normalize_datetime(a.timestamp) >= time_7d_ago]
        attacks_30d = [a for a in all_attacks if normalize_datetime(a.timestamp) >= time_30d_ago]
        
        # Successful vs failed
        successful_attacks = [a for a in all_attacks if a.success]
        failed_attacks = [a for a in all_attacks if not a.success]
        
        # Websites attacked
        websites_attacked = len(set(a.website_url for a in all_attacks))
        
        # Vulnerabilities
        successful_vulns = set(a.vulnerability_type for a in successful_attacks)
        failed_vulns = set(a.vulnerability_type for a in failed_attacks)
        
        # Attack vectors (derived from vulnerability types)
        attack_vector_counts: Dict[str, int] = {}
        for attack in all_attacks:
            vector = attack.attack_vector or attack.vulnerability_type
            attack_vector_counts[vector] = attack_vector_counts.get(vector, 0) + 1
        
        attack_vectors = [{"vector": k, "count": v} for k, v in attack_vector_counts.items()]
        
        # Website stats
        website_counts: Dict[str, Dict[str, int]] = {}
        for attack in all_attacks:
            if attack.website_url not in website_counts:
                website_counts[attack.website_url] = {"total": 0, "successful": 0}
            website_counts[attack.website_url]["total"] += 1
            if attack.success:
                website_counts[attack.website_url]["successful"] += 1
        
        website_stats = [{"url": k, "total": v["total"], "successful": v["successful"]} 
                        for k, v in website_counts.items()]
        
        # Vulnerability stats
        vuln_counts: Dict[str, Dict[str, int]] = {}
        for attack in all_attacks:
            if attack.vulnerability_type not in vuln_counts:
                vuln_counts[attack.vulnerability_type] = {"total": 0, "successful": 0}
            vuln_counts[attack.vulnerability_type]["total"] += 1
            if attack.success:
                vuln_counts[attack.vulnerability_type]["successful"] += 1
        
        vulnerability_stats = [{"type": k, "total": v["total"], "successful": v["successful"]} 
                              for k, v in vuln_counts.items()]
        
        # Technique stats
        technique_counts: Dict[str, Dict[str, int]] = {}
        for attack in all_attacks:
            if attack.technique_id not in technique_counts:
                technique_counts[attack.technique_id] = {"total": 0, "successful": 0}
            technique_counts[attack.technique_id]["total"] += 1
            if attack.success:
                technique_counts[attack.technique_id]["successful"] += 1
        
        technique_stats = [{"technique_id": k, "total": v["total"], "successful": v["successful"]} 
                          for k, v in technique_counts.items()]
        
        # Time series (last 24 hours, hourly buckets)
        time_series = []
        def normalize_datetime(dt):
            """Ensure datetime is timezone-aware"""
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        
        for i in range(24):
            hour_start = now - timedelta(hours=i+1)
            hour_end = now - timedelta(hours=i)
            hour_attacks = [a for a in all_attacks 
                          if hour_start <= normalize_datetime(a.timestamp) < hour_end]
            time_series.append({
                "timestamp": hour_start.isoformat(),
                "count": len(hour_attacks)
            })
        time_series.reverse()
        
        return StatsResponse(
            total_attacks=len(all_attacks),
            attacks_24h=len(attacks_24h),
            attacks_7d=len(attacks_7d),
            attacks_30d=len(attacks_30d),
            successful_attacks=len(successful_attacks),
            failed_attacks=len(failed_attacks),
            websites_attacked=websites_attacked,
            successful_vulnerabilities=list(successful_vulns),
            failed_vulnerabilities=list(failed_vulns),
            attack_vectors=attack_vectors,
            website_stats=website_stats,
            vulnerability_stats=vulnerability_stats,
            time_series=time_series,
            technique_stats=technique_stats
        )
    except Exception as e:
        print(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/risk-forecast", response_model=RiskForecast)
async def get_risk_forecast():
    """Get risk trajectory and forecasting - simplified for now"""
    try:
        # Temporarily return empty forecast - will implement later
        return forecaster._empty_forecast()
    except Exception as e:
        print(f"Error getting forecast: {e}")
        # Return empty forecast on error
        return forecaster._empty_forecast()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle any client messages
            data = await websocket.receive_text()
            try:
                message = json.loads(data) if data else {}
                # Echo back or handle commands
                await websocket.send_json({"type": "pong", "data": message})
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "Invalid JSON"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

