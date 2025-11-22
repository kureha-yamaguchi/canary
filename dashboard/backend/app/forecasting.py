"""Risk forecasting and trajectory analysis"""
from app.models import Attack
from app.schemas import RiskForecast
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression
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
        
        now = datetime.now(timezone.utc)
        # Ensure timestamps are timezone-aware
        recent_attacks = [a for a in attacks if (now - (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp)).days <= 7]
        
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
        now = datetime.now(timezone.utc)
        # Ensure timestamps are timezone-aware for comparison
        def days_ago(timestamp):
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            return (now - timestamp).days
        
        last_3d = [a for a in recent_attacks if days_ago(a.timestamp) <= 3]
        prev_4d = [a for a in recent_attacks if 3 < days_ago(a.timestamp) <= 7]
        
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
            success_rate = df['success'].mean() if len(df) > 0 else 0
            return {
                "predicted_attacks": predicted,
                "predicted_successful": int(predicted * success_rate),
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
        except Exception as e:
            # Fallback to simple average
            print(f"Error in forecasting: {e}")
            avg = hourly['count'].mean()
            predicted = int(avg * hours)
            success_rate = df['success'].mean()
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
        
        # Recent attack rate - ensure datetime is timezone-aware
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=24)
        # Ensure df timestamps are timezone-aware
        if df['timestamp'].dt.tz is None:
            df['timestamp'] = df['timestamp'].dt.tz_localize('UTC')
        recent = df[df['timestamp'] >= cutoff]
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
        
        now = datetime.now(timezone.utc)
        # Ensure timestamps are timezone-aware
        recent = [a for a in attacks if (now - (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp)).days <= 7]
        
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
            now = datetime.now(timezone.utc)
            # Ensure timestamps are timezone-aware
            newest = max((a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp) for a in attacks)
            oldest = min((a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp) for a in attacks)
            hours_ago = (now - newest).total_seconds() / 3600
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

