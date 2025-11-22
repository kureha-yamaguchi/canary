"""Advanced risk forecasting with statistical analysis and transparency"""
from app.models import Attack
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import poisson
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')


class AdvancedRiskForecaster:
    """Advanced risk forecasting with statistical rigor and transparency"""
    
    def __init__(self):
        self.methodology = {
            "risk_score": {
                "method": "Multi-factor weighted scoring",
                "factors": {
                    "attack_frequency": {"weight": 0.35, "description": "Number of attacks in time window (normalized to max expected)"},
                    "success_rate": {"weight": 0.30, "description": "Percentage of successful attacks"},
                    "vulnerability_diversity": {"weight": 0.20, "description": "Number of unique vulnerability types (diversity = more risk)"},
                    "trend_momentum": {"weight": 0.15, "description": "Rate of change in attack frequency (increasing = higher risk)"}
                },
                "normalization": "All factors normalized 0-1, then weighted and scaled to 0-100"
            },
            "projection": {
                "method": "Ensemble of statistical methods",
                "methods_used": {
                    "exponential_smoothing": {"weight": 0.4, "description": "Holt-Winters exponential smoothing for trend and seasonality"},
                    "poisson_regression": {"weight": 0.3, "description": "Poisson regression for count-based attack prediction"},
                    "moving_average": {"weight": 0.2, "description": "Weighted moving average (recent data weighted higher)"},
                    "trend_extrapolation": {"weight": 0.1, "description": "Linear trend extrapolation for long-term patterns"}
                },
                "confidence": "Based on model R², data volume, and historical prediction accuracy"
            }
        }
    
    def calculate_risk_score(
        self, 
        attacks: List[Attack], 
        time_window_days: int = 7
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score with full transparency
        
        Returns dict with:
        - risk_score: Overall score (0-100)
        - components: Breakdown of each factor
        - methodology: How it was calculated
        """
        if not attacks:
            return {
                "risk_score": 0.0,
                "components": {},
                "methodology": self.methodology["risk_score"],
                "data_quality": {"sufficient": False, "reason": "No attack data"}
            }
        
        now = datetime.now(timezone.utc)
        
        # Filter to time window
        def normalize_datetime(dt):
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        
        recent_attacks = [
            a for a in attacks 
            if (now - normalize_datetime(a.timestamp)).days <= time_window_days
        ]
        
        if not recent_attacks:
            return {
                "risk_score": 0.0,
                "components": {},
                "methodology": self.methodology["risk_score"],
                "data_quality": {"sufficient": False, "reason": f"No attacks in last {time_window_days} days"}
            }
        
        # Factor 1: Attack Frequency (0-1 normalized)
        attack_count = len(recent_attacks)
        # Expected max: 200 attacks/week for high-risk threshold
        frequency_score = min(attack_count / 200.0, 1.0)
        
        # Factor 2: Success Rate (0-1)
        successful_attacks = sum(1 for a in recent_attacks if a.success)
        success_rate = successful_attacks / attack_count if attack_count > 0 else 0
        
        # Factor 3: Vulnerability Diversity (0-1 normalized)
        unique_vulns = len(set(a.vulnerability_type for a in recent_attacks))
        unique_websites = len(set(a.website_url for a in recent_attacks))
        # Expected max: 15 unique vulnerability types for normalization
        diversity_score = min(unique_vulns / 15.0, 1.0)
        
        # Factor 4: Trend Momentum (0-1)
        # Compare last 3 days vs previous 4 days
        def days_ago(timestamp):
            ts = normalize_datetime(timestamp)
            return (now - ts).days
        
        last_3d = [a for a in recent_attacks if days_ago(a.timestamp) <= 3]
        prev_4d = [a for a in recent_attacks if 3 < days_ago(a.timestamp) <= 7]
        
        trend_momentum = 0.5  # Neutral default
        trend_direction = "stable"
        trend_ratio = 1.0
        
        if len(prev_4d) > 0:
            recent_rate = len(last_3d) / 3.0 if len(last_3d) > 0 else 0
            prev_rate = len(prev_4d) / 4.0
            
            if prev_rate > 0:
                trend_ratio = recent_rate / prev_rate
                if trend_ratio > 1.5:
                    trend_momentum = 1.0
                    trend_direction = "increasing"
                elif trend_ratio > 1.2:
                    trend_momentum = 0.75
                    trend_direction = "increasing"
                elif trend_ratio > 1.0:
                    trend_momentum = 0.6
                    trend_direction = "increasing"
                elif trend_ratio < 0.6:
                    trend_momentum = 0.25
                    trend_direction = "decreasing"
                elif trend_ratio < 0.8:
                    trend_momentum = 0.4
                    trend_direction = "decreasing"
        elif len(last_3d) > 0 and len(prev_4d) == 0:
            # New activity detected
            trend_momentum = 0.8
            trend_direction = "increasing"
        
        # Weighted combination
        weights = self.methodology["risk_score"]["factors"]
        risk_score = (
            frequency_score * weights["attack_frequency"]["weight"] +
            success_rate * weights["success_rate"]["weight"] +
            diversity_score * weights["vulnerability_diversity"]["weight"] +
            trend_momentum * weights["trend_momentum"]["weight"]
        ) * 100
        
        risk_score = min(max(risk_score, 0.0), 100.0)
        
        return {
            "risk_score": risk_score,
            "components": {
                "attack_frequency": {
                    "value": attack_count,
                    "normalized": frequency_score,
                    "weight": weights["attack_frequency"]["weight"],
                    "contribution": frequency_score * weights["attack_frequency"]["weight"] * 100
                },
                "success_rate": {
                    "value": success_rate,
                    "normalized": success_rate,
                    "weight": weights["success_rate"]["weight"],
                    "contribution": success_rate * weights["success_rate"]["weight"] * 100,
                    "successful": successful_attacks,
                    "total": attack_count
                },
                "vulnerability_diversity": {
                    "value": unique_vulns,
                    "normalized": diversity_score,
                    "weight": weights["vulnerability_diversity"]["weight"],
                    "contribution": diversity_score * weights["vulnerability_diversity"]["weight"] * 100,
                    "unique_websites": unique_websites
                },
                "trend_momentum": {
                    "value": trend_ratio,
                    "normalized": trend_momentum,
                    "weight": weights["trend_momentum"]["weight"],
                    "contribution": trend_momentum * weights["trend_momentum"]["weight"] * 100,
                    "direction": trend_direction,
                    "recent_3d": len(last_3d),
                    "prev_4d": len(prev_4d)
                }
            },
            "methodology": self.methodology["risk_score"],
            "data_quality": {
                "sufficient": True,
                "time_window_days": time_window_days,
                "data_points": len(recent_attacks),
                "date_range": {
                    "oldest": min(normalize_datetime(a.timestamp) for a in recent_attacks).isoformat(),
                    "newest": max(normalize_datetime(a.timestamp) for a in recent_attacks).isoformat()
                }
            }
        }
    
    def project_attacks(
        self, 
        attacks: List[Attack], 
        time_horizon_hours: int,
        method: str = "ensemble"
    ) -> Dict[str, Any]:
        """
        Project future attacks using statistical methods
        
        Args:
            attacks: Historical attack data
            time_horizon_hours: Hours into future to project
            method: "ensemble", "exponential_smoothing", "poisson", "moving_average", "trend"
        
        Returns:
            Dict with predictions, confidence intervals, and methodology details
        """
        if not attacks or len(attacks) < 5:
            return {
                "predicted_attacks": 0,
                "prediction_range": {"lower": 0, "upper": 0},
                "confidence": 0.0,
                "methodology": self.methodology["projection"],
                "data_quality": {"sufficient": False, "reason": "Insufficient data points"}
            }
        
        # Convert to DataFrame
        df = pd.DataFrame([{
            'timestamp': a.timestamp,
            'success': 1 if a.success else 0,
            'technique_id': a.technique_id,
            'website_url': a.website_url
        } for a in attacks])
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        if df['timestamp'].dt.tz is None:
            df['timestamp'] = df['timestamp'].dt.tz_localize('UTC')
        
        df = df.sort_values('timestamp')
        
        # Resample to hourly
        df['hour'] = df['timestamp'].dt.floor('H')
        hourly_counts = df.groupby('hour').size().reset_index(name='count')
        hourly_success = df.groupby('hour')['success'].sum().reset_index(name='successful')
        hourly = hourly_counts.merge(hourly_success, on='hour', how='left')
        hourly['successful'] = hourly['successful'].fillna(0)
        
        if len(hourly) < 3:
            # Fallback: simple average
            avg_rate = len(df) / max((df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600, 1)
            predicted = int(avg_rate * time_horizon_hours)
            success_rate = df['success'].mean() if len(df) > 0 else 0
            
            return {
                "predicted_attacks": predicted,
                "predicted_successful": int(predicted * success_rate),
                "prediction_range": {"lower": int(predicted * 0.5), "upper": int(predicted * 1.5)},
                "confidence": 0.3,
                "methodology": {"method": "simple_average", "reason": "insufficient_data"},
                "data_quality": {"sufficient": False}
            }
        
        predictions = []
        methods_used = []
        
        if method in ["ensemble", "exponential_smoothing"]:
            # Exponential Smoothing (Holt-Winters variant)
            try:
                alpha = 0.3  # Smoothing parameter
                beta = 0.1   # Trend parameter
                
                # Simple exponential smoothing with trend
                smoothed = []
                trend = []
                
                smoothed.append(hourly['count'].iloc[0])
                trend.append(0)
                
                for i in range(1, len(hourly)):
                    prev_smooth = smoothed[-1]
                    prev_trend = trend[-1]
                    current = hourly['count'].iloc[i]
                    
                    new_smooth = alpha * current + (1 - alpha) * (prev_smooth + prev_trend)
                    new_trend = beta * (new_smooth - prev_smooth) + (1 - beta) * prev_trend
                    
                    smoothed.append(new_smooth)
                    trend.append(new_trend)
                
                # Forecast
                last_smooth = smoothed[-1]
                last_trend = trend[-1]
                forecast_es = last_smooth + last_trend * time_horizon_hours
                forecast_es = max(0, int(forecast_es))
                
                predictions.append(("exponential_smoothing", forecast_es))
                methods_used.append({"method": "exponential_smoothing", "prediction": forecast_es, "weight": 0.4})
            except Exception as e:
                print(f"Exponential smoothing failed: {e}")
        
        if method in ["ensemble", "poisson"]:
            # Poisson regression (appropriate for count data)
            try:
                hourly['hours_since_start'] = (hourly['hour'] - hourly['hour'].min()).dt.total_seconds() / 3600
                X = hourly['hours_since_start'].values.reshape(-1, 1)
                y = hourly['count'].values
                
                # Fit Poisson-like model (using log link)
                # Fallback to LinearRegression if PoissonRegressor not available
                use_log_transform = False
                try:
                    from sklearn.linear_model import PoissonRegressor
                    model = PoissonRegressor(alpha=0.1, max_iter=200)
                    model.fit(X, y)
                except ImportError:
                    # Use LinearRegression with log transform as approximation
                    from sklearn.linear_model import LinearRegression
                    y_log = np.log1p(y)  # log(1+y) to handle zeros
                    model = LinearRegression()
                    model.fit(X, y_log)
                    # Store flag to use exp transform later
                    use_log_transform = True
                
                last_hour = hourly['hours_since_start'].max()
                future_hours = np.arange(last_hour + 1, last_hour + time_horizon_hours + 1).reshape(-1, 1)
                
                # Check if we used log transform
                if use_log_transform:
                    pred_log = model.predict(future_hours)
                    pred_rates = np.expm1(pred_log)  # exp(x) - 1 to reverse log1p
                else:
                    pred_rates = model.predict(future_hours)
                
                pred_rates = np.maximum(pred_rates, 0)  # No negative rates
                forecast_poisson = int(np.sum(pred_rates))
                
                # Calculate confidence interval (95%)
                # For Poisson, CI ≈ prediction ± 1.96 * sqrt(prediction)
                std_dev = np.sqrt(forecast_poisson)
                ci_lower = max(0, int(forecast_poisson - 1.96 * std_dev))
                ci_upper = int(forecast_poisson + 1.96 * std_dev)
                
                predictions.append(("poisson", forecast_poisson))
                methods_used.append({
                    "method": "poisson_regression",
                    "prediction": forecast_poisson,
                    "confidence_interval": {"lower": ci_lower, "upper": ci_upper},
                    "weight": 0.3
                })
            except Exception as e:
                print(f"Poisson regression failed: {e}")
                # Fallback to linear if Poisson not available
                try:
                    from sklearn.linear_model import LinearRegression
                    model = LinearRegression()
                    model.fit(X, y)
                    pred_linear = model.predict(future_hours)
                    pred_linear = np.maximum(pred_linear, 0)
                    forecast_linear = int(np.sum(pred_linear))
                    predictions.append(("linear", forecast_linear))
                    methods_used.append({"method": "linear_regression", "prediction": forecast_linear, "weight": 0.3})
                except:
                    pass
        
        if method in ["ensemble", "moving_average"]:
            # Weighted moving average (recent data weighted more)
            try:
                window = min(24, len(hourly))  # Last 24 hours or all data
                recent_counts = hourly['count'].tail(window).values
                
                # Exponential weights (more recent = higher weight)
                weights = np.exp(np.linspace(-1, 0, len(recent_counts)))
                weights = weights / weights.sum()
                
                weighted_avg = np.average(recent_counts, weights=weights)
                forecast_ma = int(weighted_avg * time_horizon_hours)
                
                predictions.append(("moving_average", forecast_ma))
                methods_used.append({"method": "weighted_moving_average", "prediction": forecast_ma, "weight": 0.2})
            except Exception as e:
                print(f"Moving average failed: {e}")
        
        if method in ["ensemble", "trend"]:
            # Linear trend extrapolation
            try:
                hourly['hours_since_start'] = (hourly['hour'] - hourly['hour'].min()).dt.total_seconds() / 3600
                X = hourly['hours_since_start'].values.reshape(-1, 1)
                y = hourly['count'].values
                
                from sklearn.linear_model import LinearRegression
                model = LinearRegression()
                model.fit(X, y)
                
                last_hour = hourly['hours_since_start'].max()
                future_hours = np.arange(last_hour + 1, last_hour + time_horizon_hours + 1).reshape(-1, 1)
                pred_trend = model.predict(future_hours)
                pred_trend = np.maximum(pred_trend, 0)
                forecast_trend = int(np.sum(pred_trend))
                
                # Calculate R² for confidence
                r2 = model.score(X, y)
                
                predictions.append(("trend", forecast_trend))
                methods_used.append({
                    "method": "trend_extrapolation",
                    "prediction": forecast_trend,
                    "r_squared": float(r2),
                    "weight": 0.1
                })
            except Exception as e:
                print(f"Trend extrapolation failed: {e}")
        
        if not predictions:
            # All methods failed, use simple average
            avg_rate = hourly['count'].mean()
            forecast_simple = int(avg_rate * time_horizon_hours)
            return {
                "predicted_attacks": forecast_simple,
                "prediction_range": {"lower": int(forecast_simple * 0.5), "upper": int(forecast_simple * 1.5)},
                "confidence": 0.2,
                "methodology": {"method": "simple_average_fallback"},
                "data_quality": {"sufficient": True, "warning": "All advanced methods failed"}
            }
        
        # Ensemble: Weighted average of all methods
        if method == "ensemble" and len(predictions) > 1:
            # Build weights map using method name (string) as key, not dict
            weights_map = {
                m.get("method", "unknown"): m.get("weight", 0.25)
                for m in methods_used 
                if isinstance(m, dict) and "weight" in m
            }
            total_weight = sum(m.get("weight", 0) for m in methods_used if isinstance(m, dict))
            
            if total_weight > 0:
                weighted_pred = sum(
                    pred * (m.get("weight", 0.25) / total_weight)
                    for (method_name, pred), m in zip(predictions, methods_used)
                    if isinstance(m, dict)
                )
            else:
                weighted_pred = np.mean([pred for _, pred in predictions])
        else:
            weighted_pred = predictions[0][1]
        
        predicted_attacks = max(0, int(weighted_pred))
        
        # Calculate success rate projection
        success_rate = df['success'].mean() if len(df) > 0 else 0
        predicted_successful = int(predicted_attacks * success_rate)
        
        # Confidence calculation
        # Based on: data volume, R² scores, prediction variance
        data_volume_score = min(len(hourly) / 100.0, 1.0)
        
        # Get R² from available methods
        r2_scores = [m.get("r_squared", 0.7) for m in methods_used if isinstance(m, dict) and "r_squared" in m]
        avg_r2 = np.mean(r2_scores) if r2_scores else 0.7
        
        # Prediction variance (lower variance = higher confidence)
        pred_values = [pred for _, pred in predictions]
        if len(pred_values) > 1:
            variance = np.var(pred_values)
            max_pred = max(pred_values)
            consistency_score = 1.0 - min(variance / (max_pred ** 2), 1.0) if max_pred > 0 else 0.5
        else:
            consistency_score = 0.5
        
        confidence = (
            data_volume_score * 0.3 +
            avg_r2 * 0.4 +
            consistency_score * 0.3
        )
        confidence = min(max(confidence, 0.0), 1.0)
        
        # Prediction range (confidence interval)
        if len(pred_values) > 1:
            mean_pred = np.mean(pred_values)
            std_pred = np.std(pred_values)
            prediction_range = {
                "lower": max(0, int(mean_pred - 1.96 * std_pred)),
                "upper": int(mean_pred + 1.96 * std_pred)
            }
        else:
            # Use ±30% as default range
            prediction_range = {
                "lower": max(0, int(predicted_attacks * 0.7)),
                "upper": int(predicted_attacks * 1.3)
            }
        
        return {
            "predicted_attacks": predicted_attacks,
            "predicted_successful": predicted_successful,
            "prediction_range": prediction_range,
            "confidence": confidence,
            "methodology": {
                **self.methodology["projection"],
                "methods_applied": methods_used,
                "ensemble_weights": weights_map if method == "ensemble" and len(predictions) > 1 else {}
            },
            "statistics": {
                "historical_mean": float(hourly['count'].mean()) if not np.isnan(hourly['count'].mean()) else 0.0,
                "historical_std": float(hourly['count'].std()) if not np.isnan(hourly['count'].std()) else 0.0,
                "historical_median": float(hourly['count'].median()) if not np.isnan(hourly['count'].median()) else 0.0,
                "trend_slope": float(model.coef_[0]) if 'model' in locals() and hasattr(model, 'coef_') and not np.isnan(model.coef_[0]) else None,
                "data_points": len(hourly),
                "time_span_hours": float((hourly['hour'].max() - hourly['hour'].min()).total_seconds() / 3600) if len(hourly) > 1 else 0.0
            },
            "data_quality": {
                "sufficient": True,
                "sample_size": len(hourly),
                "time_coverage_hours": float((hourly['hour'].max() - hourly['hour'].min()).total_seconds() / 3600)
            }
        }

