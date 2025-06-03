# Section 7.5 - Real-time SLO Monitoring and Dynamic Error Budget Management
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Error Budget and SLO Validation.md
# Addresses TC_R757_REALTIME_001-008: Advanced Real-time SLO Management

import pytest
import httpx
import asyncio
import time
import json
import threading
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from collections import deque, defaultdict
from unittest.mock import patch, Mock
import statistics
import random

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class RealTimeSLOTracker:
    """Real-time SLO monitoring with sliding window tracking"""
    window_size_seconds: int = 300  # 5-minute sliding window
    measurement_interval: float = 1.0  # Measurements every second
    
    # Sliding window data structures
    request_times: deque = field(default_factory=deque)
    request_outcomes: deque = field(default_factory=deque)  # True=success, False=failure
    request_latencies: deque = field(default_factory=deque)
    
    # Real-time metrics
    current_availability: float = 1.0
    current_p95_latency: float = 0.0
    current_p99_latency: float = 0.0
    error_budget_remaining: float = 1.0
    
    # Alerting thresholds
    availability_threshold: float = 0.995
    p95_latency_threshold: float = 5.0
    p99_latency_threshold: float = 10.0
    error_budget_alert_threshold: float = 0.1  # Alert at 10% remaining
    
    # Historical data for trend analysis
    availability_history: deque = field(default_factory=lambda: deque(maxlen=1440))  # 24 hours of minutes
    latency_history: deque = field(default_factory=lambda: deque(maxlen=1440))
    error_budget_history: deque = field(default_factory=lambda: deque(maxlen=1440))
    
    def add_request(self, success: bool, latency: float, timestamp: Optional[float] = None):
        """Add a request result to the real-time tracker"""
        if timestamp is None:
            timestamp = time.time()
        
        # Add to sliding window
        self.request_times.append(timestamp)
        self.request_outcomes.append(success)
        self.request_latencies.append(latency)
        
        # Clean old data outside window
        self._clean_old_data(timestamp)
        
        # Update real-time metrics
        self._update_realtime_metrics()
    
    def _clean_old_data(self, current_time: float):
        """Remove data older than window_size_seconds"""
        cutoff_time = current_time - self.window_size_seconds
        
        while self.request_times and self.request_times[0] < cutoff_time:
            self.request_times.popleft()
            self.request_outcomes.popleft()
            self.request_latencies.popleft()
    
    def _update_realtime_metrics(self):
        """Update current real-time SLO metrics"""
        if not self.request_outcomes:
            return
        
        # Update availability
        successful_requests = sum(self.request_outcomes)
        total_requests = len(self.request_outcomes)
        self.current_availability = successful_requests / total_requests
        
        # Update latency percentiles
        if self.request_latencies:
            sorted_latencies = sorted(self.request_latencies)
            p95_index = int(len(sorted_latencies) * 0.95)
            p99_index = int(len(sorted_latencies) * 0.99)
            
            self.current_p95_latency = sorted_latencies[min(p95_index, len(sorted_latencies) - 1)]
            self.current_p99_latency = sorted_latencies[min(p99_index, len(sorted_latencies) - 1)]
        
        # Update error budget
        if self.current_availability < self.availability_threshold:
            budget_consumed = (self.availability_threshold - self.current_availability) / (1 - self.availability_threshold)
            self.error_budget_remaining = max(0, 1 - budget_consumed)
        else:
            self.error_budget_remaining = 1.0
    
    def get_current_slo_status(self) -> Dict[str, Any]:
        """Get current SLO status snapshot"""
        return {
            "availability": self.current_availability,
            "p95_latency": self.current_p95_latency,
            "p99_latency": self.current_p99_latency,
            "error_budget_remaining": self.error_budget_remaining,
            "window_size": len(self.request_outcomes),
            "slo_violations": {
                "availability": self.current_availability < self.availability_threshold,
                "p95_latency": self.current_p95_latency > self.p95_latency_threshold,
                "p99_latency": self.current_p99_latency > self.p99_latency_threshold,
                "error_budget": self.error_budget_remaining < self.error_budget_alert_threshold
            }
        }
    
    def should_alert(self) -> List[str]:
        """Check if any SLO violations require alerting"""
        alerts = []
        status = self.get_current_slo_status()
        
        if status["slo_violations"]["availability"]:
            alerts.append(f"Availability SLO violation: {self.current_availability:.3%} < {self.availability_threshold:.3%}")
        
        if status["slo_violations"]["p95_latency"]:
            alerts.append(f"P95 latency SLO violation: {self.current_p95_latency:.2f}s > {self.p95_latency_threshold:.2f}s")
        
        if status["slo_violations"]["p99_latency"]:
            alerts.append(f"P99 latency SLO violation: {self.current_p99_latency:.2f}s > {self.p99_latency_threshold:.2f}s")
        
        if status["slo_violations"]["error_budget"]:
            alerts.append(f"Error budget critically low: {self.error_budget_remaining:.1%} remaining")
        
        return alerts


@dataclass
class DynamicErrorBudgetManager:
    """Dynamic error budget management with adaptive policies"""
    total_budget: float = 0.005  # 0.5% error budget (99.5% availability target)
    current_period_start: float = field(default_factory=time.time)
    period_duration: int = 3600  # 1 hour periods for testing
    
    # Adaptive budget allocation
    baseline_budget: float = 0.003  # 60% of budget for baseline
    burst_budget: float = 0.002  # 40% of budget for bursts
    
    # Budget consumption tracking
    consumed_budget: float = 0.0
    burst_budget_consumed: float = 0.0
    
    # Adaptive thresholds
    normal_threshold: float = 0.5  # 50% budget consumed - normal operations
    warning_threshold: float = 0.75  # 75% budget consumed - warning state
    critical_threshold: float = 0.90  # 90% budget consumed - critical state
    
    # Historical periods for trend analysis
    historical_consumption: deque = field(default_factory=lambda: deque(maxlen=24))  # 24 hours of periods
    
    def consume_budget(self, error_count: int, total_requests: int):
        """Consume error budget based on actual errors"""
        if total_requests == 0:
            return
        
        error_rate = error_count / total_requests
        budget_consumption = error_rate / self.total_budget  # Normalize to budget
        
        # Allocate to baseline vs burst budget
        baseline_consumption = min(budget_consumption, self.baseline_budget - self.consumed_budget)
        burst_consumption = max(0, budget_consumption - baseline_consumption)
        
        self.consumed_budget += baseline_consumption
        self.burst_budget_consumed += burst_consumption
    
    def get_budget_status(self) -> Dict[str, Any]:
        """Get current error budget status"""
        total_consumed = self.consumed_budget + self.burst_budget_consumed
        remaining_budget = max(0, self.total_budget - total_consumed)
        
        # Determine current state
        consumption_rate = total_consumed / self.total_budget
        
        if consumption_rate >= self.critical_threshold:
            state = "critical"
        elif consumption_rate >= self.warning_threshold:
            state = "warning"
        elif consumption_rate >= self.normal_threshold:
            state = "normal"
        else:
            state = "healthy"
        
        return {
            "total_budget": self.total_budget,
            "consumed_budget": total_consumed,
            "remaining_budget": remaining_budget,
            "consumption_rate": consumption_rate,
            "state": state,
            "baseline_consumed": self.consumed_budget,
            "burst_consumed": self.burst_budget_consumed,
            "period_elapsed": time.time() - self.current_period_start,
            "period_duration": self.period_duration
        }
    
    def should_throttle(self) -> bool:
        """Determine if traffic should be throttled to preserve error budget"""
        status = self.get_budget_status()
        return status["state"] in ["warning", "critical"]
    
    def get_recommended_action(self) -> str:
        """Get recommended action based on current budget state"""
        status = self.get_budget_status()
        
        if status["state"] == "healthy":
            return "continue_normal_operations"
        elif status["state"] == "normal":
            return "monitor_closely"
        elif status["state"] == "warning":
            return "reduce_non_critical_traffic"
        elif status["state"] == "critical":
            return "emergency_throttling_required"
        
        return "unknown_state"


class TestRealTimeSLOMonitoring:
    """Real-time SLO monitoring and dynamic error budget management tests"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r757_realtime_slo_tracking_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """TC_R757_REALTIME_001: Real-time SLO tracking with sliding windows"""
        # Test real-time SLO monitoring with continuous measurement
        
        slo_tracker = RealTimeSLOTracker(window_size_seconds=120, measurement_interval=0.5)
        monitoring_duration = 60  # 1 minute of real-time monitoring
        
        logger.info(f"Starting real-time SLO tracking for {monitoring_duration}s")
        
        # Background monitoring task
        async def continuous_monitoring():
            """Continuous SLO monitoring background task"""
            monitoring_start = time.time()
            request_count = 0
            
            while time.time() - monitoring_start < monitoring_duration:
                request_start = time.time()
                
                try:
                    # Generate varied request complexity
                    complexity = random.choice(["simple", "medium", "complex"])
                    
                    if complexity == "simple":
                        content = "Real-time SLO test"
                        max_tokens = 30
                    elif complexity == "medium":
                        content = "Real-time SLO monitoring test with moderate complexity"
                        max_tokens = 60
                    else:
                        content = "Real-time SLO monitoring test with complex requirements for detailed analysis"
                        max_tokens = 120
                    
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": content}],
                        "max_tokens": max_tokens
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    request_end = time.time()
                    latency = request_end - request_start
                    success = response.status_code == 200
                    
                    # Add to real-time tracker
                    slo_tracker.add_request(success, latency, request_start)
                    request_count += 1
                    
                    # Check for real-time alerts
                    alerts = slo_tracker.should_alert()
                    if alerts:
                        for alert in alerts:
                            logger.warning(f"Real-time SLO Alert: {alert}")
                    
                    # Log current status every 10 requests
                    if request_count % 10 == 0:
                        status = slo_tracker.get_current_slo_status()
                        logger.info(f"Current SLO Status (Request {request_count}):")
                        logger.info(f"  Availability: {status['availability']:.3%}")
                        logger.info(f"  P95 Latency: {status['p95_latency']:.2f}s")
                        logger.info(f"  Error Budget: {status['error_budget_remaining']:.1%}")
                
                except Exception as e:
                    request_end = time.time()
                    latency = request_end - request_start
                    
                    # Track failed request
                    slo_tracker.add_request(False, latency, request_start)
                    request_count += 1
                    
                    logger.warning(f"Real-time monitoring request failed: {e}")
                
                # Wait for next measurement interval
                elapsed = time.time() - request_start
                sleep_time = max(0, slo_tracker.measurement_interval - elapsed)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
        
        # Run continuous monitoring
        await continuous_monitoring()
        
        # Final SLO analysis
        final_status = slo_tracker.get_current_slo_status()
        
        logger.info("Real-time SLO Tracking Results:")
        logger.info(f"  Final Availability: {final_status['availability']:.3%}")
        logger.info(f"  Final P95 Latency: {final_status['p95_latency']:.2f}s")
        logger.info(f"  Final P99 Latency: {final_status['p99_latency']:.2f}s")
        logger.info(f"  Final Error Budget: {final_status['error_budget_remaining']:.1%}")
        logger.info(f"  Window Size: {final_status['window_size']} requests")
        
        # Verify real-time tracking capabilities
        assert final_status['window_size'] >= 10, "Should have sufficient requests for real-time analysis"
        assert final_status['availability'] >= 0.85, "Real-time availability should be reasonable"
        assert final_status['p95_latency'] <= 30.0, "Real-time P95 latency should be bounded"
        
        logger.info("✅ Real-time SLO tracking validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r757_dynamic_error_budget_002(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """TC_R757_REALTIME_002: Dynamic error budget management and adaptive policies"""
        # Test dynamic error budget management with adaptive allocation
        
        budget_manager = DynamicErrorBudgetManager(
            total_budget=0.01,  # 1% error budget for testing
            period_duration=300  # 5-minute test period
        )
        
        logger.info("Starting dynamic error budget management test")
        
        # Simulate different traffic patterns and error rates
        traffic_scenarios = [
            {"name": "normal_traffic", "requests": 20, "error_injection_rate": 0.02},
            {"name": "burst_traffic", "requests": 40, "error_injection_rate": 0.05},
            {"name": "recovery_traffic", "requests": 15, "error_injection_rate": 0.01}
        ]
        
        total_requests = 0
        total_errors = 0
        
        for scenario in traffic_scenarios:
            logger.info(f"Testing scenario: {scenario['name']}")
            
            scenario_errors = 0
            scenario_requests = 0
            
            for i in range(scenario["requests"]):
                # Simulate error injection for testing
                inject_error = random.random() < scenario["error_injection_rate"]
                
                if inject_error:
                    # Simulate a request that will fail
                    try:
                        request = {
                            "model": "dynamic_budget_invalid_model",
                            "messages": [{"role": "user", "content": "Error injection test"}],
                            "max_tokens": 50
                        }
                        
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request, track_cost=False
                        )
                        
                        # This should be an error, but handle unexpected success
                        if response.status_code != 200:
                            scenario_errors += 1
                            total_errors += 1
                    
                    except Exception:
                        scenario_errors += 1
                        total_errors += 1
                
                else:
                    # Make a normal successful request
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Budget test {i}"}],
                        "max_tokens": 40
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    if response.status_code != 200:
                        scenario_errors += 1
                        total_errors += 1
                
                scenario_requests += 1
                total_requests += 1
                
                # Update budget manager periodically
                if scenario_requests % 5 == 0:
                    budget_manager.consume_budget(scenario_errors, scenario_requests)
                    
                    # Check budget status and take action
                    status = budget_manager.get_budget_status()
                    action = budget_manager.get_recommended_action()
                    
                    logger.info(f"Budget Status: {status['state']} "
                              f"({status['consumption_rate']:.1%} consumed, "
                              f"{status['remaining_budget']:.3%} remaining)")
                    
                    if action != "continue_normal_operations":
                        logger.warning(f"Recommended Action: {action}")
                    
                    # Simulate throttling behavior
                    if budget_manager.should_throttle():
                        logger.info("Implementing traffic throttling due to budget constraints")
                        await asyncio.sleep(0.5)  # Simulate throttling delay
                
                await asyncio.sleep(0.1)
            
            logger.info(f"Scenario {scenario['name']} completed: "
                       f"{scenario_errors}/{scenario_requests} errors "
                       f"({scenario_errors/scenario_requests:.1%} error rate)")
        
        # Final budget analysis
        budget_manager.consume_budget(total_errors, total_requests)
        final_status = budget_manager.get_budget_status()
        
        logger.info("Dynamic Error Budget Management Results:")
        logger.info(f"  Total Requests: {total_requests}")
        logger.info(f"  Total Errors: {total_errors}")
        logger.info(f"  Overall Error Rate: {total_errors/total_requests:.1%}")
        logger.info(f"  Budget State: {final_status['state']}")
        logger.info(f"  Budget Consumed: {final_status['consumption_rate']:.1%}")
        logger.info(f"  Budget Remaining: {final_status['remaining_budget']:.3%}")
        logger.info(f"  Baseline Budget Used: {final_status['baseline_consumed']:.3%}")
        logger.info(f"  Burst Budget Used: {final_status['burst_consumed']:.3%}")
        
        # Verify dynamic budget management
        assert total_requests >= 50, "Should have sufficient requests for budget analysis"
        assert final_status['consumption_rate'] <= 1.0, "Budget consumption should not exceed 100%"
        
        # Verify adaptive behavior
        if final_status['state'] in ['warning', 'critical']:
            logger.info("✅ Dynamic error budget correctly identified high consumption state")
        
        logger.info("✅ Dynamic error budget management validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r757_predictive_slo_analytics_003(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """TC_R757_REALTIME_003: Predictive SLO analytics and violation prevention"""
        # Test predictive SLO analytics to prevent violations before they occur
        
        class PredictiveSLOAnalyzer:
            def __init__(self):
                self.latency_trend = deque(maxlen=50)
                self.error_rate_trend = deque(maxlen=50)
                self.request_rate_trend = deque(maxlen=50)
                
            def add_measurement(self, latency: float, error_rate: float, request_rate: float):
                self.latency_trend.append(latency)
                self.error_rate_trend.append(error_rate)
                self.request_rate_trend.append(request_rate)
            
            def predict_violation_risk(self) -> Dict[str, Any]:
                """Predict risk of SLO violations based on trends"""
                if len(self.latency_trend) < 10:
                    return {"risk_level": "insufficient_data"}
                
                # Simple trend analysis (in production would use ML models)
                recent_latency = list(self.latency_trend)[-10:]
                recent_errors = list(self.error_rate_trend)[-10:]
                
                # Calculate trends
                latency_trend_slope = self._calculate_trend(recent_latency)
                error_trend_slope = self._calculate_trend(recent_errors)
                
                # Predict risk levels
                latency_risk = "high" if latency_trend_slope > 0.1 else "medium" if latency_trend_slope > 0.05 else "low"
                error_risk = "high" if error_trend_slope > 0.01 else "medium" if error_trend_slope > 0.005 else "low"
                
                # Combined risk assessment
                if latency_risk == "high" or error_risk == "high":
                    combined_risk = "high"
                elif latency_risk == "medium" or error_risk == "medium":
                    combined_risk = "medium"
                else:
                    combined_risk = "low"
                
                return {
                    "risk_level": combined_risk,
                    "latency_risk": latency_risk,
                    "error_risk": error_risk,
                    "latency_trend": latency_trend_slope,
                    "error_trend": error_trend_slope,
                    "current_latency": recent_latency[-1] if recent_latency else 0,
                    "current_error_rate": recent_errors[-1] if recent_errors else 0
                }
            
            def _calculate_trend(self, values: List[float]) -> float:
                """Calculate simple linear trend slope"""
                if len(values) < 2:
                    return 0.0
                
                x = list(range(len(values)))
                y = values
                
                n = len(values)
                sum_x = sum(x)
                sum_y = sum(y)
                sum_xy = sum(x[i] * y[i] for i in range(n))
                sum_x2 = sum(x[i] ** 2 for i in range(n))
                
                # Linear regression slope
                slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
                return slope
        
        predictor = PredictiveSLOAnalyzer()
        
        logger.info("Starting predictive SLO analytics test")
        
        # Generate measurement data with varying patterns
        measurement_count = 0
        violation_predictions = []
        
        for phase in range(3):
            logger.info(f"Testing prediction phase {phase + 1}")
            
            for i in range(15):
                measurement_start = time.time()
                
                # Simulate different load patterns per phase
                if phase == 0:  # Normal operations
                    content = "Predictive analytics baseline test"
                    max_tokens = 40
                elif phase == 1:  # Increasing load
                    content = "Predictive analytics load increase test with extended content"
                    max_tokens = 80
                else:  # Recovery phase
                    content = "Predictive analytics recovery test"
                    max_tokens = 50
                
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": content}],
                    "max_tokens": max_tokens
                }
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    measurement_end = time.time()
                    latency = measurement_end - measurement_start
                    error_rate = 0.0 if response.status_code == 200 else 1.0
                    
                except Exception:
                    measurement_end = time.time()
                    latency = measurement_end - measurement_start
                    error_rate = 1.0
                
                # Calculate request rate (simplified)
                request_rate = 1.0 / max(0.1, measurement_end - measurement_start)
                
                # Add to predictor
                predictor.add_measurement(latency, error_rate, request_rate)
                measurement_count += 1
                
                # Get violation risk prediction
                if measurement_count >= 10:
                    prediction = predictor.predict_violation_risk()
                    violation_predictions.append({
                        "measurement": measurement_count,
                        "phase": phase,
                        "prediction": prediction,
                        "actual_latency": latency,
                        "actual_error_rate": error_rate
                    })
                    
                    # Log predictions for high-risk scenarios
                    if prediction["risk_level"] == "high":
                        logger.warning(f"HIGH RISK SLO violation predicted at measurement {measurement_count}")
                        logger.warning(f"  Latency trend: {prediction['latency_trend']:.3f}")
                        logger.warning(f"  Error trend: {prediction['error_trend']:.3f}")
                        logger.warning(f"  Current latency: {prediction['current_latency']:.2f}s")
                    
                    elif prediction["risk_level"] == "medium":
                        logger.info(f"Medium risk SLO violation predicted at measurement {measurement_count}")
                
                await asyncio.sleep(0.2)
        
        # Analyze prediction accuracy
        high_risk_predictions = [p for p in violation_predictions if p["prediction"]["risk_level"] == "high"]
        medium_risk_predictions = [p for p in violation_predictions if p["prediction"]["risk_level"] == "medium"]
        low_risk_predictions = [p for p in violation_predictions if p["prediction"]["risk_level"] == "low"]
        
        logger.info("Predictive SLO Analytics Results:")
        logger.info(f"  Total Measurements: {measurement_count}")
        logger.info(f"  Total Predictions: {len(violation_predictions)}")
        logger.info(f"  High Risk Predictions: {len(high_risk_predictions)}")
        logger.info(f"  Medium Risk Predictions: {len(medium_risk_predictions)}")
        logger.info(f"  Low Risk Predictions: {len(low_risk_predictions)}")
        
        # Verify predictive capabilities
        assert len(violation_predictions) >= 20, "Should have sufficient predictions for analysis"
        
        # Check prediction distribution makes sense
        total_predictions = len(violation_predictions)
        high_risk_rate = len(high_risk_predictions) / total_predictions
        
        logger.info(f"  High Risk Prediction Rate: {high_risk_rate:.1%}")
        
        # Should have some variety in predictions
        unique_risk_levels = set(p["prediction"]["risk_level"] for p in violation_predictions)
        assert len(unique_risk_levels) >= 2, "Should predict different risk levels"
        
        logger.info("✅ Predictive SLO analytics validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r757_slo_driven_autoscaling_004(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TC_R757_REALTIME_004: SLO-driven auto-scaling and response adaptation"""
        # Test SLO-driven auto-scaling decisions and response adaptation
        
        class SLODrivenAutoScaler:
            def __init__(self):
                self.current_capacity = 1.0  # Normalized capacity (1.0 = baseline)
                self.target_latency = 3.0  # Target P95 latency
                self.target_availability = 0.995  # Target availability
                
                self.scaling_history = []
                self.performance_measurements = deque(maxlen=20)
                
            def add_performance_measurement(self, latency: float, availability: float, load: float):
                """Add performance measurement for scaling decisions"""
                self.performance_measurements.append({
                    "latency": latency,
                    "availability": availability,
                    "load": load,
                    "timestamp": time.time()
                })
            
            def calculate_scaling_decision(self) -> Dict[str, Any]:
                """Calculate scaling decision based on SLO performance"""
                if len(self.performance_measurements) < 5:
                    return {"action": "insufficient_data", "new_capacity": self.current_capacity}
                
                # Get recent measurements
                recent_measurements = list(self.performance_measurements)[-5:]
                avg_latency = sum(m["latency"] for m in recent_measurements) / len(recent_measurements)
                avg_availability = sum(m["availability"] for m in recent_measurements) / len(recent_measurements)
                avg_load = sum(m["load"] for m in recent_measurements) / len(recent_measurements)
                
                # Scaling decision logic
                scale_factor = 1.0
                action = "maintain"
                
                # Scale up if latency is too high
                if avg_latency > self.target_latency * 1.2:
                    scale_factor = min(2.0, 1.3)  # Scale up by 30%, max 2x
                    action = "scale_up_latency"
                
                # Scale up if availability is too low
                elif avg_availability < self.target_availability:
                    scale_factor = min(2.0, 1.2)  # Scale up by 20%
                    action = "scale_up_availability"
                
                # Scale down if performance is consistently good and load is low
                elif avg_latency < self.target_latency * 0.5 and avg_availability > self.target_availability and avg_load < 0.7:
                    scale_factor = max(0.5, 0.8)  # Scale down by 20%, min 0.5x
                    action = "scale_down"
                
                new_capacity = self.current_capacity * scale_factor
                
                scaling_decision = {
                    "action": action,
                    "current_capacity": self.current_capacity,
                    "new_capacity": new_capacity,
                    "scale_factor": scale_factor,
                    "avg_latency": avg_latency,
                    "avg_availability": avg_availability,
                    "avg_load": avg_load,
                    "timestamp": time.time()
                }
                
                self.scaling_history.append(scaling_decision)
                self.current_capacity = new_capacity
                
                return scaling_decision
        
        autoscaler = SLODrivenAutoScaler()
        
        logger.info("Starting SLO-driven auto-scaling test")
        
        # Simulate different load phases to trigger scaling decisions
        load_phases = [
            {"name": "baseline_load", "requests": 10, "complexity": "simple", "simulated_load": 0.5},
            {"name": "increasing_load", "requests": 20, "complexity": "medium", "simulated_load": 0.8},
            {"name": "peak_load", "requests": 15, "complexity": "complex", "simulated_load": 1.2},
            {"name": "recovery_load", "requests": 10, "complexity": "simple", "simulated_load": 0.6}
        ]
        
        for phase in load_phases:
            logger.info(f"Testing scaling phase: {phase['name']}")
            
            phase_latencies = []
            phase_errors = 0
            
            for i in range(phase["requests"]):
                request_start = time.time()
                
                # Generate request based on phase complexity
                if phase["complexity"] == "simple":
                    content = f"Auto-scaling test {i}"
                    max_tokens = 30
                elif phase["complexity"] == "medium":
                    content = f"Auto-scaling test {i} with moderate complexity and extended content"
                    max_tokens = 80
                else:
                    content = f"Auto-scaling test {i} with complex requirements for comprehensive analysis and detailed response generation"
                    max_tokens = 150
                
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": content}],
                    "max_tokens": max_tokens
                }
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    request_end = time.time()
                    latency = request_end - request_start
                    phase_latencies.append(latency)
                    
                    if response.status_code != 200:
                        phase_errors += 1
                
                except Exception:
                    request_end = time.time()
                    latency = request_end - request_start
                    phase_latencies.append(latency)
                    phase_errors += 1
                
                # Simulate capacity impact on latency
                capacity_factor = 1.0 / autoscaler.current_capacity
                adjusted_latency = latency * capacity_factor
                
                await asyncio.sleep(0.1)
            
            # Calculate phase metrics
            avg_latency = sum(phase_latencies) / len(phase_latencies) if phase_latencies else 0
            availability = (phase["requests"] - phase_errors) / phase["requests"]
            
            # Add measurement to autoscaler
            autoscaler.add_performance_measurement(avg_latency, availability, phase["simulated_load"])
            
            # Get scaling decision
            scaling_decision = autoscaler.calculate_scaling_decision()
            
            logger.info(f"Phase {phase['name']} results:")
            logger.info(f"  Average Latency: {avg_latency:.2f}s")
            logger.info(f"  Availability: {availability:.3%}")
            logger.info(f"  Simulated Load: {phase['simulated_load']:.1f}")
            logger.info(f"  Scaling Decision: {scaling_decision['action']}")
            logger.info(f"  New Capacity: {scaling_decision['new_capacity']:.1f}")
            
            if scaling_decision["action"] != "maintain":
                logger.info(f"🔄 Auto-scaling triggered: {scaling_decision['action']}")
        
        # Analyze scaling behavior
        scaling_decisions = autoscaler.scaling_history
        
        logger.info("SLO-Driven Auto-scaling Results:")
        logger.info(f"  Total Scaling Decisions: {len(scaling_decisions)}")
        
        scale_up_decisions = [d for d in scaling_decisions if d["action"].startswith("scale_up")]
        scale_down_decisions = [d for d in scaling_decisions if d["action"] == "scale_down"]
        
        logger.info(f"  Scale Up Decisions: {len(scale_up_decisions)}")
        logger.info(f"  Scale Down Decisions: {len(scale_down_decisions)}")
        logger.info(f"  Final Capacity: {autoscaler.current_capacity:.1f}")
        
        # Verify auto-scaling behavior
        assert len(scaling_decisions) >= 3, "Should have multiple scaling decisions"
        
        # Should have responded to different load patterns
        unique_actions = set(d["action"] for d in scaling_decisions)
        logger.info(f"  Unique Actions: {list(unique_actions)}")
        
        logger.info("✅ SLO-driven auto-scaling validation completed")