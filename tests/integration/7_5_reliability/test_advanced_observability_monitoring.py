# Section 7.5 - Advanced Observability and Distributed Monitoring
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Monitoring and Observability Reliability.md
# Addresses TC_R759_DISTRIBUTED_TRACING_001-008: Enhanced Monitoring Scenarios

import pytest
import httpx
import asyncio
import time
import json
import uuid
import threading
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from collections import deque, defaultdict
import statistics
import random

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class TraceSpan:
    """Distributed tracing span"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: float
    end_time: Optional[float] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "pending"  # pending, success, error
    
    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    def finish(self, status: str = "success"):
        """Finish the span"""
        self.end_time = time.time()
        self.status = status
    
    def add_tag(self, key: str, value: Any):
        """Add a tag to the span"""
        self.tags[key] = value
    
    def add_log(self, message: str, level: str = "info", **kwargs):
        """Add a log entry to the span"""
        self.logs.append({
            "timestamp": time.time(),
            "level": level,
            "message": message,
            **kwargs
        })


@dataclass
class DistributedTrace:
    """Complete distributed trace"""
    trace_id: str
    spans: List[TraceSpan] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    
    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    @property
    def span_count(self) -> int:
        return len(self.spans)
    
    @property
    def error_count(self) -> int:
        return sum(1 for span in self.spans if span.status == "error")
    
    def add_span(self, span: TraceSpan):
        """Add a span to the trace"""
        self.spans.append(span)
    
    def get_root_spans(self) -> List[TraceSpan]:
        """Get root spans (no parent)"""
        return [span for span in self.spans if span.parent_span_id is None]
    
    def get_critical_path(self) -> List[TraceSpan]:
        """Get the critical path through the trace"""
        if not self.spans:
            return []
        
        # Simple critical path: longest duration chain
        root_spans = self.get_root_spans()
        if not root_spans:
            return []
        
        longest_path = []
        max_duration = 0
        
        for root in root_spans:
            path = self._get_span_chain(root)
            path_duration = sum(span.duration for span in path)
            
            if path_duration > max_duration:
                max_duration = path_duration
                longest_path = path
        
        return longest_path
    
    def _get_span_chain(self, span: TraceSpan) -> List[TraceSpan]:
        """Get chain of spans starting from given span"""
        chain = [span]
        
        # Find child spans
        children = [s for s in self.spans if s.parent_span_id == span.span_id]
        if children:
            # Take the longest child chain
            longest_child_chain = []
            for child in children:
                child_chain = self._get_span_chain(child)
                if len(child_chain) > len(longest_child_chain):
                    longest_child_chain = child_chain
            chain.extend(longest_child_chain)
        
        return chain


class DistributedTracingSystem:
    """Distributed tracing system for observability testing"""
    
    def __init__(self):
        self.active_traces: Dict[str, DistributedTrace] = {}
        self.completed_traces: Dict[str, DistributedTrace] = {}
        self.active_spans: Dict[str, TraceSpan] = {}
        
        # Sampling configuration
        self.sample_rate = 1.0  # 100% sampling for testing
        self.max_trace_duration = 300  # 5 minutes max trace duration
        
        # Metrics collection
        self.trace_metrics = {
            "total_traces": 0,
            "completed_traces": 0,
            "error_traces": 0,
            "avg_trace_duration": 0.0,
            "avg_spans_per_trace": 0.0
        }
    
    def start_trace(self, operation_name: str) -> str:
        """Start a new distributed trace"""
        trace_id = str(uuid.uuid4())
        
        trace = DistributedTrace(trace_id=trace_id)
        self.active_traces[trace_id] = trace
        self.trace_metrics["total_traces"] += 1
        
        # Create root span
        root_span = self.start_span(trace_id, operation_name)
        
        return trace_id
    
    def start_span(self, trace_id: str, operation_name: str, 
                   parent_span_id: Optional[str] = None) -> str:
        """Start a new span within a trace"""
        span_id = str(uuid.uuid4())
        
        span = TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=time.time()
        )
        
        self.active_spans[span_id] = span
        
        if trace_id in self.active_traces:
            self.active_traces[trace_id].add_span(span)
        
        return span_id
    
    def finish_span(self, span_id: str, status: str = "success", **tags):
        """Finish a span"""
        if span_id in self.active_spans:
            span = self.active_spans[span_id]
            span.finish(status)
            
            # Add tags
            for key, value in tags.items():
                span.add_tag(key, value)
            
            del self.active_spans[span_id]
    
    def finish_trace(self, trace_id: str):
        """Finish a trace"""
        if trace_id in self.active_traces:
            trace = self.active_traces[trace_id]
            trace.end_time = time.time()
            
            # Move to completed traces
            self.completed_traces[trace_id] = trace
            del self.active_traces[trace_id]
            
            # Update metrics
            self.trace_metrics["completed_traces"] += 1
            
            if trace.error_count > 0:
                self.trace_metrics["error_traces"] += 1
            
            # Update averages
            completed_traces = list(self.completed_traces.values())
            if completed_traces:
                total_duration = sum(t.duration for t in completed_traces)
                total_spans = sum(t.span_count for t in completed_traces)
                
                self.trace_metrics["avg_trace_duration"] = total_duration / len(completed_traces)
                self.trace_metrics["avg_spans_per_trace"] = total_spans / len(completed_traces)
    
    def get_trace_analytics(self) -> Dict[str, Any]:
        """Get trace analytics and insights"""
        completed_traces = list(self.completed_traces.values())
        
        if not completed_traces:
            return {"error": "no_completed_traces"}
        
        # Duration analytics
        durations = [t.duration for t in completed_traces]
        span_counts = [t.span_count for t in completed_traces]
        error_counts = [t.error_count for t in completed_traces]
        
        analytics = {
            "trace_count": len(completed_traces),
            "duration_stats": {
                "min": min(durations),
                "max": max(durations),
                "mean": statistics.mean(durations),
                "median": statistics.median(durations),
                "p95": statistics.quantiles(durations, n=20)[18] if len(durations) > 10 else max(durations)
            },
            "span_stats": {
                "min": min(span_counts),
                "max": max(span_counts),
                "mean": statistics.mean(span_counts),
                "total": sum(span_counts)
            },
            "error_stats": {
                "total_errors": sum(error_counts),
                "error_rate": sum(1 for t in completed_traces if t.error_count > 0) / len(completed_traces),
                "avg_errors_per_trace": statistics.mean(error_counts)
            }
        }
        
        return analytics
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect anomalies in trace data"""
        completed_traces = list(self.completed_traces.values())
        anomalies = []
        
        if len(completed_traces) < 10:
            return anomalies
        
        durations = [t.duration for t in completed_traces]
        mean_duration = statistics.mean(durations)
        stdev_duration = statistics.stdev(durations) if len(durations) > 1 else 0
        
        # Detect duration anomalies (> 2 standard deviations)
        duration_threshold = mean_duration + (2 * stdev_duration)
        
        for trace in completed_traces:
            if trace.duration > duration_threshold:
                anomalies.append({
                    "type": "high_duration",
                    "trace_id": trace.trace_id,
                    "value": trace.duration,
                    "threshold": duration_threshold,
                    "severity": "medium"
                })
            
            # Detect high error rates
            if trace.error_count > 0:
                error_rate = trace.error_count / max(1, trace.span_count)
                if error_rate > 0.2:  # > 20% error rate
                    anomalies.append({
                        "type": "high_error_rate",
                        "trace_id": trace.trace_id,
                        "value": error_rate,
                        "threshold": 0.2,
                        "severity": "high"
                    })
        
        return anomalies


@dataclass
class ObservabilityAlert:
    """Observability alert"""
    alert_id: str
    alert_type: str
    severity: str  # low, medium, high, critical
    title: str
    description: str
    timestamp: float
    source_component: str
    metrics: Dict[str, Any]
    resolved: bool = False
    resolution_time: Optional[float] = None


class IntelligentAlertingSystem:
    """Intelligent alerting system with adaptive thresholds"""
    
    def __init__(self):
        self.alerts: List[ObservabilityAlert] = []
        self.alert_rules: Dict[str, Dict[str, Any]] = {}
        self.metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Setup default alert rules
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Setup default alerting rules"""
        self.alert_rules = {
            "high_latency": {
                "threshold": 5.0,
                "window_size": 10,
                "severity": "medium",
                "adaptive": True
            },
            "low_success_rate": {
                "threshold": 0.95,
                "window_size": 20,
                "severity": "high",
                "adaptive": True
            },
            "high_error_rate": {
                "threshold": 0.05,
                "window_size": 15,
                "severity": "high",
                "adaptive": False
            },
            "anomalous_behavior": {
                "threshold": 2.0,  # Standard deviations
                "window_size": 30,
                "severity": "medium",
                "adaptive": True
            }
        }
    
    def add_metric(self, metric_name: str, value: float, timestamp: Optional[float] = None):
        """Add a metric measurement"""
        if timestamp is None:
            timestamp = time.time()
        
        self.metric_history[metric_name].append({
            "value": value,
            "timestamp": timestamp
        })
        
        # Check for alerts
        self._check_alert_conditions(metric_name, value)
    
    def _check_alert_conditions(self, metric_name: str, current_value: float):
        """Check if current metric triggers any alerts"""
        
        # Check latency alerts
        if "latency" in metric_name.lower():
            self._check_latency_alerts(metric_name, current_value)
        
        # Check success rate alerts
        elif "success" in metric_name.lower():
            self._check_success_rate_alerts(metric_name, current_value)
        
        # Check error rate alerts
        elif "error" in metric_name.lower():
            self._check_error_rate_alerts(metric_name, current_value)
        
        # Check for anomalous behavior
        self._check_anomaly_alerts(metric_name, current_value)
    
    def _check_latency_alerts(self, metric_name: str, latency: float):
        """Check for high latency alerts"""
        rule = self.alert_rules["high_latency"]
        
        # Get adaptive threshold if enabled
        threshold = self._get_adaptive_threshold("high_latency", metric_name) if rule["adaptive"] else rule["threshold"]
        
        if latency > threshold:
            self._create_alert(
                alert_type="high_latency",
                severity=rule["severity"],
                title=f"High Latency Detected",
                description=f"Latency {latency:.2f}s exceeds threshold {threshold:.2f}s",
                source_component=metric_name,
                metrics={"latency": latency, "threshold": threshold}
            )
    
    def _check_success_rate_alerts(self, metric_name: str, success_rate: float):
        """Check for low success rate alerts"""
        rule = self.alert_rules["low_success_rate"]
        
        threshold = self._get_adaptive_threshold("low_success_rate", metric_name) if rule["adaptive"] else rule["threshold"]
        
        if success_rate < threshold:
            self._create_alert(
                alert_type="low_success_rate",
                severity=rule["severity"],
                title=f"Low Success Rate Detected",
                description=f"Success rate {success_rate:.1%} below threshold {threshold:.1%}",
                source_component=metric_name,
                metrics={"success_rate": success_rate, "threshold": threshold}
            )
    
    def _check_error_rate_alerts(self, metric_name: str, error_rate: float):
        """Check for high error rate alerts"""
        rule = self.alert_rules["high_error_rate"]
        
        if error_rate > rule["threshold"]:
            self._create_alert(
                alert_type="high_error_rate",
                severity=rule["severity"],
                title=f"High Error Rate Detected",
                description=f"Error rate {error_rate:.1%} exceeds threshold {rule['threshold']:.1%}",
                source_component=metric_name,
                metrics={"error_rate": error_rate, "threshold": rule["threshold"]}
            )
    
    def _check_anomaly_alerts(self, metric_name: str, current_value: float):
        """Check for anomalous behavior alerts"""
        history = self.metric_history[metric_name]
        
        if len(history) < 10:
            return
        
        # Calculate statistical anomaly
        values = [m["value"] for m in history]
        mean_value = statistics.mean(values)
        stdev_value = statistics.stdev(values) if len(values) > 1 else 0
        
        if stdev_value > 0:
            z_score = abs(current_value - mean_value) / stdev_value
            threshold = self.alert_rules["anomalous_behavior"]["threshold"]
            
            if z_score > threshold:
                self._create_alert(
                    alert_type="anomalous_behavior",
                    severity=self.alert_rules["anomalous_behavior"]["severity"],
                    title=f"Anomalous Behavior Detected",
                    description=f"Value {current_value:.2f} is {z_score:.1f} standard deviations from mean",
                    source_component=metric_name,
                    metrics={"value": current_value, "z_score": z_score, "mean": mean_value, "stdev": stdev_value}
                )
    
    def _get_adaptive_threshold(self, rule_name: str, metric_name: str) -> float:
        """Get adaptive threshold based on historical data"""
        base_threshold = self.alert_rules[rule_name]["threshold"]
        history = self.metric_history[metric_name]
        
        if len(history) < 20:
            return base_threshold
        
        # Calculate adaptive threshold based on recent performance
        recent_values = [m["value"] for m in list(history)[-20:]]
        mean_recent = statistics.mean(recent_values)
        
        # Adjust threshold based on recent performance
        if rule_name == "high_latency":
            # For latency: adaptive threshold is mean + 50%
            return max(base_threshold, mean_recent * 1.5)
        elif rule_name == "low_success_rate":
            # For success rate: adaptive threshold is mean - 10%
            return min(base_threshold, mean_recent * 0.9)
        
        return base_threshold
    
    def _create_alert(self, alert_type: str, severity: str, title: str, 
                     description: str, source_component: str, metrics: Dict[str, Any]):
        """Create a new alert"""
        alert = ObservabilityAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            timestamp=time.time(),
            source_component=source_component,
            metrics=metrics
        )
        
        self.alerts.append(alert)
        logger.warning(f"🚨 ALERT: {title} - {description}")
    
    def get_active_alerts(self) -> List[ObservabilityAlert]:
        """Get all active (unresolved) alerts"""
        return [alert for alert in self.alerts if not alert.resolved]
    
    def resolve_alert(self, alert_id: str):
        """Resolve an alert"""
        for alert in self.alerts:
            if alert.alert_id == alert_id and not alert.resolved:
                alert.resolved = True
                alert.resolution_time = time.time()
                logger.info(f"✅ Alert resolved: {alert.title}")
                break
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of alerting activity"""
        active_alerts = self.get_active_alerts()
        resolved_alerts = [a for a in self.alerts if a.resolved]
        
        # Count by severity
        severity_counts = defaultdict(int)
        for alert in active_alerts:
            severity_counts[alert.severity] += 1
        
        # Count by type
        type_counts = defaultdict(int)
        for alert in self.alerts:
            type_counts[alert.alert_type] += 1
        
        return {
            "total_alerts": len(self.alerts),
            "active_alerts": len(active_alerts),
            "resolved_alerts": len(resolved_alerts),
            "severity_breakdown": dict(severity_counts),
            "type_breakdown": dict(type_counts),
            "resolution_rate": len(resolved_alerts) / max(1, len(self.alerts))
        }


class TestAdvancedObservabilityMonitoring:
    """Advanced observability and distributed monitoring tests"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r759_distributed_tracing_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TC_R759_DISTRIBUTED_TRACING_001: Distributed tracing and correlation reliability"""
        # Test distributed tracing across API requests and system components
        
        tracing_system = DistributedTracingSystem()
        
        logger.info("🔍 Starting distributed tracing reliability test")
        
        # Create multiple traced operations to test correlation
        tracing_scenarios = [
            {
                "operation": "simple_chat_completion",
                "requests": [
                    {"content": "Simple tracing test", "max_tokens": 30}
                ]
            },
            {
                "operation": "multi_step_conversation",
                "requests": [
                    {"content": "Start conversation for tracing", "max_tokens": 40},
                    {"content": "Continue conversation", "max_tokens": 40},
                    {"content": "End conversation", "max_tokens": 40}
                ]
            },
            {
                "operation": "complex_analysis_request",
                "requests": [
                    {"content": "Complex analysis for distributed tracing test: " + "analyze " * 100, "max_tokens": 200}
                ]
            }
        ]
        
        for scenario in tracing_scenarios:
            # Start trace for this scenario
            trace_id = tracing_system.start_trace(scenario["operation"])
            
            logger.info(f"🔗 Starting trace {trace_id} for {scenario['operation']}")
            
            # Get root span
            root_spans = [span for span in tracing_system.active_spans.values() 
                         if span.trace_id == trace_id and span.parent_span_id is None]
            root_span_id = root_spans[0].span_id if root_spans else None
            
            # Execute requests within the trace
            for i, req_config in enumerate(scenario["requests"]):
                # Start span for this request
                request_span_id = tracing_system.start_span(
                    trace_id, f"api_request_{i+1}", root_span_id
                )
                
                # Add request metadata to span
                if request_span_id in tracing_system.active_spans:
                    span = tracing_system.active_spans[request_span_id]
                    span.add_tag("request_type", "chat_completion")
                    span.add_tag("max_tokens", req_config["max_tokens"])
                    span.add_tag("content_length", len(req_config["content"]))
                
                request_start = time.time()
                
                try:
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": req_config["content"]}],
                        "max_tokens": req_config["max_tokens"]
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    request_end = time.time()
                    
                    # Add response metadata to span
                    if request_span_id in tracing_system.active_spans:
                        span = tracing_system.active_spans[request_span_id]
                        span.add_tag("response_status", response.status_code)
                        span.add_tag("response_time", request_end - request_start)
                        
                        if response.status_code == 200:
                            response_data = response.json()
                            span.add_tag("response_tokens", len(str(response_data)))
                            span.add_log("Request completed successfully")
                        else:
                            span.add_log("Request failed", level="error", status_code=response.status_code)
                    
                    # Finish span
                    status = "success" if response.status_code == 200 else "error"
                    tracing_system.finish_span(request_span_id, status,
                                             response_status=response.status_code,
                                             latency=request_end - request_start)
                
                except Exception as e:
                    request_end = time.time()
                    
                    # Add error information to span
                    if request_span_id in tracing_system.active_spans:
                        span = tracing_system.active_spans[request_span_id]
                        span.add_log("Request exception", level="error", error=str(e))
                    
                    tracing_system.finish_span(request_span_id, "error",
                                             error=str(e),
                                             latency=request_end - request_start)
                
                await asyncio.sleep(0.3)
            
            # Finish the trace
            tracing_system.finish_trace(trace_id)
            
            logger.info(f"✅ Completed trace {trace_id}")
        
        # Analyze distributed tracing results
        analytics = tracing_system.get_trace_analytics()
        anomalies = tracing_system.detect_anomalies()
        
        logger.info("Distributed Tracing Reliability Results:")
        logger.info(f"  Completed Traces: {analytics['trace_count']}")
        logger.info(f"  Average Duration: {analytics['duration_stats']['mean']:.2f}s")
        logger.info(f"  Average Spans per Trace: {analytics['span_stats']['mean']:.1f}")
        logger.info(f"  Error Rate: {analytics['error_stats']['error_rate']:.1%}")
        logger.info(f"  Detected Anomalies: {len(anomalies)}")
        
        # Verify tracing reliability
        assert analytics["trace_count"] >= len(tracing_scenarios), \
            "Should have completed all traced scenarios"
        
        assert analytics["span_stats"]["total"] >= analytics["trace_count"], \
            "Should have at least one span per trace"
        
        assert analytics["error_stats"]["error_rate"] <= 0.5, \
            f"Error rate should be reasonable: {analytics['error_stats']['error_rate']:.1%}"
        
        # Verify trace correlation
        completed_traces = list(tracing_system.completed_traces.values())
        for trace in completed_traces:
            # Each trace should have proper span relationships
            root_spans = trace.get_root_spans()
            assert len(root_spans) >= 1, f"Trace {trace.trace_id} should have root span"
            
            # Verify span timing relationships
            for span in trace.spans:
                if span.parent_span_id:
                    parent_span = next((s for s in trace.spans if s.span_id == span.parent_span_id), None)
                    if parent_span:
                        assert span.start_time >= parent_span.start_time, \
                            "Child span should start after parent span"
        
        logger.info("✅ Distributed tracing reliability validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r759_intelligent_alerting_002(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """TC_R759_DISTRIBUTED_TRACING_002: Intelligent alerting and escalation management"""
        # Test intelligent alerting system with adaptive thresholds
        
        alerting_system = IntelligentAlertingSystem()
        
        logger.info("🚨 Starting intelligent alerting system test")
        
        # Phase 1: Generate baseline metrics to establish adaptive thresholds
        logger.info("📊 Establishing baseline metrics for adaptive thresholds")
        
        baseline_duration = 30  # 30 seconds of baseline
        baseline_start = time.time()
        
        while time.time() - baseline_start < baseline_duration:
            start_time = time.time()
            
            try:
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Baseline alerting test"}],
                    "max_tokens": 40
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                end_time = time.time()
                latency = end_time - start_time
                success = response.status_code == 200
                
                # Add metrics to alerting system
                alerting_system.add_metric("api_latency", latency)
                alerting_system.add_metric("api_success_rate", 1.0 if success else 0.0)
                alerting_system.add_metric("api_error_rate", 0.0 if success else 1.0)
            
            except Exception:
                end_time = time.time()
                latency = end_time - start_time
                
                alerting_system.add_metric("api_latency", latency)
                alerting_system.add_metric("api_success_rate", 0.0)
                alerting_system.add_metric("api_error_rate", 1.0)
            
            await asyncio.sleep(1.0)
        
        baseline_alerts = len(alerting_system.get_active_alerts())
        logger.info(f"Baseline period generated {baseline_alerts} alerts")
        
        # Phase 2: Inject anomalies to trigger intelligent alerts
        logger.info("💥 Injecting anomalies to trigger intelligent alerts")
        
        anomaly_scenarios = [
            {
                "type": "high_latency",
                "description": "Inject high latency requests",
                "duration": 15,
                "injection_rate": 0.7
            },
            {
                "type": "high_error_rate", 
                "description": "Inject error responses",
                "duration": 10,
                "injection_rate": 0.4
            },
            {
                "type": "anomalous_patterns",
                "description": "Inject unusual request patterns",
                "duration": 20,
                "injection_rate": 0.5
            }
        ]
        
        for scenario in anomaly_scenarios:
            logger.info(f"🔥 Starting anomaly injection: {scenario['description']}")
            
            scenario_start = time.time()
            
            while time.time() - scenario_start < scenario["duration"]:
                inject_anomaly = random.random() < scenario["injection_rate"]
                start_time = time.time()
                
                try:
                    if inject_anomaly:
                        if scenario["type"] == "high_latency":
                            # Inject high latency with large request
                            request = {
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": "High latency test: " + "data " * 500}],
                                "max_tokens": 200
                            }
                        
                        elif scenario["type"] == "high_error_rate":
                            # Inject errors with invalid model
                            request = {
                                "model": "intelligent_alerting_invalid_model",
                                "messages": [{"role": "user", "content": "Error injection test"}],
                                "max_tokens": 50
                            }
                        
                        else:  # anomalous_patterns
                            # Inject unusual patterns
                            content = "Anomaly test: " + "pattern " * random.randint(50, 200)
                            request = {
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": content}],
                                "max_tokens": random.randint(100, 300)
                            }
                    
                    else:
                        # Normal request
                        request = {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Normal alerting test"}],
                            "max_tokens": 40
                        }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, 
                        track_cost=(scenario["type"] != "high_error_rate")
                    )
                    
                    end_time = time.time()
                    latency = end_time - start_time
                    success = response.status_code == 200
                
                except Exception:
                    end_time = time.time()
                    latency = end_time - start_time
                    success = False
                
                # Add metrics
                alerting_system.add_metric("api_latency", latency)
                alerting_system.add_metric("api_success_rate", 1.0 if success else 0.0)
                alerting_system.add_metric("api_error_rate", 0.0 if success else 1.0)
                
                await asyncio.sleep(0.5)
            
            current_alerts = alerting_system.get_active_alerts()
            logger.info(f"After {scenario['type']}: {len(current_alerts)} active alerts")
        
        # Phase 3: Recovery period and alert resolution
        logger.info("🔄 Recovery period - testing alert resolution")
        
        recovery_duration = 20
        recovery_start = time.time()
        
        while time.time() - recovery_start < recovery_duration:
            start_time = time.time()
            
            try:
                # Normal requests during recovery
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Recovery test"}],
                    "max_tokens": 30
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                end_time = time.time()
                latency = end_time - start_time
                success = response.status_code == 200
                
                # Add recovery metrics
                alerting_system.add_metric("api_latency", latency)
                alerting_system.add_metric("api_success_rate", 1.0 if success else 0.0)
                alerting_system.add_metric("api_error_rate", 0.0 if success else 1.0)
            
            except Exception:
                end_time = time.time()
                latency = end_time - start_time
                
                alerting_system.add_metric("api_latency", latency)
                alerting_system.add_metric("api_success_rate", 0.0)
                alerting_system.add_metric("api_error_rate", 1.0)
            
            await asyncio.sleep(1.0)
        
        # Simulate alert resolution
        active_alerts = alerting_system.get_active_alerts()
        for alert in active_alerts[:len(active_alerts)//2]:  # Resolve half the alerts
            alerting_system.resolve_alert(alert.alert_id)
        
        # Analyze intelligent alerting results
        alert_summary = alerting_system.get_alert_summary()
        
        logger.info("Intelligent Alerting System Results:")
        logger.info(f"  Total Alerts Generated: {alert_summary['total_alerts']}")
        logger.info(f"  Active Alerts: {alert_summary['active_alerts']}")
        logger.info(f"  Resolved Alerts: {alert_summary['resolved_alerts']}")
        logger.info(f"  Resolution Rate: {alert_summary['resolution_rate']:.1%}")
        logger.info(f"  Severity Breakdown: {alert_summary['severity_breakdown']}")
        logger.info(f"  Type Breakdown: {alert_summary['type_breakdown']}")
        
        # Verify intelligent alerting
        assert alert_summary["total_alerts"] > baseline_alerts, \
            "Should have generated alerts during anomaly injection"
        
        assert alert_summary["resolution_rate"] >= 0.3, \
            f"Should have resolved some alerts: {alert_summary['resolution_rate']:.1%}"
        
        # Should have detected different types of anomalies
        assert len(alert_summary["type_breakdown"]) >= 2, \
            "Should have detected multiple types of anomalies"
        
        # Should have alerts of different severities
        assert len(alert_summary["severity_breakdown"]) >= 2, \
            "Should have generated alerts of different severities"
        
        logger.info("✅ Intelligent alerting system validation completed")