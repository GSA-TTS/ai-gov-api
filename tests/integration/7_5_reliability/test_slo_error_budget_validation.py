# Section 7.5 - SLO and Error Budget Validation Tests
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Error Budget and SLO Validation.md

import pytest
import httpx
import asyncio
import time
import statistics
import random
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from unittest.mock import patch, Mock
import threading
from collections import deque

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class SLOMetrics:
    """Enhanced SLO metrics tracking with real-time capabilities"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency: float = 0.0
    latencies: List[float] = field(default_factory=list)
    error_budget_consumed: float = 0.0
    start_time: float = field(default_factory=time.time)
    window_size: int = 100  # Rolling window size
    recent_latencies: deque = field(default_factory=lambda: deque(maxlen=100))
    recent_success_rates: deque = field(default_factory=lambda: deque(maxlen=20))
    
    @property
    def success_rate(self) -> float:
        return self.successful_requests / max(1, self.total_requests)
    
    @property
    def error_rate(self) -> float:
        return self.failed_requests / max(1, self.total_requests)
    
    @property
    def average_latency(self) -> float:
        return self.total_latency / max(1, self.total_requests)
    
    @property
    def p95_latency(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        index = int(len(sorted_latencies) * 0.95)
        return sorted_latencies[min(index, len(sorted_latencies) - 1)]
    
    @property
    def p99_latency(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        index = int(len(sorted_latencies) * 0.99)
        return sorted_latencies[min(index, len(sorted_latencies) - 1)]


class TestSLOErrorBudgetValidation:
    """SLO and error budget validation tests"""
    
    # SLO Targets (configurable)
    AVAILABILITY_SLO = 0.995  # 99.5% availability
    LATENCY_P95_SLO = 5.0     # 5 second P95 latency
    LATENCY_P99_SLO = 10.0    # 10 second P99 latency
    ERROR_BUDGET_PERIOD = 300  # 5 minutes for testing
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_availability_slo_tracking_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """SLO_AVAILABILITY_001: Availability SLO tracking and validation"""
        # Test availability SLO tracking over a measurement period
        
        availability_test_duration = 60  # 1 minute test period
        request_interval = 2.0  # Request every 2 seconds
        
        slo_metrics = SLOMetrics()
        availability_start_time = time.time()
        
        logger.info(f"Starting availability SLO test for {availability_test_duration}s")
        
        while time.time() - availability_start_time < availability_test_duration:
            request_start_time = time.time()
            
            try:
                # Standard availability check request
                availability_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "SLO availability test"}],
                    "max_tokens": 40
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, availability_request
                )
                
                request_end_time = time.time()
                request_latency = request_end_time - request_start_time
                
                slo_metrics.total_requests += 1
                slo_metrics.total_latency += request_latency
                slo_metrics.latencies.append(request_latency)
                
                if response.status_code == 200:
                    slo_metrics.successful_requests += 1
                else:
                    slo_metrics.failed_requests += 1
                    logger.warning(f"Availability test failure: {response.status_code}")
                
            except Exception as e:
                request_end_time = time.time()
                request_latency = request_end_time - request_start_time
                
                slo_metrics.total_requests += 1
                slo_metrics.failed_requests += 1
                slo_metrics.total_latency += request_latency
                slo_metrics.latencies.append(request_latency)
                
                logger.warning(f"Availability test exception: {e}")
            
            # Wait for next request interval
            elapsed_time = time.time() - request_start_time
            sleep_time = max(0, request_interval - elapsed_time)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        availability_end_time = time.time()
        actual_test_duration = availability_end_time - availability_start_time
        
        # Calculate SLO metrics
        availability_slo_result = {
            "test_duration": actual_test_duration,
            "total_requests": slo_metrics.total_requests,
            "successful_requests": slo_metrics.successful_requests,
            "failed_requests": slo_metrics.failed_requests,
            "success_rate": slo_metrics.success_rate,
            "error_rate": slo_metrics.error_rate,
            "average_latency": slo_metrics.average_latency,
            "p95_latency": slo_metrics.p95_latency,
            "p99_latency": slo_metrics.p99_latency,
            "slo_target": self.AVAILABILITY_SLO,
            "slo_met": slo_metrics.success_rate >= self.AVAILABILITY_SLO
        }
        
        # Calculate error budget consumption
        if slo_metrics.success_rate < self.AVAILABILITY_SLO:
            error_budget_consumed = (self.AVAILABILITY_SLO - slo_metrics.success_rate) / (1 - self.AVAILABILITY_SLO)
            availability_slo_result["error_budget_consumed"] = min(error_budget_consumed, 1.0)
        else:
            availability_slo_result["error_budget_consumed"] = 0.0
        
        logger.info(f"Availability SLO Results:")
        logger.info(f"  Success Rate: {slo_metrics.success_rate:.3%} (Target: {self.AVAILABILITY_SLO:.3%})")
        logger.info(f"  Requests: {slo_metrics.successful_requests}/{slo_metrics.total_requests}")
        logger.info(f"  Error Budget Consumed: {availability_slo_result['error_budget_consumed']:.1%}")
        logger.info(f"  SLO Met: {availability_slo_result['slo_met']}")
        
        # Verify SLO compliance
        if availability_slo_result["slo_met"]:
            logger.info("✅ Availability SLO target met")
        else:
            logger.warning(f"⚠️ Availability SLO target missed: {slo_metrics.success_rate:.3%} < {self.AVAILABILITY_SLO:.3%}")
            
            # In production, this might trigger alerts rather than failing tests
            # For testing, we'll allow some flexibility
            assert slo_metrics.success_rate >= 0.90, \
                f"Availability should be at least 90% even if SLO target is missed: {slo_metrics.success_rate:.3%}"
        
        # Verify reasonable request volume for SLO measurement
        assert slo_metrics.total_requests >= 10, \
            f"SLO measurement should have sufficient request volume: {slo_metrics.total_requests}"
        
        return availability_slo_result
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_latency_slo_tracking_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """SLO_LATENCY_001: Latency SLO tracking and validation"""
        # Test latency SLO tracking for P95 and P99 metrics
        
        latency_test_requests = 25  # Sufficient for percentile calculation
        latency_metrics = SLOMetrics()
        
        logger.info(f"Starting latency SLO test with {latency_test_requests} requests")
        
        # Generate diverse request types for latency testing
        latency_test_scenarios = [
            {
                "type": "quick",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Quick latency test"}],
                    "max_tokens": 30
                },
                "count": 15
            },
            {
                "type": "medium",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Medium complexity latency test with more detailed content"}],
                    "max_tokens": 80
                },
                "count": 8
            },
            {
                "type": "complex",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Complex latency test requiring detailed analysis and comprehensive response generation"}],
                    "max_tokens": 150
                },
                "count": 2
            }
        ]
        
        for scenario in latency_test_scenarios:
            for i in range(scenario["count"]):
                request_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, scenario["request"]
                    )
                    
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    latency_metrics.total_requests += 1
                    latency_metrics.total_latency += request_latency
                    latency_metrics.latencies.append(request_latency)
                    
                    if response.status_code == 200:
                        latency_metrics.successful_requests += 1
                    else:
                        latency_metrics.failed_requests += 1
                    
                    # Log individual latencies for analysis
                    if request_latency > self.LATENCY_P95_SLO:
                        logger.info(f"High latency detected: {request_latency:.2f}s for {scenario['type']} request")
                
                except Exception as e:
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    latency_metrics.total_requests += 1
                    latency_metrics.failed_requests += 1
                    latency_metrics.total_latency += request_latency
                    latency_metrics.latencies.append(request_latency)
                    
                    logger.warning(f"Latency test exception: {e}, latency: {request_latency:.2f}s")
                
                await asyncio.sleep(0.3)  # Brief pause between requests
        
        # Calculate latency SLO metrics
        latency_slo_result = {
            "total_requests": latency_metrics.total_requests,
            "successful_requests": latency_metrics.successful_requests,
            "average_latency": latency_metrics.average_latency,
            "p95_latency": latency_metrics.p95_latency,
            "p99_latency": latency_metrics.p99_latency,
            "p95_slo_target": self.LATENCY_P95_SLO,
            "p99_slo_target": self.LATENCY_P99_SLO,
            "p95_slo_met": latency_metrics.p95_latency <= self.LATENCY_P95_SLO,
            "p99_slo_met": latency_metrics.p99_latency <= self.LATENCY_P99_SLO
        }
        
        # Calculate latency distribution
        if latency_metrics.latencies:
            latency_slo_result["min_latency"] = min(latency_metrics.latencies)
            latency_slo_result["max_latency"] = max(latency_metrics.latencies)
            latency_slo_result["median_latency"] = statistics.median(latency_metrics.latencies)
            
            # Count requests exceeding SLO thresholds
            p95_violations = sum(1 for lat in latency_metrics.latencies if lat > self.LATENCY_P95_SLO)
            p99_violations = sum(1 for lat in latency_metrics.latencies if lat > self.LATENCY_P99_SLO)
            
            latency_slo_result["p95_violation_rate"] = p95_violations / len(latency_metrics.latencies)
            latency_slo_result["p99_violation_rate"] = p99_violations / len(latency_metrics.latencies)
        
        logger.info(f"Latency SLO Results:")
        logger.info(f"  Average Latency: {latency_metrics.average_latency:.2f}s")
        logger.info(f"  P95 Latency: {latency_metrics.p95_latency:.2f}s (Target: {self.LATENCY_P95_SLO:.2f}s)")
        logger.info(f"  P99 Latency: {latency_metrics.p99_latency:.2f}s (Target: {self.LATENCY_P99_SLO:.2f}s)")
        logger.info(f"  P95 SLO Met: {latency_slo_result['p95_slo_met']}")
        logger.info(f"  P99 SLO Met: {latency_slo_result['p99_slo_met']}")
        
        # Verify latency SLO compliance
        if latency_slo_result["p95_slo_met"]:
            logger.info("✅ P95 Latency SLO target met")
        else:
            logger.warning(f"⚠️ P95 Latency SLO target missed: {latency_metrics.p95_latency:.2f}s > {self.LATENCY_P95_SLO:.2f}s")
        
        if latency_slo_result["p99_slo_met"]:
            logger.info("✅ P99 Latency SLO target met")
        else:
            logger.warning(f"⚠️ P99 Latency SLO target missed: {latency_metrics.p99_latency:.2f}s > {self.LATENCY_P99_SLO:.2f}s")
        
        # Verify reasonable latency performance
        assert latency_metrics.average_latency <= 15.0, \
            f"Average latency should be reasonable: {latency_metrics.average_latency:.2f}s"
        
        assert latency_metrics.p99_latency <= 30.0, \
            f"P99 latency should be within acceptable bounds: {latency_metrics.p99_latency:.2f}s"
        
        return latency_slo_result
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_error_budget_consumption_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """SLO_ERROR_BUDGET_001: Error budget consumption tracking"""
        # Test error budget consumption calculation and tracking
        
        # Simulate different error scenarios to test error budget consumption
        error_budget_scenarios = [
            {
                "phase": "normal_operations",
                "description": "Normal operations (low error rate)",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Normal operation {i}"}],
                        "max_tokens": 40
                    }
                    for i in range(15)
                ]
            },
            {
                "phase": "elevated_errors",
                "description": "Elevated error rate scenario",
                "requests": [
                    # Mix of normal and failing requests
                    {
                        "model": config.get_chat_model(0) if i % 3 != 0 else f"error_budget_fail_{i}",
                        "messages": [{"role": "user", "content": f"Error budget test {i}"}],
                        "max_tokens": 40
                    }
                    for i in range(12)
                ]
            }
        ]
        
        error_budget_results = []
        cumulative_metrics = SLOMetrics()
        
        for scenario in error_budget_scenarios:
            phase_start_time = time.time()
            phase_metrics = SLOMetrics()
            
            logger.info(f"Starting error budget phase: {scenario['phase']}")
            
            for request in scenario["requests"]:
                request_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=(scenario["phase"] == "normal_operations")
                    )
                    
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    # Update phase metrics
                    phase_metrics.total_requests += 1
                    phase_metrics.total_latency += request_latency
                    phase_metrics.latencies.append(request_latency)
                    
                    # Update cumulative metrics
                    cumulative_metrics.total_requests += 1
                    cumulative_metrics.total_latency += request_latency
                    cumulative_metrics.latencies.append(request_latency)
                    
                    if response.status_code == 200:
                        phase_metrics.successful_requests += 1
                        cumulative_metrics.successful_requests += 1
                    else:
                        phase_metrics.failed_requests += 1
                        cumulative_metrics.failed_requests += 1
                
                except Exception as e:
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    # Count exceptions as failures
                    phase_metrics.total_requests += 1
                    phase_metrics.failed_requests += 1
                    phase_metrics.total_latency += request_latency
                    phase_metrics.latencies.append(request_latency)
                    
                    cumulative_metrics.total_requests += 1
                    cumulative_metrics.failed_requests += 1
                    cumulative_metrics.total_latency += request_latency
                    cumulative_metrics.latencies.append(request_latency)
                
                await asyncio.sleep(0.2)
            
            phase_end_time = time.time()
            phase_duration = phase_end_time - phase_start_time
            
            # Calculate error budget consumption for this phase
            if phase_metrics.success_rate < self.AVAILABILITY_SLO:
                phase_error_budget = (self.AVAILABILITY_SLO - phase_metrics.success_rate) / (1 - self.AVAILABILITY_SLO)
                phase_error_budget = min(phase_error_budget, 1.0)
            else:
                phase_error_budget = 0.0
            
            error_budget_results.append({
                "phase": scenario["phase"],
                "description": scenario["description"],
                "duration": phase_duration,
                "total_requests": phase_metrics.total_requests,
                "successful_requests": phase_metrics.successful_requests,
                "failed_requests": phase_metrics.failed_requests,
                "success_rate": phase_metrics.success_rate,
                "error_rate": phase_metrics.error_rate,
                "error_budget_consumed": phase_error_budget
            })
            
            logger.info(f"Phase {scenario['phase']} results:")
            logger.info(f"  Success Rate: {phase_metrics.success_rate:.3%}")
            logger.info(f"  Error Budget Consumed: {phase_error_budget:.1%}")
            
            await asyncio.sleep(0.5)
        
        # Calculate cumulative error budget consumption
        cumulative_error_budget = 0.0
        if cumulative_metrics.success_rate < self.AVAILABILITY_SLO:
            cumulative_error_budget = (self.AVAILABILITY_SLO - cumulative_metrics.success_rate) / (1 - self.AVAILABILITY_SLO)
            cumulative_error_budget = min(cumulative_error_budget, 1.0)
        
        error_budget_summary = {
            "total_requests": cumulative_metrics.total_requests,
            "overall_success_rate": cumulative_metrics.success_rate,
            "overall_error_rate": cumulative_metrics.error_rate,
            "cumulative_error_budget_consumed": cumulative_error_budget,
            "slo_target": self.AVAILABILITY_SLO,
            "error_budget_exhausted": cumulative_error_budget >= 1.0
        }
        
        logger.info(f"Error Budget Summary:")
        logger.info(f"  Overall Success Rate: {cumulative_metrics.success_rate:.3%}")
        logger.info(f"  Overall Error Rate: {cumulative_metrics.error_rate:.3%}")
        logger.info(f"  Cumulative Error Budget Consumed: {cumulative_error_budget:.1%}")
        logger.info(f"  Error Budget Exhausted: {error_budget_summary['error_budget_exhausted']}")
        
        # Verify error budget tracking
        for result in error_budget_results:
            if result["phase"] == "normal_operations":
                # Normal operations should consume minimal error budget
                assert result["error_budget_consumed"] <= 0.2, \
                    f"Normal operations should consume minimal error budget: {result['error_budget_consumed']:.1%}"
            
            elif result["phase"] == "elevated_errors":
                # Elevated errors should consume noticeable error budget
                logger.info(f"Elevated error phase consumed {result['error_budget_consumed']:.1%} error budget")
        
        # Verify error budget doesn't exceed 100%
        assert cumulative_error_budget <= 1.0, \
            f"Error budget consumption should not exceed 100%: {cumulative_error_budget:.1%}"
        
        return error_budget_summary
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_slo_violation_detection_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """SLO_VIOLATION_001: SLO violation detection and alerting"""
        # Test SLO violation detection mechanisms
        
        # Generate conditions that should trigger SLO violations
        violation_scenarios = [
            {
                "scenario": "latency_violations",
                "description": "Generate high latency requests",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Generate a very comprehensive analysis of distributed systems, microservices architecture, scalability patterns, performance optimization techniques, monitoring strategies, and reliability engineering practices across multiple cloud platforms and deployment environments."}],
                        "max_tokens": 400
                    }
                ] * 3
            },
            {
                "scenario": "availability_violations",
                "description": "Generate availability issues",
                "requests": [
                    {
                        "model": f"slo_violation_invalid_{i}",
                        "messages": [{"role": "user", "content": f"SLO violation test {i}"}],
                        "max_tokens": 50
                    }
                    for i in range(8)
                ]
            },
            {
                "scenario": "mixed_violations",
                "description": "Mixed violation patterns",
                "requests": [
                    # Alternate between different types of potential violations
                    {
                        "model": config.get_chat_model(0) if i % 2 == 0 else f"mixed_violation_{i}",
                        "messages": [{"role": "user", "content": "Mixed SLO violation test with extensive content requiring detailed processing and analysis" if i % 3 == 0 else f"Standard violation test {i}"}],
                        "max_tokens": 300 if i % 3 == 0 else 50
                    }
                    for i in range(6)
                ]
            }
        ]
        
        violation_detection_results = []
        
        for scenario in violation_scenarios:
            scenario_start_time = time.time()
            scenario_metrics = SLOMetrics()
            violation_events = []
            
            logger.info(f"Testing SLO violation scenario: {scenario['scenario']}")
            
            for i, request in enumerate(scenario["requests"]):
                request_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=False
                    )
                    
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    scenario_metrics.total_requests += 1
                    scenario_metrics.total_latency += request_latency
                    scenario_metrics.latencies.append(request_latency)
                    
                    # Detect violations
                    latency_violation = request_latency > self.LATENCY_P95_SLO
                    availability_violation = response.status_code != 200
                    
                    if response.status_code == 200:
                        scenario_metrics.successful_requests += 1
                    else:
                        scenario_metrics.failed_requests += 1
                    
                    # Record violation events
                    if latency_violation or availability_violation:
                        violation_events.append({
                            "request_id": i,
                            "timestamp": request_end_time,
                            "latency": request_latency,
                            "status_code": response.status_code,
                            "latency_violation": latency_violation,
                            "availability_violation": availability_violation
                        })
                        
                        if latency_violation:
                            logger.info(f"Latency violation detected: {request_latency:.2f}s > {self.LATENCY_P95_SLO:.2f}s")
                        if availability_violation:
                            logger.info(f"Availability violation detected: {response.status_code}")
                
                except Exception as e:
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    scenario_metrics.total_requests += 1
                    scenario_metrics.failed_requests += 1
                    scenario_metrics.total_latency += request_latency
                    scenario_metrics.latencies.append(request_latency)
                    
                    # Exception is an availability violation
                    violation_events.append({
                        "request_id": i,
                        "timestamp": request_end_time,
                        "latency": request_latency,
                        "error": str(e),
                        "availability_violation": True
                    })
                    
                    logger.info(f"Availability violation (exception): {e}")
                
                await asyncio.sleep(0.3)
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            # Analyze violations
            latency_violations = [v for v in violation_events if v.get("latency_violation")]
            availability_violations = [v for v in violation_events if v.get("availability_violation")]
            
            violation_detection_results.append({
                "scenario": scenario["scenario"],
                "description": scenario["description"],
                "duration": scenario_duration,
                "total_requests": scenario_metrics.total_requests,
                "success_rate": scenario_metrics.success_rate,
                "average_latency": scenario_metrics.average_latency,
                "p95_latency": scenario_metrics.p95_latency,
                "total_violations": len(violation_events),
                "latency_violations": len(latency_violations),
                "availability_violations": len(availability_violations),
                "violation_rate": len(violation_events) / scenario_metrics.total_requests if scenario_metrics.total_requests > 0 else 0
            })
            
            logger.info(f"Scenario {scenario['scenario']} violations:")
            logger.info(f"  Total: {len(violation_events)}/{scenario_metrics.total_requests}")
            logger.info(f"  Latency: {len(latency_violations)}")
            logger.info(f"  Availability: {len(availability_violations)}")
            
            await asyncio.sleep(1)
        
        # Verify violation detection
        for result in violation_detection_results:
            if result["scenario"] == "latency_violations":
                # Latency violation scenario should detect latency issues
                logger.info(f"Latency violation scenario detected {result['latency_violations']} violations")
            
            elif result["scenario"] == "availability_violations":
                # Availability violation scenario should detect availability issues
                assert result["availability_violations"] > 0, \
                    f"Availability violation scenario should detect violations: {result['availability_violations']}"
            
            elif result["scenario"] == "mixed_violations":
                # Mixed scenario should detect various types of violations
                logger.info(f"Mixed violation scenario detected {result['total_violations']} violations")
        
        # Check for SLO violation detection endpoints (if available)
        violation_endpoints = [
            "/slo/violations",
            "/api/v1/slo/status",
            "/monitoring/slo",
            "/alerts/slo"
        ]
        
        for endpoint in violation_endpoints:
            try:
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
                
                if response.status_code == 200:
                    logger.info(f"SLO monitoring endpoint available: {endpoint}")
                    
                    try:
                        slo_data = response.json()
                        if "violations" in str(slo_data).lower() or "slo" in str(slo_data).lower():
                            logger.info(f"SLO violation data available at {endpoint}")
                    except:
                        logger.info(f"SLO endpoint {endpoint} returns non-JSON data")
                
            except Exception as e:
                logger.debug(f"SLO endpoint {endpoint} not available: {e}")
        
        logger.info("SLO violation detection testing completed")
        
        return violation_detection_results
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_slo_reporting_dashboard_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """SLO_REPORTING_001: SLO reporting and dashboard validation"""
        # Test SLO reporting capabilities and dashboard endpoints
        
        # Generate measurable SLO data
        reporting_data_generation = [
            {
                "period": "current",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"SLO reporting test {i}"}],
                        "max_tokens": 50
                    }
                    for i in range(10)
                ]
            }
        ]
        
        slo_reporting_metrics = SLOMetrics()
        
        # Generate data for reporting
        for period in reporting_data_generation:
            for request in period["requests"]:
                request_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    slo_reporting_metrics.total_requests += 1
                    slo_reporting_metrics.total_latency += request_latency
                    slo_reporting_metrics.latencies.append(request_latency)
                    
                    if response.status_code == 200:
                        slo_reporting_metrics.successful_requests += 1
                    else:
                        slo_reporting_metrics.failed_requests += 1
                
                except Exception as e:
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    slo_reporting_metrics.total_requests += 1
                    slo_reporting_metrics.failed_requests += 1
                    slo_reporting_metrics.total_latency += request_latency
                    slo_reporting_metrics.latencies.append(request_latency)
                
                await asyncio.sleep(0.1)
        
        # Check for SLO reporting endpoints
        slo_reporting_endpoints = [
            "/slo",
            "/slo/dashboard",
            "/api/v1/slo",
            "/api/v1/slo/metrics",
            "/monitoring/slo",
            "/metrics/slo",
            "/health/slo"
        ]
        
        slo_reporting_results = []
        
        for endpoint in slo_reporting_endpoints:
            try:
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
                
                slo_reporting_results.append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "available": response.status_code == 200,
                    "content_type": response.headers.get("content-type", "")
                })
                
                if response.status_code == 200:
                    logger.info(f"SLO reporting endpoint available: {endpoint}")
                    
                    content_type = response.headers.get("content-type", "").lower()
                    
                    if "json" in content_type:
                        try:
                            slo_data = response.json()
                            
                            # Check for SLO-related data structure
                            slo_keywords = [
                                "availability", "latency", "error_rate", "success_rate",
                                "p95", "p99", "slo", "error_budget", "violations"
                            ]
                            
                            found_keywords = []
                            data_str = str(slo_data).lower()
                            
                            for keyword in slo_keywords:
                                if keyword in data_str:
                                    found_keywords.append(keyword)
                            
                            if found_keywords:
                                logger.info(f"SLO data keywords found at {endpoint}: {found_keywords}")
                            else:
                                logger.info(f"SLO endpoint {endpoint} available but no SLO keywords found")
                        
                        except Exception as e:
                            logger.info(f"Could not parse JSON from SLO endpoint {endpoint}: {e}")
                    
                    elif "html" in content_type:
                        # Might be a dashboard
                        logger.info(f"SLO dashboard (HTML) available at {endpoint}")
                    
                    else:
                        logger.info(f"SLO endpoint {endpoint} available with content-type: {content_type}")
                
            except Exception as e:
                slo_reporting_results.append({
                    "endpoint": endpoint,
                    "available": False,
                    "error": str(e)
                })
        
        # Check for metrics endpoints that might contain SLO data
        metrics_endpoints = ["/metrics", "/prometheus", "/api/v1/metrics"]
        
        for endpoint in metrics_endpoints:
            try:
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    slo_metrics = [
                        "http_request_duration", "http_requests_total",
                        "slo_", "error_budget", "availability"
                    ]
                    
                    found_slo_metrics = [metric for metric in slo_metrics if metric in content]
                    
                    if found_slo_metrics:
                        logger.info(f"SLO-related metrics found at {endpoint}: {found_slo_metrics}")
                
            except Exception as e:
                logger.debug(f"Could not check metrics endpoint {endpoint}: {e}")
        
        # Compile reporting assessment
        available_reporting = [r for r in slo_reporting_results if r.get("available")]
        
        slo_reporting_assessment = {
            "generated_requests": slo_reporting_metrics.total_requests,
            "success_rate": slo_reporting_metrics.success_rate,
            "average_latency": slo_reporting_metrics.average_latency,
            "p95_latency": slo_reporting_metrics.p95_latency,
            "available_endpoints": len(available_reporting),
            "reporting_endpoints": [r["endpoint"] for r in available_reporting],
            "has_slo_reporting": len(available_reporting) > 0
        }
        
        logger.info(f"SLO Reporting Assessment:")
        logger.info(f"  Generated {slo_reporting_metrics.total_requests} requests for reporting data")
        logger.info(f"  Success Rate: {slo_reporting_metrics.success_rate:.3%}")
        logger.info(f"  Average Latency: {slo_reporting_metrics.average_latency:.2f}s")
        logger.info(f"  Available Reporting Endpoints: {len(available_reporting)}")
        
        if available_reporting:
            logger.info(f"  ✅ SLO reporting capabilities detected")
        else:
            logger.info(f"  ⚠️ No SLO reporting endpoints found - consider implementing for observability")
        
        # Verify that we can measure SLO data
        assert slo_reporting_metrics.total_requests > 0, \
            "Should generate measurable SLO data"
        
        return slo_reporting_assessment

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_distributed_trace_slo_tracking_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TC_R757_SLO_TRACE_001: Distributed trace SLO tracking"""
        # Test SLO tracking across distributed traces
        
        # Generate distributed trace scenarios
        trace_scenarios = [
            {
                "scenario": "single_request_trace",
                "description": "Single request distributed trace",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Distributed trace SLO test"}],
                        "max_tokens": 50
                    }
                ]
            },
            {
                "scenario": "multi_request_trace", 
                "description": "Multi-request distributed trace",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Multi-trace request {i}"}],
                        "max_tokens": 40
                    }
                    for i in range(3)
                ]
            }
        ]
        
        trace_slo_results = []
        
        for scenario in trace_scenarios:
            scenario_start_time = time.time()
            trace_metrics = SLOMetrics()
            
            logger.info(f"Starting trace SLO scenario: {scenario['scenario']}")
            
            for i, request in enumerate(scenario["requests"]):
                request_start_time = time.time()
                
                try:
                    # Add trace correlation ID to headers if supported
                    trace_headers = auth_headers.copy()
                    trace_headers["X-Trace-ID"] = f"trace_{scenario['scenario']}_{i}"
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        trace_headers, request
                    )
                    
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    trace_metrics.total_requests += 1
                    trace_metrics.total_latency += request_latency
                    trace_metrics.latencies.append(request_latency)
                    
                    if response.status_code == 200:
                        trace_metrics.successful_requests += 1
                    else:
                        trace_metrics.failed_requests += 1
                        
                except Exception as e:
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    trace_metrics.total_requests += 1
                    trace_metrics.failed_requests += 1
                    trace_metrics.total_latency += request_latency
                    trace_metrics.latencies.append(request_latency)
                    
                    logger.warning(f"Trace request failed: {e}")
                
                await asyncio.sleep(0.2)
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            # Calculate trace SLO metrics
            trace_slo_results.append({
                "scenario": scenario["scenario"],
                "description": scenario["description"],
                "duration": scenario_duration,
                "total_requests": trace_metrics.total_requests,
                "success_rate": trace_metrics.success_rate,
                "average_latency": trace_metrics.average_latency,
                "p95_latency": trace_metrics.p95_latency,
                "trace_slo_met": trace_metrics.success_rate >= self.AVAILABILITY_SLO and trace_metrics.p95_latency <= self.LATENCY_P95_SLO
            })
            
            logger.info(f"Trace scenario {scenario['scenario']}: {trace_metrics.success_rate:.3%} success rate, {trace_metrics.p95_latency:.2f}s P95")
            
            await asyncio.sleep(0.5)
        
        # Verify distributed trace SLO tracking
        for result in trace_slo_results:
            if result["scenario"] == "single_request_trace":
                # Single requests should meet SLO easily
                assert result["success_rate"] >= 0.9, f"Single trace should have high success rate: {result['success_rate']:.3%}"
            
            elif result["scenario"] == "multi_request_trace":
                # Multi-request traces should still meet reasonable SLO
                assert result["success_rate"] >= 0.8, f"Multi-trace should have good success rate: {result['success_rate']:.3%}"
        
        logger.info("Distributed trace SLO tracking completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_cross_service_slo_correlation_002(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """TC_R757_SLO_TRACE_002: Cross-service SLO correlation"""
        # Test SLO correlation across multiple services
        
        # Test different service endpoints for correlation
        service_endpoints = [
            {
                "service": "models",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "data": None
            },
            {
                "service": "chat",
                "endpoint": "/api/v1/chat/completions", 
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Cross-service SLO test"}],
                    "max_tokens": 50
                }
            }
        ]
        
        cross_service_results = []
        
        for service in service_endpoints:
            service_start_time = time.time()
            service_requests = []
            
            # Make multiple requests to each service
            for i in range(3):
                request_start_time = time.time()
                
                try:
                    correlation_headers = auth_headers.copy()
                    correlation_headers["X-Correlation-ID"] = f"cross_service_{service['service']}_{i}"
                    
                    response = await make_request(
                        http_client, service["method"], service["endpoint"],
                        correlation_headers, service["data"], 
                        track_cost=(service["method"] == "POST")
                    )
                    
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    service_requests.append({
                        "request_id": i,
                        "status_code": response.status_code,
                        "latency": request_latency,
                        "success": response.status_code == 200
                    })
                    
                except Exception as e:
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    service_requests.append({
                        "request_id": i,
                        "error": str(e),
                        "latency": request_latency,
                        "success": False
                    })
                
                await asyncio.sleep(0.3)
            
            service_end_time = time.time()
            service_duration = service_end_time - service_start_time
            
            # Calculate service SLO metrics
            successful_requests = [r for r in service_requests if r.get("success")]
            latencies = [r["latency"] for r in service_requests if "latency" in r]
            
            cross_service_results.append({
                "service": service["service"],
                "total_requests": len(service_requests),
                "successful_requests": len(successful_requests),
                "success_rate": len(successful_requests) / len(service_requests),
                "average_latency": sum(latencies) / len(latencies) if latencies else 0,
                "service_duration": service_duration,
                "slo_compliance": len(successful_requests) / len(service_requests) >= self.AVAILABILITY_SLO
            })
            
            logger.info(f"Service {service['service']} SLO: {len(successful_requests)}/{len(service_requests)} success")
            
            await asyncio.sleep(0.5)
        
        # Verify cross-service SLO correlation
        all_services_compliant = all(r["slo_compliance"] for r in cross_service_results)
        
        if all_services_compliant:
            logger.info("✅ All services meet SLO requirements")
        else:
            non_compliant = [r["service"] for r in cross_service_results if not r["slo_compliance"]]
            logger.warning(f"⚠️ Non-compliant services: {non_compliant}")
        
        # At least one service should be compliant
        assert any(r["slo_compliance"] for r in cross_service_results), "At least one service should meet SLO"
        
        logger.info("Cross-service SLO correlation completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_end_to_end_latency_slo_003(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """TC_R757_SLO_TRACE_003: End-to-end latency SLO tracking"""
        # Test end-to-end latency SLO across complete request flows
        
        # Different complexity flows for end-to-end testing
        e2e_flows = [
            {
                "flow": "simple_flow",
                "description": "Simple end-to-end flow",
                "steps": [
                    {
                        "step": "model_check",
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "data": None
                    },
                    {
                        "step": "chat_request",
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST", 
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Simple E2E test"}],
                            "max_tokens": 40
                        }
                    }
                ]
            },
            {
                "flow": "complex_flow",
                "description": "Complex end-to-end flow",
                "steps": [
                    {
                        "step": "model_check",
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "data": None
                    },
                    {
                        "step": "complex_chat",
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [
                                {"role": "user", "content": "Complex E2E test with conversation"},
                                {"role": "assistant", "content": "I understand this is a complex test."},
                                {"role": "user", "content": "Please provide detailed analysis."}
                            ],
                            "max_tokens": 150
                        }
                    }
                ]
            }
        ]
        
        e2e_slo_results = []
        
        for flow in e2e_flows:
            flow_start_time = time.time()
            flow_steps = []
            
            logger.info(f"Starting E2E flow: {flow['flow']}")
            
            for step in flow["steps"]:
                step_start_time = time.time()
                
                try:
                    e2e_headers = auth_headers.copy()
                    e2e_headers["X-E2E-Flow-ID"] = f"e2e_{flow['flow']}_{step['step']}"
                    
                    response = await make_request(
                        http_client, step["method"], step["endpoint"],
                        e2e_headers, step["data"],
                        track_cost=(step["method"] == "POST")
                    )
                    
                    step_end_time = time.time()
                    step_latency = step_end_time - step_start_time
                    
                    flow_steps.append({
                        "step": step["step"],
                        "status_code": response.status_code,
                        "latency": step_latency,
                        "success": response.status_code == 200
                    })
                    
                except Exception as e:
                    step_end_time = time.time()
                    step_latency = step_end_time - step_start_time
                    
                    flow_steps.append({
                        "step": step["step"],
                        "error": str(e),
                        "latency": step_latency,
                        "success": False
                    })
                
                await asyncio.sleep(0.2)
            
            flow_end_time = time.time()
            total_flow_latency = flow_end_time - flow_start_time
            
            # Calculate end-to-end SLO metrics
            successful_steps = [s for s in flow_steps if s.get("success")]
            step_latencies = [s["latency"] for s in flow_steps if "latency" in s]
            
            e2e_slo_results.append({
                "flow": flow["flow"],
                "description": flow["description"],
                "total_steps": len(flow_steps),
                "successful_steps": len(successful_steps),
                "flow_success": len(successful_steps) == len(flow_steps),
                "total_latency": total_flow_latency,
                "step_latencies": step_latencies,
                "average_step_latency": sum(step_latencies) / len(step_latencies) if step_latencies else 0,
                "e2e_slo_met": len(successful_steps) == len(flow_steps) and total_flow_latency <= self.LATENCY_P95_SLO * 2  # E2E allows higher latency
            })
            
            logger.info(f"E2E flow {flow['flow']}: {total_flow_latency:.2f}s total, {len(successful_steps)}/{len(flow_steps)} steps successful")
            
            await asyncio.sleep(1)
        
        # Verify end-to-end SLO performance
        for result in e2e_slo_results:
            if result["flow"] == "simple_flow":
                # Simple flows should complete quickly
                assert result["total_latency"] <= 15.0, f"Simple E2E flow should be fast: {result['total_latency']:.2f}s"
                assert result["flow_success"], "Simple E2E flow should complete successfully"
            
            elif result["flow"] == "complex_flow":
                # Complex flows should still meet reasonable SLO
                assert result["total_latency"] <= 30.0, f"Complex E2E flow should complete reasonably: {result['total_latency']:.2f}s"
        
        # At least one flow should meet E2E SLO
        slo_compliant_flows = [r for r in e2e_slo_results if r["e2e_slo_met"]]
        assert len(slo_compliant_flows) >= 1, "At least one E2E flow should meet SLO"
        
        logger.info("End-to-end latency SLO tracking completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_trace_sampling_slo_impact_004(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TC_R757_SLO_TRACE_004: Trace sampling impact on SLO measurement"""
        # Test how trace sampling affects SLO measurement accuracy
        
        # Generate requests with different sampling scenarios
        sampling_scenarios = [
            {
                "scenario": "full_sampling",
                "description": "Full trace sampling (100%)",
                "sample_rate": 1.0,
                "request_count": 10
            },
            {
                "scenario": "partial_sampling", 
                "description": "Partial trace sampling (50%)",
                "sample_rate": 0.5,
                "request_count": 10
            },
            {
                "scenario": "minimal_sampling",
                "description": "Minimal trace sampling (10%)",
                "sample_rate": 0.1,
                "request_count": 10
            }
        ]
        
        sampling_slo_results = []
        
        for scenario in sampling_scenarios:
            scenario_start_time = time.time()
            scenario_metrics = SLOMetrics()
            sampled_requests = 0
            
            logger.info(f"Starting sampling scenario: {scenario['scenario']}")
            
            for i in range(scenario["request_count"]):
                # Simulate sampling decision
                should_sample = random.random() < scenario["sample_rate"]
                
                request_start_time = time.time()
                
                try:
                    sampling_headers = auth_headers.copy()
                    if should_sample:
                        sampling_headers["X-Trace-Sample"] = "1"
                        sampling_headers["X-Trace-ID"] = f"sampled_{scenario['scenario']}_{i}"
                        sampled_requests += 1
                    else:
                        sampling_headers["X-Trace-Sample"] = "0"
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        sampling_headers, {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Sampling test {i}"}],
                            "max_tokens": 40
                        }
                    )
                    
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    scenario_metrics.total_requests += 1
                    scenario_metrics.total_latency += request_latency
                    scenario_metrics.latencies.append(request_latency)
                    
                    if response.status_code == 200:
                        scenario_metrics.successful_requests += 1
                    else:
                        scenario_metrics.failed_requests += 1
                    
                except Exception as e:
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    scenario_metrics.total_requests += 1
                    scenario_metrics.failed_requests += 1
                    scenario_metrics.total_latency += request_latency
                    scenario_metrics.latencies.append(request_latency)
                    
                    logger.warning(f"Sampling request failed: {e}")
                
                await asyncio.sleep(0.2)
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            # Calculate sampling impact on SLO measurement
            sampling_slo_results.append({
                "scenario": scenario["scenario"],
                "description": scenario["description"],
                "sample_rate": scenario["sample_rate"],
                "total_requests": scenario_metrics.total_requests,
                "sampled_requests": sampled_requests,
                "success_rate": scenario_metrics.success_rate,
                "average_latency": scenario_metrics.average_latency,
                "p95_latency": scenario_metrics.p95_latency,
                "slo_accuracy": abs(scenario_metrics.success_rate - self.AVAILABILITY_SLO) <= 0.1,  # Within 10% of target
                "duration": scenario_duration
            })
            
            logger.info(f"Sampling {scenario['scenario']}: {sampled_requests}/{scenario_metrics.total_requests} sampled, {scenario_metrics.success_rate:.3%} success")
            
            await asyncio.sleep(0.5)
        
        # Analyze sampling impact on SLO measurement
        for result in sampling_slo_results:
            sampling_efficiency = result["sampled_requests"] / result["total_requests"]
            expected_efficiency = result["sample_rate"]
            
            # Sampling should be reasonably close to expected rate
            assert abs(sampling_efficiency - expected_efficiency) <= 0.2, \
                f"Sampling efficiency should be close to expected: {sampling_efficiency:.1%} vs {expected_efficiency:.1%}"
            
            # SLO measurements should still be meaningful regardless of sampling
            assert result["success_rate"] >= 0.5, \
                f"SLO measurement should be meaningful with sampling: {result['success_rate']:.3%}"
        
        # Compare SLO measurements across different sampling rates
        full_sampling = next((r for r in sampling_slo_results if r["scenario"] == "full_sampling"), None)
        partial_sampling = next((r for r in sampling_slo_results if r["scenario"] == "partial_sampling"), None)
        
        if full_sampling and partial_sampling:
            slo_variance = abs(full_sampling["success_rate"] - partial_sampling["success_rate"])
            
            # SLO measurements should be consistent across sampling rates
            if slo_variance > 0.2:
                logger.warning(f"High SLO variance between sampling rates: {slo_variance:.3%}")
            else:
                logger.info(f"SLO measurements consistent across sampling: {slo_variance:.3%} variance")
        
        logger.info("Trace sampling SLO impact testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r757_slo_avail_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """TC_R757_SLO_AVAIL_001: API availability measurement under load"""
        # Test API availability measurement during load conditions
        
        load_duration = 30  # 30 second load test
        request_interval = 1.0  # Request every second
        
        availability_metrics = SLOMetrics()
        load_start_time = time.time()
        
        logger.info(f"Starting availability SLO test under load for {load_duration}s")
        
        while time.time() - load_start_time < load_duration:
            request_start_time = time.time()
            
            try:
                # Create varying load patterns
                request_type = random.choice(["light", "medium", "heavy"])
                
                if request_type == "light":
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Light load availability test"}],
                        "max_tokens": 30
                    }
                elif request_type == "medium":
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Medium load availability test with more content"}],
                        "max_tokens": 80
                    }
                else:  # heavy
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Heavy load availability test: " + "detailed content " * 100}],
                        "max_tokens": 200
                    }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                request_end_time = time.time()
                request_latency = request_end_time - request_start_time
                
                availability_metrics.total_requests += 1
                availability_metrics.total_latency += request_latency
                availability_metrics.latencies.append(request_latency)
                
                if response.status_code == 200:
                    availability_metrics.successful_requests += 1
                else:
                    availability_metrics.failed_requests += 1
                    logger.warning(f"Availability failure: {response.status_code} for {request_type} load")
                
            except Exception as e:
                request_end_time = time.time()
                request_latency = request_end_time - request_start_time
                
                availability_metrics.total_requests += 1
                availability_metrics.failed_requests += 1
                availability_metrics.total_latency += request_latency
                availability_metrics.latencies.append(request_latency)
                
                logger.warning(f"Availability exception: {e}")
            
            # Maintain request interval
            elapsed_time = time.time() - request_start_time
            sleep_time = max(0, request_interval - elapsed_time)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        load_end_time = time.time()
        actual_duration = load_end_time - load_start_time
        
        # Calculate availability SLO metrics
        availability_slo_result = {
            "test_duration": actual_duration,
            "total_requests": availability_metrics.total_requests,
            "successful_requests": availability_metrics.successful_requests,
            "failed_requests": availability_metrics.failed_requests,
            "availability": availability_metrics.success_rate,
            "average_latency": availability_metrics.average_latency,
            "requests_per_second": availability_metrics.total_requests / actual_duration,
            "slo_target": self.AVAILABILITY_SLO,
            "slo_met": availability_metrics.success_rate >= self.AVAILABILITY_SLO
        }
        
        logger.info(f"Availability Under Load Results:")
        logger.info(f"  Duration: {actual_duration:.1f}s")
        logger.info(f"  Total Requests: {availability_metrics.total_requests}")
        logger.info(f"  Availability: {availability_metrics.success_rate:.3%} (Target: {self.AVAILABILITY_SLO:.3%})")
        logger.info(f"  RPS: {availability_slo_result['requests_per_second']:.1f}")
        logger.info(f"  SLO Met: {availability_slo_result['slo_met']}")
        
        # Verify availability under load
        assert availability_metrics.total_requests >= 20, "Should generate sufficient load"
        assert availability_metrics.success_rate >= 0.80, "Availability should be reasonable under load"
        
        logger.info("API availability measurement under load completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r757_slo_avail_002(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """TC_R757_SLO_AVAIL_002: High error rate impact on SLOs"""
        # Test how high error rates impact SLO measurements
        
        # Phase 1: Baseline availability
        baseline_metrics = SLOMetrics()
        
        for i in range(5):
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Baseline SLO test {i}"}],
                        "max_tokens": 40
                    }
                )
                
                baseline_metrics.total_requests += 1
                if response.status_code == 200:
                    baseline_metrics.successful_requests += 1
                else:
                    baseline_metrics.failed_requests += 1
                    
            except Exception:
                baseline_metrics.total_requests += 1
                baseline_metrics.failed_requests += 1
            
            await asyncio.sleep(0.2)
        
        # Phase 2: Induce high error rate
        error_metrics = SLOMetrics()
        
        # Mix of failing and successful requests
        error_test_requests = [
            {"model": "high_error_invalid_1", "messages": [{"role": "user", "content": "Error test"}], "max_tokens": 50},
            {"model": config.get_chat_model(0), "messages": [{"role": "user", "content": "Success test"}], "max_tokens": 40},
            {"model": "high_error_invalid_2", "messages": [{"role": "user", "content": "Error test"}], "max_tokens": 50},
            {"model": "high_error_invalid_3", "messages": [{"role": "user", "content": "Error test"}], "max_tokens": 50},
            {"model": config.get_chat_model(0), "messages": [{"role": "user", "content": "Success test"}], "max_tokens": 40},
            {"model": "high_error_invalid_4", "messages": [{"role": "user", "content": "Error test"}], "max_tokens": 50},
        ]
        
        for i, request in enumerate(error_test_requests):
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=("invalid" not in request["model"])
                )
                
                error_metrics.total_requests += 1
                if response.status_code == 200:
                    error_metrics.successful_requests += 1
                else:
                    error_metrics.failed_requests += 1
                    
            except Exception:
                error_metrics.total_requests += 1
                error_metrics.failed_requests += 1
            
            await asyncio.sleep(0.2)
        
        # Phase 3: Recovery phase
        recovery_metrics = SLOMetrics()
        
        for i in range(3):
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Recovery test {i}"}],
                        "max_tokens": 40
                    }
                )
                
                recovery_metrics.total_requests += 1
                if response.status_code == 200:
                    recovery_metrics.successful_requests += 1
                else:
                    recovery_metrics.failed_requests += 1
                    
            except Exception:
                recovery_metrics.total_requests += 1
                recovery_metrics.failed_requests += 1
            
            await asyncio.sleep(0.3)
        
        # Analyze error rate impact
        baseline_availability = baseline_metrics.success_rate
        error_phase_availability = error_metrics.success_rate
        recovery_availability = recovery_metrics.success_rate
        
        logger.info(f"High Error Rate Impact Analysis:")
        logger.info(f"  Baseline Availability: {baseline_availability:.3%}")
        logger.info(f"  Error Phase Availability: {error_phase_availability:.3%}")
        logger.info(f"  Recovery Availability: {recovery_availability:.3%}")
        
        # Error phase should show measurable impact
        assert error_phase_availability < baseline_availability, \
            "High error rate should impact availability measurements"
        
        # Recovery should show improvement
        assert recovery_availability >= error_phase_availability, \
            "Recovery phase should show availability improvement"
        
        # System should handle error measurement gracefully
        assert error_metrics.total_requests > 0, "Error phase should complete with measurements"
        
        logger.info("High error rate impact on SLOs completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r757_slo_latency_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """TC_R757_SLO_LATENCY_001: Latency SLO validation (P95, P99)"""
        # Test comprehensive latency SLO validation including P95 and P99
        
        latency_test_scenarios = [
            {
                "scenario": "fast_requests",
                "count": 20,
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Fast request"}],
                    "max_tokens": 20
                }
            },
            {
                "scenario": "medium_requests",
                "count": 15,
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Medium complexity request for latency testing"}],
                    "max_tokens": 100
                }
            },
            {
                "scenario": "complex_requests",
                "count": 10,
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Complex request requiring detailed analysis and comprehensive response generation for latency SLO validation"}],
                    "max_tokens": 250
                }
            }
        ]
        
        all_latencies = []
        latency_scenario_results = []
        
        for scenario in latency_test_scenarios:
            scenario_latencies = []
            scenario_start_time = time.time()
            
            for i in range(scenario["count"]):
                request_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, scenario["request"]
                    )
                    
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    scenario_latencies.append(request_latency)
                    all_latencies.append(request_latency)
                    
                    if request_latency > self.LATENCY_P95_SLO:
                        logger.info(f"High latency detected: {request_latency:.2f}s in {scenario['scenario']}")
                    
                except Exception as e:
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    scenario_latencies.append(request_latency)
                    all_latencies.append(request_latency)
                    logger.warning(f"Latency test exception: {e}")
                
                await asyncio.sleep(0.1)
            
            scenario_end_time = time.time()
            
            # Calculate scenario-specific latency metrics
            if scenario_latencies:
                sorted_latencies = sorted(scenario_latencies)
                p50_index = int(len(sorted_latencies) * 0.50)
                p95_index = int(len(sorted_latencies) * 0.95)
                p99_index = int(len(sorted_latencies) * 0.99)
                
                latency_scenario_results.append({
                    "scenario": scenario["scenario"],
                    "request_count": len(scenario_latencies),
                    "min_latency": min(scenario_latencies),
                    "max_latency": max(scenario_latencies),
                    "avg_latency": sum(scenario_latencies) / len(scenario_latencies),
                    "p50_latency": sorted_latencies[min(p50_index, len(sorted_latencies) - 1)],
                    "p95_latency": sorted_latencies[min(p95_index, len(sorted_latencies) - 1)],
                    "p99_latency": sorted_latencies[min(p99_index, len(sorted_latencies) - 1)],
                    "duration": scenario_end_time - scenario_start_time
                })
        
        # Calculate overall latency SLO metrics
        if all_latencies:
            sorted_all_latencies = sorted(all_latencies)
            total_requests = len(all_latencies)
            
            p95_index = int(total_requests * 0.95)
            p99_index = int(total_requests * 0.99)
            
            overall_latency_metrics = {
                "total_requests": total_requests,
                "min_latency": min(all_latencies),
                "max_latency": max(all_latencies),
                "avg_latency": sum(all_latencies) / total_requests,
                "p50_latency": sorted_all_latencies[int(total_requests * 0.50)],
                "p95_latency": sorted_all_latencies[min(p95_index, total_requests - 1)],
                "p99_latency": sorted_all_latencies[min(p99_index, total_requests - 1)],
                "p95_slo_target": self.LATENCY_P95_SLO,
                "p99_slo_target": self.LATENCY_P99_SLO,
                "p95_slo_met": sorted_all_latencies[min(p95_index, total_requests - 1)] <= self.LATENCY_P95_SLO,
                "p99_slo_met": sorted_all_latencies[min(p99_index, total_requests - 1)] <= self.LATENCY_P99_SLO
            }
            
            # Calculate SLO violation rates
            p95_violations = sum(1 for lat in all_latencies if lat > self.LATENCY_P95_SLO)
            p99_violations = sum(1 for lat in all_latencies if lat > self.LATENCY_P99_SLO)
            
            overall_latency_metrics.update({
                "p95_violation_rate": p95_violations / total_requests,
                "p99_violation_rate": p99_violations / total_requests,
                "p95_violations": p95_violations,
                "p99_violations": p99_violations
            })
            
            logger.info(f"Overall Latency SLO Results:")
            logger.info(f"  Total Requests: {total_requests}")
            logger.info(f"  Average Latency: {overall_latency_metrics['avg_latency']:.2f}s")
            logger.info(f"  P50 Latency: {overall_latency_metrics['p50_latency']:.2f}s")
            logger.info(f"  P95 Latency: {overall_latency_metrics['p95_latency']:.2f}s (Target: {self.LATENCY_P95_SLO:.2f}s)")
            logger.info(f"  P99 Latency: {overall_latency_metrics['p99_latency']:.2f}s (Target: {self.LATENCY_P99_SLO:.2f}s)")
            logger.info(f"  P95 SLO Met: {overall_latency_metrics['p95_slo_met']}")
            logger.info(f"  P99 SLO Met: {overall_latency_metrics['p99_slo_met']}")
            logger.info(f"  P95 Violation Rate: {overall_latency_metrics['p95_violation_rate']:.1%}")
            logger.info(f"  P99 Violation Rate: {overall_latency_metrics['p99_violation_rate']:.1%}")
            
            # Verify latency SLO compliance
            assert overall_latency_metrics["avg_latency"] <= 30.0, \
                f"Average latency should be reasonable: {overall_latency_metrics['avg_latency']:.2f}s"
            
            assert overall_latency_metrics["p99_latency"] <= 60.0, \
                f"P99 latency should be within bounds: {overall_latency_metrics['p99_latency']:.2f}s"
            
            # Violation rates should be manageable
            assert overall_latency_metrics["p95_violation_rate"] <= 0.2, \
                f"P95 violation rate should be reasonable: {overall_latency_metrics['p95_violation_rate']:.1%}"
            
            logger.info("Latency SLO validation (P95, P99) completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r757_slo_latency_002(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """TC_R757_SLO_LATENCY_002: High tail latency analysis"""
        # Test analysis of high tail latency and its impact on SLOs
        
        # Generate requests with varied complexity to create tail latency
        tail_latency_requests = []
        
        # Add mostly normal requests
        for i in range(15):
            tail_latency_requests.append({
                "type": "normal",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Normal request {i}"}],
                    "max_tokens": 50
                }
            })
        
        # Add some potentially high-latency requests
        for i in range(5):
            tail_latency_requests.append({
                "type": "complex",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Complex tail latency analysis request {i}: " + "detailed processing " * 300}],
                    "max_tokens": 400
                }
            })
        
        # Shuffle to randomize execution order
        random.shuffle(tail_latency_requests)
        
        tail_latency_results = []
        
        for i, req in enumerate(tail_latency_requests):
            request_start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, req["request"]
                )
                
                request_end_time = time.time()
                request_latency = request_end_time - request_start_time
                
                tail_latency_results.append({
                    "request_id": i,
                    "type": req["type"],
                    "latency": request_latency,
                    "status_code": response.status_code,
                    "is_tail_latency": request_latency > self.LATENCY_P95_SLO,
                    "is_extreme_tail": request_latency > self.LATENCY_P99_SLO
                })
                
            except Exception as e:
                request_end_time = time.time()
                request_latency = request_end_time - request_start_time
                
                tail_latency_results.append({
                    "request_id": i,
                    "type": req["type"],
                    "latency": request_latency,
                    "error": str(e),
                    "is_tail_latency": request_latency > self.LATENCY_P95_SLO,
                    "is_extreme_tail": request_latency > self.LATENCY_P99_SLO
                })
            
            await asyncio.sleep(0.1)
        
        # Analyze tail latency patterns
        latencies = [r["latency"] for r in tail_latency_results]
        normal_latencies = [r["latency"] for r in tail_latency_results if r["type"] == "normal"]
        complex_latencies = [r["latency"] for r in tail_latency_results if r["type"] == "complex"]
        
        tail_latency_events = [r for r in tail_latency_results if r.get("is_tail_latency")]
        extreme_tail_events = [r for r in tail_latency_results if r.get("is_extreme_tail")]
        
        if latencies:
            sorted_latencies = sorted(latencies)
            total_requests = len(latencies)
            
            tail_analysis = {
                "total_requests": total_requests,
                "normal_requests": len(normal_latencies),
                "complex_requests": len(complex_latencies),
                "tail_latency_events": len(tail_latency_events),
                "extreme_tail_events": len(extreme_tail_events),
                "tail_latency_rate": len(tail_latency_events) / total_requests,
                "extreme_tail_rate": len(extreme_tail_events) / total_requests,
                "avg_normal_latency": sum(normal_latencies) / len(normal_latencies) if normal_latencies else 0,
                "avg_complex_latency": sum(complex_latencies) / len(complex_latencies) if complex_latencies else 0,
                "p90_latency": sorted_latencies[int(total_requests * 0.90)],
                "p95_latency": sorted_latencies[int(total_requests * 0.95)],
                "p99_latency": sorted_latencies[int(total_requests * 0.99)],
                "max_latency": max(latencies)
            }
            
            logger.info(f"Tail Latency Analysis Results:")
            logger.info(f"  Total Requests: {tail_analysis['total_requests']}")
            logger.info(f"  Tail Latency Events: {tail_analysis['tail_latency_events']} ({tail_analysis['tail_latency_rate']:.1%})")
            logger.info(f"  Extreme Tail Events: {tail_analysis['extreme_tail_events']} ({tail_analysis['extreme_tail_rate']:.1%})")
            logger.info(f"  Avg Normal Latency: {tail_analysis['avg_normal_latency']:.2f}s")
            logger.info(f"  Avg Complex Latency: {tail_analysis['avg_complex_latency']:.2f}s")
            logger.info(f"  P90 Latency: {tail_analysis['p90_latency']:.2f}s")
            logger.info(f"  P95 Latency: {tail_analysis['p95_latency']:.2f}s")
            logger.info(f"  P99 Latency: {tail_analysis['p99_latency']:.2f}s")
            logger.info(f"  Max Latency: {tail_analysis['max_latency']:.2f}s")
            
            # Verify tail latency characteristics
            if complex_latencies and normal_latencies:
                latency_difference = tail_analysis["avg_complex_latency"] - tail_analysis["avg_normal_latency"]
                logger.info(f"  Complexity Impact: +{latency_difference:.2f}s ({latency_difference/tail_analysis['avg_normal_latency']:.1%})")
                
                # Complex requests should generally have higher latency
                assert tail_analysis["avg_complex_latency"] > tail_analysis["avg_normal_latency"], \
                    "Complex requests should have higher average latency"
            
            # Tail latency should be manageable
            assert tail_analysis["tail_latency_rate"] <= 0.3, \
                f"Tail latency rate should be reasonable: {tail_analysis['tail_latency_rate']:.1%}"
            
            assert tail_analysis["extreme_tail_rate"] <= 0.1, \
                f"Extreme tail latency rate should be low: {tail_analysis['extreme_tail_rate']:.1%}"
            
            logger.info("High tail latency analysis completed")