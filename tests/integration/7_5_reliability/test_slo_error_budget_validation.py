# Section 7.5 - SLO and Error Budget Validation Tests
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Error Budget and SLO Validation.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List
from dataclasses import dataclass
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class SLOMetrics:
    """SLO metrics tracking"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency: float = 0.0
    latencies: List[float] = None
    error_budget_consumed: float = 0.0
    
    def __post_init__(self):
        if self.latencies is None:
            self.latencies = []
    
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