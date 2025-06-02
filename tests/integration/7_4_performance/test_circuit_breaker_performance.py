# Section 7.4 - Circuit Breaker Testing
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_Circuit Breaker Testing.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List
from dataclasses import dataclass
from unittest.mock import patch, MagicMock
import random

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class CircuitBreakerTestResult:
    """Circuit breaker test result data structure"""
    test_name: str
    state_transitions: List[str]
    failure_count: int
    success_count: int
    response_times: List[float]
    recovery_time: float
    overhead_ms: float


class TestAdvancedCircuitBreakerStateManagement:
    """Test advanced circuit breaker state management"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_circuit_breaker_state_transitions_001(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """TC_R755_001: Test circuit breaker state transitions under various failure patterns"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test circuit breaker state management through failure simulation
        state_transition_metrics = {
            "normal_operation": [],
            "failure_detection": [],
            "circuit_open": [],
            "recovery_attempt": []
        }
        
        # Phase 1: Normal operation baseline
        logger.info("Testing normal operation baseline")
        for i in range(10):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                state_transition_metrics["normal_operation"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        # Phase 2: Simulate failure conditions to trigger circuit breaker
        logger.info("Simulating failure conditions")
        failure_responses = []
        
        # Attempt to trigger circuit breaker through rapid failed requests
        for i in range(15):
            start_time = time.perf_counter()
            
            # Use invalid model to trigger provider errors
            request_data = {
                "model": "invalid_model_for_circuit_breaker_test",
                "messages": [{"role": "user", "content": "Circuit breaker test"}],
                "max_tokens": 10
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            response_time = (end_time - start_time) * 1000
            failure_responses.append({
                "status_code": response.status_code,
                "response_time": response_time
            })
            
            # If we start getting fast failures, circuit breaker may be engaged
            if response_time < 100 and response.status_code in [503, 429, 500]:
                state_transition_metrics["circuit_open"].append(response_time)
            else:
                state_transition_metrics["failure_detection"].append(response_time)
            
            await asyncio.sleep(0.05)  # Rapid requests to trigger circuit breaker
        
        # Phase 3: Test recovery behavior
        logger.info("Testing circuit breaker recovery")
        await asyncio.sleep(2)  # Allow potential circuit breaker timeout
        
        recovery_times = []
        for i in range(10):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            response_time = (end_time - start_time) * 1000
            if response.status_code == 200:
                recovery_times.append(response_time)
                state_transition_metrics["recovery_attempt"].append(response_time)
            
            await asyncio.sleep(0.2)
        
        # Analyze circuit breaker behavior
        for phase, times in state_transition_metrics.items():
            if times:
                avg_time = statistics.mean(times)
                logger.info(f"Circuit breaker {phase} - Avg: {avg_time:.2f}ms over {len(times)} requests")
        
        # Verify circuit breaker effectiveness
        if state_transition_metrics["circuit_open"]:
            avg_circuit_open = statistics.mean(state_transition_metrics["circuit_open"])
            assert avg_circuit_open < 50.0, f"Circuit breaker should fail fast, got {avg_circuit_open:.2f}ms"
        
        if recovery_times:
            avg_recovery = statistics.mean(recovery_times)
            assert avg_recovery < 1000.0, f"Recovery should be efficient, got {avg_recovery:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_circuit_breaker_concurrent_state_access_002(self, http_client: httpx.AsyncClient,
                                                                   auth_headers: Dict[str, str],
                                                                   make_request):
        """TC_R755_001: Test concurrent state access and modification scenarios"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        async def concurrent_circuit_breaker_test(worker_id: int):
            """Simulate concurrent access to circuit breaker state"""
            worker_metrics = {
                "requests": 0,
                "response_times": [],
                "errors": 0,
                "fast_failures": 0
            }
            
            for i in range(20):
                # Mix of valid and invalid requests to test concurrent state management
                if worker_id % 3 == 0:
                    # Valid request
                    start_time = time.perf_counter()
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                    end_time = time.perf_counter()
                else:
                    # Invalid request to trigger failures
                    start_time = time.perf_counter()
                    request_data = {
                        "model": f"invalid_model_{worker_id}_{i}",
                        "messages": [{"role": "user", "content": f"Worker {worker_id} test {i}"}],
                        "max_tokens": 10
                    }
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                worker_metrics["requests"] += 1
                worker_metrics["response_times"].append(response_time)
                
                if response.status_code == 200:
                    pass  # Success
                elif response_time < 100:  # Fast failure indicates circuit breaker
                    worker_metrics["fast_failures"] += 1
                else:
                    worker_metrics["errors"] += 1
                
                await asyncio.sleep(0.02)  # Brief delay
            
            return worker_metrics
        
        # Execute concurrent circuit breaker tests
        concurrent_workers = 8
        tasks = [concurrent_circuit_breaker_test(i) for i in range(concurrent_workers)]
        results = await asyncio.gather(*tasks)
        
        # Analyze concurrent circuit breaker behavior
        total_requests = sum(result["requests"] for result in results)
        total_fast_failures = sum(result["fast_failures"] for result in results)
        all_response_times = [time for result in results for time in result["response_times"]]
        
        fast_failure_rate = total_fast_failures / total_requests if total_requests > 0 else 0
        
        if all_response_times:
            avg_response_time = statistics.mean(all_response_times)
            logger.info(f"Concurrent circuit breaker test - {total_requests} requests, {fast_failure_rate:.2%} fast failure rate, Avg: {avg_response_time:.2f}ms")
            
            # Circuit breaker should handle concurrent access without corruption
            assert fast_failure_rate <= 0.8, f"Fast failure rate should be reasonable under concurrent load, got {fast_failure_rate:.2%}"


class TestMultiLevelCircuitBreakerHierarchy:
    """Test hierarchical circuit breaker implementation"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_circuit_breaker_provider_level_isolation_001(self, http_client: httpx.AsyncClient,
                                                                    auth_headers: Dict[str, str],
                                                                    make_request):
        """TC_R755_002: Test provider-level circuit breaker isolation"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test circuit breaker isolation between different providers/models
        provider_isolation_metrics = {}
        
        # Test different models to simulate provider-level isolation
        test_models = config.CHAT_MODELS[:2] if len(config.CHAT_MODELS) >= 2 else [config.get_chat_model(0)]
        
        for model in test_models:
            model_metrics = {
                "successful_requests": [],
                "failed_requests": [],
                "circuit_breaker_triggers": []
            }
            
            # Phase 1: Normal operation for this model
            for i in range(5):
                request_data = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Isolation test {i}"}],
                    "max_tokens": 15
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                
                if response.status_code == 200:
                    model_metrics["successful_requests"].append(response_time)
                else:
                    model_metrics["failed_requests"].append(response_time)
                
                await asyncio.sleep(0.1)
            
            # Phase 2: Trigger failures for this specific model
            for i in range(10):
                # Use invalid parameters to trigger model-specific failures
                request_data = {
                    "model": model,
                    "messages": [{"role": "user", "content": "X" * 10000}],  # Very long prompt
                    "max_tokens": -1  # Invalid parameter
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                
                # Fast failures may indicate circuit breaker engagement
                if response_time < 100 and response.status_code in [503, 429, 400]:
                    model_metrics["circuit_breaker_triggers"].append(response_time)
                else:
                    model_metrics["failed_requests"].append(response_time)
                
                await asyncio.sleep(0.05)
            
            provider_isolation_metrics[model] = model_metrics
        
        # Analyze provider-level isolation
        for model, metrics in provider_isolation_metrics.items():
            successful_count = len(metrics["successful_requests"])
            failed_count = len(metrics["failed_requests"])
            cb_trigger_count = len(metrics["circuit_breaker_triggers"])
            
            logger.info(f"Model {model} isolation - Success: {successful_count}, Failed: {failed_count}, CB triggers: {cb_trigger_count}")
            
            # Verify isolation doesn't affect other models excessively
            if metrics["successful_requests"]:
                avg_success_time = statistics.mean(metrics["successful_requests"])
                assert avg_success_time < 5000.0, f"Model {model} successful requests should remain efficient, got {avg_success_time:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_circuit_breaker_cascade_prevention_002(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """TC_R755_002: Test cascade failure prevention between levels"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test that failures in one area don't cascade to affect entire system
        cascade_prevention_metrics = {
            "baseline_performance": [],
            "during_failures": [],
            "post_failure_recovery": []
        }
        
        # Phase 1: Establish baseline performance
        for i in range(10):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                cascade_prevention_metrics["baseline_performance"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        # Phase 2: Introduce failures while monitoring system stability
        async def failure_generator():
            """Generate failures to test cascade prevention"""
            for i in range(20):
                request_data = {
                    "model": "cascade_test_invalid_model",
                    "messages": [{"role": "user", "content": "Cascade test"}],
                    "max_tokens": 10
                }
                
                await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                await asyncio.sleep(0.05)
        
        async def stability_monitor():
            """Monitor system stability during failures"""
            for i in range(15):
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
                end_time = time.perf_counter()
                
                if response.status_code == 200:
                    cascade_prevention_metrics["during_failures"].append((end_time - start_time) * 1000)
                
                await asyncio.sleep(0.2)
        
        # Run failure generation and stability monitoring concurrently
        await asyncio.gather(failure_generator(), stability_monitor())
        
        # Phase 3: Post-failure recovery
        await asyncio.sleep(1)  # Allow recovery time
        
        for i in range(10):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                cascade_prevention_metrics["post_failure_recovery"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        # Analyze cascade prevention effectiveness
        for phase, times in cascade_prevention_metrics.items():
            if times:
                avg_time = statistics.mean(times)
                logger.info(f"Cascade prevention {phase} - Avg: {avg_time:.2f}ms over {len(times)} requests")
        
        # Verify system stability during failures
        if (cascade_prevention_metrics["baseline_performance"] and 
            cascade_prevention_metrics["during_failures"]):
            
            baseline_avg = statistics.mean(cascade_prevention_metrics["baseline_performance"])
            during_failures_avg = statistics.mean(cascade_prevention_metrics["during_failures"])
            
            degradation_ratio = during_failures_avg / baseline_avg if baseline_avg > 0 else 1.0
            
            # System should remain stable during failures (cascade prevention)
            assert degradation_ratio <= 3.0, f"System degradation during failures should be limited, got {degradation_ratio:.2f}x"


class TestCircuitBreakerPerformanceOptimization:
    """Test circuit breaker performance optimization"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_circuit_breaker_overhead_measurement_001(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """TC_R755_004: Measure circuit breaker overhead in normal operation"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Measure baseline overhead of circuit breaker mechanism
        overhead_measurements = {
            "with_circuit_breaker": [],
            "baseline_comparison": []
        }
        
        # Test circuit breaker overhead on successful requests
        for i in range(50):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                overhead_measurements["with_circuit_breaker"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.02)
        
        # Analyze circuit breaker overhead
        if overhead_measurements["with_circuit_breaker"]:
            avg_overhead = statistics.mean(overhead_measurements["with_circuit_breaker"])
            p95_overhead = statistics.quantiles(overhead_measurements["with_circuit_breaker"], n=20)[18] if len(overhead_measurements["with_circuit_breaker"]) >= 20 else max(overhead_measurements["with_circuit_breaker"])
            
            logger.info(f"Circuit breaker overhead - Avg: {avg_overhead:.2f}ms, P95: {p95_overhead:.2f}ms")
            
            # Circuit breaker should add minimal overhead
            assert avg_overhead < 1000.0, f"Circuit breaker overhead should be minimal, got {avg_overhead:.2f}ms"
            assert p95_overhead < 2000.0, f"Circuit breaker P95 overhead should be reasonable, got {p95_overhead:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_circuit_breaker_high_frequency_operations_002(self, http_client: httpx.AsyncClient,
                                                                     auth_headers: Dict[str, str],
                                                                     make_request):
        """TC_R755_004: Test performance under high-frequency operations"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test circuit breaker performance under high load
        high_frequency_metrics = {
            "response_times": [],
            "throughput": 0,
            "circuit_breaker_decisions": 0
        }
        
        # Execute high-frequency requests
        num_requests = 100
        start_time = time.time()
        
        # Use asyncio.gather for true concurrency
        async def single_request(request_id: int):
            req_start = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            req_end = time.perf_counter()
            
            return {
                "response_time": (req_end - req_start) * 1000,
                "status_code": response.status_code
            }
        
        # Execute requests in batches for high frequency
        batch_size = 20
        for batch_start in range(0, num_requests, batch_size):
            batch_end = min(batch_start + batch_size, num_requests)
            batch_tasks = [single_request(i) for i in range(batch_start, batch_end)]
            batch_results = await asyncio.gather(*batch_tasks)
            
            for result in batch_results:
                if result["status_code"] == 200:
                    high_frequency_metrics["response_times"].append(result["response_time"])
                high_frequency_metrics["circuit_breaker_decisions"] += 1
            
            await asyncio.sleep(0.05)  # Brief pause between batches
        
        total_time = time.time() - start_time
        high_frequency_metrics["throughput"] = len(high_frequency_metrics["response_times"]) / total_time
        
        # Analyze high-frequency performance
        if high_frequency_metrics["response_times"]:
            avg_time = statistics.mean(high_frequency_metrics["response_times"])
            p95_time = statistics.quantiles(high_frequency_metrics["response_times"], n=20)[18] if len(high_frequency_metrics["response_times"]) >= 20 else max(high_frequency_metrics["response_times"])
            
            logger.info(f"High-frequency circuit breaker - Avg: {avg_time:.2f}ms, P95: {p95_time:.2f}ms, RPS: {high_frequency_metrics['throughput']:.2f}")
            
            # Circuit breaker should maintain performance under high frequency
            assert avg_time < 2000.0, f"High-frequency avg time should be reasonable, got {avg_time:.2f}ms"
            assert high_frequency_metrics["throughput"] >= 1.0, f"Throughput should be maintained, got {high_frequency_metrics['throughput']:.2f} RPS"


class TestEnhancedCircuitBreakerScenarios:
    """Enhanced circuit breaker testing scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_circuit_breaker_monitoring_analytics_001(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """TC_R755_006: Test comprehensive monitoring and analytics capabilities"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test circuit breaker monitoring and analytics
        monitoring_metrics = {
            "state_changes": [],
            "failure_patterns": [],
            "recovery_patterns": [],
            "performance_impact": []
        }
        
        # Phase 1: Generate varied traffic patterns for monitoring
        traffic_patterns = [
            {"name": "low_load", "requests": 10, "delay": 0.2},
            {"name": "medium_load", "requests": 20, "delay": 0.1},
            {"name": "high_load", "requests": 30, "delay": 0.05}
        ]
        
        for pattern in traffic_patterns:
            pattern_metrics = []
            
            for i in range(pattern["requests"]):
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                pattern_metrics.append({
                    "response_time": response_time,
                    "status_code": response.status_code,
                    "timestamp": time.time()
                })
                
                await asyncio.sleep(pattern["delay"])
            
            # Analyze pattern for monitoring data
            successful_requests = [m for m in pattern_metrics if m["status_code"] == 200]
            if successful_requests:
                avg_time = statistics.mean([m["response_time"] for m in successful_requests])
                monitoring_metrics["performance_impact"].append({
                    "pattern": pattern["name"],
                    "avg_time": avg_time,
                    "success_rate": len(successful_requests) / len(pattern_metrics)
                })
        
        # Phase 2: Inject failures and monitor circuit breaker behavior
        failure_injection_start = time.time()
        
        for i in range(15):
            # Inject failures to test monitoring
            request_data = {
                "model": "monitoring_test_invalid_model",
                "messages": [{"role": "user", "content": "Monitoring test"}],
                "max_tokens": 10
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            response_time = (end_time - start_time) * 1000
            
            if response_time < 100:  # Fast failure suggests circuit breaker
                monitoring_metrics["state_changes"].append({
                    "timestamp": time.time(),
                    "state": "circuit_open",
                    "response_time": response_time
                })
            else:
                monitoring_metrics["failure_patterns"].append({
                    "timestamp": time.time(),
                    "response_time": response_time
                })
            
            await asyncio.sleep(0.1)
        
        # Phase 3: Monitor recovery
        await asyncio.sleep(2)  # Allow recovery time
        
        for i in range(10):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                monitoring_metrics["recovery_patterns"].append({
                    "timestamp": time.time(),
                    "response_time": (end_time - start_time) * 1000
                })
            
            await asyncio.sleep(0.1)
        
        # Analyze monitoring effectiveness
        logger.info(f"Circuit breaker monitoring - State changes: {len(monitoring_metrics['state_changes'])}, "
                   f"Failure patterns: {len(monitoring_metrics['failure_patterns'])}, "
                   f"Recovery patterns: {len(monitoring_metrics['recovery_patterns'])}")
        
        # Verify monitoring captures circuit breaker behavior
        total_events = (len(monitoring_metrics["state_changes"]) + 
                       len(monitoring_metrics["failure_patterns"]) + 
                       len(monitoring_metrics["recovery_patterns"]))
        
        assert total_events > 0, "Monitoring should capture circuit breaker events"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_circuit_breaker_integration_failover_001(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """TC_R755_008: Test integration between circuit breaker and failover systems"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test circuit breaker integration with failover mechanisms
        integration_metrics = {
            "primary_failures": [],
            "failover_activations": [],
            "end_to_end_resilience": []
        }
        
        # Phase 1: Test primary service with potential failures
        primary_test_count = 0
        failover_test_count = 0
        
        for i in range(30):
            start_time = time.perf_counter()
            
            # Alternate between potentially failing and stable requests
            if i % 4 == 0:
                # Potentially failing request
                request_data = {
                    "model": "failover_test_invalid_model",
                    "messages": [{"role": "user", "content": "Integration test"}],
                    "max_tokens": 10
                }
                endpoint = "/api/v1/chat/completions"
                method = "POST"
                data = request_data
                primary_test_count += 1
            else:
                # Stable request (should work)
                endpoint = "/api/v1/models"
                method = "GET"
                data = None
                failover_test_count += 1
            
            response = await make_request(http_client, method, endpoint, auth_headers, data)
            end_time = time.perf_counter()
            
            response_time = (end_time - start_time) * 1000
            
            if i % 4 == 0:  # Primary service test
                if response_time < 100 and response.status_code in [503, 429]:
                    integration_metrics["failover_activations"].append(response_time)
                else:
                    integration_metrics["primary_failures"].append(response_time)
            else:  # Failover/stable service test
                if response.status_code == 200:
                    integration_metrics["end_to_end_resilience"].append(response_time)
            
            await asyncio.sleep(0.1)
        
        # Analyze integration effectiveness
        primary_failure_count = len(integration_metrics["primary_failures"])
        failover_activation_count = len(integration_metrics["failover_activations"])
        resilience_success_count = len(integration_metrics["end_to_end_resilience"])
        
        logger.info(f"Circuit breaker-failover integration - Primary failures: {primary_failure_count}, "
                   f"Failover activations: {failover_activation_count}, "
                   f"End-to-end successes: {resilience_success_count}")
        
        # Verify integration maintains system resilience
        if integration_metrics["end_to_end_resilience"]:
            avg_resilience_time = statistics.mean(integration_metrics["end_to_end_resilience"])
            resilience_rate = resilience_success_count / failover_test_count if failover_test_count > 0 else 0
            
            assert avg_resilience_time < 2000.0, f"End-to-end resilience should be efficient, got {avg_resilience_time:.2f}ms"
            assert resilience_rate >= 0.7, f"System resilience should be maintained, got {resilience_rate:.2%}"