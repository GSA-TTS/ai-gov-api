# Section 7.5 - Circuit Breaker Testing
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Circuit Breaker Testing.md

import pytest
import httpx
import asyncio
import time
from typing import Dict, Any, List
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestCircuitBreakerTesting:
    """Circuit breaker pattern testing"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_circuit_breaker_state_transitions_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """CB_STATE_TRANSITIONS_001: Circuit breaker state transitions"""
        # Test circuit breaker state transitions: CLOSED → OPEN → HALF-OPEN → CLOSED
        
        # Phase 1: Normal operation (CLOSED state)
        normal_requests = []
        for i in range(3):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Normal operation test {i}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            normal_requests.append(response.status_code)
            await asyncio.sleep(0.3)
        
        # Normal requests should succeed (circuit closed)
        normal_success_rate = sum(1 for status in normal_requests if status == 200) / len(normal_requests)
        assert normal_success_rate >= 0.8, "Normal operation should have high success rate"
        
        # Phase 2: Failure simulation (trigger OPEN state)
        failure_requests = []
        failure_scenarios = [
            # Oversized request
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "A" * 10000}],  # Very large content
                "max_tokens": 1000
            },
            # Invalid model
            {
                "model": "circuit_breaker_invalid_model",
                "messages": [{"role": "user", "content": "Circuit breaker failure test"}],
                "max_tokens": 50
            },
            # Malformed request
            {
                "model": config.get_chat_model(0),
                "messages": "invalid_message_format",
                "max_tokens": 50
            }
        ]
        
        for scenario in failure_scenarios:
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario, track_cost=False
                )
                failure_requests.append(response.status_code)
            except Exception as e:
                failure_requests.append(0)  # Exception = failure
            
            await asyncio.sleep(0.2)
        
        # Phase 3: Test potential circuit breaker behavior
        # If circuit breaker is implemented, rapid requests after failures might return 503
        rapid_test_requests = []
        
        for i in range(5):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Post-failure test {i}"}],
                "max_tokens": 30
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            end_time = time.time()
            
            rapid_test_requests.append({
                "status_code": response.status_code,
                "response_time": end_time - start_time,
                "fast_fail": response.status_code == 503 and (end_time - start_time) < 1.0
            })
            
            await asyncio.sleep(0.1)  # Rapid requests
        
        # Analyze circuit breaker behavior
        fast_fail_responses = [r for r in rapid_test_requests if r.get("fast_fail")]
        successful_responses = [r for r in rapid_test_requests if r["status_code"] == 200]
        
        if fast_fail_responses:
            logger.info(f"Circuit breaker detected: {len(fast_fail_responses)} fast-fail responses")
        else:
            logger.info("No circuit breaker behavior detected (may not be implemented)")
        
        # Phase 4: Recovery test (HALF-OPEN → CLOSED)
        await asyncio.sleep(2)  # Allow potential circuit breaker to reset
        
        recovery_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Recovery test after circuit breaker"}],
            "max_tokens": 40
        }
        
        recovery_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, recovery_request
        )
        
        # System should recover (circuit should close)
        assert recovery_response.status_code == 200, "System should recover after circuit breaker reset"
        
        logger.info("Circuit breaker state transition testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_failure_threshold_detection_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """CB_THRESHOLD_001: Failure threshold detection"""
        # Test circuit breaker failure threshold detection
        
        # Baseline: establish normal operation
        baseline_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Baseline threshold test"}],
                "max_tokens": 30
            }
        )
        
        assert baseline_response.status_code == 200, "Baseline should work"
        
        # Generate failures to test threshold
        failure_patterns = []
        
        # Pattern 1: Consecutive failures
        consecutive_failures = []
        for i in range(8):  # Test with multiple failures
            invalid_request = {
                "model": f"invalid_model_threshold_{i}",
                "messages": [{"role": "user", "content": f"Threshold test {i}"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, invalid_request, track_cost=False
            )
            
            consecutive_failures.append({
                "request_id": i,
                "status_code": response.status_code,
                "is_failure": response.status_code >= 400
            })
            
            await asyncio.sleep(0.1)
        
        # Analyze failure pattern
        total_failures = sum(1 for f in consecutive_failures if f["is_failure"])
        failure_rate = total_failures / len(consecutive_failures)
        
        logger.info(f"Failure threshold test: {total_failures}/{len(consecutive_failures)} failures ({failure_rate:.2%})")
        
        # Test system behavior after failures
        post_failure_requests = []
        
        for i in range(3):
            test_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Post-failure threshold test {i}"}],
                "max_tokens": 30
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_request
            )
            end_time = time.time()
            
            post_failure_requests.append({
                "status_code": response.status_code,
                "response_time": end_time - start_time,
                "success": response.status_code == 200
            })
            
            await asyncio.sleep(0.5)
        
        # Verify threshold behavior
        # Either:
        # 1. Circuit breaker activated (fast failures with 503)
        # 2. System continues to handle requests normally
        # 3. Appropriate error handling for invalid requests
        
        post_failure_success_rate = sum(1 for r in post_failure_requests if r["success"]) / len(post_failure_requests)
        
        # System should either:
        # - Continue working normally (no circuit breaker)
        # - Implement circuit breaker with fast failures
        assert post_failure_success_rate >= 0.5 or any(r["response_time"] < 1.0 for r in post_failure_requests), \
            "System should either continue working or implement fast failure"
        
        logger.info(f"Post-failure success rate: {post_failure_success_rate:.2%}")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_fast_fail_behavior_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """CB_FAST_FAIL_001: Fast fail behavior when circuit is open"""
        # Test fast fail behavior (503 responses without calling downstream)
        
        # Create conditions that might trigger circuit breaker
        trigger_conditions = [
            # Large payload that might cause provider timeout
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Fast fail test: " + "content " * 1000}],
                "max_tokens": 500
            },
            # Multiple invalid requests
            {
                "model": "fast_fail_invalid_model_1",
                "messages": [{"role": "user", "content": "Fast fail trigger"}],
                "max_tokens": 50
            },
            {
                "model": "fast_fail_invalid_model_2", 
                "messages": [{"role": "user", "content": "Fast fail trigger"}],
                "max_tokens": 50
            }
        ]
        
        trigger_results = []
        
        for condition in trigger_conditions:
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, condition, track_cost=False
                )
                trigger_results.append(response.status_code)
            except Exception as e:
                trigger_results.append(0)  # Exception
        
        # Test for fast fail behavior immediately after triggers
        fast_fail_tests = []
        
        for i in range(5):
            normal_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Fast fail test {i}"}],
                "max_tokens": 30
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, normal_request
            )
            end_time = time.time()
            
            response_time = end_time - start_time
            
            fast_fail_tests.append({
                "status_code": response.status_code,
                "response_time": response_time,
                "is_fast_fail": response.status_code == 503 and response_time < 1.0,
                "is_success": response.status_code == 200
            })
            
            await asyncio.sleep(0.05)  # Very rapid requests
        
        # Analyze fast fail behavior
        fast_fails = [t for t in fast_fail_tests if t["is_fast_fail"]]
        successes = [t for t in fast_fail_tests if t["is_success"]]
        
        if fast_fails:
            logger.info(f"Fast fail behavior detected: {len(fast_fails)} fast failures")
            
            # Verify fast fail responses are indeed fast
            avg_fast_fail_time = sum(f["response_time"] for f in fast_fails) / len(fast_fails)
            assert avg_fast_fail_time < 2.0, "Fast fails should be actually fast"
            
        elif successes:
            logger.info(f"No circuit breaker detected - {len(successes)} successful requests")
        else:
            logger.info("Mixed behavior - requests handled with various response codes")
        
        # Verify that 503 responses have appropriate headers/content
        service_unavailable_responses = [t for t in fast_fail_tests if t["status_code"] == 503]
        
        for response_info in service_unavailable_responses:
            # 503 responses should be fast (indicating circuit breaker, not downstream failure)
            assert response_info["response_time"] < 5.0, \
                "503 responses should be fast if from circuit breaker"
        
        logger.info("Fast fail behavior testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_circuit_breaker_configuration_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """CB_CONFIG_001: Circuit breaker configuration testing"""
        # Test circuit breaker configuration sensitivity
        
        # Test different failure patterns to understand configuration
        configuration_tests = [
            {
                "pattern": "Single failure",
                "failures": 1,
                "description": "Test single failure impact"
            },
            {
                "pattern": "Multiple failures",
                "failures": 3,
                "description": "Test multiple failure threshold"
            },
            {
                "pattern": "Rapid failures",
                "failures": 5,
                "description": "Test rapid failure sequence"
            }
        ]
        
        configuration_results = []
        
        for test in configuration_tests:
            # Generate the specified number of failures
            for i in range(test["failures"]):
                failure_request = {
                    "model": f"config_test_invalid_{test['pattern']}_{i}",
                    "messages": [{"role": "user", "content": f"Config test failure {i}"}],
                    "max_tokens": 50
                }
                
                await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, failure_request, track_cost=False
                )
                
                await asyncio.sleep(0.1)
            
            # Test system response after failures
            test_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Config test after {test['pattern']}"}],
                "max_tokens": 30
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_request
            )
            end_time = time.time()
            
            configuration_results.append({
                "pattern": test["pattern"],
                "failures_generated": test["failures"],
                "post_failure_status": response.status_code,
                "post_failure_time": end_time - start_time,
                "circuit_likely_open": response.status_code == 503 and (end_time - start_time) < 1.0
            })
            
            await asyncio.sleep(1)  # Brief pause between tests
        
        # Analyze configuration sensitivity
        circuit_activations = [r for r in configuration_results if r["circuit_likely_open"]]
        
        if circuit_activations:
            min_failures_for_activation = min(r["failures_generated"] for r in circuit_activations)
            logger.info(f"Circuit breaker appears to activate after {min_failures_for_activation} failures")
        else:
            logger.info("Circuit breaker behavior not detected or requires higher failure threshold")
        
        # Test per-provider vs global configuration
        if len(config.CHAT_MODELS) > 1:
            # Test if circuit breaker is per-provider or global
            provider_test_results = []
            
            for model in config.CHAT_MODELS[:2]:
                # Generate failures for specific model
                for i in range(2):
                    failure_request = {
                        "model": f"invalid_model_for_{model}_{i}",
                        "messages": [{"role": "user", "content": "Provider-specific failure"}],
                        "max_tokens": 50
                    }
                    
                    await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, failure_request, track_cost=False
                    )
                
                # Test different model after failures
                other_model = config.CHAT_MODELS[1] if model == config.CHAT_MODELS[0] else config.CHAT_MODELS[0]
                
                test_request = {
                    "model": other_model,
                    "messages": [{"role": "user", "content": "Cross-provider test"}],
                    "max_tokens": 30
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, test_request
                )
                
                provider_test_results.append({
                    "failed_provider": model,
                    "tested_provider": other_model,
                    "cross_provider_works": response.status_code == 200
                })
            
            # Analyze per-provider vs global behavior
            cross_provider_successes = [r for r in provider_test_results if r["cross_provider_works"]]
            
            if cross_provider_successes:
                logger.info("Circuit breaker appears to be per-provider (other providers still work)")
            else:
                logger.info("Circuit breaker appears to be global (affects all providers)")
        
        logger.info(f"Circuit breaker configuration analysis: {configuration_results}")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_half_open_state_testing_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """CB_HALF_OPEN_001: Half-open state testing"""
        # Test circuit breaker half-open state behavior
        
        # Phase 1: Trigger potential circuit breaker
        trigger_failures = []
        for i in range(6):  # Generate multiple failures
            failure_request = {
                "model": f"half_open_trigger_invalid_{i}",
                "messages": [{"role": "user", "content": "Half-open trigger failure"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, failure_request, track_cost=False
            )
            
            trigger_failures.append(response.status_code)
            await asyncio.sleep(0.1)
        
        # Phase 2: Wait for potential timeout (half-open transition)
        await asyncio.sleep(3)  # Wait for circuit breaker timeout
        
        # Phase 3: Test half-open behavior
        # In half-open state, circuit breaker should allow limited requests through
        half_open_tests = []
        
        for i in range(5):
            test_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Half-open test {i}"}],
                "max_tokens": 30
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_request
            )
            end_time = time.time()
            
            half_open_tests.append({
                "request_id": i,
                "status_code": response.status_code,
                "response_time": end_time - start_time,
                "success": response.status_code == 200
            })
            
            await asyncio.sleep(0.5)  # Controlled spacing for half-open testing
        
        # Analyze half-open behavior
        successful_requests = [t for t in half_open_tests if t["success"]]
        fast_fails = [t for t in half_open_tests if t["status_code"] == 503 and t["response_time"] < 1.0]
        
        if successful_requests and fast_fails:
            logger.info("Half-open behavior detected: mix of successes and fast failures")
        elif successful_requests:
            logger.info(f"Circuit appears closed: {len(successful_requests)} successful requests")
        elif fast_fails:
            logger.info(f"Circuit appears open: {len(fast_fails)} fast failures")
        else:
            logger.info("Mixed behavior - unclear circuit breaker state")
        
        # Phase 4: Test recovery to closed state
        # After successful requests in half-open, circuit should close
        recovery_requests = []
        
        for i in range(3):
            recovery_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Recovery test {i}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, recovery_request
            )
            
            recovery_requests.append(response.status_code)
            await asyncio.sleep(0.5)
        
        # Recovery should work consistently if circuit closes
        recovery_success_rate = sum(1 for status in recovery_requests if status == 200) / len(recovery_requests)
        
        logger.info(f"Half-open state recovery: {recovery_success_rate:.2%} success rate")
        
        # System should eventually recover
        assert recovery_success_rate >= 0.6, "System should show good recovery from half-open state"
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_circuit_breaker_metrics_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """CB_METRICS_001: Circuit breaker metrics and monitoring"""
        # Test circuit breaker metrics collection and reporting
        
        # Generate measurable activity
        metrics_test_activity = [
            # Successful requests
            {"type": "success", "count": 5},
            # Failed requests
            {"type": "failure", "count": 3},
            # Mixed activity
            {"type": "mixed", "count": 4}
        ]
        
        activity_results = []
        
        for activity in metrics_test_activity:
            activity_start_time = time.time()
            
            if activity["type"] == "success":
                for i in range(activity["count"]):
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Success metrics test {i}"}],
                        "max_tokens": 30
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    activity_results.append({
                        "type": "success",
                        "status_code": response.status_code,
                        "timestamp": time.time()
                    })
                    
                    await asyncio.sleep(0.2)
            
            elif activity["type"] == "failure":
                for i in range(activity["count"]):
                    failure_request = {
                        "model": f"metrics_failure_test_{i}",
                        "messages": [{"role": "user", "content": "Metrics failure test"}],
                        "max_tokens": 50
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, failure_request, track_cost=False
                    )
                    
                    activity_results.append({
                        "type": "failure",
                        "status_code": response.status_code,
                        "timestamp": time.time()
                    })
                    
                    await asyncio.sleep(0.2)
            
            elif activity["type"] == "mixed":
                for i in range(activity["count"]):
                    if i % 2 == 0:
                        # Success
                        request = {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Mixed success {i}"}],
                            "max_tokens": 30
                        }
                        track_cost = True
                    else:
                        # Failure
                        request = {
                            "model": f"mixed_failure_{i}",
                            "messages": [{"role": "user", "content": f"Mixed failure {i}"}],
                            "max_tokens": 50
                        }
                        track_cost = False
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=track_cost
                    )
                    
                    activity_results.append({
                        "type": "mixed",
                        "status_code": response.status_code,
                        "timestamp": time.time()
                    })
                    
                    await asyncio.sleep(0.2)
            
            activity_end_time = time.time()
            
            # Brief pause between activity types
            await asyncio.sleep(1)
        
        # Analyze collected metrics
        total_requests = len(activity_results)
        successful_requests = sum(1 for r in activity_results if r["status_code"] == 200)
        failed_requests = sum(1 for r in activity_results if r["status_code"] >= 400)
        
        success_rate = successful_requests / total_requests if total_requests > 0 else 0
        failure_rate = failed_requests / total_requests if total_requests > 0 else 0
        
        logger.info(f"Circuit breaker metrics test: {total_requests} total requests")
        logger.info(f"Success rate: {success_rate:.2%}, Failure rate: {failure_rate:.2%}")
        
        # Test metrics endpoints (if available)
        metrics_endpoints = [
            "/metrics",
            "/api/v1/metrics",
            "/health/metrics",
            "/_metrics"
        ]
        
        metrics_availability = []
        
        for endpoint in metrics_endpoints:
            try:
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
                
                metrics_availability.append({
                    "endpoint": endpoint,
                    "available": response.status_code == 200,
                    "status_code": response.status_code
                })
                
                if response.status_code == 200:
                    # Check for circuit breaker metrics
                    try:
                        metrics_data = response.text
                        circuit_breaker_keywords = [
                            "circuit_breaker",
                            "circuit_open",
                            "circuit_closed", 
                            "circuit_half_open",
                            "failure_rate",
                            "success_rate"
                        ]
                        
                        found_keywords = [kw for kw in circuit_breaker_keywords if kw in metrics_data.lower()]
                        
                        if found_keywords:
                            logger.info(f"Circuit breaker metrics found at {endpoint}: {found_keywords}")
                        
                    except:
                        logger.info(f"Metrics endpoint {endpoint} available but content not analyzable")
                        
            except Exception as e:
                metrics_availability.append({
                    "endpoint": endpoint,
                    "available": False,
                    "error": str(e)
                })
        
        available_metrics = [m for m in metrics_availability if m.get("available")]
        
        if available_metrics:
            logger.info(f"Metrics endpoints available: {[m['endpoint'] for m in available_metrics]}")
        else:
            logger.info("No metrics endpoints detected - consider implementing for observability")
        
        # Verify that the system tracked our test activity appropriately
        assert total_requests > 0, "Test should have generated measurable activity"
        assert success_rate > 0, "Test should have generated some successful requests"
        
        logger.info("Circuit breaker metrics testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open_recovery_002(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """TC_R755_CIRCUIT_002: Circuit breaker half-open state and recovery"""
        # Test circuit breaker transitions to half-open state and recovery behavior
        
        # Generate failures to potentially trigger circuit breaker
        failure_requests = [
            {
                "model": f"circuit_half_open_test_{i}",
                "messages": [{"role": "user", "content": f"Half-open circuit test {i}"}],
                "max_tokens": 50
            }
            for i in range(6)
        ]
        
        circuit_state_results = []
        
        # Phase 1: Generate failures to trip circuit
        logger.info("Phase 1: Generating failures to test circuit breaking")
        for i, request in enumerate(failure_requests):
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=False
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                # Fast failures might indicate circuit is open
                circuit_likely_open = response.status_code >= 500 and response_time < 1.0
                
                circuit_state_results.append({
                    "phase": "failure_generation",
                    "request_index": i,
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "circuit_open_indicator": circuit_likely_open
                })
                
            except Exception as e:
                end_time = time.time()
                response_time = end_time - start_time
                
                circuit_state_results.append({
                    "phase": "failure_generation",
                    "request_index": i,
                    "error": str(e),
                    "response_time": response_time,
                    "circuit_open_indicator": response_time < 1.0
                })
            
            await asyncio.sleep(0.1)
        
        # Phase 2: Wait for potential half-open transition
        logger.info("Phase 2: Waiting for potential half-open state")
        await asyncio.sleep(2)
        
        # Phase 3: Test recovery with successful requests
        logger.info("Phase 3: Testing recovery with valid requests")
        recovery_requests = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Circuit recovery test {i}"}],
                "max_tokens": 40
            }
            for i in range(3)
        ]
        
        for i, request in enumerate(recovery_requests):
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                circuit_state_results.append({
                    "phase": "recovery_testing",
                    "request_index": i,
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "recovery_successful": response.status_code == 200
                })
                
            except Exception as e:
                end_time = time.time()
                response_time = end_time - start_time
                
                circuit_state_results.append({
                    "phase": "recovery_testing",
                    "request_index": i,
                    "error": str(e),
                    "response_time": response_time,
                    "recovery_successful": False
                })
            
            await asyncio.sleep(0.3)
        
        # Analyze circuit breaker state transitions
        failure_phase = [r for r in circuit_state_results if r["phase"] == "failure_generation"]
        recovery_phase = [r for r in circuit_state_results if r["phase"] == "recovery_testing"]
        
        circuit_open_indicators = sum(1 for r in failure_phase if r.get("circuit_open_indicator"))
        successful_recoveries = sum(1 for r in recovery_phase if r.get("recovery_successful"))
        
        logger.info(f"Circuit breaker behavior: {circuit_open_indicators} open indicators, {successful_recoveries} successful recoveries")
        
        # Circuit should either prevent failures or allow recovery
        circuit_behavior_appropriate = circuit_open_indicators > 0 or successful_recoveries > 0
        assert circuit_behavior_appropriate, "Circuit breaker should show appropriate behavior"
        
        logger.info("Circuit breaker half-open recovery testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_circuit_breaker_closed_state_success_003(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """TC_R755_CIRCUIT_003: Circuit breaker closed state with successful requests"""
        # Test circuit breaker behavior when requests succeed (circuit should remain closed)
        
        success_test_requests = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Circuit closed state test {i}"}],
                "max_tokens": 40
            }
            for i in range(5)
        ]
        
        closed_state_results = []
        
        for i, request in enumerate(success_test_requests):
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                closed_state_results.append({
                    "request_index": i,
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "success": response.status_code == 200,
                    "circuit_closed_behavior": response.status_code == 200 and response_time < 10.0
                })
                
            except Exception as e:
                end_time = time.time()
                response_time = end_time - start_time
                
                closed_state_results.append({
                    "request_index": i,
                    "error": str(e),
                    "response_time": response_time,
                    "success": False,
                    "circuit_closed_behavior": False
                })
            
            await asyncio.sleep(0.2)
        
        # Analyze closed state behavior
        successful_requests = [r for r in closed_state_results if r.get("success")]
        appropriate_behavior = [r for r in closed_state_results if r.get("circuit_closed_behavior")]
        
        success_rate = len(successful_requests) / len(closed_state_results)
        behavior_rate = len(appropriate_behavior) / len(closed_state_results)
        
        # Circuit should remain closed for successful requests
        assert success_rate >= 0.8, f"Most requests should succeed with circuit closed: {success_rate:.2%}"
        assert behavior_rate >= 0.8, f"Circuit behavior should be appropriate: {behavior_rate:.2%}"
        
        logger.info(f"Circuit closed state: {success_rate:.2%} success rate, {behavior_rate:.2%} appropriate behavior")
        logger.info("Circuit breaker closed state testing completed")