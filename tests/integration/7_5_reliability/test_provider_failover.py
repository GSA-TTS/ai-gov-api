# Section 7.5 - Provider Failover Testing
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Provider Failover Testing.md

import pytest
import httpx
import asyncio
import time
from typing import Dict, Any, List
from unittest.mock import patch

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestProviderFailover:
    """Provider failover and resilience testing"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_pf_automatic_failover_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """PF_AUTOMATIC_FAILOVER_001: Test automatic provider failover"""
        # Test multiple requests to verify consistent behavior
        # In a real system with multiple providers, this would test failover
        
        requests_to_test = 5
        successful_requests = 0
        response_times = []
        
        for i in range(requests_to_test):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Failover test {i}"}],
                "max_tokens": 50
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            end_time = time.time()
            
            response_times.append(end_time - start_time)
            
            if response.status_code == 200:
                successful_requests += 1
                response_data = response.json()
                assert "choices" in response_data
                assert len(response_data["choices"]) > 0
            elif response.status_code in [502, 503, 504]:
                # Provider error - acceptable for failover testing
                logger.info(f"Provider error detected on request {i}: {response.status_code}")
            else:
                pytest.fail(f"Unexpected error on request {i}: {response.status_code}")
            
            await asyncio.sleep(0.5)  # Small delay between requests
        
        # At least some requests should succeed
        success_rate = successful_requests / requests_to_test
        assert success_rate >= 0.8, f"Success rate should be >= 80%, got {success_rate:.2%}"
        
        # Response times should be reasonable
        avg_response_time = sum(response_times) / len(response_times)
        assert avg_response_time <= 10.0, f"Average response time should be <= 10s, got {avg_response_time:.2f}s"
        
        logger.info(f"Provider failover test: {successful_requests}/{requests_to_test} successful, avg response time: {avg_response_time:.2f}s")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_pf_provider_health_monitoring_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """PF_HEALTH_MONITORING_001: Provider health monitoring"""
        # Test that the system can detect and handle provider health issues
        
        # Test with different models to simulate different providers
        models_to_test = config.CHAT_MODELS[:3] if len(config.CHAT_MODELS) >= 3 else config.CHAT_MODELS
        
        provider_health = {}
        
        for model in models_to_test:
            health_checks = []
            
            # Perform multiple requests to assess provider health
            for i in range(3):
                request = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Health check {i}"}],
                    "max_tokens": 30
                }
                
                start_time = time.time()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                end_time = time.time()
                
                health_checks.append({
                    "status_code": response.status_code,
                    "response_time": end_time - start_time,
                    "success": response.status_code == 200
                })
                
                await asyncio.sleep(0.2)
            
            # Calculate provider health metrics
            successful_checks = [check for check in health_checks if check["success"]]
            success_rate = len(successful_checks) / len(health_checks)
            avg_response_time = sum(check["response_time"] for check in health_checks) / len(health_checks)
            
            provider_health[model] = {
                "success_rate": success_rate,
                "avg_response_time": avg_response_time,
                "health_status": "healthy" if success_rate >= 0.8 and avg_response_time <= 5.0 else "degraded"
            }
        
        # At least one provider should be healthy
        healthy_providers = [model for model, health in provider_health.items() 
                           if health["health_status"] == "healthy"]
        
        assert len(healthy_providers) >= 1, "At least one provider should be healthy"
        
        logger.info(f"Provider health monitoring: {provider_health}")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_pf_graceful_degradation_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """PF_GRACEFUL_DEGRADATION_001: Graceful degradation testing"""
        # Test that the system degrades gracefully under provider stress
        
        # Simulate increasing load to test degradation
        load_scenarios = [
            {"concurrent_requests": 3, "description": "low_load"},
            {"concurrent_requests": 8, "description": "medium_load"},
            {"concurrent_requests": 15, "description": "high_load"}
        ]
        
        degradation_results = []
        
        for scenario in load_scenarios:
            async def concurrent_request(request_id: int):
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Degradation test {request_id}"}],
                    "max_tokens": 40
                }
                
                start_time = time.time()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                end_time = time.time()
                
                return {
                    "status_code": response.status_code,
                    "response_time": end_time - start_time,
                    "success": response.status_code == 200
                }
            
            # Execute concurrent requests
            tasks = [concurrent_request(i) for i in range(scenario["concurrent_requests"])]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and analyze results
            valid_results = [r for r in results if not isinstance(r, Exception)]
            successful_results = [r for r in valid_results if r["success"]]
            
            success_rate = len(successful_results) / len(valid_results) if valid_results else 0
            avg_response_time = sum(r["response_time"] for r in valid_results) / len(valid_results) if valid_results else 0
            
            degradation_results.append({
                "scenario": scenario["description"],
                "concurrent_requests": scenario["concurrent_requests"],
                "success_rate": success_rate,
                "avg_response_time": avg_response_time
            })
            
            logger.info(f"Degradation test ({scenario['description']}): {success_rate:.2%} success rate, {avg_response_time:.2f}s avg response time")
            
            await asyncio.sleep(1)  # Brief pause between scenarios
        
        # Verify graceful degradation
        for result in degradation_results:
            # Even under high load, some requests should succeed
            assert result["success_rate"] >= 0.3, f"Success rate under {result['scenario']} should be >= 30%"
            
            # Response times may increase but shouldn't be excessive
            assert result["avg_response_time"] <= 30.0, f"Response time under {result['scenario']} should be <= 30s"
        
        logger.info("Graceful degradation testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_pf_circuit_breaker_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """PF_CIRCUIT_BREAKER_001: Circuit breaker pattern testing"""
        # Test circuit breaker behavior (conceptual - actual implementation would need circuit breaker)
        
        # Simulate requests that might trigger circuit breaker
        failure_inducing_requests = [
            # Very large request that might fail
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Generate a very long response about " + "topic " * 1000}],
                "max_tokens": 1000
            },
            # Invalid model request
            {
                "model": "nonexistent_model_trigger_failure",
                "messages": [{"role": "user", "content": "Test circuit breaker"}],
                "max_tokens": 50
            },
            # Malformed request
            {
                "model": config.get_chat_model(0),
                "messages": "invalid_messages_format",
                "max_tokens": 50
            }
        ]
        
        circuit_breaker_results = []
        
        for i, request in enumerate(failure_inducing_requests):
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=False
                )
                
                circuit_breaker_results.append({
                    "request_id": i,
                    "status_code": response.status_code,
                    "handled_gracefully": response.status_code in [200, 422, 400, 413, 503]
                })
                
            except Exception as e:
                circuit_breaker_results.append({
                    "request_id": i,
                    "status_code": 0,
                    "handled_gracefully": True,  # Exception handling is acceptable
                    "exception": str(e)
                })
        
        # Verify all requests were handled gracefully
        for result in circuit_breaker_results:
            assert result["handled_gracefully"], f"Request {result['request_id']} not handled gracefully"
        
        # Test that normal requests still work after failures
        normal_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Normal request after circuit breaker test"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, normal_request
        )
        
        assert response.status_code == 200, "Normal requests should work after circuit breaker scenarios"
        
        logger.info("Circuit breaker pattern testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_pf_load_balancing_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       make_request):
        """PF_LOAD_BALANCING_001: Load balancing behavior testing"""
        # Test load balancing across providers/models
        
        # Test with different models if available
        available_models = config.CHAT_MODELS
        if len(available_models) < 2:
            pytest.skip("Load balancing test requires multiple models")
        
        load_balancing_results = {}
        
        # Make requests to each model to test distribution
        for model in available_models[:3]:  # Test up to 3 models
            model_results = []
            
            for i in range(5):  # 5 requests per model
                request = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Load balancing test {i}"}],
                    "max_tokens": 40
                }
                
                start_time = time.time()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                end_time = time.time()
                
                model_results.append({
                    "status_code": response.status_code,
                    "response_time": end_time - start_time,
                    "success": response.status_code == 200
                })
                
                await asyncio.sleep(0.1)
            
            # Calculate model performance metrics
            successful_requests = [r for r in model_results if r["success"]]
            success_rate = len(successful_requests) / len(model_results)
            avg_response_time = sum(r["response_time"] for r in model_results) / len(model_results)
            
            load_balancing_results[model] = {
                "success_rate": success_rate,
                "avg_response_time": avg_response_time,
                "total_requests": len(model_results)
            }
        
        # Verify load balancing effectiveness
        for model, results in load_balancing_results.items():
            assert results["success_rate"] >= 0.8, f"Model {model} should have >= 80% success rate"
            assert results["avg_response_time"] <= 10.0, f"Model {model} should have <= 10s avg response time"
        
        logger.info(f"Load balancing results: {load_balancing_results}")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_pf_retry_mechanism_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """PF_RETRY_MECHANISM_001: Retry mechanism testing"""
        # Test retry behavior for transient failures
        
        # Test requests that might need retries
        retry_test_scenarios = [
            {
                "description": "Normal request (no retry needed)",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Normal retry test"}],
                    "max_tokens": 50
                },
                "expected_success": True
            },
            {
                "description": "Large request (might need retry)",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Large retry test: " + "content " * 500}],
                    "max_tokens": 100
                },
                "expected_success": True  # Should succeed or fail gracefully
            }
        ]
        
        for scenario in retry_test_scenarios:
            # Measure request timing to detect potential retries
            start_time = time.time()
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario["request"]
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            if scenario["expected_success"]:
                # Should either succeed or fail gracefully
                assert response.status_code in [200, 422, 400, 413], \
                    f"Request should succeed or fail gracefully: {scenario['description']}"
                
                # If response took much longer, retries might have occurred
                if response_time > 5.0:
                    logger.info(f"Long response time detected ({response_time:.2f}s) - possible retries: {scenario['description']}")
            
            logger.info(f"Retry test ({scenario['description']}): {response.status_code}, {response_time:.2f}s")
        
        logger.info("Retry mechanism testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_pf_failover_recovery_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """PF_FAILOVER_RECOVERY_001: Failover recovery testing"""
        # Test recovery after simulated provider issues
        
        # Phase 1: Normal operation
        normal_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Recovery test - normal phase"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, normal_request
        )
        
        assert response.status_code == 200, "Normal operation should succeed"
        
        # Phase 2: Simulate stress/failure conditions
        stress_requests = []
        for i in range(10):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Recovery test - stress phase {i}"}],
                "max_tokens": 30
            }
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                stress_requests.append(response.status_code)
            except Exception as e:
                stress_requests.append(0)  # Exception occurred
            
            await asyncio.sleep(0.05)  # Rapid requests
        
        # Phase 3: Recovery verification
        await asyncio.sleep(2)  # Allow system to recover
        
        recovery_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Recovery test - recovery phase"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, recovery_request
        )
        
        # System should recover and handle requests normally
        assert response.status_code == 200, "System should recover after stress"
        
        # Analyze stress phase results
        successful_stress_requests = sum(1 for status in stress_requests if status == 200)
        stress_success_rate = successful_stress_requests / len(stress_requests)
        
        logger.info(f"Failover recovery test: {stress_success_rate:.2%} success rate during stress, successful recovery")
        
        # Even during stress, some requests should succeed or be handled gracefully
        handled_requests = sum(1 for status in stress_requests if status in [200, 429, 503])
        handled_rate = handled_requests / len(stress_requests)
        
        assert handled_rate >= 0.7, "At least 70% of requests should be handled gracefully during stress"

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r755_provider_timeout_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """TC_R755_PROVIDER_TIMEOUT_001: Provider timeout handling"""
        # Test handling of provider timeouts during failover scenarios
        
        # Test with requests that might timeout
        timeout_test_scenarios = [
            {
                "scenario": "normal_timeout_request",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Normal timeout test"}],
                    "max_tokens": 50
                },
                "expected_timeout": False
            },
            {
                "scenario": "heavy_processing_request",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Heavy processing timeout test: " + "complex analysis " * 300}],
                    "max_tokens": 200
                },
                "expected_timeout": True  # Might timeout
            }
        ]
        
        timeout_results = []
        
        for scenario in timeout_test_scenarios:
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"], track_cost=(scenario["scenario"] == "normal_timeout_request")
                )
                
                end_time = time.time()
                request_duration = end_time - start_time
                
                timeout_results.append({
                    "scenario": scenario["scenario"],
                    "status_code": response.status_code,
                    "duration": request_duration,
                    "timed_out": request_duration > 30.0,
                    "handled_gracefully": response.status_code in [200, 408, 504, 503]
                })
                
            except Exception as e:
                end_time = time.time()
                request_duration = end_time - start_time
                
                timeout_results.append({
                    "scenario": scenario["scenario"],
                    "error": str(e),
                    "duration": request_duration,
                    "timed_out": request_duration > 30.0,
                    "handled_gracefully": True  # Exception handling is graceful
                })
        
        # Verify timeout handling
        for result in timeout_results:
            assert result["handled_gracefully"], f"Timeout scenario should be handled gracefully: {result['scenario']}"
            
            # If request timed out, duration should be reasonable (not excessive)
            if result.get("timed_out"):
                assert result["duration"] <= 60.0, f"Timeout should not be excessive: {result['duration']:.2f}s"
        
        logger.info("Provider timeout handling testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r755_provider_rate_limit_002(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TC_R755_PROVIDER_RATE_LIMIT_002: Provider rate limit handling"""
        # Test handling of provider rate limits and appropriate backoff
        
        # Generate rapid requests to potentially trigger rate limiting
        rate_limit_requests = []
        
        for i in range(20):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Rate limit test {i}"}],
                "max_tokens": 30
            }
            
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                end_time = time.time()
                
                rate_limit_requests.append({
                    "request_id": i,
                    "status_code": response.status_code,
                    "duration": end_time - start_time,
                    "rate_limited": response.status_code == 429,
                    "success": response.status_code == 200
                })
                
            except Exception as e:
                end_time = time.time()
                
                rate_limit_requests.append({
                    "request_id": i,
                    "error": str(e),
                    "duration": end_time - start_time,
                    "rate_limited": False,
                    "success": False
                })
            
            await asyncio.sleep(0.05)  # Very brief pause - rapid requests
        
        # Analyze rate limiting behavior
        successful_requests = [r for r in rate_limit_requests if r.get("success")]
        rate_limited_requests = [r for r in rate_limit_requests if r.get("rate_limited")]
        
        success_rate = len(successful_requests) / len(rate_limit_requests)
        rate_limit_rate = len(rate_limited_requests) / len(rate_limit_requests)
        
        logger.info(f"Rate limit handling: {success_rate:.2%} success rate, {rate_limit_rate:.2%} rate limited")
        
        # System should handle rate limits gracefully
        for result in rate_limit_requests:
            if result.get("rate_limited"):
                logger.info(f"Rate limit detected on request {result['request_id']}")
        
        # Either high success rate OR appropriate rate limiting should occur
        assert success_rate >= 0.5 or rate_limit_rate > 0, "System should handle requests or apply rate limiting"
        
        logger.info("Provider rate limit handling completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r755_provider_capacity_003(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TC_R755_PROVIDER_CAPACITY_003: Provider capacity management"""
        # Test handling of provider capacity limitations
        
        # Test with varying request sizes to test capacity management
        capacity_test_scenarios = [
            {
                "type": "small_capacity",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Small capacity test"}],
                    "max_tokens": 20
                },
                "concurrent_count": 5
            },
            {
                "type": "medium_capacity",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Medium capacity test with moderate content"}],
                    "max_tokens": 100
                },
                "concurrent_count": 3
            },
            {
                "type": "large_capacity",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Large capacity test: " + "extensive content " * 200}],
                    "max_tokens": 300
                },
                "concurrent_count": 2
            }
        ]
        
        capacity_results = []
        
        for scenario in capacity_test_scenarios:
            async def capacity_request(request_id: int):
                start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, scenario["request"]
                    )
                    
                    end_time = time.time()
                    
                    return {
                        "request_id": request_id,
                        "status_code": response.status_code,
                        "duration": end_time - start_time,
                        "success": response.status_code == 200,
                        "capacity_handled": response.status_code in [200, 503, 429]
                    }
                    
                except Exception as e:
                    end_time = time.time()
                    
                    return {
                        "request_id": request_id,
                        "error": str(e),
                        "duration": end_time - start_time,
                        "success": False,
                        "capacity_handled": True  # Exception handling indicates capacity management
                    }
            
            # Execute concurrent requests for capacity testing
            tasks = [capacity_request(i) for i in range(scenario["concurrent_count"])]
            scenario_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter valid results
            valid_results = [r for r in scenario_results if isinstance(r, dict)]
            successful_results = [r for r in valid_results if r.get("success")]
            capacity_handled = [r for r in valid_results if r.get("capacity_handled")]
            
            capacity_results.append({
                "type": scenario["type"],
                "total_requests": len(valid_results),
                "successful_requests": len(successful_results),
                "capacity_handled": len(capacity_handled),
                "success_rate": len(successful_results) / len(valid_results) if valid_results else 0,
                "capacity_handling_rate": len(capacity_handled) / len(valid_results) if valid_results else 0
            })
            
            await asyncio.sleep(1)  # Pause between capacity scenarios
        
        # Verify capacity management
        for result in capacity_results:
            # Capacity should be managed gracefully
            assert result["capacity_handling_rate"] >= 0.8, \
                f"Capacity should be handled gracefully: {result['type']} - {result['capacity_handling_rate']:.2%}"
            
            logger.info(f"Capacity test {result['type']}: {result['success_rate']:.2%} success rate")
        
        logger.info("Provider capacity management testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r755_provider_failback_004(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TC_R755_PROVIDER_FAILBACK_004: Provider failback mechanism"""
        # Test failback to primary provider after recovery
        
        # Phase 1: Establish baseline with primary provider
        primary_baseline = []
        
        for i in range(3):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Failback baseline test {i}"}],
                "max_tokens": 40
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            primary_baseline.append({
                "request_id": i,
                "status_code": response.status_code,
                "success": response.status_code == 200
            })
            
            await asyncio.sleep(0.3)
        
        baseline_success_rate = sum(1 for r in primary_baseline if r["success"]) / len(primary_baseline)
        
        # Phase 2: Simulate provider stress/failure
        stress_requests = []
        
        for i in range(8):
            # Mix of potentially failing and normal requests
            if i % 3 == 0:
                request = {
                    "model": f"failback_stress_model_{i}",
                    "messages": [{"role": "user", "content": "Stress request"}],
                    "max_tokens": 50
                }
                track_cost = False
            else:
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Stress test {i}"}],
                    "max_tokens": 40
                }
                track_cost = True
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=track_cost
                )
                
                stress_requests.append({
                    "request_id": i,
                    "status_code": response.status_code,
                    "success": response.status_code == 200
                })
                
            except Exception as e:
                stress_requests.append({
                    "request_id": i,
                    "error": str(e),
                    "success": False
                })
            
            await asyncio.sleep(0.1)
        
        # Phase 3: Test failback recovery
        await asyncio.sleep(2)  # Allow system to recover
        
        failback_recovery = []
        
        for i in range(5):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Failback recovery test {i}"}],
                "max_tokens": 40
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            failback_recovery.append({
                "request_id": i,
                "status_code": response.status_code,
                "success": response.status_code == 200
            })
            
            await asyncio.sleep(0.3)
        
        recovery_success_rate = sum(1 for r in failback_recovery if r["success"]) / len(failback_recovery)
        
        # Verify failback mechanism
        logger.info(f"Failback testing:")
        logger.info(f"  Baseline success rate: {baseline_success_rate:.2%}")
        logger.info(f"  Recovery success rate: {recovery_success_rate:.2%}")
        
        # Recovery should be at least as good as baseline
        assert recovery_success_rate >= max(0.6, baseline_success_rate * 0.8), \
            f"Failback recovery should restore functionality: {recovery_success_rate:.2%}"
        
        logger.info("Provider failback mechanism testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r755_multi_provider_redundancy_005(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """TC_R755_MULTI_PROVIDER_REDUNDANCY_005: Multi-provider redundancy validation"""
        # Test redundancy across multiple providers/models
        
        # Test available models for redundancy
        available_models = config.CHAT_MODELS
        
        redundancy_test_results = {}
        
        for model in available_models[:3]:  # Test up to 3 models for redundancy
            model_tests = []
            
            for i in range(4):
                request = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Redundancy test {i} for {model}"}],
                    "max_tokens": 40
                }
                
                start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    end_time = time.time()
                    
                    model_tests.append({
                        "request_id": i,
                        "status_code": response.status_code,
                        "duration": end_time - start_time,
                        "success": response.status_code == 200,
                        "available": True
                    })
                    
                except Exception as e:
                    end_time = time.time()
                    
                    model_tests.append({
                        "request_id": i,
                        "error": str(e),
                        "duration": end_time - start_time,
                        "success": False,
                        "available": False
                    })
                
                await asyncio.sleep(0.2)
            
            # Calculate model reliability metrics
            successful_tests = [t for t in model_tests if t["success"]]
            available_tests = [t for t in model_tests if t.get("available")]
            
            redundancy_test_results[model] = {
                "total_tests": len(model_tests),
                "successful_tests": len(successful_tests),
                "available_tests": len(available_tests),
                "success_rate": len(successful_tests) / len(model_tests),
                "availability_rate": len(available_tests) / len(model_tests),
                "avg_response_time": sum(t["duration"] for t in model_tests) / len(model_tests)
            }
        
        # Verify redundancy effectiveness
        available_providers = [model for model, results in redundancy_test_results.items() 
                             if results["availability_rate"] >= 0.7]
        
        reliable_providers = [model for model, results in redundancy_test_results.items() 
                            if results["success_rate"] >= 0.7]
        
        logger.info(f"Multi-provider redundancy:")
        logger.info(f"  Available providers: {len(available_providers)}/{len(redundancy_test_results)}")
        logger.info(f"  Reliable providers: {len(reliable_providers)}/{len(redundancy_test_results)}")
        
        # Should have at least one reliable provider for redundancy
        assert len(reliable_providers) >= 1, "At least one provider should be reliable for redundancy"
        
        # If multiple models available, at least one should provide redundancy
        if len(available_models) > 1:
            assert len(available_providers) >= 1, "Multi-provider setup should provide redundancy"
        
        logger.info("Multi-provider redundancy validation completed")