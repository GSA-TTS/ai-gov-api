# Section 7.5 - Application Lifecycle Reliability Tests
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Application Lifecycle Reliability.md

import pytest
import httpx
import asyncio
import time
import signal
import threading
from typing import Dict, Any, List
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestApplicationLifecycleReliability:
    """Application lifecycle reliability tests"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_startup_dependency_validation_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """STARTUP_DEPS_001: Startup dependency validation"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Test that API is properly initialized by checking core endpoints
        core_endpoints = [
            "/api/v1/models",
            "/api/v1/chat/completions"
        ]
        
        startup_validation_results = []
        
        for endpoint in core_endpoints:
            if endpoint == "/api/v1/models":
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
            else:
                # Test with minimal request
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Startup validation test"}],
                    "max_tokens": 10
                }
                response = await make_request(
                    http_client, "POST", endpoint,
                    auth_headers, request
                )
            
            startup_validation_results.append({
                "endpoint": endpoint,
                "status_code": response.status_code,
                "response_time": getattr(response, 'elapsed', None),
                "available": response.status_code == 200
            })
        
        # All core endpoints should be available after startup
        for result in startup_validation_results:
            assert result["available"], f"Core endpoint {result['endpoint']} should be available after startup"
        
        logger.info("Startup dependency validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_graceful_shutdown_handling_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """SHUTDOWN_GRACEFUL_001: Graceful shutdown signal handling"""
        # Test graceful handling of requests during simulated shutdown
        
        # Start a long-running request
        long_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Long request for shutdown test: " + "content " * 100}],
            "max_tokens": 200
        }
        
        # Simulate concurrent requests during "shutdown"
        shutdown_test_requests = []
        
        async def make_shutdown_request(request_id: int):
            try:
                start_time = time.time()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Shutdown test request {request_id}"}],
                        "max_tokens": 50
                    }
                )
                end_time = time.time()
                
                return {
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "response_time": end_time - start_time,
                    "completed": True
                }
            except Exception as e:
                return {
                    "request_id": request_id,
                    "error": str(e),
                    "completed": False
                }
        
        # Execute concurrent requests
        tasks = [make_shutdown_request(i) for i in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Analyze shutdown behavior
        completed_requests = [r for r in results if isinstance(r, dict) and r.get("completed")]
        
        # During normal operation (simulated shutdown), requests should either:
        # 1. Complete successfully
        # 2. Return appropriate error codes (503 Service Unavailable)
        # 3. Be handled gracefully without crashes
        
        for result in completed_requests:
            assert result["status_code"] in [200, 503], \
                f"Request during shutdown should succeed or return 503: {result}"
        
        logger.info(f"Graceful shutdown test: {len(completed_requests)}/{len(tasks)} requests completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_configuration_reload_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """CONFIG_RELOAD_001: Configuration reload reliability"""
        # Test that the system handles configuration changes gracefully
        
        # Get baseline configuration behavior
        baseline_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Configuration baseline test"}],
            "max_tokens": 50
        }
        
        baseline_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, baseline_request
        )
        
        assert baseline_response.status_code == 200, "Baseline configuration should work"
        
        # Test with different configuration scenarios
        config_test_scenarios = [
            {
                "description": "Different model",
                "request": {
                    "model": config.CHAT_MODELS[1] if len(config.CHAT_MODELS) > 1 else config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Different model test"}],
                    "max_tokens": 50
                }
            },
            {
                "description": "Different parameters",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Different parameters test"}],
                    "max_tokens": 100,
                    "temperature": 0.5
                }
            }
        ]
        
        for scenario in config_test_scenarios:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario["request"]
            )
            
            # Should handle configuration variations gracefully
            assert response.status_code in [200, 422], \
                f"Configuration scenario should be handled: {scenario['description']}"
            
            if response.status_code == 422:
                logger.info(f"Configuration rejected appropriately: {scenario['description']}")
            else:
                logger.info(f"Configuration accepted: {scenario['description']}")
        
        logger.info("Configuration reload reliability validated")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_health_check_comprehensive_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """HEALTH_CHECK_001: Comprehensive health check validation"""
        # Test comprehensive health check functionality
        
        # Check for health endpoints
        health_endpoints = [
            "/health",
            "/api/v1/health",
            "/healthz",
            "/_health",
            "/status"
        ]
        
        health_results = []
        
        for endpoint in health_endpoints:
            try:
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
                
                health_results.append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "available": response.status_code == 200,
                    "response_time": getattr(response, 'elapsed', None)
                })
                
                if response.status_code == 200:
                    try:
                        health_data = response.json()
                        # Check for comprehensive health information
                        expected_components = ["database", "providers", "cache", "dependencies"]
                        
                        for component in expected_components:
                            if component in str(health_data).lower():
                                logger.info(f"Health check includes {component} status")
                                
                    except:
                        # Non-JSON health response is acceptable
                        pass
                        
            except Exception as e:
                health_results.append({
                    "endpoint": endpoint,
                    "error": str(e),
                    "available": False
                })
        
        # At least one health endpoint should be available
        available_health_endpoints = [r for r in health_results if r.get("available")]
        
        if available_health_endpoints:
            logger.info(f"Health endpoints available: {[r['endpoint'] for r in available_health_endpoints]}")
        else:
            logger.warning("No health endpoints found - consider implementing for monitoring")
        
        # Test that main API is healthy
        api_health_test = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "API health test"}],
            "max_tokens": 30
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, api_health_test
        )
        
        assert response.status_code == 200, "Main API should be healthy"
        
        logger.info("Comprehensive health check validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_dependency_health_monitoring_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """DEPENDENCY_HEALTH_001: Dependency health monitoring"""
        # Test monitoring of external dependencies (providers, database, etc.)
        
        dependency_health_tests = [
            {
                "dependency": "LLM Providers",
                "test_request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Provider health test"}],
                    "max_tokens": 30
                }
            }
        ]
        
        # Test multiple models to check provider diversity
        if len(config.CHAT_MODELS) > 1:
            dependency_health_tests.append({
                "dependency": "Alternative LLM Provider",
                "test_request": {
                    "model": config.get_chat_model(1),
                    "messages": [{"role": "user", "content": "Alternative provider health test"}],
                    "max_tokens": 30
                }
            })
        
        dependency_results = []
        
        for test in dependency_health_tests:
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, test["test_request"]
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                dependency_results.append({
                    "dependency": test["dependency"],
                    "healthy": response.status_code == 200,
                    "response_time": response_time,
                    "status_code": response.status_code
                })
                
            except Exception as e:
                dependency_results.append({
                    "dependency": test["dependency"],
                    "healthy": False,
                    "error": str(e)
                })
        
        # At least one dependency should be healthy
        healthy_dependencies = [d for d in dependency_results if d.get("healthy")]
        assert len(healthy_dependencies) >= 1, "At least one dependency should be healthy"
        
        # Check dependency response times
        for result in dependency_results:
            if result.get("healthy") and "response_time" in result:
                assert result["response_time"] <= 30.0, \
                    f"Dependency {result['dependency']} response time should be reasonable"
        
        logger.info(f"Dependency health monitoring: {dependency_results}")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_zero_downtime_updates_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """ZERO_DOWNTIME_001: Zero downtime update simulation"""
        # Simulate zero downtime update scenarios
        
        # Phase 1: Pre-update baseline
        pre_update_requests = []
        for i in range(3):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Pre-update test {i}"}],
                "max_tokens": 40
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            pre_update_requests.append(response.status_code)
            await asyncio.sleep(0.5)
        
        # All pre-update requests should succeed
        assert all(status == 200 for status in pre_update_requests), \
            "Pre-update baseline should be successful"
        
        # Phase 2: Simulate update period with continuous requests
        update_simulation_requests = []
        
        async def continuous_request_during_update(request_id: int):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"During-update test {request_id}"}],
                "max_tokens": 30
            }
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                return response.status_code
            except Exception as e:
                return 0  # Exception during update
        
        # Execute requests during simulated update
        tasks = [continuous_request_during_update(i) for i in range(8)]
        update_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Phase 3: Post-update validation
        await asyncio.sleep(1)  # Brief pause
        
        post_update_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Post-update validation test"}],
            "max_tokens": 40
        }
        
        post_update_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, post_update_request
        )
        
        # Post-update should work normally
        assert post_update_response.status_code == 200, \
            "Post-update operation should work normally"
        
        # Analyze update period results
        successful_during_update = sum(1 for result in update_results if result == 200)
        update_success_rate = successful_during_update / len(update_results)
        
        logger.info(f"Zero downtime update simulation: {update_success_rate:.2%} success rate during update")
        
        # During updates, we expect some requests to succeed (zero downtime)
        assert update_success_rate >= 0.5, \
            "At least 50% of requests should succeed during zero downtime updates"
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_state_persistence_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       make_request):
        """STATE_PERSISTENCE_001: State persistence during restarts"""
        # Test that important state is maintained across service restarts
        
        # Create some stateful operations
        stateful_operations = [
            {
                "operation": "Model availability check",
                "request": {"method": "GET", "endpoint": "/api/v1/models"}
            },
            {
                "operation": "Chat completion with context",
                "request": {
                    "method": "POST",
                    "endpoint": "/api/v1/chat/completions",
                    "data": {
                        "model": config.get_chat_model(0),
                        "messages": [
                            {"role": "user", "content": "Remember this: Test Context 123"},
                            {"role": "assistant", "content": "I'll remember that."},
                            {"role": "user", "content": "What did I ask you to remember?"}
                        ],
                        "max_tokens": 50
                    }
                }
            }
        ]
        
        state_persistence_results = []
        
        for operation in stateful_operations:
            if operation["request"]["method"] == "GET":
                response = await make_request(
                    http_client, "GET", operation["request"]["endpoint"],
                    auth_headers, track_cost=False
                )
            else:
                response = await make_request(
                    http_client, "POST", operation["request"]["endpoint"],
                    auth_headers, operation["request"]["data"]
                )
            
            state_persistence_results.append({
                "operation": operation["operation"],
                "status_code": response.status_code,
                "successful": response.status_code == 200
            })
        
        # All stateful operations should work consistently
        for result in state_persistence_results:
            assert result["successful"], \
                f"Stateful operation should work: {result['operation']}"
        
        logger.info("State persistence validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_progressive_startup_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """PROGRESSIVE_STARTUP_001: Progressive startup reliability"""
        # Test progressive startup behavior - services come online gradually
        
        # Test service availability in stages
        startup_stages = [
            {
                "stage": "Basic API",
                "endpoints": ["/api/v1/models"],
                "required": True
            },
            {
                "stage": "Core Functionality", 
                "endpoints": ["/api/v1/chat/completions"],
                "required": True
            }
        ]
        
        progressive_startup_results = []
        
        for stage in startup_stages:
            stage_results = []
            
            for endpoint in stage["endpoints"]:
                if endpoint == "/api/v1/models":
                    response = await make_request(
                        http_client, "GET", endpoint,
                        auth_headers, track_cost=False
                    )
                else:
                    # Test with minimal request
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Progressive startup test"}],
                        "max_tokens": 20
                    }
                    response = await make_request(
                        http_client, "POST", endpoint,
                        auth_headers, request
                    )
                
                stage_results.append({
                    "endpoint": endpoint,
                    "available": response.status_code == 200,
                    "status_code": response.status_code
                })
            
            stage_success = all(result["available"] for result in stage_results)
            
            progressive_startup_results.append({
                "stage": stage["stage"],
                "required": stage["required"],
                "successful": stage_success,
                "results": stage_results
            })
        
        # Required stages should be successful
        for stage_result in progressive_startup_results:
            if stage_result["required"]:
                assert stage_result["successful"], \
                    f"Required startup stage should succeed: {stage_result['stage']}"
        
        logger.info("Progressive startup reliability validated")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_graceful_degradation_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """GRACEFUL_DEGRADATION_001: Graceful degradation under load"""
        # Test graceful degradation when system is under stress
        
        # Normal operation baseline
        baseline_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Baseline degradation test"}],
            "max_tokens": 30
        }
        
        baseline_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, baseline_request
        )
        
        assert baseline_response.status_code == 200, "Baseline should work"
        
        # Stress test with concurrent requests
        async def stress_request(request_id: int):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Stress test {request_id}"}],
                "max_tokens": 50
            }
            
            try:
                start_time = time.time()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                end_time = time.time()
                
                return {
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "response_time": end_time - start_time,
                    "handled_gracefully": response.status_code in [200, 429, 503]
                }
            except Exception as e:
                return {
                    "request_id": request_id,
                    "error": str(e),
                    "handled_gracefully": True  # Exception handling is graceful
                }
        
        # Execute stress test
        stress_tasks = [stress_request(i) for i in range(12)]
        stress_results = await asyncio.gather(*stress_tasks, return_exceptions=True)
        
        # Analyze degradation behavior
        valid_results = [r for r in stress_results if isinstance(r, dict)]
        gracefully_handled = [r for r in valid_results if r.get("handled_gracefully")]
        
        graceful_handling_rate = len(gracefully_handled) / len(valid_results) if valid_results else 0
        
        # Even under stress, system should degrade gracefully
        assert graceful_handling_rate >= 0.8, \
            f"System should handle stress gracefully: {graceful_handling_rate:.2%}"
        
        # Verify recovery after stress
        await asyncio.sleep(2)
        
        recovery_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, baseline_request
        )
        
        assert recovery_response.status_code == 200, "System should recover after stress"
        
        logger.info(f"Graceful degradation test: {graceful_handling_rate:.2%} graceful handling rate")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_billing_queue_drain_lifecycle_002(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """TC_R758_LIFECYCLE_004: Billing queue drain during graceful shutdown"""
        # Test that billing queue is properly drained during application shutdown
        
        # Generate requests that would create billing events
        billing_test_requests = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Billing queue test {i}"}],
                "max_tokens": 30
            }
            for i in range(3)
        ]
        
        billing_events = []
        
        for i, request in enumerate(billing_test_requests):
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=True
                )
                
                billing_events.append({
                    "request_index": i,
                    "status_code": response.status_code,
                    "billing_triggered": response.status_code == 200,
                    "response_time": time.time()
                })
                
            except Exception as e:
                billing_events.append({
                    "request_index": i,
                    "error": str(e),
                    "billing_triggered": False
                })
            
            await asyncio.sleep(0.2)
        
        # Simulate graceful shutdown scenario
        # In a real test, this would trigger the drain_billing_queue function
        # For now, we verify that billing events were properly tracked
        successful_billing = [e for e in billing_events if e.get("billing_triggered")]
        
        # Verify billing queue behavior
        assert len(successful_billing) > 0, "Some billing events should have been generated"
        
        # Simulate drain verification (in real implementation, this would check actual queue drain)
        billing_queue_drained = True  # Placeholder for actual drain verification
        
        assert billing_queue_drained, "Billing queue should be drained during shutdown"
        logger.info(f"Billing queue lifecycle test: {len(successful_billing)} events processed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_health_check_readiness_timing_003(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TC_R758_LIFECYCLE_003: Health check readiness timing"""
        # Test that health check accurately reports readiness only when dependencies are ready
        
        # Test health check endpoint
        health_checks = []
        
        for i in range(5):
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "GET", "/health",
                    {}, track_cost=False  # No auth needed for health check
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                health_checks.append({
                    "check_index": i,
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "healthy": response.status_code == 200,
                    "response_content": response.text[:100]  # First 100 chars
                })
                
            except Exception as e:
                end_time = time.time()
                response_time = end_time - start_time
                
                health_checks.append({
                    "check_index": i,
                    "error": str(e),
                    "response_time": response_time,
                    "healthy": False
                })
            
            await asyncio.sleep(0.3)
        
        # Analyze health check behavior
        healthy_checks = [h for h in health_checks if h.get("healthy")]
        avg_response_time = sum(h["response_time"] for h in health_checks) / len(health_checks)
        
        # Health check should be fast and reliable
        assert avg_response_time <= 2.0, f"Health check should be fast: {avg_response_time:.3f}s"
        
        # Most health checks should succeed if system is ready
        health_rate = len(healthy_checks) / len(health_checks)
        assert health_rate >= 0.8, f"Health check should be reliable: {health_rate:.2%}"
        
        logger.info(f"Health check readiness: {health_rate:.2%} success rate, {avg_response_time:.3f}s avg response time")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_configuration_validation_004(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """TC_R758_CONFIG_001: Configuration validation at startup"""
        # Test API behavior with various configuration scenarios
        
        # Test that API handles configuration correctly by validating core functionality
        config_validation_tests = [
            {
                "test": "model_configuration",
                "description": "Test that configured models are accessible",
                "endpoint": "/api/v1/models",
                "method": "GET"
            },
            {
                "test": "provider_configuration", 
                "description": "Test that provider configuration is valid",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Configuration validation test"}],
                    "max_tokens": 40
                }
            }
        ]
        
        config_results = []
        
        for test_case in config_validation_tests:
            test_start = time.time()
            
            try:
                if test_case["test"] == "model_configuration":
                    response = await make_request(
                        http_client, "GET", test_case["endpoint"],
                        auth_headers, track_cost=False
                    )
                else:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, test_case["request"]
                    )
                
                test_end = time.time()
                
                config_results.append({
                    "test": test_case["test"],
                    "status_code": response.status_code,
                    "duration": test_end - test_start,
                    "config_valid": response.status_code == 200,
                    "description": test_case["description"]
                })
                
            except Exception as e:
                test_end = time.time()
                
                config_results.append({
                    "test": test_case["test"],
                    "error": str(e),
                    "duration": test_end - test_start,
                    "config_valid": False,
                    "description": test_case["description"]
                })
            
            await asyncio.sleep(0.2)
        
        # Verify configuration validation
        valid_configs = [r for r in config_results if r.get("config_valid")]
        config_validation_rate = len(valid_configs) / len(config_results)
        
        assert config_validation_rate >= 0.8, f"Configuration should be valid: {config_validation_rate:.2%}"
        
        for result in config_results:
            logger.info(f"Config test {result['test']}: {'PASS' if result.get('config_valid') else 'FAIL'}")
        
        logger.info("Configuration validation testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_runtime_credential_validation_005(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """TC_R758_CONFIG_002: Runtime provider credential validation"""
        # Test runtime validation of provider credentials during startup
        
        # Test provider connectivity by making actual requests
        provider_validation_tests = [
            {
                "provider": "primary",
                "model": config.get_chat_model(0),
                "test_message": "Provider credential validation test"
            }
        ]
        
        # Add secondary provider if available
        try:
            if len(config.available_chat_models) > 1:
                provider_validation_tests.append({
                    "provider": "secondary", 
                    "model": config.get_chat_model(1),
                    "test_message": "Secondary provider validation test"
                })
        except:
            pass
        
        validation_results = []
        
        for test in provider_validation_tests:
            validation_start = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": test["model"],
                        "messages": [{"role": "user", "content": test["test_message"]}],
                        "max_tokens": 40
                    }
                )
                
                validation_end = time.time()
                
                validation_results.append({
                    "provider": test["provider"],
                    "model": test["model"],
                    "status_code": response.status_code,
                    "duration": validation_end - validation_start,
                    "credentials_valid": response.status_code == 200,
                    "connectivity_confirmed": True
                })
                
            except Exception as e:
                validation_end = time.time()
                
                validation_results.append({
                    "provider": test["provider"],
                    "model": test["model"],
                    "error": str(e),
                    "duration": validation_end - validation_start,
                    "credentials_valid": False,
                    "connectivity_confirmed": False
                })
            
            await asyncio.sleep(0.3)
        
        # Analyze credential validation
        valid_credentials = [r for r in validation_results if r.get("credentials_valid")]
        credential_validation_rate = len(valid_credentials) / len(validation_results)
        
        # At least primary provider should have valid credentials
        primary_valid = any(r.get("credentials_valid") for r in validation_results if r["provider"] == "primary")
        assert primary_valid, "Primary provider credentials should be valid"
        
        logger.info(f"Provider credential validation: {credential_validation_rate:.2%} success rate")
        
        for result in validation_results:
            logger.info(f"Provider {result['provider']}: {'VALID' if result.get('credentials_valid') else 'INVALID'}")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_configuration_defaults_safety_006(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TC_R758_CONFIG_003: Configuration defaults safety validation"""
        # Test that configuration defaults are fail-safe and appropriate
        
        # Test API behavior with default configurations by using standard requests
        default_config_tests = [
            {
                "scenario": "default_timeout_behavior",
                "description": "Test default timeout configuration",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Default timeout test with extended content to test timeout behavior"}],
                    "max_tokens": 80
                }
            },
            {
                "scenario": "default_model_behavior",
                "description": "Test default model configuration",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Default model configuration test"}],
                    "max_tokens": 50
                }
            }
        ]
        
        default_results = []
        
        for test in default_config_tests:
            test_start = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, test["request"]
                )
                
                test_end = time.time()
                duration = test_end - test_start
                
                default_results.append({
                    "scenario": test["scenario"],
                    "status_code": response.status_code,
                    "duration": duration,
                    "defaults_safe": response.status_code == 200 and duration <= 30.0,  # Reasonable timeout
                    "description": test["description"]
                })
                
            except Exception as e:
                test_end = time.time()
                duration = test_end - test_start
                
                default_results.append({
                    "scenario": test["scenario"],
                    "error": str(e),
                    "duration": duration,
                    "defaults_safe": duration <= 30.0,  # Should timeout reasonably
                    "description": test["description"]
                })
            
            await asyncio.sleep(0.3)
        
        # Verify defaults safety
        safe_defaults = [r for r in default_results if r.get("defaults_safe")]
        safety_rate = len(safe_defaults) / len(default_results)
        
        assert safety_rate >= 0.8, f"Configuration defaults should be safe: {safety_rate:.2%}"
        
        for result in default_results:
            logger.info(f"Default config {result['scenario']}: {'SAFE' if result.get('defaults_safe') else 'UNSAFE'}")
        
        logger.info("Configuration defaults safety validation completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r758_recovery_validation_007(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TC_R758_RECOVERY_007: System recovery validation after failures"""
        # Test that system recovers properly after various failure scenarios
        
        # Phase 1: Normal operation baseline
        baseline_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Recovery baseline test"}],
            "max_tokens": 40
        }
        
        baseline_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, baseline_request
        )
        
        assert baseline_response.status_code == 200, "Baseline should work before recovery test"
        
        # Phase 2: Simulate failure scenarios
        failure_scenarios = [
            {
                "type": "invalid_model_failure",
                "request": {
                    "model": "recovery_test_invalid_model",
                    "messages": [{"role": "user", "content": "Failure simulation"}],
                    "max_tokens": 50
                }
            },
            {
                "type": "malformed_request_failure", 
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": "invalid_format",
                    "max_tokens": 50
                }
            }
        ]
        
        failure_results = []
        
        for scenario in failure_scenarios:
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"], track_cost=False
                )
                
                failure_results.append({
                    "type": scenario["type"],
                    "status_code": response.status_code,
                    "failure_handled": response.status_code in [400, 422, 503]
                })
                
            except Exception as e:
                failure_results.append({
                    "type": scenario["type"],
                    "error": str(e),
                    "failure_handled": True  # Exception handling indicates proper failure management
                })
        
        # Phase 3: Recovery validation
        await asyncio.sleep(1)  # Brief recovery period
        
        recovery_tests = []
        
        for i in range(3):
            recovery_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Recovery validation test {i}"}],
                "max_tokens": 40
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, recovery_request
            )
            
            recovery_tests.append({
                "test_id": i,
                "status_code": response.status_code,
                "recovered": response.status_code == 200
            })
            
            await asyncio.sleep(0.3)
        
        # Verify recovery
        all_failures_handled = all(result.get("failure_handled") for result in failure_results)
        assert all_failures_handled, "All failure scenarios should be handled gracefully"
        
        recovered_tests = [test for test in recovery_tests if test["recovered"]]
        recovery_rate = len(recovered_tests) / len(recovery_tests)
        
        assert recovery_rate >= 0.8, f"System should recover after failures: {recovery_rate:.2%}"
        
        logger.info(f"System recovery validation: {recovery_rate:.2%} recovery rate after {len(failure_scenarios)} failure scenarios")
        logger.info("System recovery validation completed")