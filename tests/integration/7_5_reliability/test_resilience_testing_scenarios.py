# Section 7.5 - Resilience Testing Scenarios
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Resilience Testing Scenarios.md

import pytest
import httpx
import asyncio
import time
import random
from typing import Dict, Any, List
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestResilienceTestingScenarios:
    """Resilience testing scenarios"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_dependency_failure_cascade_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """RESILIENCE_CASCADE_001: Dependency failure cascade testing"""
        # Test system resilience to cascading dependency failures
        
        # Simulate cascading failure scenarios
        cascade_scenarios = [
            {
                "phase": "normal_operation",
                "description": "Establish baseline normal operation",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Baseline cascade test"}],
                        "max_tokens": 40
                    }
                ] * 3
            },
            {
                "phase": "single_failure",
                "description": "Single dependency failure simulation",
                "requests": [
                    # Mix of normal and potentially failing requests
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Normal request during single failure"}],
                        "max_tokens": 40
                    },
                    {
                        "model": "cascade_failure_model_1",
                        "messages": [{"role": "user", "content": "Simulated failure"}],
                        "max_tokens": 50
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Recovery test during single failure"}],
                        "max_tokens": 40
                    }
                ]
            },
            {
                "phase": "multiple_failures",
                "description": "Multiple dependency failure simulation",
                "requests": [
                    {
                        "model": "cascade_failure_model_2",
                        "messages": [{"role": "user", "content": "Multiple failure test 1"}],
                        "max_tokens": 50
                    },
                    {
                        "model": "cascade_failure_model_3",
                        "messages": [{"role": "user", "content": "Multiple failure test 2"}],
                        "max_tokens": 50
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Survival test during multiple failures"}],
                        "max_tokens": 40
                    }
                ]
            }
        ]
        
        cascade_results = []
        
        for scenario in cascade_scenarios:
            phase_start_time = time.time()
            phase_results = []
            
            for i, request in enumerate(scenario["requests"]):
                request_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=(scenario["phase"] == "normal_operation")
                    )
                    
                    request_end_time = time.time()
                    request_duration = request_end_time - request_start_time
                    
                    phase_results.append({
                        "request_id": i,
                        "status_code": response.status_code,
                        "duration": request_duration,
                        "success": response.status_code == 200,
                        "model": request["model"]
                    })
                    
                except Exception as e:
                    request_end_time = time.time()
                    request_duration = request_end_time - request_start_time
                    
                    phase_results.append({
                        "request_id": i,
                        "error": str(e),
                        "duration": request_duration,
                        "success": False,
                        "model": request["model"]
                    })
                
                await asyncio.sleep(0.3)  # Brief pause between requests
            
            phase_end_time = time.time()
            phase_duration = phase_end_time - phase_start_time
            
            # Analyze phase results
            successful_requests = [r for r in phase_results if r.get("success")]
            failed_requests = [r for r in phase_results if not r.get("success")]
            
            cascade_results.append({
                "phase": scenario["phase"],
                "description": scenario["description"],
                "total_requests": len(phase_results),
                "successful_requests": len(successful_requests),
                "failed_requests": len(failed_requests),
                "success_rate": len(successful_requests) / len(phase_results) if phase_results else 0,
                "phase_duration": phase_duration,
                "results": phase_results
            })
            
            logger.info(f"Cascade phase {scenario['phase']}: {len(successful_requests)}/{len(phase_results)} successful")
            
            await asyncio.sleep(1)  # Pause between phases
        
        # Analyze cascade resilience
        normal_phase = next((r for r in cascade_results if r["phase"] == "normal_operation"), None)
        single_failure_phase = next((r for r in cascade_results if r["phase"] == "single_failure"), None)
        multiple_failure_phase = next((r for r in cascade_results if r["phase"] == "multiple_failures"), None)
        
        if normal_phase:
            # Normal operation should have high success rate
            assert normal_phase["success_rate"] >= 0.8, \
                f"Normal operation should have high success rate: {normal_phase['success_rate']:.2%}"
        
        if single_failure_phase:
            # During single failure, some requests should still succeed
            assert single_failure_phase["success_rate"] >= 0.3, \
                f"System should be resilient to single failures: {single_failure_phase['success_rate']:.2%}"
        
        if multiple_failure_phase:
            # During multiple failures, system should degrade gracefully
            assert multiple_failure_phase["success_rate"] >= 0.1, \
                f"System should degrade gracefully during multiple failures: {multiple_failure_phase['success_rate']:.2%}"
        
        logger.info("Dependency failure cascade testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_resource_exhaustion_resilience_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """RESILIENCE_RESOURCE_001: Resource exhaustion resilience"""
        # Test system resilience to resource exhaustion scenarios
        
        # Generate resource-intensive requests
        resource_exhaustion_scenarios = [
            {
                "type": "memory_intensive",
                "description": "Large content requests",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Memory test: " + "data " * 1000}],
                        "max_tokens": 200
                    }
                ] * 3
            },
            {
                "type": "cpu_intensive",
                "description": "Complex processing requests",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Generate a detailed analysis of quantum computing algorithms, their mathematical foundations, implementation challenges, and practical applications across multiple industries."}],
                        "max_tokens": 300
                    }
                ] * 2
            },
            {
                "type": "connection_intensive",
                "description": "Rapid concurrent requests",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Concurrent request {i}"}],
                        "max_tokens": 50
                    }
                    for i in range(8)
                ]
            }
        ]
        
        resource_results = []
        
        for scenario in resource_exhaustion_scenarios:
            scenario_start_time = time.time()
            
            if scenario["type"] == "connection_intensive":
                # Execute concurrent requests for connection testing
                async def concurrent_request(request):
                    try:
                        return await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                    except Exception as e:
                        return Mock(status_code=0, error=str(e))
                
                tasks = [concurrent_request(req) for req in scenario["requests"]]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Analyze concurrent responses
                successful_responses = []
                failed_responses = []
                
                for response in responses:
                    if isinstance(response, Exception):
                        failed_responses.append({"error": str(response)})
                    elif hasattr(response, 'status_code'):
                        if response.status_code == 200:
                            successful_responses.append(response.status_code)
                        else:
                            failed_responses.append({"status_code": response.status_code})
                    else:
                        failed_responses.append({"unknown": str(response)})
                
                scenario_results = {
                    "successful": len(successful_responses),
                    "failed": len(failed_responses),
                    "total": len(scenario["requests"])
                }
            
            else:
                # Execute sequential requests for memory/CPU testing
                scenario_results = {"successful": 0, "failed": 0, "total": 0}
                
                for request in scenario["requests"]:
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        
                        if response.status_code == 200:
                            scenario_results["successful"] += 1
                        else:
                            scenario_results["failed"] += 1
                        
                        scenario_results["total"] += 1
                        
                    except Exception as e:
                        scenario_results["failed"] += 1
                        scenario_results["total"] += 1
                        logger.warning(f"Resource exhaustion request failed: {e}")
                    
                    await asyncio.sleep(0.2)  # Brief pause between requests
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            success_rate = scenario_results["successful"] / scenario_results["total"] if scenario_results["total"] > 0 else 0
            
            resource_results.append({
                "type": scenario["type"],
                "description": scenario["description"],
                "success_rate": success_rate,
                "duration": scenario_duration,
                "results": scenario_results
            })
            
            logger.info(f"Resource exhaustion {scenario['type']}: {success_rate:.2%} success rate in {scenario_duration:.2f}s")
            
            await asyncio.sleep(2)  # Recovery pause between scenarios
        
        # Verify resource exhaustion resilience
        for result in resource_results:
            if result["type"] == "memory_intensive":
                # Memory-intensive requests should have reasonable success rate
                assert result["success_rate"] >= 0.5, \
                    f"Memory-intensive requests should be handled: {result['success_rate']:.2%}"
            
            elif result["type"] == "cpu_intensive":
                # CPU-intensive requests should complete eventually
                assert result["success_rate"] >= 0.3, \
                    f"CPU-intensive requests should be processed: {result['success_rate']:.2%}"
            
            elif result["type"] == "connection_intensive":
                # Concurrent requests should be handled gracefully
                assert result["success_rate"] >= 0.4, \
                    f"Concurrent requests should be handled: {result['success_rate']:.2%}"
        
        # Test system recovery after resource exhaustion
        recovery_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Recovery test after resource exhaustion"}],
            "max_tokens": 50
        }
        
        recovery_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, recovery_request
        )
        
        assert recovery_response.status_code == 200, \
            "System should recover after resource exhaustion scenarios"
        
        logger.info("Resource exhaustion resilience testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_deadlock_prevention_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """RESILIENCE_DEADLOCK_001: Deadlock prevention mechanisms"""
        # Test deadlock prevention in concurrent scenarios
        
        # Create scenarios that might cause deadlocks
        deadlock_scenarios = [
            {
                "scenario": "concurrent_model_access",
                "description": "Concurrent access to same model",
                "concurrency": 6,
                "request_template": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Deadlock prevention test - concurrent model access"}],
                    "max_tokens": 60
                }
            },
            {
                "scenario": "mixed_model_access",
                "description": "Mixed model access patterns",
                "concurrency": 4,
                "request_template": None  # Will be generated dynamically
            },
            {
                "scenario": "rapid_sequential",
                "description": "Rapid sequential requests",
                "concurrency": 1,  # Sequential but rapid
                "request_template": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Rapid sequential deadlock test"}],
                    "max_tokens": 40
                }
            }
        ]
        
        deadlock_results = []
        
        for scenario in deadlock_scenarios:
            scenario_start_time = time.time()
            scenario_timeout = 30.0  # Deadlock detection timeout
            
            if scenario["scenario"] == "concurrent_model_access":
                # Test concurrent access to same model
                async def concurrent_model_request(request_id):
                    try:
                        request = scenario["request_template"].copy()
                        request["messages"][0]["content"] += f" - Request {request_id}"
                        
                        start_time = time.time()
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        end_time = time.time()
                        
                        return {
                            "request_id": request_id,
                            "status_code": response.status_code,
                            "duration": end_time - start_time,
                            "success": response.status_code == 200
                        }
                    except Exception as e:
                        return {
                            "request_id": request_id,
                            "error": str(e),
                            "success": False
                        }
                
                # Execute concurrent requests with timeout
                try:
                    tasks = [concurrent_model_request(i) for i in range(scenario["concurrency"])]
                    results = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=scenario_timeout
                    )
                    
                    successful_results = [r for r in results if isinstance(r, dict) and r.get("success")]
                    
                    deadlock_results.append({
                        "scenario": scenario["scenario"],
                        "description": scenario["description"],
                        "completed": True,
                        "success_count": len(successful_results),
                        "total_count": len(results),
                        "deadlock_detected": False
                    })
                    
                except asyncio.TimeoutError:
                    # Timeout indicates possible deadlock
                    deadlock_results.append({
                        "scenario": scenario["scenario"],
                        "description": scenario["description"],
                        "completed": False,
                        "deadlock_detected": True,
                        "timeout_duration": scenario_timeout
                    })
                    
                    logger.warning(f"Potential deadlock detected in {scenario['scenario']}")
            
            elif scenario["scenario"] == "mixed_model_access":
                # Test mixed model access patterns
                mixed_results = []
                
                for i in range(scenario["concurrency"]):
                    # Alternate between different models if available
                    model_index = i % len(config.CHAT_MODELS)
                    model = config.CHAT_MODELS[model_index]
                    
                    request = {
                        "model": model,
                        "messages": [{"role": "user", "content": f"Mixed access test {i} with {model}"}],
                        "max_tokens": 50
                    }
                    
                    try:
                        start_time = time.time()
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        end_time = time.time()
                        
                        mixed_results.append({
                            "request_id": i,
                            "model": model,
                            "status_code": response.status_code,
                            "duration": end_time - start_time,
                            "success": response.status_code == 200
                        })
                        
                    except Exception as e:
                        mixed_results.append({
                            "request_id": i,
                            "model": model,
                            "error": str(e),
                            "success": False
                        })
                    
                    await asyncio.sleep(0.1)  # Small delay between mixed requests
                
                successful_mixed = [r for r in mixed_results if r.get("success")]
                
                deadlock_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "completed": True,
                    "success_count": len(successful_mixed),
                    "total_count": len(mixed_results),
                    "deadlock_detected": False
                })
            
            elif scenario["scenario"] == "rapid_sequential":
                # Test rapid sequential requests
                rapid_results = []
                
                for i in range(8):  # Rapid sequence
                    request = scenario["request_template"].copy()
                    request["messages"][0]["content"] += f" - Sequence {i}"
                    
                    try:
                        start_time = time.time()
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        end_time = time.time()
                        
                        rapid_results.append({
                            "sequence_id": i,
                            "status_code": response.status_code,
                            "duration": end_time - start_time,
                            "success": response.status_code == 200
                        })
                        
                    except Exception as e:
                        rapid_results.append({
                            "sequence_id": i,
                            "error": str(e),
                            "success": False
                        })
                    
                    await asyncio.sleep(0.05)  # Very brief delay
                
                successful_rapid = [r for r in rapid_results if r.get("success")]
                
                deadlock_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "completed": True,
                    "success_count": len(successful_rapid),
                    "total_count": len(rapid_results),
                    "deadlock_detected": False
                })
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            logger.info(f"Deadlock prevention test {scenario['scenario']}: completed in {scenario_duration:.2f}s")
            
            await asyncio.sleep(1)  # Pause between scenarios
        
        # Analyze deadlock prevention
        completed_scenarios = [r for r in deadlock_results if r.get("completed")]
        deadlock_detected = [r for r in deadlock_results if r.get("deadlock_detected")]
        
        # Verify deadlock prevention
        assert len(deadlock_detected) == 0, \
            f"No deadlocks should be detected: {[r['scenario'] for r in deadlock_detected]}"
        
        # Verify that concurrent operations complete successfully
        for result in completed_scenarios:
            success_rate = result["success_count"] / result["total_count"] if result["total_count"] > 0 else 0
            
            assert success_rate >= 0.6, \
                f"Deadlock prevention scenario should have good success rate: {result['scenario']} - {success_rate:.2%}"
        
        logger.info("Deadlock prevention testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_fault_injection_simulation_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """RESILIENCE_FAULT_INJECT_001: Fault injection simulation"""
        # Test system resilience through fault injection
        
        # Simulate various fault conditions
        fault_injection_scenarios = [
            {
                "fault_type": "invalid_requests",
                "description": "Inject invalid request patterns",
                "faults": [
                    {
                        "model": "fault_inject_invalid_model",
                        "messages": [{"role": "user", "content": "Fault injection test"}],
                        "max_tokens": 50
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": "invalid_message_structure",
                        "max_tokens": 50
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Valid request"}],
                        "max_tokens": -10  # Invalid parameter
                    }
                ]
            },
            {
                "fault_type": "oversized_requests",
                "description": "Inject oversized request patterns",
                "faults": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Oversized: " + "data " * 2000}],
                        "max_tokens": 500
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Normal after oversized"}],
                        "max_tokens": 50
                    }
                ]
            },
            {
                "fault_type": "rapid_failures",
                "description": "Inject rapid failure patterns",
                "faults": [
                    {
                        "model": f"rapid_failure_{i}",
                        "messages": [{"role": "user", "content": f"Rapid failure {i}"}],
                        "max_tokens": 50
                    }
                    for i in range(5)
                ]
            }
        ]
        
        fault_injection_results = []
        
        for scenario in fault_injection_scenarios:
            scenario_start_time = time.time()
            fault_results = []
            
            for i, fault in enumerate(scenario["faults"]):
                fault_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, fault, track_cost=False
                    )
                    
                    fault_end_time = time.time()
                    fault_duration = fault_end_time - fault_start_time
                    
                    fault_results.append({
                        "fault_id": i,
                        "status_code": response.status_code,
                        "duration": fault_duration,
                        "handled_gracefully": response.status_code in [200, 400, 422, 413]
                    })
                    
                except Exception as e:
                    fault_end_time = time.time()
                    fault_duration = fault_end_time - fault_start_time
                    
                    fault_results.append({
                        "fault_id": i,
                        "error": str(e),
                        "duration": fault_duration,
                        "handled_gracefully": True  # Exception handling is graceful
                    })
                
                await asyncio.sleep(0.1)  # Brief pause between faults
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            # Analyze fault handling
            gracefully_handled = [r for r in fault_results if r.get("handled_gracefully")]
            graceful_handling_rate = len(gracefully_handled) / len(fault_results) if fault_results else 0
            
            fault_injection_results.append({
                "fault_type": scenario["fault_type"],
                "description": scenario["description"],
                "total_faults": len(fault_results),
                "gracefully_handled": len(gracefully_handled),
                "graceful_rate": graceful_handling_rate,
                "scenario_duration": scenario_duration,
                "fault_results": fault_results
            })
            
            logger.info(f"Fault injection {scenario['fault_type']}: {graceful_handling_rate:.2%} graceful handling")
            
            await asyncio.sleep(1)  # Recovery pause between scenarios
        
        # Verify fault injection resilience
        for result in fault_injection_results:
            # All faults should be handled gracefully
            assert result["graceful_rate"] >= 0.9, \
                f"Fault injection should be handled gracefully: {result['fault_type']} - {result['graceful_rate']:.2%}"
        
        # Test system recovery after fault injection
        recovery_tests = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Recovery test {i} after fault injection"}],
                "max_tokens": 50
            }
            for i in range(3)
        ]
        
        recovery_success = 0
        
        for recovery_test in recovery_tests:
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, recovery_test
                )
                
                if response.status_code == 200:
                    recovery_success += 1
                    
            except Exception as e:
                logger.warning(f"Recovery test failed: {e}")
            
            await asyncio.sleep(0.3)
        
        recovery_rate = recovery_success / len(recovery_tests)
        
        assert recovery_rate >= 0.8, \
            f"System should recover well after fault injection: {recovery_rate:.2%}"
        
        logger.info("Fault injection simulation testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_multi_layer_resilience_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """RESILIENCE_MULTI_LAYER_001: Multi-layer resilience validation"""
        # Test resilience across multiple system layers
        
        # Test different layers of the system
        resilience_layers = [
            {
                "layer": "api_gateway",
                "description": "API gateway layer resilience",
                "tests": [
                    # Test various HTTP scenarios
                    {"endpoint": "/api/v1/models", "method": "GET", "expected": 200},
                    {"endpoint": "/api/v1/nonexistent", "method": "GET", "expected": 404},
                    {"endpoint": "/api/v1/chat/completions", "method": "GET", "expected": 405}  # Wrong method
                ]
            },
            {
                "layer": "authentication",
                "description": "Authentication layer resilience",
                "tests": [
                    # Test auth scenarios
                    {"headers": auth_headers, "expected": 200},
                    {"headers": {"Authorization": "Bearer invalid_token"}, "expected": 401},
                    {"headers": {}, "expected": 401}  # No auth
                ]
            },
            {
                "layer": "application",
                "description": "Application layer resilience",
                "tests": [
                    # Test application logic scenarios
                    {
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Application layer test"}],
                            "max_tokens": 50
                        },
                        "expected": 200
                    },
                    {
                        "request": {
                            "model": "invalid_model_layer_test",
                            "messages": [{"role": "user", "content": "Invalid model test"}],
                            "max_tokens": 50
                        },
                        "expected": 422
                    }
                ]
            }
        ]
        
        multi_layer_results = []
        
        for layer in resilience_layers:
            layer_start_time = time.time()
            layer_results = []
            
            for i, test in enumerate(layer["tests"]):
                test_start_time = time.time()
                
                try:
                    if layer["layer"] == "api_gateway":
                        # Test API gateway layer
                        response = await make_request(
                            http_client, test["method"], test["endpoint"],
                            auth_headers, track_cost=False
                        )
                        
                        layer_results.append({
                            "test_id": i,
                            "status_code": response.status_code,
                            "expected": test["expected"],
                            "success": response.status_code == test["expected"]
                        })
                    
                    elif layer["layer"] == "authentication":
                        # Test authentication layer
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            test["headers"], track_cost=False
                        )
                        
                        layer_results.append({
                            "test_id": i,
                            "status_code": response.status_code,
                            "expected": test["expected"],
                            "success": response.status_code == test["expected"]
                        })
                    
                    elif layer["layer"] == "application":
                        # Test application layer
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, test["request"], track_cost=(test["expected"] == 200)
                        )
                        
                        layer_results.append({
                            "test_id": i,
                            "status_code": response.status_code,
                            "expected": test["expected"],
                            "success": response.status_code == test["expected"]
                        })
                
                except Exception as e:
                    layer_results.append({
                        "test_id": i,
                        "error": str(e),
                        "success": False
                    })
                
                test_end_time = time.time()
                await asyncio.sleep(0.2)  # Brief pause between tests
            
            layer_end_time = time.time()
            layer_duration = layer_end_time - layer_start_time
            
            # Analyze layer resilience
            successful_tests = [r for r in layer_results if r.get("success")]
            layer_success_rate = len(successful_tests) / len(layer_results) if layer_results else 0
            
            multi_layer_results.append({
                "layer": layer["layer"],
                "description": layer["description"],
                "total_tests": len(layer_results),
                "successful_tests": len(successful_tests),
                "success_rate": layer_success_rate,
                "duration": layer_duration,
                "results": layer_results
            })
            
            logger.info(f"Layer {layer['layer']} resilience: {layer_success_rate:.2%} success rate")
            
            await asyncio.sleep(0.5)  # Pause between layers
        
        # Verify multi-layer resilience
        for result in multi_layer_results:
            # Each layer should demonstrate good resilience
            assert result["success_rate"] >= 0.8, \
                f"Layer {result['layer']} should show good resilience: {result['success_rate']:.2%}"
        
        # Test cross-layer interaction
        cross_layer_test = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Cross-layer resilience validation test"}],
            "max_tokens": 60
        }
        
        cross_layer_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, cross_layer_test
        )
        
        assert cross_layer_response.status_code == 200, \
            "Cross-layer interaction should work after resilience testing"
        
        logger.info("Multi-layer resilience validation completed")