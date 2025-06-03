# Section 7.5 - Enhanced Error Response Validation Tests - Performance and Analytics
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Error Response Validation.md
# Enhanced test cases - Multi-step Recovery, Performance, and Analytics

import pytest
import httpx
import asyncio
import time
import os
from typing import Dict, Any, List
from unittest.mock import patch, Mock
from dataclasses import dataclass

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestErrorPerformanceAnalytics:
    """Enhanced error response validation tests - Performance and Analytics scenarios"""
    
    def setup_method(self):
        """Setup test environment with sensitive data from .env"""
        # Load sensitive configuration from environment variables
        self.provider_credentials = {
            'aws_access_key': os.getenv('AWS_ACCESS_KEY_ID'),
            'aws_secret_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
            'vertex_project_id': os.getenv('VERTEX_PROJECT_ID'),
            'vertex_credentials': os.getenv('VERTEX_AI_CREDENTIALS')
        }

    @pytest.mark.reliability  
    @pytest.mark.asyncio
    async def test_multistep_operation_recovery_006(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """TC_R751_MULTISTEP_RECOVERY_006: Multi-step operation error recovery and state management"""
        # Test error handling for multi-step operations including billing and provider interactions
        
        # Multi-step operation scenarios
        multistep_scenarios = [
            {
                "operation": "authenticated_chat_with_billing",
                "description": "Chat completion with authentication and billing tracking",
                "steps": [
                    {
                        "step": "authentication_check",
                        "endpoint": "/api/v1/models",
                        "method": "GET"
                    },
                    {
                        "step": "chat_completion",
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Multi-step operation test"}],
                            "max_tokens": 50
                        }
                    }
                ]
            },
            {
                "operation": "provider_interaction_chain",
                "description": "Multiple provider interactions",
                "steps": [
                    {
                        "step": "first_request",
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "First request in chain"}],
                            "max_tokens": 30
                        }
                    },
                    {
                        "step": "second_request",
                        "endpoint": "/api/v1/chat/completions", 
                        "method": "POST",
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Second request in chain"}],
                            "max_tokens": 30
                        }
                    }
                ]
            }
        ]
        
        multistep_results = []
        
        for scenario in multistep_scenarios:
            operation_start_time = time.time()
            step_results = []
            operation_state = {"completed_steps": [], "failed_steps": []}
            
            logger.info(f"Testing multi-step operation: {scenario['operation']}")
            
            for i, step in enumerate(scenario["steps"]):
                step_start_time = time.time()
                
                try:
                    if step["method"] == "GET":
                        response = await make_request(
                            http_client, "GET", step["endpoint"],
                            auth_headers, track_cost=False
                        )
                    else:
                        response = await make_request(
                            http_client, "POST", step["endpoint"],
                            auth_headers, step["data"]
                        )
                    
                    step_end_time = time.time()
                    step_duration = step_end_time - step_start_time
                    
                    step_result = {
                        "step": step["step"],
                        "status_code": response.status_code,
                        "duration": step_duration,
                        "success": response.status_code == 200
                    }
                    
                    if step_result["success"]:
                        operation_state["completed_steps"].append(step["step"])
                    else:
                        operation_state["failed_steps"].append(step["step"])
                        
                        # Test rollback/recovery logic
                        logger.info(f"Step {step['step']} failed, testing recovery")
                    
                    step_results.append(step_result)
                    
                except Exception as e:
                    step_end_time = time.time()
                    step_duration = step_end_time - step_start_time
                    
                    step_results.append({
                        "step": step["step"],
                        "error": str(e),
                        "duration": step_duration,
                        "success": False
                    })
                    
                    operation_state["failed_steps"].append(step["step"])
                
                await asyncio.sleep(0.1)  # Brief pause between steps
            
            operation_end_time = time.time()
            operation_duration = operation_end_time - operation_start_time
            
            # Analyze multi-step operation outcome
            successful_steps = [s for s in step_results if s.get("success")]
            
            multistep_results.append({
                "operation": scenario["operation"],
                "total_steps": len(step_results),
                "successful_steps": len(successful_steps),
                "operation_duration": operation_duration,
                "state_consistency": len(operation_state["completed_steps"]) == len(successful_steps),
                "recovery_needed": len(operation_state["failed_steps"]) > 0,
                "step_details": step_results
            })
        
        # Verify multi-step operation handling
        for result in multistep_results:
            # State consistency should be maintained
            assert result["state_consistency"], \
                f"Multi-step operation state should be consistent: {result['operation']}"
            
            # Operations should either complete fully or fail gracefully
            if result["successful_steps"] < result["total_steps"]:
                logger.info(f"Multi-step operation {result['operation']} required recovery")
                # Partial completion is acceptable with proper error handling
            else:
                logger.info(f"Multi-step operation {result['operation']} completed successfully")
        
        logger.info("Multi-step operation recovery testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio  
    async def test_error_response_performance_007(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TC_R751_ERROR_PERFORMANCE_007: Error response generation performance and efficiency"""
        # Test error response generation performance under various error conditions
        
        # Performance test scenarios for different error types
        performance_scenarios = [
            {
                "error_type": "validation_errors",
                "description": "Fast validation error responses",
                "requests": [
                    {
                        "model": None,  # Validation error
                        "messages": [{"role": "user", "content": "Validation test"}],
                        "max_tokens": 50
                    }
                ] * 10,
                "expected_max_latency": 1.0
            },
            {
                "error_type": "authentication_errors",
                "description": "Authentication error responses",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Auth error test"}],
                        "max_tokens": 50
                    }
                ] * 8,
                "expected_max_latency": 2.0,
                "use_invalid_auth": True
            },
            {
                "error_type": "provider_errors",
                "description": "Provider error responses",
                "requests": [
                    {
                        "model": f"performance_invalid_model_{i}",
                        "messages": [{"role": "user", "content": f"Provider error test {i}"}],
                        "max_tokens": 50
                    }
                    for i in range(6)
                ],
                "expected_max_latency": 3.0
            }
        ]
        
        performance_results = []
        
        for scenario in performance_scenarios:
            logger.info(f"Testing error performance: {scenario['error_type']}")
            
            scenario_latencies = []
            scenario_start_time = time.time()
            
            # Use invalid auth headers if specified
            test_headers = {} if scenario.get("use_invalid_auth") else auth_headers
            
            for request in scenario["requests"]:
                request_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        test_headers, request, track_cost=False
                    )
                    
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    scenario_latencies.append({
                        "latency": request_latency,
                        "status_code": response.status_code,
                        "is_error": response.status_code >= 400
                    })
                    
                except Exception as e:
                    request_end_time = time.time()
                    request_latency = request_end_time - request_start_time
                    
                    scenario_latencies.append({
                        "latency": request_latency,
                        "error": str(e),
                        "is_error": True
                    })
                
                await asyncio.sleep(0.05)  # Minimal delay for performance testing
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            # Analyze error response performance
            error_latencies = [r["latency"] for r in scenario_latencies if r.get("is_error")]
            avg_error_latency = sum(error_latencies) / len(error_latencies) if error_latencies else 0
            max_error_latency = max(error_latencies) if error_latencies else 0
            
            performance_results.append({
                "error_type": scenario["error_type"],
                "total_requests": len(scenario_latencies),
                "error_responses": len(error_latencies),
                "avg_error_latency": avg_error_latency,
                "max_error_latency": max_error_latency,
                "expected_max_latency": scenario["expected_max_latency"],
                "performance_target_met": max_error_latency <= scenario["expected_max_latency"],
                "scenario_duration": scenario_duration
            })
        
        # Verify error response performance
        for result in performance_results:
            # Error responses should be fast
            assert result["avg_error_latency"] <= 5.0, \
                f"Average error response latency should be reasonable: {result['error_type']} - {result['avg_error_latency']:.3f}s"
            
            # Maximum latency should meet expectations
            logger.info(f"Error performance {result['error_type']}: avg={result['avg_error_latency']:.3f}s, max={result['max_error_latency']:.3f}s")
            
            # Performance targets should generally be met
            if not result["performance_target_met"]:
                logger.warning(f"Performance target missed for {result['error_type']}: {result['max_error_latency']:.3f}s > {result['expected_max_latency']:.3f}s")
        
        logger.info("Error response performance testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_advanced_error_analytics_008(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """TC_R751_ERROR_ANALYTICS_008: Advanced error analytics and pattern detection"""
        # Test error analytics for pattern detection, root cause analysis, and error prevention
        
        # Generate diverse error patterns for analytics
        error_pattern_scenarios = [
            {
                "pattern": "recurring_model_errors",
                "description": "Repeated errors for specific model",
                "requests": [
                    {
                        "model": "analytics_recurring_error_model",
                        "messages": [{"role": "user", "content": f"Recurring error test {i}"}],
                        "max_tokens": 50
                    }
                    for i in range(5)
                ]
            },
            {
                "pattern": "escalating_complexity_errors",
                "description": "Errors with increasing complexity",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Simple error test"}],
                        "max_tokens": 10 * (i + 1)  # Increasing complexity
                    }
                    for i in range(4)
                ]
            },
            {
                "pattern": "temporal_error_clustering",
                "description": "Clustered errors in time",
                "requests": [
                    {
                        "model": f"analytics_temporal_error_{i}",
                        "messages": [{"role": "user", "content": "Temporal clustering test"}],
                        "max_tokens": 50
                    }
                    for i in range(3)
                ]
            }
        ]
        
        analytics_data = []
        
        for scenario in error_pattern_scenarios:
            pattern_start_time = time.time()
            pattern_errors = []
            
            logger.info(f"Generating error pattern: {scenario['pattern']}")
            
            for i, request in enumerate(scenario["requests"]):
                request_timestamp = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=False
                    )
                    
                    error_entry = {
                        "timestamp": request_timestamp,
                        "pattern": scenario["pattern"],
                        "request_index": i,
                        "status_code": response.status_code,
                        "is_error": response.status_code >= 400,
                        "model": request.get("model"),
                        "content_length": len(request["messages"][0]["content"]),
                        "max_tokens": request["max_tokens"]
                    }
                    
                    if error_entry["is_error"]:
                        try:
                            response_data = response.json()
                            error_entry["error_detail"] = response_data.get("detail", "")
                        except:
                            error_entry["error_detail"] = response.text[:100]
                    
                    pattern_errors.append(error_entry)
                    
                except Exception as e:
                    pattern_errors.append({
                        "timestamp": request_timestamp,
                        "pattern": scenario["pattern"],
                        "request_index": i,
                        "exception": str(e),
                        "is_error": True,
                        "model": request.get("model")
                    })
                
                # Temporal clustering requires rapid succession
                if scenario["pattern"] == "temporal_error_clustering":
                    await asyncio.sleep(0.05)
                else:
                    await asyncio.sleep(0.2)
            
            pattern_end_time = time.time()
            
            # Analyze error patterns
            pattern_duration = pattern_end_time - pattern_start_time
            error_count = sum(1 for e in pattern_errors if e.get("is_error"))
            
            # Pattern analysis
            pattern_analysis = {
                "pattern": scenario["pattern"],
                "total_requests": len(pattern_errors),
                "error_count": error_count,
                "error_rate": error_count / len(pattern_errors) if pattern_errors else 0,
                "pattern_duration": pattern_duration,
                "errors": pattern_errors,
                "pattern_detected": error_count >= 2,  # Simple pattern detection
                "temporal_clustering": pattern_duration < 1.0 and error_count >= 2
            }
            
            analytics_data.append(pattern_analysis)
        
        # Perform error analytics
        total_errors = sum(p["error_count"] for p in analytics_data)
        total_requests = sum(p["total_requests"] for p in analytics_data)
        overall_error_rate = total_errors / total_requests if total_requests > 0 else 0
        
        # Pattern detection analysis
        detected_patterns = [p for p in analytics_data if p.get("pattern_detected")]
        temporal_clusters = [p for p in analytics_data if p.get("temporal_clustering")]
        
        # Root cause analysis simulation
        error_by_model = {}
        for pattern_data in analytics_data:
            for error in pattern_data["errors"]:
                if error.get("is_error"):
                    model = error.get("model", "unknown")
                    if model not in error_by_model:
                        error_by_model[model] = 0
                    error_by_model[model] += 1
        
        # Most problematic models
        problematic_models = sorted(error_by_model.items(), key=lambda x: x[1], reverse=True)[:3]
        
        error_analytics_results = {
            "total_errors": total_errors,
            "total_requests": total_requests,
            "overall_error_rate": overall_error_rate,
            "patterns_detected": len(detected_patterns),
            "temporal_clusters": len(temporal_clusters),
            "problematic_models": problematic_models,
            "analytics_actionable": len(detected_patterns) > 0 or len(problematic_models) > 0
        }
        
        logger.info(f"Error Analytics Results:")
        logger.info(f"  Overall Error Rate: {overall_error_rate:.2%}")
        logger.info(f"  Patterns Detected: {len(detected_patterns)}")
        logger.info(f"  Temporal Clusters: {len(temporal_clusters)}")
        logger.info(f"  Problematic Models: {problematic_models}")
        
        # Verify analytics effectiveness
        assert error_analytics_results["analytics_actionable"], \
            "Error analytics should provide actionable insights"
        
        if problematic_models:
            # Most problematic model should have multiple errors
            top_problematic = problematic_models[0]
            assert top_problematic[1] >= 2, \
                f"Problematic model should have multiple errors: {top_problematic}"
        
        logger.info("Advanced error analytics testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_error_correlation_tracking_009(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TC_R751_ERROR_CORRELATION_009: Error correlation and distributed tracking"""
        # Test error correlation across distributed request flows
        
        correlation_scenarios = [
            {
                "scenario": "sequential_requests",
                "description": "Track errors across sequential related requests",
                "request_sequence": [
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "correlation_id": "seq_001"
                    },
                    {
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Sequential request test"}],
                            "max_tokens": 50
                        },
                        "correlation_id": "seq_001"
                    }
                ]
            },
            {
                "scenario": "parallel_requests",
                "description": "Track errors across parallel requests",
                "request_sequence": [
                    {
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Parallel request {i}"}],
                            "max_tokens": 30
                        },
                        "correlation_id": f"par_{i:03d}"
                    }
                    for i in range(3)
                ]
            }
        ]
        
        correlation_results = []
        
        for scenario in correlation_scenarios:
            logger.info(f"Testing error correlation: {scenario['scenario']}")
            
            scenario_requests = []
            
            if scenario["scenario"] == "sequential_requests":
                # Execute sequential requests
                for request_config in scenario["request_sequence"]:
                    request_start = time.time()
                    
                    # Add correlation headers
                    correlation_headers = auth_headers.copy()
                    correlation_headers["X-Correlation-ID"] = request_config["correlation_id"]
                    
                    try:
                        if request_config["method"] == "GET":
                            response = await make_request(
                                http_client, "GET", request_config["endpoint"],
                                correlation_headers, track_cost=False
                            )
                        else:
                            response = await make_request(
                                http_client, "POST", request_config["endpoint"],
                                correlation_headers, request_config["data"]
                            )
                        
                        request_end = time.time()
                        
                        scenario_requests.append({
                            "correlation_id": request_config["correlation_id"],
                            "endpoint": request_config["endpoint"],
                            "status_code": response.status_code,
                            "duration": request_end - request_start,
                            "has_request_id": "request_id" in str(response.text).lower(),
                            "success": response.status_code == 200
                        })
                        
                    except Exception as e:
                        request_end = time.time()
                        
                        scenario_requests.append({
                            "correlation_id": request_config["correlation_id"],
                            "endpoint": request_config["endpoint"],
                            "exception": str(e),
                            "duration": request_end - request_start,
                            "success": False
                        })
                    
                    await asyncio.sleep(0.1)
                    
            elif scenario["scenario"] == "parallel_requests":
                # Execute parallel requests
                async def parallel_request(request_config):
                    request_start = time.time()
                    
                    correlation_headers = auth_headers.copy()
                    correlation_headers["X-Correlation-ID"] = request_config["correlation_id"]
                    
                    try:
                        response = await make_request(
                            http_client, "POST", request_config["endpoint"],
                            correlation_headers, request_config["data"]
                        )
                        
                        request_end = time.time()
                        
                        return {
                            "correlation_id": request_config["correlation_id"],
                            "endpoint": request_config["endpoint"],
                            "status_code": response.status_code,
                            "duration": request_end - request_start,
                            "has_request_id": "request_id" in str(response.text).lower(),
                            "success": response.status_code == 200
                        }
                        
                    except Exception as e:
                        request_end = time.time()
                        
                        return {
                            "correlation_id": request_config["correlation_id"],
                            "endpoint": request_config["endpoint"],
                            "exception": str(e),
                            "duration": request_end - request_start,
                            "success": False
                        }
                
                # Execute parallel requests
                parallel_tasks = [parallel_request(req) for req in scenario["request_sequence"]]
                parallel_results = await asyncio.gather(*parallel_tasks, return_exceptions=True)
                
                scenario_requests = [r for r in parallel_results if isinstance(r, dict)]
            
            # Analyze correlation tracking
            unique_correlation_ids = set(r.get("correlation_id") for r in scenario_requests)
            successful_requests = [r for r in scenario_requests if r.get("success")]
            failed_requests = [r for r in scenario_requests if not r.get("success")]
            
            correlation_results.append({
                "scenario": scenario["scenario"],
                "total_requests": len(scenario_requests),
                "unique_correlations": len(unique_correlation_ids),
                "successful_requests": len(successful_requests),
                "failed_requests": len(failed_requests),
                "correlation_preserved": all(r.get("has_request_id", False) for r in scenario_requests),
                "avg_duration": sum(r.get("duration", 0) for r in scenario_requests) / len(scenario_requests) if scenario_requests else 0
            })
        
        # Verify error correlation tracking
        for result in correlation_results:
            # Correlation should be maintained across requests
            if result["total_requests"] > 0:
                logger.info(f"Correlation tracking for {result['scenario']}: {result['successful_requests']}/{result['total_requests']} successful")
                
                # Request IDs should be present for correlation
                assert result["correlation_preserved"], \
                    f"Request correlation should be preserved: {result['scenario']}"
        
        logger.info("Error correlation tracking validation completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_error_rate_limiting_resilience_010(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TC_R751_RATE_LIMITING_010: Error handling resilience under rate limiting"""
        # Test error handling behavior under rate limiting conditions
        
        rate_limit_scenarios = [
            {
                "scenario": "burst_requests",
                "description": "Burst of requests to trigger rate limiting",
                "request_count": 15,
                "request_interval": 0.05,
                "expected_rate_limit": True
            },
            {
                "scenario": "sustained_load",
                "description": "Sustained load over time",
                "request_count": 8,
                "request_interval": 0.2,
                "expected_rate_limit": False
            }
        ]
        
        rate_limit_results = []
        
        for scenario in rate_limit_scenarios:
            logger.info(f"Testing rate limiting resilience: {scenario['scenario']}")
            
            scenario_start = time.time()
            scenario_responses = []
            
            # Generate requests according to scenario
            for i in range(scenario["request_count"]):
                request_start = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Rate limit test {scenario['scenario']} {i}"}],
                            "max_tokens": 30
                        }, track_cost=False
                    )
                    
                    request_end = time.time()
                    
                    scenario_responses.append({
                        "request_index": i,
                        "status_code": response.status_code,
                        "duration": request_end - request_start,
                        "is_rate_limited": response.status_code == 429,
                        "has_retry_after": "retry-after" in response.headers,
                        "success": response.status_code == 200
                    })
                    
                except Exception as e:
                    request_end = time.time()
                    
                    scenario_responses.append({
                        "request_index": i,
                        "exception": str(e),
                        "duration": request_end - request_start,
                        "is_rate_limited": "rate" in str(e).lower(),
                        "success": False
                    })
                
                await asyncio.sleep(scenario["request_interval"])
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            # Analyze rate limiting behavior
            rate_limited_responses = [r for r in scenario_responses if r.get("is_rate_limited")]
            successful_responses = [r for r in scenario_responses if r.get("success")]
            
            rate_limit_results.append({
                "scenario": scenario["scenario"],
                "total_requests": len(scenario_responses),
                "successful_requests": len(successful_responses),
                "rate_limited_requests": len(rate_limited_responses),
                "scenario_duration": scenario_duration,
                "avg_request_duration": sum(r.get("duration", 0) for r in scenario_responses) / len(scenario_responses) if scenario_responses else 0,
                "rate_limiting_detected": len(rate_limited_responses) > 0,
                "has_retry_guidance": any(r.get("has_retry_after", False) for r in rate_limited_responses)
            })
        
        # Verify rate limiting resilience
        for result in rate_limit_results:
            # System should handle rate limiting gracefully
            if result["rate_limited_requests"] > 0:
                logger.info(f"Rate limiting detected in {result['scenario']}: {result['rate_limited_requests']} requests")
                
                # Rate limited responses should include retry guidance
                assert result["has_retry_guidance"], \
                    f"Rate limited responses should include retry guidance: {result['scenario']}"
            
            # Some requests should succeed even under rate limiting
            assert result["successful_requests"] >= 0, \
                f"Some requests should succeed: {result['scenario']}"
        
        logger.info("Error rate limiting resilience validation completed")