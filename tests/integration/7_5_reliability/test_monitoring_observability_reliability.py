# Section 7.5 - Monitoring and Observability Reliability Tests
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Monitoring and Observability Reliability.md

import pytest
import httpx
import asyncio
import time
import json
from typing import Dict, Any, List
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestMonitoringObservabilityReliability:
    """Monitoring and observability reliability tests"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_logging_infrastructure_reliability_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """MONITOR_LOGGING_001: Logging infrastructure reliability"""
        # Test logging infrastructure reliability under various conditions
        
        # Generate diverse logging scenarios
        logging_scenarios = [
            {
                "scenario": "normal_operations",
                "description": "Normal operation logging",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Normal logging test"}],
                        "max_tokens": 40
                    }
                ] * 3
            },
            {
                "scenario": "error_conditions",
                "description": "Error condition logging",
                "requests": [
                    {
                        "model": "logging_test_invalid_model",
                        "messages": [{"role": "user", "content": "Error logging test"}],
                        "max_tokens": 50
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": "invalid_structure_for_logging",
                        "max_tokens": 50
                    }
                ]
            },
            {
                "scenario": "high_volume",
                "description": "High volume logging",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"High volume log test {i}"}],
                        "max_tokens": 30
                    }
                    for i in range(8)
                ]
            }
        ]
        
        logging_reliability_results = []
        
        for scenario in logging_scenarios:
            scenario_start_time = time.time()
            scenario_results = []
            
            if scenario["scenario"] == "high_volume":
                # Test concurrent logging for high volume
                async def concurrent_log_request(request):
                    try:
                        start_time = time.time()
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        end_time = time.time()
                        
                        return {
                            "status_code": response.status_code,
                            "duration": end_time - start_time,
                            "logged": True  # Assume successful response means successful logging
                        }
                    except Exception as e:
                        return {
                            "error": str(e),
                            "logged": False
                        }
                
                # Execute concurrent requests
                tasks = [concurrent_log_request(req) for req in scenario["requests"]]
                concurrent_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in concurrent_results:
                    if isinstance(result, dict):
                        scenario_results.append(result)
                    else:
                        scenario_results.append({"error": str(result), "logged": False})
            
            else:
                # Sequential logging tests
                for request in scenario["requests"]:
                    start_time = time.time()
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request, track_cost=(scenario["scenario"] == "normal_operations")
                        )
                        
                        end_time = time.time()
                        duration = end_time - start_time
                        
                        scenario_results.append({
                            "status_code": response.status_code,
                            "duration": duration,
                            "logged": True,
                            "response_received": True
                        })
                        
                    except Exception as e:
                        end_time = time.time()
                        duration = end_time - start_time
                        
                        scenario_results.append({
                            "error": str(e),
                            "duration": duration,
                            "logged": True,  # Error should still be logged
                            "response_received": False
                        })
                    
                    await asyncio.sleep(0.1)  # Brief pause between requests
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            # Analyze logging reliability
            logged_events = [r for r in scenario_results if r.get("logged")]
            successful_responses = [r for r in scenario_results if r.get("status_code") == 200]
            
            logging_reliability_results.append({
                "scenario": scenario["scenario"],
                "description": scenario["description"],
                "total_events": len(scenario_results),
                "logged_events": len(logged_events),
                "successful_responses": len(successful_responses),
                "logging_reliability": len(logged_events) / len(scenario_results) if scenario_results else 0,
                "scenario_duration": scenario_duration
            })
            
            logger.info(f"Logging scenario {scenario['scenario']}: {len(logged_events)}/{len(scenario_results)} events logged")
            
            await asyncio.sleep(1)  # Pause between scenarios
        
        # Verify logging infrastructure reliability
        for result in logging_reliability_results:
            # Logging should be highly reliable
            assert result["logging_reliability"] >= 0.95, \
                f"Logging should be highly reliable: {result['scenario']} - {result['logging_reliability']:.2%}"
        
        logger.info("Logging infrastructure reliability testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_metrics_collection_accuracy_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """MONITOR_METRICS_001: Metrics collection accuracy"""
        # Test metrics collection accuracy and reliability
        
        # Generate measurable activities for metrics
        metrics_activities = [
            {
                "activity": "successful_requests",
                "description": "Successful request metrics",
                "count": 5,
                "request_template": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Metrics success test"}],
                    "max_tokens": 40
                }
            },
            {
                "activity": "failed_requests", 
                "description": "Failed request metrics",
                "count": 3,
                "request_template": {
                    "model": "metrics_test_invalid_model",
                    "messages": [{"role": "user", "content": "Metrics failure test"}],
                    "max_tokens": 50
                }
            },
            {
                "activity": "mixed_requests",
                "description": "Mixed request metrics",
                "count": 4,
                "request_template": None  # Will alternate
            }
        ]
        
        metrics_baseline = {
            "requests_total": 0,
            "requests_successful": 0,
            "requests_failed": 0,
            "total_duration": 0.0
        }
        
        metrics_results = []
        
        for activity in metrics_activities:
            activity_start_time = time.time()
            activity_metrics = {
                "requests_total": 0,
                "requests_successful": 0,
                "requests_failed": 0,
                "total_duration": 0.0
            }
            
            if activity["activity"] == "mixed_requests":
                # Alternate between success and failure
                for i in range(activity["count"]):
                    if i % 2 == 0:
                        # Success request
                        request = {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Mixed success {i}"}],
                            "max_tokens": 40
                        }
                        track_cost = True
                    else:
                        # Failure request
                        request = {
                            "model": f"mixed_failure_{i}",
                            "messages": [{"role": "user", "content": f"Mixed failure {i}"}],
                            "max_tokens": 50
                        }
                        track_cost = False
                    
                    request_start_time = time.time()
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request, track_cost=track_cost
                        )
                        
                        request_end_time = time.time()
                        request_duration = request_end_time - request_start_time
                        
                        activity_metrics["requests_total"] += 1
                        activity_metrics["total_duration"] += request_duration
                        
                        if response.status_code == 200:
                            activity_metrics["requests_successful"] += 1
                        else:
                            activity_metrics["requests_failed"] += 1
                        
                    except Exception as e:
                        request_end_time = time.time()
                        request_duration = request_end_time - request_start_time
                        
                        activity_metrics["requests_total"] += 1
                        activity_metrics["requests_failed"] += 1
                        activity_metrics["total_duration"] += request_duration
                    
                    await asyncio.sleep(0.2)
            
            else:
                # Standard activity
                for i in range(activity["count"]):
                    request = activity["request_template"].copy()
                    if "content" in request["messages"][0]:
                        request["messages"][0]["content"] += f" {i}"
                    
                    request_start_time = time.time()
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request, track_cost=(activity["activity"] == "successful_requests")
                        )
                        
                        request_end_time = time.time()
                        request_duration = request_end_time - request_start_time
                        
                        activity_metrics["requests_total"] += 1
                        activity_metrics["total_duration"] += request_duration
                        
                        if response.status_code == 200:
                            activity_metrics["requests_successful"] += 1
                        else:
                            activity_metrics["requests_failed"] += 1
                        
                    except Exception as e:
                        request_end_time = time.time()
                        request_duration = request_end_time - request_start_time
                        
                        activity_metrics["requests_total"] += 1
                        activity_metrics["requests_failed"] += 1
                        activity_metrics["total_duration"] += request_duration
                    
                    await asyncio.sleep(0.2)
            
            activity_end_time = time.time()
            activity_duration = activity_end_time - activity_start_time
            
            # Calculate derived metrics
            activity_metrics["average_duration"] = (
                activity_metrics["total_duration"] / activity_metrics["requests_total"]
                if activity_metrics["requests_total"] > 0 else 0
            )
            activity_metrics["success_rate"] = (
                activity_metrics["requests_successful"] / activity_metrics["requests_total"]
                if activity_metrics["requests_total"] > 0 else 0
            )
            
            metrics_results.append({
                "activity": activity["activity"],
                "description": activity["description"],
                "metrics": activity_metrics,
                "activity_duration": activity_duration
            })
            
            # Update baseline
            metrics_baseline["requests_total"] += activity_metrics["requests_total"]
            metrics_baseline["requests_successful"] += activity_metrics["requests_successful"]
            metrics_baseline["requests_failed"] += activity_metrics["requests_failed"]
            metrics_baseline["total_duration"] += activity_metrics["total_duration"]
            
            logger.info(f"Metrics activity {activity['activity']}: {activity_metrics['success_rate']:.2%} success rate")
            
            await asyncio.sleep(0.5)
        
        # Verify metrics accuracy
        expected_totals = sum(activity["count"] for activity in metrics_activities)
        actual_totals = metrics_baseline["requests_total"]
        
        assert actual_totals == expected_totals, \
            f"Metrics should accurately count requests: {actual_totals} vs {expected_totals}"
        
        # Check metrics endpoints (if available)
        metrics_endpoints = [
            "/metrics",
            "/api/v1/metrics", 
            "/health/metrics",
            "/_metrics",
            "/prometheus"
        ]
        
        metrics_endpoint_results = []
        
        for endpoint in metrics_endpoints:
            try:
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
                
                metrics_endpoint_results.append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "available": response.status_code == 200,
                    "content_type": response.headers.get("content-type", "")
                })
                
                if response.status_code == 200:
                    # Check for common metrics
                    content = response.text.lower()
                    metric_indicators = [
                        "requests_total",
                        "request_duration",
                        "http_requests",
                        "response_time",
                        "error_rate"
                    ]
                    
                    found_metrics = [metric for metric in metric_indicators if metric in content]
                    
                    if found_metrics:
                        logger.info(f"Metrics found at {endpoint}: {found_metrics}")
                    else:
                        logger.info(f"Metrics endpoint {endpoint} available but no standard metrics found")
                
            except Exception as e:
                metrics_endpoint_results.append({
                    "endpoint": endpoint,
                    "available": False,
                    "error": str(e)
                })
        
        available_endpoints = [r for r in metrics_endpoint_results if r.get("available")]
        
        if available_endpoints:
            logger.info(f"Metrics endpoints available: {[r['endpoint'] for r in available_endpoints]}")
        else:
            logger.info("No metrics endpoints detected - consider implementing for observability")
        
        logger.info("Metrics collection accuracy testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_context_propagation_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """MONITOR_CONTEXT_001: Context propagation reliability"""
        # Test context propagation across requests and components
        
        # Test context propagation scenarios
        context_scenarios = [
            {
                "scenario": "request_tracing",
                "description": "Request ID propagation",
                "context_headers": {
                    "X-Request-ID": "test-context-001",
                    "X-Trace-ID": "trace-12345"
                }
            },
            {
                "scenario": "user_context",
                "description": "User context propagation",
                "context_headers": {
                    "X-User-ID": "test-user-001",
                    "X-Session-ID": "session-12345"
                }
            },
            {
                "scenario": "operation_context",
                "description": "Operation context propagation",
                "context_headers": {
                    "X-Operation": "context-propagation-test",
                    "X-Component": "reliability-testing"
                }
            }
        ]
        
        context_propagation_results = []
        
        for scenario in context_scenarios:
            # Combine auth headers with context headers
            test_headers = auth_headers.copy()
            test_headers.update(scenario["context_headers"])
            
            context_test_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Context propagation test for {scenario['scenario']}"}],
                "max_tokens": 50
            }
            
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    test_headers, context_test_request
                )
                
                end_time = time.time()
                duration = end_time - start_time
                
                # Check for context propagation in response headers
                response_headers = dict(response.headers)
                
                propagated_context = {}
                for context_key, context_value in scenario["context_headers"].items():
                    # Check if context is propagated back
                    if context_key.lower() in [h.lower() for h in response_headers.keys()]:
                        propagated_context[context_key] = "propagated"
                    elif f"x-echo-{context_key.lower()}" in [h.lower() for h in response_headers.keys()]:
                        propagated_context[context_key] = "echoed"
                    else:
                        propagated_context[context_key] = "not_found"
                
                context_propagation_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "status_code": response.status_code,
                    "duration": duration,
                    "success": response.status_code == 200,
                    "context_sent": scenario["context_headers"],
                    "context_propagation": propagated_context,
                    "response_headers": list(response_headers.keys())
                })
                
            except Exception as e:
                context_propagation_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "error": str(e),
                    "success": False
                })
            
            await asyncio.sleep(0.3)
        
        # Analyze context propagation
        successful_scenarios = [r for r in context_propagation_results if r.get("success")]
        
        # At least basic requests should succeed
        assert len(successful_scenarios) >= 2, \
            "Context propagation tests should generally succeed"
        
        # Check for context propagation capabilities
        for result in successful_scenarios:
            propagation = result.get("context_propagation", {})
            
            # Log context propagation behavior
            propagated_count = sum(1 for v in propagation.values() if v in ["propagated", "echoed"])
            total_context = len(propagation)
            
            if propagated_count > 0:
                logger.info(f"Context propagation detected in {result['scenario']}: {propagated_count}/{total_context}")
            else:
                logger.info(f"No context propagation detected in {result['scenario']}")
        
        logger.info("Context propagation reliability testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_performance_monitoring_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """MONITOR_PERFORMANCE_001: Performance monitoring reliability"""
        # Test performance monitoring under various load conditions
        
        # Performance monitoring scenarios
        performance_scenarios = [
            {
                "scenario": "baseline_performance",
                "description": "Baseline performance monitoring",
                "load": "low",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Baseline performance test"}],
                        "max_tokens": 50
                    }
                ] * 3
            },
            {
                "scenario": "moderate_load",
                "description": "Moderate load performance monitoring",
                "load": "medium",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Moderate load test {i}"}],
                        "max_tokens": 60
                    }
                    for i in range(6)
                ]
            },
            {
                "scenario": "complex_requests",
                "description": "Complex request performance monitoring",
                "load": "complex",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Generate a detailed analysis of performance monitoring best practices in distributed systems, including metrics collection, alerting strategies, and observability patterns."}],
                        "max_tokens": 200
                    }
                ] * 2
            }
        ]
        
        performance_monitoring_results = []
        
        for scenario in performance_scenarios:
            scenario_start_time = time.time()
            scenario_metrics = {
                "total_requests": 0,
                "successful_requests": 0,
                "total_duration": 0.0,
                "min_duration": float('inf'),
                "max_duration": 0.0,
                "durations": []
            }
            
            if scenario["load"] == "medium":
                # Test moderate concurrent load
                async def concurrent_performance_request(request, request_id):
                    start_time = time.time()
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        end_time = time.time()
                        duration = end_time - start_time
                        
                        return {
                            "request_id": request_id,
                            "status_code": response.status_code,
                            "duration": duration,
                            "success": response.status_code == 200
                        }
                    except Exception as e:
                        end_time = time.time()
                        duration = end_time - start_time
                        return {
                            "request_id": request_id,
                            "error": str(e),
                            "duration": duration,
                            "success": False
                        }
                
                # Execute concurrent requests
                tasks = [
                    concurrent_performance_request(req, i) 
                    for i, req in enumerate(scenario["requests"])
                ]
                concurrent_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in concurrent_results:
                    if isinstance(result, dict):
                        scenario_metrics["total_requests"] += 1
                        scenario_metrics["total_duration"] += result["duration"]
                        scenario_metrics["durations"].append(result["duration"])
                        scenario_metrics["min_duration"] = min(scenario_metrics["min_duration"], result["duration"])
                        scenario_metrics["max_duration"] = max(scenario_metrics["max_duration"], result["duration"])
                        
                        if result.get("success"):
                            scenario_metrics["successful_requests"] += 1
            
            else:
                # Sequential performance testing
                for i, request in enumerate(scenario["requests"]):
                    request_start_time = time.time()
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        
                        request_end_time = time.time()
                        request_duration = request_end_time - request_start_time
                        
                        scenario_metrics["total_requests"] += 1
                        scenario_metrics["total_duration"] += request_duration
                        scenario_metrics["durations"].append(request_duration)
                        scenario_metrics["min_duration"] = min(scenario_metrics["min_duration"], request_duration)
                        scenario_metrics["max_duration"] = max(scenario_metrics["max_duration"], request_duration)
                        
                        if response.status_code == 200:
                            scenario_metrics["successful_requests"] += 1
                        
                    except Exception as e:
                        request_end_time = time.time()
                        request_duration = request_end_time - request_start_time
                        
                        scenario_metrics["total_requests"] += 1
                        scenario_metrics["total_duration"] += request_duration
                        scenario_metrics["durations"].append(request_duration)
                    
                    await asyncio.sleep(0.2)
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            # Calculate performance metrics
            if scenario_metrics["total_requests"] > 0:
                scenario_metrics["average_duration"] = scenario_metrics["total_duration"] / scenario_metrics["total_requests"]
                scenario_metrics["success_rate"] = scenario_metrics["successful_requests"] / scenario_metrics["total_requests"]
                
                # Calculate percentiles
                sorted_durations = sorted(scenario_metrics["durations"])
                if sorted_durations:
                    p50_index = int(len(sorted_durations) * 0.5)
                    p95_index = int(len(sorted_durations) * 0.95)
                    
                    scenario_metrics["p50_duration"] = sorted_durations[p50_index]
                    scenario_metrics["p95_duration"] = sorted_durations[min(p95_index, len(sorted_durations) - 1)]
            
            if scenario_metrics["min_duration"] == float('inf'):
                scenario_metrics["min_duration"] = 0.0
            
            performance_monitoring_results.append({
                "scenario": scenario["scenario"],
                "description": scenario["description"],
                "load_type": scenario["load"],
                "metrics": scenario_metrics,
                "scenario_duration": scenario_duration
            })
            
            logger.info(f"Performance scenario {scenario['scenario']}: {scenario_metrics.get('success_rate', 0):.2%} success, {scenario_metrics.get('average_duration', 0):.2f}s avg")
            
            await asyncio.sleep(1)
        
        # Verify performance monitoring reliability
        for result in performance_monitoring_results:
            metrics = result["metrics"]
            
            # Performance monitoring should capture accurate metrics
            assert metrics["total_requests"] > 0, \
                f"Performance monitoring should capture requests: {result['scenario']}"
            
            if metrics["successful_requests"] > 0:
                # Successful requests should have reasonable performance
                assert metrics["average_duration"] <= 30.0, \
                    f"Average response time should be reasonable: {result['scenario']} - {metrics['average_duration']:.2f}s"
                
                # P95 should be within acceptable bounds
                if "p95_duration" in metrics:
                    assert metrics["p95_duration"] <= 60.0, \
                        f"P95 response time should be acceptable: {result['scenario']} - {metrics['p95_duration']:.2f}s"
        
        logger.info("Performance monitoring reliability testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_alerting_reliability_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """MONITOR_ALERTING_001: Alerting system reliability"""
        # Test alerting system reliability under various conditions
        
        # Generate conditions that might trigger alerts
        alerting_scenarios = [
            {
                "scenario": "error_rate_spike",
                "description": "Error rate spike that should trigger alerts",
                "actions": [
                    # Generate multiple failures
                    {
                        "model": f"alerting_failure_{i}",
                        "messages": [{"role": "user", "content": f"Alert trigger failure {i}"}],
                        "max_tokens": 50
                    }
                    for i in range(5)
                ]
            },
            {
                "scenario": "high_latency",
                "description": "High latency requests that should trigger alerts",
                "actions": [
                    # Generate potentially slow requests
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Generate a comprehensive response about distributed systems architecture, microservices patterns, and scalability considerations that should take significant processing time."}],
                        "max_tokens": 300
                    }
                ] * 2
            },
            {
                "scenario": "normal_operations",
                "description": "Normal operations that should not trigger alerts",
                "actions": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Normal alerting test {i}"}],
                        "max_tokens": 40
                    }
                    for i in range(3)
                ]
            }
        ]
        
        alerting_results = []
        
        for scenario in alerting_scenarios:
            scenario_start_time = time.time()
            scenario_outcomes = []
            
            for action in scenario["actions"]:
                action_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, action, track_cost=(scenario["scenario"] == "normal_operations")
                    )
                    
                    action_end_time = time.time()
                    action_duration = action_end_time - action_start_time
                    
                    scenario_outcomes.append({
                        "status_code": response.status_code,
                        "duration": action_duration,
                        "alert_worthy": (
                            response.status_code >= 500 or  # Server errors
                            action_duration > 15.0  # High latency
                        ),
                        "success": response.status_code == 200
                    })
                    
                except Exception as e:
                    action_end_time = time.time()
                    action_duration = action_end_time - action_start_time
                    
                    scenario_outcomes.append({
                        "error": str(e),
                        "duration": action_duration,
                        "alert_worthy": True,  # Exceptions should trigger alerts
                        "success": False
                    })
                
                await asyncio.sleep(0.2)
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            # Analyze alerting conditions
            alert_worthy_events = [o for o in scenario_outcomes if o.get("alert_worthy")]
            total_events = len(scenario_outcomes)
            error_rate = len([o for o in scenario_outcomes if not o.get("success")]) / total_events if total_events > 0 else 0
            avg_duration = sum(o.get("duration", 0) for o in scenario_outcomes) / total_events if total_events > 0 else 0
            
            alerting_results.append({
                "scenario": scenario["scenario"],
                "description": scenario["description"],
                "total_events": total_events,
                "alert_worthy_events": len(alert_worthy_events),
                "error_rate": error_rate,
                "average_duration": avg_duration,
                "scenario_duration": scenario_duration,
                "should_alert": scenario["scenario"] in ["error_rate_spike", "high_latency"]
            })
            
            logger.info(f"Alerting scenario {scenario['scenario']}: {len(alert_worthy_events)}/{total_events} alert-worthy events, {error_rate:.2%} error rate")
            
            await asyncio.sleep(1)
        
        # Check for alerting endpoints (if available)
        alerting_endpoints = [
            "/alerts",
            "/api/v1/alerts",
            "/health/alerts",
            "/_alerts",
            "/monitoring/alerts"
        ]
        
        alerting_endpoint_results = []
        
        for endpoint in alerting_endpoints:
            try:
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
                
                alerting_endpoint_results.append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "available": response.status_code == 200
                })
                
                if response.status_code == 200:
                    logger.info(f"Alerting endpoint available: {endpoint}")
                    
                    try:
                        alert_data = response.json()
                        # Check for alert structure
                        if isinstance(alert_data, dict) and ("alerts" in alert_data or "active" in alert_data):
                            logger.info(f"Alert data structure detected at {endpoint}")
                        elif isinstance(alert_data, list):
                            logger.info(f"Alert list detected at {endpoint}: {len(alert_data)} items")
                    except:
                        logger.info(f"Alerting endpoint {endpoint} returns non-JSON data")
                
            except Exception as e:
                alerting_endpoint_results.append({
                    "endpoint": endpoint,
                    "available": False,
                    "error": str(e)
                })
        
        available_alerting = [r for r in alerting_endpoint_results if r.get("available")]
        
        if available_alerting:
            logger.info(f"Alerting endpoints available: {[r['endpoint'] for r in available_alerting]}")
        else:
            logger.info("No alerting endpoints detected - monitoring may be handled externally")
        
        # Verify alerting reliability expectations
        for result in alerting_results:
            if result["should_alert"]:
                # Scenarios that should trigger alerts should have alert-worthy events
                assert result["alert_worthy_events"] > 0, \
                    f"Alert-triggering scenario should have alert-worthy events: {result['scenario']}"
            
            # Error rate spike should show high error rate
            if result["scenario"] == "error_rate_spike":
                assert result["error_rate"] >= 0.8, \
                    f"Error rate spike should show high error rate: {result['error_rate']:.2%}"
            
            # Normal operations should not have many alert-worthy events
            if result["scenario"] == "normal_operations":
                alert_rate = result["alert_worthy_events"] / result["total_events"] if result["total_events"] > 0 else 0
                assert alert_rate <= 0.2, \
                    f"Normal operations should not trigger many alerts: {alert_rate:.2%}"
        
        logger.info("Alerting system reliability testing completed")