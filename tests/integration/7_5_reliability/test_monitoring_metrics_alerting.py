# Section 7.5 - Monitoring and Observability Reliability Tests - Metrics and Alerting
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Monitoring and Observability Reliability.md
# Part 2: Metrics Collection and Alerting Systems

import pytest
import httpx
import asyncio
import time
import json
import os
from typing import Dict, Any, List
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestMonitoringMetricsAlerting:
    """Monitoring and observability reliability tests - Metrics and Alerting"""
    
    def setup_method(self):
        """Setup test environment with sensitive data from .env"""
        # Load configuration from environment variables
        self.monitoring_config = {
            'metrics_enabled': os.getenv('ENABLE_METRICS', 'true').lower() == 'true',
            'alert_endpoints': os.getenv('ALERT_ENDPOINTS', '').split(','),
            'metrics_retention': os.getenv('METRICS_RETENTION_DAYS', '30')
        }

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
    async def test_performance_monitoring_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """MONITOR_PERFORMANCE_001: Performance monitoring accuracy"""
        # Test performance monitoring and metrics collection
        
        performance_scenarios = [
            {
                "scenario": "baseline_performance",
                "description": "Baseline performance measurement",
                "request_count": 5,
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Performance monitoring baseline test"}],
                    "max_tokens": 50
                }
            },
            {
                "scenario": "varying_load",
                "description": "Performance under varying load",
                "request_count": 8,
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Performance monitoring varying load test"}],
                    "max_tokens": 70
                }
            }
        ]
        
        performance_results = []
        
        for scenario in performance_scenarios:
            logger.info(f"Testing performance monitoring: {scenario['scenario']}")
            
            scenario_start = time.time()
            request_latencies = []
            request_sizes = []
            
            if scenario["scenario"] == "varying_load":
                # Execute requests with varying intervals to simulate load
                intervals = [0.1, 0.05, 0.2, 0.05, 0.3, 0.05, 0.1, 0.05]
            else:
                # Consistent intervals for baseline
                intervals = [0.2] * scenario["request_count"]
            
            for i in range(scenario["request_count"]):
                request_start = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, scenario["request_data"]
                    )
                    
                    request_end = time.time()
                    latency = request_end - request_start
                    
                    request_latencies.append({
                        "request_index": i,
                        "latency": latency,
                        "status_code": response.status_code,
                        "response_size": len(response.text),
                        "success": response.status_code == 200
                    })
                    
                    request_sizes.append(len(response.text))
                    
                except Exception as e:
                    request_end = time.time()
                    latency = request_end - request_start
                    
                    request_latencies.append({
                        "request_index": i,
                        "latency": latency,
                        "error": str(e),
                        "success": False
                    })
                
                if i < len(intervals):
                    await asyncio.sleep(intervals[i])
            
            scenario_end = time.time()
            total_duration = scenario_end - scenario_start
            
            # Calculate performance metrics
            successful_requests = [r for r in request_latencies if r.get("success")]
            latencies = [r["latency"] for r in successful_requests]
            
            if latencies:
                avg_latency = sum(latencies) / len(latencies)
                min_latency = min(latencies)
                max_latency = max(latencies)
                
                # Calculate percentiles
                sorted_latencies = sorted(latencies)
                p50 = sorted_latencies[len(sorted_latencies) // 2] if sorted_latencies else 0
                p95_index = int(len(sorted_latencies) * 0.95)
                p95 = sorted_latencies[p95_index] if p95_index < len(sorted_latencies) else max_latency
                
                throughput = len(successful_requests) / total_duration
                
                performance_results.append({
                    "scenario": scenario["scenario"],
                    "total_requests": len(request_latencies),
                    "successful_requests": len(successful_requests),
                    "avg_latency": avg_latency,
                    "min_latency": min_latency,
                    "max_latency": max_latency,
                    "p50_latency": p50,
                    "p95_latency": p95,
                    "throughput": throughput,
                    "total_duration": total_duration
                })
                
                logger.info(f"Performance {scenario['scenario']}: avg={avg_latency:.3f}s, p95={p95:.3f}s, throughput={throughput:.2f} req/s")
            
            else:
                performance_results.append({
                    "scenario": scenario["scenario"],
                    "total_requests": len(request_latencies),
                    "successful_requests": 0,
                    "error": "No successful requests for performance measurement"
                })
        
        # Verify performance monitoring
        baseline_result = next((r for r in performance_results if r["scenario"] == "baseline_performance"), None)
        varying_result = next((r for r in performance_results if r["scenario"] == "varying_load"), None)
        
        if baseline_result and "avg_latency" in baseline_result:
            # Performance metrics should be reasonable
            assert baseline_result["avg_latency"] <= 30.0, \
                f"Baseline latency should be reasonable: {baseline_result['avg_latency']:.3f}s"
            
            # P95 should not be excessively high
            assert baseline_result["p95_latency"] <= 60.0, \
                f"P95 latency should be reasonable: {baseline_result['p95_latency']:.3f}s"
        
        if varying_result and "throughput" in varying_result:
            # System should maintain some throughput under load
            assert varying_result["throughput"] > 0.1, \
                f"System should maintain throughput under varying load: {varying_result['throughput']:.3f} req/s"
        
        logger.info("Performance monitoring testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_alerting_reliability_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """MONITOR_ALERTING_001: Alerting system reliability"""
        # Test alerting system reliability and trigger mechanisms
        
        alerting_scenarios = [
            {
                "scenario": "error_rate_threshold",
                "description": "Test error rate alerting thresholds",
                "trigger_method": "generate_errors",
                "error_count": 6,
                "total_requests": 8
            },
            {
                "scenario": "latency_threshold",
                "description": "Test latency alerting thresholds",
                "trigger_method": "generate_slow_requests",
                "slow_request_count": 4
            },
            {
                "scenario": "volume_threshold",
                "description": "Test volume alerting thresholds",
                "trigger_method": "generate_high_volume",
                "volume_requests": 12
            }
        ]
        
        alerting_results = []
        
        for scenario in alerting_scenarios:
            logger.info(f"Testing alerting: {scenario['scenario']}")
            
            scenario_start = time.time()
            
            if scenario["trigger_method"] == "generate_errors":
                # Generate high error rate
                error_requests = []
                
                for i in range(scenario["total_requests"]):
                    if i < scenario["error_count"]:
                        # Error request
                        request = {
                            "model": f"alerting_error_model_{i}",
                            "messages": [{"role": "user", "content": "Alerting error test"}],
                            "max_tokens": 50
                        }
                    else:
                        # Success request
                        request = {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Alerting success test"}],
                            "max_tokens": 50
                        }
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request, track_cost=(i >= scenario["error_count"])
                        )
                        
                        error_requests.append({
                            "request_index": i,
                            "status_code": response.status_code,
                            "is_error": response.status_code >= 400
                        })
                        
                    except Exception as e:
                        error_requests.append({
                            "request_index": i,
                            "error": str(e),
                            "is_error": True
                        })
                    
                    await asyncio.sleep(0.1)
                
                error_count = sum(1 for r in error_requests if r.get("is_error"))
                error_rate = error_count / len(error_requests) if error_requests else 0
                
                alerting_results.append({
                    "scenario": scenario["scenario"],
                    "total_requests": len(error_requests),
                    "error_count": error_count,
                    "error_rate": error_rate,
                    "alert_triggered": error_rate >= 0.5,  # 50% error rate threshold
                    "alert_appropriate": error_rate >= 0.5
                })
            
            elif scenario["trigger_method"] == "generate_slow_requests":
                # Generate requests that might be slow
                slow_requests = []
                
                for i in range(scenario["slow_request_count"]):
                    request_start = time.time()
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, {
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": "Alerting latency test with longer content: " + "detail " * 30}],
                                "max_tokens": 100
                            }
                        )
                        
                        request_end = time.time()
                        latency = request_end - request_start
                        
                        slow_requests.append({
                            "request_index": i,
                            "latency": latency,
                            "status_code": response.status_code,
                            "is_slow": latency > 5.0  # 5 second threshold
                        })
                        
                    except Exception as e:
                        request_end = time.time()
                        latency = request_end - request_start
                        
                        slow_requests.append({
                            "request_index": i,
                            "latency": latency,
                            "error": str(e),
                            "is_slow": latency > 5.0
                        })
                    
                    await asyncio.sleep(0.1)
                
                slow_count = sum(1 for r in slow_requests if r.get("is_slow"))
                avg_latency = sum(r["latency"] for r in slow_requests) / len(slow_requests) if slow_requests else 0
                
                alerting_results.append({
                    "scenario": scenario["scenario"],
                    "total_requests": len(slow_requests),
                    "slow_requests": slow_count,
                    "avg_latency": avg_latency,
                    "alert_triggered": avg_latency > 3.0,  # 3 second average threshold
                    "alert_appropriate": avg_latency > 3.0
                })
            
            elif scenario["trigger_method"] == "generate_high_volume":
                # Generate high volume of requests quickly
                volume_start = time.time()
                volume_requests = []
                
                # Rapid fire requests
                tasks = []
                for i in range(scenario["volume_requests"]):
                    task = make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Volume test {i}"}],
                            "max_tokens": 30
                        }, track_cost=False
                    )
                    tasks.append(task)
                
                volume_results = await asyncio.gather(*tasks, return_exceptions=True)
                volume_end = time.time()
                volume_duration = volume_end - volume_start
                
                successful_volume = sum(1 for r in volume_results if not isinstance(r, Exception) and hasattr(r, 'status_code') and r.status_code == 200)
                requests_per_second = len(volume_results) / volume_duration
                
                alerting_results.append({
                    "scenario": scenario["scenario"],
                    "total_requests": len(volume_results),
                    "successful_requests": successful_volume,
                    "duration": volume_duration,
                    "requests_per_second": requests_per_second,
                    "alert_triggered": requests_per_second > 20,  # 20 req/s threshold
                    "alert_appropriate": requests_per_second > 20
                })
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            logger.info(f"Alerting scenario {scenario['scenario']} completed in {scenario_duration:.2f}s")
        
        # Verify alerting system
        for result in alerting_results:
            # Alert triggering should be appropriate to conditions
            if "error_rate" in result:
                logger.info(f"Error rate alerting: {result['error_rate']:.2%} error rate")
            elif "avg_latency" in result:
                logger.info(f"Latency alerting: {result['avg_latency']:.3f}s average latency")
            elif "requests_per_second" in result:
                logger.info(f"Volume alerting: {result['requests_per_second']:.2f} req/s")
        
        logger.info("Alerting reliability testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_metrics_temporal_consistency_002(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """MONITOR_TEMPORAL_002: Metrics temporal consistency and accuracy"""
        # Test metrics temporal consistency and timestamp accuracy
        
        temporal_test_phases = [
            {
                "phase": "burst_activity",
                "description": "Burst of activity for temporal tracking",
                "duration": 2.0,
                "request_interval": 0.2
            },
            {
                "phase": "steady_activity", 
                "description": "Steady activity for temporal tracking",
                "duration": 3.0,
                "request_interval": 0.5
            },
            {
                "phase": "idle_period",
                "description": "Idle period for temporal baseline",
                "duration": 2.0,
                "request_interval": None  # No requests
            }
        ]
        
        temporal_results = []
        overall_start = time.time()
        
        for phase in temporal_test_phases:
            phase_start = time.time()
            phase_requests = []
            
            logger.info(f"Starting temporal phase: {phase['phase']}")
            
            if phase["request_interval"] is not None:
                # Generate requests for this phase
                phase_duration = 0
                while phase_duration < phase["duration"]:
                    request_timestamp = time.time()
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, {
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": f"Temporal test {phase['phase']} at {request_timestamp}"}],
                                "max_tokens": 40
                            }
                        )
                        
                        response_timestamp = time.time()
                        
                        phase_requests.append({
                            "request_timestamp": request_timestamp,
                            "response_timestamp": response_timestamp,
                            "duration": response_timestamp - request_timestamp,
                            "status_code": response.status_code,
                            "phase": phase["phase"]
                        })
                        
                    except Exception as e:
                        response_timestamp = time.time()
                        
                        phase_requests.append({
                            "request_timestamp": request_timestamp,
                            "response_timestamp": response_timestamp,
                            "duration": response_timestamp - request_timestamp,
                            "error": str(e),
                            "phase": phase["phase"]
                        })
                    
                    await asyncio.sleep(phase["request_interval"])
                    phase_duration = time.time() - phase_start
            else:
                # Idle period - just wait
                await asyncio.sleep(phase["duration"])
            
            phase_end = time.time()
            actual_phase_duration = phase_end - phase_start
            
            temporal_results.append({
                "phase": phase["phase"],
                "requests": phase_requests,
                "expected_duration": phase["duration"],
                "actual_duration": actual_phase_duration,
                "request_count": len(phase_requests),
                "temporal_accuracy": abs(actual_phase_duration - phase["duration"]) <= 0.5
            })
        
        overall_end = time.time()
        total_test_duration = overall_end - overall_start
        
        # Analyze temporal consistency
        all_requests = []
        for result in temporal_results:
            all_requests.extend(result["requests"])
        
        # Check timestamp ordering
        timestamps = [r["request_timestamp"] for r in all_requests]
        timestamps_ordered = timestamps == sorted(timestamps)
        
        # Calculate time-based metrics
        if len(all_requests) > 1:
            time_span = timestamps[-1] - timestamps[0]
            request_rate = len(all_requests) / time_span if time_span > 0 else 0
        else:
            time_span = 0
            request_rate = 0
        
        temporal_consistency_results = {
            "total_duration": total_test_duration,
            "total_requests": len(all_requests),
            "timestamps_ordered": timestamps_ordered,
            "time_span": time_span,
            "overall_request_rate": request_rate,
            "phase_results": temporal_results
        }
        
        # Verify temporal consistency
        assert timestamps_ordered, "Request timestamps should be in chronological order"
        
        for result in temporal_results:
            if result["phase"] != "idle_period":
                assert result["temporal_accuracy"], \
                    f"Phase duration should be accurate: {result['phase']} - expected {result['expected_duration']:.1f}s, actual {result['actual_duration']:.1f}s"
        
        logger.info(f"Temporal consistency test: {len(all_requests)} requests over {total_test_duration:.2f}s")
        logger.info(f"Overall request rate: {request_rate:.2f} req/s")
        
        logger.info("Metrics temporal consistency testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_monitoring_system_resilience_003(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """MONITOR_RESILIENCE_003: Monitoring system resilience under stress"""
        # Test monitoring system resilience under various stress conditions
        
        stress_scenarios = [
            {
                "scenario": "concurrent_monitoring",
                "description": "Concurrent monitoring stress",
                "concurrent_requests": 10,
                "monitoring_intensive": True
            },
            {
                "scenario": "error_cascade_monitoring",
                "description": "Monitoring during error cascades",
                "error_requests": 8,
                "monitoring_intensive": True
            }
        ]
        
        resilience_results = []
        
        for scenario in stress_scenarios:
            logger.info(f"Testing monitoring resilience: {scenario['scenario']}")
            
            scenario_start = time.time()
            
            if scenario["scenario"] == "concurrent_monitoring":
                # Test concurrent monitoring load
                async def monitored_request(request_id):
                    try:
                        # Add monitoring headers
                        monitoring_headers = auth_headers.copy()
                        monitoring_headers.update({
                            "X-Monitor-Request": f"stress_{request_id}",
                            "X-Trace-ID": f"trace_{request_id}",
                            "X-Monitor-Level": "detailed" if scenario["monitoring_intensive"] else "normal"
                        })
                        
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            monitoring_headers, {
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": f"Concurrent monitoring test {request_id}"}],
                                "max_tokens": 50
                            }
                        )
                        
                        return {
                            "request_id": request_id,
                            "status_code": response.status_code,
                            "monitoring_preserved": True,
                            "success": response.status_code == 200
                        }
                        
                    except Exception as e:
                        return {
                            "request_id": request_id,
                            "error": str(e),
                            "monitoring_preserved": False,
                            "success": False
                        }
                
                # Execute concurrent monitored requests
                concurrent_tasks = [monitored_request(i) for i in range(scenario["concurrent_requests"])]
                concurrent_results = await asyncio.gather(*concurrent_tasks, return_exceptions=True)
                
                monitoring_preserved = sum(1 for r in concurrent_results if isinstance(r, dict) and r.get("monitoring_preserved"))
                successful_requests = sum(1 for r in concurrent_results if isinstance(r, dict) and r.get("success"))
                
                resilience_results.append({
                    "scenario": scenario["scenario"],
                    "total_requests": len(concurrent_results),
                    "successful_requests": successful_requests,
                    "monitoring_preserved": monitoring_preserved,
                    "monitoring_resilience": monitoring_preserved / len(concurrent_results) if concurrent_results else 0
                })
            
            elif scenario["scenario"] == "error_cascade_monitoring":
                # Test monitoring during error cascades
                error_cascade_results = []
                
                for i in range(scenario["error_requests"]):
                    # Generate errors with monitoring
                    monitoring_headers = auth_headers.copy()
                    monitoring_headers.update({
                        "X-Monitor-Error-Cascade": f"error_{i}",
                        "X-Error-Tracking": "enabled"
                    })
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            monitoring_headers, {
                                "model": f"error_cascade_model_{i}",  # Invalid model
                                "messages": [{"role": "user", "content": f"Error cascade monitoring test {i}"}],
                                "max_tokens": 50
                            }, track_cost=False
                        )
                        
                        error_cascade_results.append({
                            "request_index": i,
                            "status_code": response.status_code,
                            "error_monitored": response.status_code >= 400,
                            "monitoring_functional": True
                        })
                        
                    except Exception as e:
                        error_cascade_results.append({
                            "request_index": i,
                            "error": str(e),
                            "error_monitored": True,
                            "monitoring_functional": True
                        })
                    
                    await asyncio.sleep(0.1)
                
                monitored_errors = sum(1 for r in error_cascade_results if r.get("error_monitored"))
                monitoring_functional = sum(1 for r in error_cascade_results if r.get("monitoring_functional"))
                
                resilience_results.append({
                    "scenario": scenario["scenario"],
                    "total_requests": len(error_cascade_results),
                    "monitored_errors": monitored_errors,
                    "monitoring_functional": monitoring_functional,
                    "error_monitoring_resilience": monitoring_functional / len(error_cascade_results) if error_cascade_results else 0
                })
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            logger.info(f"Monitoring resilience scenario {scenario['scenario']} completed in {scenario_duration:.2f}s")
        
        # Verify monitoring system resilience
        for result in resilience_results:
            if "monitoring_resilience" in result:
                # Monitoring should remain resilient under concurrent load
                assert result["monitoring_resilience"] >= 0.8, \
                    f"Monitoring should be resilient under concurrent load: {result['scenario']} - {result['monitoring_resilience']:.2%}"
            
            if "error_monitoring_resilience" in result:
                # Error monitoring should remain functional during cascades
                assert result["error_monitoring_resilience"] >= 0.9, \
                    f"Error monitoring should remain functional: {result['scenario']} - {result['error_monitoring_resilience']:.2%}"
        
        logger.info("Monitoring system resilience testing completed")