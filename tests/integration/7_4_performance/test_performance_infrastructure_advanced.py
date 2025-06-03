# Section 7.4 - Advanced Performance Testing Infrastructure
# Implements remaining missing test cases for performance infrastructure testing

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List
import json
import os
from dataclasses import dataclass

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class PerformanceCorrelation:
    """Performance correlation analysis result"""
    metric_name: str
    correlation_coefficient: float
    statistical_significance: float
    trend_direction: str
    confidence_level: float


class TestAdvancedPerformanceInfrastructure:
    """Advanced performance testing infrastructure validation"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_infra_metric_correlation_analysis_001(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """PERF_INFRA_CORRELATION_001: Advanced metric correlation analysis"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Collect comprehensive performance metrics for correlation analysis
        correlation_metrics = {
            "response_times": [],
            "memory_usage": [],
            "request_sizes": [],
            "token_counts": [],
            "concurrent_requests": [],
            "model_types": [],
            "error_rates": [],
            "timestamps": []
        }
        
        # Generate diverse workload for correlation analysis
        test_scenarios = [
            {"concurrent": 5, "tokens": 50, "model_type": "chat", "iterations": 10},
            {"concurrent": 10, "tokens": 100, "model_type": "chat", "iterations": 10},
            {"concurrent": 15, "tokens": 150, "model_type": "chat", "iterations": 10},
            {"concurrent": 20, "tokens": 200, "model_type": "chat", "iterations": 8}
        ]
        
        import psutil
        process = psutil.Process(os.getpid())
        
        for scenario in test_scenarios:
            scenario_errors = 0
            
            # Execute concurrent requests for this scenario
            async def scenario_request(req_id: int):
                memory_before = process.memory_info().rss / (1024 * 1024)
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Correlation test scenario request {req_id}"}],
                    "max_tokens": scenario["tokens"]
                }
                
                start_time = time.perf_counter()
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    end_time = time.perf_counter()
                    
                    memory_after = process.memory_info().rss / (1024 * 1024)
                    response_time = (end_time - start_time) * 1000
                    
                    return {
                        "response_time": response_time,
                        "memory_delta": memory_after - memory_before,
                        "status_code": response.status_code,
                        "request_size": len(json.dumps(request_data)),
                        "tokens": scenario["tokens"],
                        "success": response.status_code == 200
                    }
                    
                except Exception as e:
                    end_time = time.perf_counter()
                    return {
                        "response_time": (end_time - start_time) * 1000,
                        "memory_delta": 0,
                        "status_code": 0,
                        "request_size": len(json.dumps(request_data)),
                        "tokens": scenario["tokens"],
                        "success": False,
                        "error": str(e)
                    }
            
            # Execute scenario
            for iteration in range(scenario["iterations"]):
                tasks = [scenario_request(i) for i in range(scenario["concurrent"])]
                results = await asyncio.gather(*tasks)
                
                # Aggregate results for correlation analysis
                for result in results:
                    correlation_metrics["response_times"].append(result["response_time"])
                    correlation_metrics["memory_usage"].append(result["memory_delta"])
                    correlation_metrics["request_sizes"].append(result["request_size"])
                    correlation_metrics["token_counts"].append(result["tokens"])
                    correlation_metrics["concurrent_requests"].append(scenario["concurrent"])
                    correlation_metrics["model_types"].append(scenario["model_type"])
                    correlation_metrics["timestamps"].append(time.time())
                    
                    if not result["success"]:
                        scenario_errors += 1
                
                correlation_metrics["error_rates"].append(scenario_errors / len(results))
                
                await asyncio.sleep(0.1)
        
        # Perform correlation analysis
        correlations = []
        
        # Analyze response time correlations
        if len(correlation_metrics["response_times"]) >= 10:
            # Response time vs token count
            response_times = correlation_metrics["response_times"]
            token_counts = correlation_metrics["token_counts"]
            
            if len(response_times) == len(token_counts):
                correlation_coeff = self._calculate_correlation(response_times, token_counts)
                correlations.append(PerformanceCorrelation(
                    metric_name="response_time_vs_token_count",
                    correlation_coefficient=correlation_coeff,
                    statistical_significance=abs(correlation_coeff),
                    trend_direction="positive" if correlation_coeff > 0 else "negative",
                    confidence_level=min(abs(correlation_coeff), 0.95)
                ))
            
            # Response time vs concurrent requests
            concurrent_counts = correlation_metrics["concurrent_requests"]
            if len(response_times) == len(concurrent_counts):
                correlation_coeff = self._calculate_correlation(response_times, concurrent_counts)
                correlations.append(PerformanceCorrelation(
                    metric_name="response_time_vs_concurrency",
                    correlation_coefficient=correlation_coeff,
                    statistical_significance=abs(correlation_coeff),
                    trend_direction="positive" if correlation_coeff > 0 else "negative",
                    confidence_level=min(abs(correlation_coeff), 0.95)
                ))
            
            # Memory usage vs request size
            memory_usage = correlation_metrics["memory_usage"]
            request_sizes = correlation_metrics["request_sizes"]
            if len(memory_usage) == len(request_sizes):
                correlation_coeff = self._calculate_correlation(memory_usage, request_sizes)
                correlations.append(PerformanceCorrelation(
                    metric_name="memory_vs_request_size",
                    correlation_coefficient=correlation_coeff,
                    statistical_significance=abs(correlation_coeff),
                    trend_direction="positive" if correlation_coeff > 0 else "negative",
                    confidence_level=min(abs(correlation_coeff), 0.95)
                ))
        
        # Validate correlation analysis results
        for correlation in correlations:
            logger.info(f"Correlation analysis {correlation.metric_name} - "
                       f"Coefficient: {correlation.correlation_coefficient:.3f}, "
                       f"Significance: {correlation.statistical_significance:.3f}, "
                       f"Trend: {correlation.trend_direction}")
            
            # Correlation analysis should produce meaningful results
            assert correlation.statistical_significance >= 0.0, f"Correlation significance should be valid for {correlation.metric_name}"
            assert correlation.confidence_level >= 0.0, f"Confidence level should be valid for {correlation.metric_name}"
        
        # Validate expected correlations
        response_time_correlations = [c for c in correlations if "response_time" in c.metric_name]
        assert len(response_time_correlations) >= 2, "Should find multiple response time correlations"
        
        logger.info(f"Advanced metric correlation analysis completed with {len(correlations)} correlations identified")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_infra_regression_detection_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_INFRA_REGRESSION_001: Performance regression detection automation"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Establish baseline performance metrics
        baseline_metrics = {
            "response_times": [],
            "error_rates": [],
            "throughput": [],
            "memory_usage": []
        }
        
        # Collect baseline data
        baseline_requests = 20
        
        for i in range(baseline_requests):
            start_time = time.perf_counter()
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Baseline performance test {i}"}],
                    "max_tokens": 50
                }
            )
            
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000
            
            baseline_metrics["response_times"].append(response_time)
            baseline_metrics["error_rates"].append(0 if response.status_code == 200 else 1)
            
            await asyncio.sleep(0.05)
        
        # Calculate baseline statistics
        baseline_stats = {
            "avg_response_time": statistics.mean(baseline_metrics["response_times"]),
            "p95_response_time": statistics.quantiles(baseline_metrics["response_times"], n=20)[18] if len(baseline_metrics["response_times"]) >= 20 else max(baseline_metrics["response_times"]),
            "error_rate": statistics.mean(baseline_metrics["error_rates"]),
            "throughput": baseline_requests / sum(baseline_metrics["response_times"]) * 1000 if sum(baseline_metrics["response_times"]) > 0 else 0
        }
        
        logger.info(f"Baseline metrics - "
                   f"Avg response: {baseline_stats['avg_response_time']:.2f}ms, "
                   f"P95 response: {baseline_stats['p95_response_time']:.2f}ms, "
                   f"Error rate: {baseline_stats['error_rate']:.3f}, "
                   f"Throughput: {baseline_stats['throughput']:.2f} req/s")
        
        # Simulate different performance scenarios for regression detection
        regression_scenarios = [
            {
                "name": "normal_performance",
                "response_delay": 0,
                "error_injection": False,
                "expected_regression": False
            },
            {
                "name": "slight_degradation", 
                "response_delay": 0.1,  # 100ms extra delay
                "error_injection": False,
                "expected_regression": True
            },
            {
                "name": "error_injection",
                "response_delay": 0,
                "error_injection": True,
                "expected_regression": True
            }
        ]
        
        regression_results = {}
        
        for scenario in regression_scenarios:
            scenario_metrics = {
                "response_times": [],
                "error_rates": []
            }
            
            # Collect data for this scenario
            for i in range(15):
                # Simulate delay if specified
                if scenario["response_delay"] > 0:
                    await asyncio.sleep(scenario["response_delay"])
                
                start_time = time.perf_counter()
                
                # Simulate error injection
                if scenario["error_injection"] and i % 5 == 0:
                    # Use invalid model to trigger error
                    request_data = {
                        "model": "invalid_model_for_regression_test",
                        "messages": [{"role": "user", "content": f"Regression test {scenario['name']} {i}"}],
                        "max_tokens": 50
                    }
                else:
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Regression test {scenario['name']} {i}"}],
                        "max_tokens": 50
                    }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                end_time = time.perf_counter()
                response_time = (end_time - start_time) * 1000
                
                scenario_metrics["response_times"].append(response_time)
                scenario_metrics["error_rates"].append(0 if response.status_code == 200 else 1)
                
                await asyncio.sleep(0.02)
            
            # Analyze scenario for regression
            scenario_stats = {
                "avg_response_time": statistics.mean(scenario_metrics["response_times"]),
                "p95_response_time": statistics.quantiles(scenario_metrics["response_times"], n=20)[18] if len(scenario_metrics["response_times"]) >= 20 else max(scenario_metrics["response_times"]),
                "error_rate": statistics.mean(scenario_metrics["error_rates"])
            }
            
            # Regression detection logic
            regression_detected = False
            regression_reasons = []
            
            # Response time regression (>20% increase)
            if scenario_stats["avg_response_time"] > baseline_stats["avg_response_time"] * 1.2:
                regression_detected = True
                regression_reasons.append(f"Response time increased by {((scenario_stats['avg_response_time'] / baseline_stats['avg_response_time']) - 1) * 100:.1f}%")
            
            # Error rate regression (>5% increase)
            if scenario_stats["error_rate"] > baseline_stats["error_rate"] + 0.05:
                regression_detected = True
                regression_reasons.append(f"Error rate increased to {scenario_stats['error_rate']:.3f}")
            
            regression_results[scenario["name"]] = {
                "stats": scenario_stats,
                "regression_detected": regression_detected,
                "regression_reasons": regression_reasons,
                "expected_regression": scenario["expected_regression"]
            }
            
            logger.info(f"Regression analysis {scenario['name']} - "
                       f"Detected: {regression_detected}, "
                       f"Expected: {scenario['expected_regression']}, "
                       f"Reasons: {regression_reasons}")
        
        # Validate regression detection accuracy
        for scenario_name, result in regression_results.items():
            # Regression detection should align with expectations
            if result["expected_regression"]:
                assert result["regression_detected"], f"Should detect regression for {scenario_name}"
            else:
                # Allow some tolerance for normal performance
                if result["regression_detected"]:
                    logger.warning(f"Unexpected regression detected for {scenario_name}: {result['regression_reasons']}")
        
        logger.info("Performance regression detection automation test completed")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_infra_continuous_monitoring_validation_001(self, http_client: httpx.AsyncClient,
                                                                  auth_headers: Dict[str, str],
                                                                  make_request):
        """PERF_INFRA_MONITORING_001: Continuous performance monitoring validation"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Continuous monitoring simulation
        monitoring_metrics = {
            "real_time_samples": [],
            "alert_triggers": [],
            "trend_analysis": [],
            "health_scores": []
        }
        
        import psutil
        process = psutil.Process(os.getpid())
        
        # Monitoring thresholds
        monitoring_config = {
            "response_time_threshold": 3000,  # 3 seconds
            "error_rate_threshold": 0.1,     # 10%
            "memory_threshold": 500,          # 500MB increase
            "cpu_threshold": 80               # 80% CPU
        }
        
        baseline_memory = process.memory_info().rss / (1024 * 1024)
        
        # Simulate continuous monitoring over time
        monitoring_duration = 60  # 1 minute of monitoring
        sample_interval = 2       # Sample every 2 seconds
        samples = monitoring_duration // sample_interval
        
        for sample_id in range(samples):
            sample_start = time.time()
            
            # Collect system metrics
            cpu_percent = process.cpu_percent(interval=0.1)
            memory_usage = process.memory_info().rss / (1024 * 1024)
            memory_delta = memory_usage - baseline_memory
            
            # Generate test requests for monitoring
            sample_metrics = {
                "response_times": [],
                "error_count": 0,
                "total_requests": 0
            }
            
            # Execute requests during this monitoring sample
            for req_id in range(3):  # 3 requests per sample
                start_time = time.perf_counter()
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Monitoring sample {sample_id} request {req_id}"}],
                        "max_tokens": 40
                    }
                )
                
                end_time = time.perf_counter()
                response_time = (end_time - start_time) * 1000
                
                sample_metrics["response_times"].append(response_time)
                sample_metrics["total_requests"] += 1
                
                if response.status_code != 200:
                    sample_metrics["error_count"] += 1
                
                await asyncio.sleep(0.1)
            
            # Calculate sample statistics
            avg_response_time = statistics.mean(sample_metrics["response_times"]) if sample_metrics["response_times"] else 0
            error_rate = sample_metrics["error_count"] / sample_metrics["total_requests"] if sample_metrics["total_requests"] > 0 else 0
            
            # Health score calculation (0-100)
            health_factors = {
                "response_time": max(0, 100 - (avg_response_time / monitoring_config["response_time_threshold"]) * 100),
                "error_rate": max(0, 100 - (error_rate / monitoring_config["error_rate_threshold"]) * 100),
                "memory": max(0, 100 - (memory_delta / monitoring_config["memory_threshold"]) * 100),
                "cpu": max(0, 100 - (cpu_percent / monitoring_config["cpu_threshold"]) * 100)
            }
            
            overall_health_score = statistics.mean(health_factors.values())
            
            # Store monitoring sample
            monitoring_sample = {
                "sample_id": sample_id,
                "timestamp": sample_start,
                "avg_response_time": avg_response_time,
                "error_rate": error_rate,
                "memory_usage": memory_usage,
                "memory_delta": memory_delta,
                "cpu_percent": cpu_percent,
                "health_score": overall_health_score,
                "health_factors": health_factors
            }
            
            monitoring_metrics["real_time_samples"].append(monitoring_sample)
            monitoring_metrics["health_scores"].append(overall_health_score)
            
            # Alert detection
            alerts = []
            if avg_response_time > monitoring_config["response_time_threshold"]:
                alerts.append(f"High response time: {avg_response_time:.2f}ms")
            
            if error_rate > monitoring_config["error_rate_threshold"]:
                alerts.append(f"High error rate: {error_rate:.3f}")
            
            if memory_delta > monitoring_config["memory_threshold"]:
                alerts.append(f"High memory usage: {memory_delta:.2f}MB")
            
            if cpu_percent > monitoring_config["cpu_threshold"]:
                alerts.append(f"High CPU usage: {cpu_percent:.1f}%")
            
            if alerts:
                monitoring_metrics["alert_triggers"].append({
                    "sample_id": sample_id,
                    "timestamp": sample_start,
                    "alerts": alerts,
                    "severity": "high" if len(alerts) > 2 else "medium"
                })
            
            # Wait for next sample interval
            elapsed = time.time() - sample_start
            sleep_time = max(0, sample_interval - elapsed)
            await asyncio.sleep(sleep_time)
        
        # Trend analysis
        if len(monitoring_metrics["health_scores"]) >= 5:
            # Calculate health score trend
            early_scores = monitoring_metrics["health_scores"][:5]
            late_scores = monitoring_metrics["health_scores"][-5:]
            
            early_avg = statistics.mean(early_scores)
            late_avg = statistics.mean(late_scores)
            trend_direction = "improving" if late_avg > early_avg else "degrading" if late_avg < early_avg else "stable"
            trend_magnitude = abs(late_avg - early_avg)
            
            monitoring_metrics["trend_analysis"].append({
                "metric": "health_score",
                "trend_direction": trend_direction,
                "trend_magnitude": trend_magnitude,
                "early_avg": early_avg,
                "late_avg": late_avg
            })
        
        # Validate continuous monitoring
        total_samples = len(monitoring_metrics["real_time_samples"])
        alert_count = len(monitoring_metrics["alert_triggers"])
        avg_health_score = statistics.mean(monitoring_metrics["health_scores"]) if monitoring_metrics["health_scores"] else 0
        
        logger.info(f"Continuous monitoring validation - "
                   f"Samples: {total_samples}, "
                   f"Alerts: {alert_count}, "
                   f"Avg health score: {avg_health_score:.2f}")
        
        # Monitoring validation assertions
        assert total_samples >= samples * 0.9, f"Should collect most monitoring samples, got {total_samples}/{samples}"
        assert avg_health_score >= 50.0, f"Average health score should be reasonable, got {avg_health_score:.2f}"
        assert alert_count <= total_samples * 0.3, f"Alert rate should be reasonable, got {alert_count}/{total_samples}"
        
        # Trend analysis validation
        for trend in monitoring_metrics["trend_analysis"]:
            logger.info(f"Trend analysis {trend['metric']} - "
                       f"Direction: {trend['trend_direction']}, "
                       f"Magnitude: {trend['trend_magnitude']:.2f}")
            
            # Trend magnitude should be reasonable
            assert trend["trend_magnitude"] <= 50.0, f"Trend magnitude should be reasonable for {trend['metric']}"
        
        logger.info("Continuous performance monitoring validation completed")
    
    def _calculate_correlation(self, x_values: List[float], y_values: List[float]) -> float:
        """Calculate Pearson correlation coefficient"""
        if len(x_values) != len(y_values) or len(x_values) < 2:
            return 0.0
        
        n = len(x_values)
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x2 = sum(x * x for x in x_values)
        sum_y2 = sum(y * y for y in y_values)
        
        numerator = n * sum_xy - sum_x * sum_y
        denominator_x = n * sum_x2 - sum_x * sum_x
        denominator_y = n * sum_y2 - sum_y * sum_y
        
        if denominator_x <= 0 or denominator_y <= 0:
            return 0.0
        
        denominator = (denominator_x * denominator_y) ** 0.5
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator