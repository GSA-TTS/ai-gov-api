# Section 7.4 - Database Performance & Connection Management
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_Database Performance & Connection Management.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import psutil
import os
import concurrent.futures
from unittest.mock import patch

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class DatabasePerformanceResult:
    """Database performance test result data structure"""
    test_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time: float
    p95_response_time: float
    db_connection_count: int
    query_efficiency_score: float


class TestConnectionPoolManagement:
    """Test database connection pool management and exhaustion scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_db_pool_exhaustion_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """PERF_DB_POOL_EXHAUSTION_001: Test connection pool behavior under high concurrent load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test connection pool exhaustion with high concurrency
        pool_exhaustion_metrics = {
            "successful_requests": 0,
            "failed_requests": 0,
            "response_times": [],
            "error_types": {},
            "timeout_requests": 0
        }
        
        async def concurrent_db_request(request_id: int):
            """Simulate concurrent database-intensive request"""
            try:
                start_time = time.perf_counter()
                
                # Use authenticated endpoint to force database lookup
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
                
                end_time = time.perf_counter()
                response_time = (end_time - start_time) * 1000
                
                if response.status_code == 200:
                    return {"status": "success", "response_time": response_time}
                else:
                    return {"status": "failed", "response_time": response_time, "status_code": response.status_code}
                    
            except asyncio.TimeoutError:
                return {"status": "timeout", "response_time": 30000}  # 30 second timeout
            except Exception as e:
                return {"status": "error", "response_time": 0, "error": str(e)}
        
        # Generate high concurrent load that should exceed typical connection pool size
        concurrent_requests = 50  # Should exceed typical pool size of 5-10
        
        start_time = time.time()
        tasks = [concurrent_db_request(i) for i in range(concurrent_requests)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.time() - start_time
        
        # Analyze connection pool exhaustion behavior
        for result in results:
            if isinstance(result, dict):
                if result["status"] == "success":
                    pool_exhaustion_metrics["successful_requests"] += 1
                    pool_exhaustion_metrics["response_times"].append(result["response_time"])
                elif result["status"] == "timeout":
                    pool_exhaustion_metrics["timeout_requests"] += 1
                else:
                    pool_exhaustion_metrics["failed_requests"] += 1
                    error_type = result.get("status", "unknown")
                    pool_exhaustion_metrics["error_types"][error_type] = pool_exhaustion_metrics["error_types"].get(error_type, 0) + 1
        
        success_rate = pool_exhaustion_metrics["successful_requests"] / concurrent_requests
        timeout_rate = pool_exhaustion_metrics["timeout_requests"] / concurrent_requests
        
        if pool_exhaustion_metrics["response_times"]:
            avg_response_time = statistics.mean(pool_exhaustion_metrics["response_times"])
            p95_response_time = statistics.quantiles(pool_exhaustion_metrics["response_times"], n=20)[18] if len(pool_exhaustion_metrics["response_times"]) >= 20 else max(pool_exhaustion_metrics["response_times"])
            
            logger.info(f"Connection pool exhaustion test - "
                       f"Success rate: {success_rate:.2%}, "
                       f"Timeout rate: {timeout_rate:.2%}, "
                       f"Avg response: {avg_response_time:.2f}ms, "
                       f"P95 response: {p95_response_time:.2f}ms")
            
            # Verify connection pool handles high load reasonably
            assert success_rate >= 0.70, f"Success rate should be reasonable under high load, got {success_rate:.2%}"
            assert timeout_rate <= 0.20, f"Timeout rate should be manageable, got {timeout_rate:.2%}"
            assert avg_response_time < 10000.0, f"Average response time should be reasonable, got {avg_response_time:.2f}ms"
        else:
            pytest.fail("No successful requests during connection pool exhaustion test")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_db_pool_recovery_002(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """PERF_DB_POOL_RECOVERY_002: Test connection pool recovery after stress"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Phase 1: Establish baseline performance
        baseline_metrics = []
        for i in range(10):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                baseline_metrics.append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        baseline_avg = statistics.mean(baseline_metrics) if baseline_metrics else 0
        
        # Phase 2: Induce connection pool stress
        stress_tasks = []
        for i in range(30):  # Moderate stress
            task = asyncio.create_task(make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            ))
            stress_tasks.append(task)
        
        # Wait for stress to complete
        await asyncio.gather(*stress_tasks, return_exceptions=True)
        
        # Phase 3: Allow brief recovery time
        await asyncio.sleep(2)
        
        # Phase 4: Test recovery performance
        recovery_metrics = []
        for i in range(15):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                recovery_metrics.append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        recovery_avg = statistics.mean(recovery_metrics) if recovery_metrics else 0
        
        # Analyze recovery effectiveness
        recovery_ratio = recovery_avg / baseline_avg if baseline_avg > 0 else 1.0
        
        logger.info(f"Connection pool recovery - "
                   f"Baseline: {baseline_avg:.2f}ms, "
                   f"Recovery: {recovery_avg:.2f}ms, "
                   f"Recovery ratio: {recovery_ratio:.2f}x")
        
        # Verify connection pool recovers well
        assert recovery_ratio <= 2.0, f"Connection pool should recover to reasonable performance, got {recovery_ratio:.2f}x baseline"
        assert recovery_avg < 2000.0, f"Recovery performance should be good, got {recovery_avg:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_db_connection_burst_003(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """PERF_DB_CONNECTION_BURST_003: Test connection pool behavior during request bursts"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test burst handling with multiple sudden spikes
        burst_scenarios = [
            {"name": "small_burst", "concurrent_requests": 15, "burst_count": 3},
            {"name": "medium_burst", "concurrent_requests": 25, "burst_count": 2},
            {"name": "large_burst", "concurrent_requests": 40, "burst_count": 1}
        ]
        
        burst_results = {}
        
        for scenario in burst_scenarios:
            scenario_metrics = {
                "successful_bursts": 0,
                "total_requests": 0,
                "successful_requests": 0,
                "avg_response_times": [],
                "burst_completion_times": []
            }
            
            for burst_num in range(scenario["burst_count"]):
                # Generate burst of concurrent requests
                async def burst_request(req_id: int):
                    start_time = time.perf_counter()
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                    end_time = time.perf_counter()
                    return {
                        "response_time": (end_time - start_time) * 1000,
                        "success": response.status_code == 200
                    }
                
                burst_start = time.perf_counter()
                burst_tasks = [burst_request(i) for i in range(scenario["concurrent_requests"])]
                burst_results_list = await asyncio.gather(*burst_tasks, return_exceptions=True)
                burst_end = time.perf_counter()
                
                burst_completion_time = (burst_end - burst_start) * 1000
                scenario_metrics["burst_completion_times"].append(burst_completion_time)
                
                # Analyze burst results
                burst_successful = 0
                burst_response_times = []
                
                for result in burst_results_list:
                    if isinstance(result, dict):
                        scenario_metrics["total_requests"] += 1
                        if result["success"]:
                            burst_successful += 1
                            scenario_metrics["successful_requests"] += 1
                            burst_response_times.append(result["response_time"])
                
                if burst_response_times:
                    scenario_metrics["avg_response_times"].extend(burst_response_times)
                
                if burst_successful >= scenario["concurrent_requests"] * 0.8:  # 80% success rate
                    scenario_metrics["successful_bursts"] += 1
                
                # Brief pause between bursts
                await asyncio.sleep(1)
            
            burst_results[scenario["name"]] = scenario_metrics
        
        # Analyze burst handling effectiveness
        for scenario_name, metrics in burst_results.items():
            if metrics["avg_response_times"]:
                avg_response_time = statistics.mean(metrics["avg_response_times"])
                avg_burst_completion = statistics.mean(metrics["burst_completion_times"])
                success_rate = metrics["successful_requests"] / metrics["total_requests"] if metrics["total_requests"] > 0 else 0
                
                logger.info(f"{scenario_name} - "
                           f"Success rate: {success_rate:.2%}, "
                           f"Avg response: {avg_response_time:.2f}ms, "
                           f"Avg burst completion: {avg_burst_completion:.2f}ms")
                
                # Verify burst handling
                assert success_rate >= 0.75, f"{scenario_name} success rate should be good, got {success_rate:.2%}"
                assert avg_response_time < 5000.0, f"{scenario_name} response time should be reasonable, got {avg_response_time:.2f}ms"


class TestQueryPerformance:
    """Test database query performance and optimization"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_db_query_auth_key_lookup_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """PERF_DB_QUERY_AUTH_KEY_LOOKUP_001: Test API key lookup query performance"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test authentication query performance under load
        auth_lookup_metrics = {
            "response_times": [],
            "successful_lookups": 0,
            "failed_lookups": 0,
            "lookup_efficiency": []
        }
        
        # Generate sustained authentication load
        for i in range(100):
            start_time = time.perf_counter()
            
            # Use authenticated endpoint to trigger API key lookup
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000
            
            if response.status_code == 200:
                auth_lookup_metrics["successful_lookups"] += 1
                auth_lookup_metrics["response_times"].append(response_time)
                
                # Calculate lookup efficiency (assuming most time is auth lookup for /models)
                if response_time > 0:
                    auth_lookup_metrics["lookup_efficiency"].append(1000 / response_time)  # lookups per second
            else:
                auth_lookup_metrics["failed_lookups"] += 1
            
            await asyncio.sleep(0.02)  # High frequency
        
        # Analyze authentication query performance
        if auth_lookup_metrics["response_times"]:
            avg_response_time = statistics.mean(auth_lookup_metrics["response_times"])
            p95_response_time = statistics.quantiles(auth_lookup_metrics["response_times"], n=20)[18] if len(auth_lookup_metrics["response_times"]) >= 20 else max(auth_lookup_metrics["response_times"])
            success_rate = auth_lookup_metrics["successful_lookups"] / (auth_lookup_metrics["successful_lookups"] + auth_lookup_metrics["failed_lookups"])
            
            logger.info(f"Auth key lookup performance - "
                       f"Avg: {avg_response_time:.2f}ms, "
                       f"P95: {p95_response_time:.2f}ms, "
                       f"Success rate: {success_rate:.2%}")
            
            # Verify authentication query performance
            assert avg_response_time < 100.0, f"Auth lookup avg time should be fast, got {avg_response_time:.2f}ms"
            assert p95_response_time < 200.0, f"Auth lookup P95 time should be fast, got {p95_response_time:.2f}ms"
            assert success_rate >= 0.99, f"Auth lookup success rate should be high, got {success_rate:.2%}"
        else:
            pytest.fail("No successful authentication lookups recorded")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_db_query_optimization_002(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """PERF_DB_QUERY_OPTIMIZATION_002: Test query optimization effectiveness"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test query optimization by measuring consistent performance
        optimization_metrics = {
            "cold_queries": [],
            "warm_queries": [],
            "query_consistency": []
        }
        
        # Cold query performance (first few queries)
        for i in range(5):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                optimization_metrics["cold_queries"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        # Warm query performance (after cache/connection warmup)
        for i in range(20):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                optimization_metrics["warm_queries"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.05)
        
        # Analyze query optimization
        if optimization_metrics["cold_queries"] and optimization_metrics["warm_queries"]:
            cold_avg = statistics.mean(optimization_metrics["cold_queries"])
            warm_avg = statistics.mean(optimization_metrics["warm_queries"])
            warm_std = statistics.stdev(optimization_metrics["warm_queries"]) if len(optimization_metrics["warm_queries"]) > 1 else 0
            
            optimization_ratio = cold_avg / warm_avg if warm_avg > 0 else 1.0
            consistency_score = warm_std / warm_avg if warm_avg > 0 else 0
            
            logger.info(f"Query optimization - "
                       f"Cold avg: {cold_avg:.2f}ms, "
                       f"Warm avg: {warm_avg:.2f}ms, "
                       f"Optimization ratio: {optimization_ratio:.2f}x, "
                       f"Consistency score: {consistency_score:.3f}")
            
            # Verify query optimization effectiveness
            assert warm_avg < 500.0, f"Warm queries should be fast, got {warm_avg:.2f}ms"
            assert consistency_score <= 0.5, f"Query performance should be consistent, got {consistency_score:.3f}"
            assert optimization_ratio >= 0.8, f"Optimization should maintain performance, got {optimization_ratio:.2f}x"


class TestSessionLifecycleManagement:
    """Test database session lifecycle and transaction overhead"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_db_session_overhead_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """PERF_DB_SESSION_OVERHEAD_001: Measure database session management overhead"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test session overhead by comparing simple vs complex operations
        session_overhead_metrics = {
            "simple_operations": [],
            "complex_operations": [],
            "session_efficiency": []
        }
        
        # Test simple operations (minimal database interaction)
        for i in range(30):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                session_overhead_metrics["simple_operations"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.05)
        
        # Test complex operations (multiple database interactions)
        for i in range(20):
            start_time = time.perf_counter()
            
            # Make multiple requests that should each create a session
            response1 = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            
            if response1.status_code == 200:
                # Follow up with another request
                response2 = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Session test {i}"}],
                        "max_tokens": 10
                    }
                )
                
                end_time = time.perf_counter()
                if response2.status_code == 200:
                    session_overhead_metrics["complex_operations"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        # Analyze session overhead
        if session_overhead_metrics["simple_operations"] and session_overhead_metrics["complex_operations"]:
            simple_avg = statistics.mean(session_overhead_metrics["simple_operations"])
            complex_avg = statistics.mean(session_overhead_metrics["complex_operations"])
            
            # Estimate session overhead per operation
            overhead_per_operation = (complex_avg - simple_avg) / 2 if complex_avg > simple_avg else 0
            efficiency_ratio = simple_avg / complex_avg if complex_avg > 0 else 1.0
            
            logger.info(f"Session overhead - "
                       f"Simple avg: {simple_avg:.2f}ms, "
                       f"Complex avg: {complex_avg:.2f}ms, "
                       f"Overhead per operation: {overhead_per_operation:.2f}ms, "
                       f"Efficiency ratio: {efficiency_ratio:.3f}")
            
            # Verify session overhead is reasonable
            assert overhead_per_operation <= 50.0, f"Session overhead should be minimal, got {overhead_per_operation:.2f}ms per operation"
            assert simple_avg < 200.0, f"Simple operations should be fast, got {simple_avg:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_db_transaction_performance_004(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_DB_TRANSACTION_PERFORMANCE_004: Test transaction performance under concurrent load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test transaction performance with concurrent operations
        transaction_metrics = {
            "concurrent_requests": [],
            "sequential_requests": [],
            "contention_indicators": []
        }
        
        # Sequential baseline (no transaction contention)
        for i in range(15):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                transaction_metrics["sequential_requests"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        # Concurrent transaction test
        async def concurrent_transaction_test(request_id: int):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                return (end_time - start_time) * 1000
            return None
        
        # Execute concurrent transactions
        concurrent_tasks = [concurrent_transaction_test(i) for i in range(20)]
        concurrent_results = await asyncio.gather(*concurrent_tasks, return_exceptions=True)
        
        # Collect successful concurrent results
        for result in concurrent_results:
            if isinstance(result, (int, float)) and result is not None:
                transaction_metrics["concurrent_requests"].append(result)
        
        # Analyze transaction performance
        if transaction_metrics["sequential_requests"] and transaction_metrics["concurrent_requests"]:
            sequential_avg = statistics.mean(transaction_metrics["sequential_requests"])
            concurrent_avg = statistics.mean(transaction_metrics["concurrent_requests"])
            concurrent_std = statistics.stdev(transaction_metrics["concurrent_requests"]) if len(transaction_metrics["concurrent_requests"]) > 1 else 0
            
            contention_ratio = concurrent_avg / sequential_avg if sequential_avg > 0 else 1.0
            variability_score = concurrent_std / concurrent_avg if concurrent_avg > 0 else 0
            
            logger.info(f"Transaction performance - "
                       f"Sequential avg: {sequential_avg:.2f}ms, "
                       f"Concurrent avg: {concurrent_avg:.2f}ms, "
                       f"Contention ratio: {contention_ratio:.2f}x, "
                       f"Variability: {variability_score:.3f}")
            
            # Verify transaction performance under concurrency
            assert contention_ratio <= 3.0, f"Transaction contention should be manageable, got {contention_ratio:.2f}x"
            assert concurrent_avg < 1000.0, f"Concurrent transactions should be efficient, got {concurrent_avg:.2f}ms"
            assert variability_score <= 1.0, f"Transaction performance should be consistent, got {variability_score:.3f}"


class TestEnhancedDatabaseScenarios:
    """Enhanced database performance testing scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_db_resilience_failover_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """PERF_DB_RESILIENCE_FAILOVER_001: Test database connection resilience"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test database resilience by simulating stress and recovery
        resilience_metrics = {
            "baseline_performance": [],
            "stress_performance": [],
            "recovery_performance": [],
            "error_rates": {"baseline": 0, "stress": 0, "recovery": 0}
        }
        
        # Phase 1: Baseline performance
        for i in range(10):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                resilience_metrics["baseline_performance"].append((end_time - start_time) * 1000)
            else:
                resilience_metrics["error_rates"]["baseline"] += 1
            
            await asyncio.sleep(0.1)
        
        # Phase 2: Stress test (simulate connection pressure)
        stress_tasks = []
        for i in range(30):
            task = asyncio.create_task(make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            ))
            stress_tasks.append(task)
        
        stress_start = time.perf_counter()
        stress_results = await asyncio.gather(*stress_tasks, return_exceptions=True)
        stress_duration = (time.perf_counter() - stress_start) * 1000
        
        # Analyze stress results
        for result in stress_results:
            if hasattr(result, 'status_code'):
                if result.status_code == 200:
                    # Estimate response time based on total duration
                    resilience_metrics["stress_performance"].append(stress_duration / len(stress_results))
                else:
                    resilience_metrics["error_rates"]["stress"] += 1
        
        # Phase 3: Recovery test
        await asyncio.sleep(2)  # Allow recovery time
        
        for i in range(15):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                resilience_metrics["recovery_performance"].append((end_time - start_time) * 1000)
            else:
                resilience_metrics["error_rates"]["recovery"] += 1
            
            await asyncio.sleep(0.1)
        
        # Analyze resilience
        baseline_avg = statistics.mean(resilience_metrics["baseline_performance"]) if resilience_metrics["baseline_performance"] else 0
        recovery_avg = statistics.mean(resilience_metrics["recovery_performance"]) if resilience_metrics["recovery_performance"] else 0
        
        recovery_ratio = recovery_avg / baseline_avg if baseline_avg > 0 else 1.0
        
        logger.info(f"Database resilience - "
                   f"Baseline: {baseline_avg:.2f}ms, "
                   f"Recovery: {recovery_avg:.2f}ms, "
                   f"Recovery ratio: {recovery_ratio:.2f}x")
        
        # Verify resilience
        assert recovery_ratio <= 2.0, f"Recovery should be reasonable, got {recovery_ratio:.2f}x baseline"
        assert resilience_metrics["error_rates"]["recovery"] <= 2, f"Recovery errors should be minimal"
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_db_scaling_capacity_006(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """PERF_DB_SCALING_CAPACITY_006: Test database scaling and capacity planning"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test database capacity by gradually increasing load
        scaling_metrics = {
            "load_levels": {},
            "capacity_indicators": [],
            "performance_degradation": []
        }
        
        # Test different load levels
        load_levels = [5, 10, 20, 30]
        
        for load_level in load_levels:
            level_metrics = {
                "successful_requests": 0,
                "failed_requests": 0,
                "response_times": [],
                "throughput": 0
            }
            
            # Generate load at this level
            start_time = time.time()
            
            async def load_request(req_id: int):
                req_start = time.perf_counter()
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
                req_end = time.perf_counter()
                
                return {
                    "response_time": (req_end - req_start) * 1000,
                    "success": response.status_code == 200
                }
            
            # Execute load in batches
            batch_size = 5
            for batch_start in range(0, load_level, batch_size):
                batch_end = min(batch_start + batch_size, load_level)
                batch_tasks = [load_request(i) for i in range(batch_start, batch_end)]
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, dict):
                        if result["success"]:
                            level_metrics["successful_requests"] += 1
                            level_metrics["response_times"].append(result["response_time"])
                        else:
                            level_metrics["failed_requests"] += 1
                
                await asyncio.sleep(0.1)  # Brief pause between batches
            
            total_time = time.time() - start_time
            level_metrics["throughput"] = level_metrics["successful_requests"] / total_time if total_time > 0 else 0
            
            scaling_metrics["load_levels"][load_level] = level_metrics
            
            # Brief pause between load levels
            await asyncio.sleep(1)
        
        # Analyze scaling behavior
        for load_level, metrics in scaling_metrics["load_levels"].items():
            if metrics["response_times"]:
                avg_response_time = statistics.mean(metrics["response_times"])
                success_rate = metrics["successful_requests"] / (metrics["successful_requests"] + metrics["failed_requests"]) if (metrics["successful_requests"] + metrics["failed_requests"]) > 0 else 0
                
                logger.info(f"Load level {load_level} - "
                           f"Success rate: {success_rate:.2%}, "
                           f"Avg response: {avg_response_time:.2f}ms, "
                           f"Throughput: {metrics['throughput']:.2f} RPS")
                
                # Verify scaling capacity
                assert success_rate >= 0.80, f"Load level {load_level} success rate should be good, got {success_rate:.2%}"
                
                # Track performance degradation
                if load_level == min(load_levels):
                    baseline_response_time = avg_response_time
                else:
                    degradation = avg_response_time / baseline_response_time if baseline_response_time > 0 else 1.0
                    scaling_metrics["performance_degradation"].append(degradation)
        
        # Verify overall scaling behavior
        if scaling_metrics["performance_degradation"]:
            max_degradation = max(scaling_metrics["performance_degradation"])
            assert max_degradation <= 5.0, f"Performance degradation should be reasonable, got {max_degradation:.2f}x"