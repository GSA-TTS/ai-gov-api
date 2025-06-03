# Section 7.4 - Application Server & Framework Performance Testing
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_Application Server & Framework Performance.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List
import concurrent.futures
import threading
import gc
import psutil
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestFastAPIServerPerformance:
    """Test FastAPI application server performance characteristics"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_server_single_worker_baseline_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """PERF_SERVER_SINGLE_WORKER_001: Test single worker baseline performance"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Baseline single worker performance test
        baseline_metrics = {
            "response_times": [],
            "throughput": 0,
            "memory_usage": [],
            "cpu_usage": []
        }
        
        # Monitor system resources
        process = psutil.Process(os.getpid())
        
        # Execute baseline requests
        num_requests = 20
        start_time = time.time()
        
        for i in range(num_requests):
            # Measure CPU and memory before request
            cpu_before = process.cpu_percent()
            memory_before = process.memory_info().rss / (1024 * 1024)  # MB
            
            request_start = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            request_end = time.perf_counter()
            
            # Measure CPU and memory after request
            cpu_after = process.cpu_percent()
            memory_after = process.memory_info().rss / (1024 * 1024)  # MB
            
            if response.status_code == 200:
                baseline_metrics["response_times"].append((request_end - request_start) * 1000)
                baseline_metrics["cpu_usage"].append(max(cpu_after - cpu_before, 0))
                baseline_metrics["memory_usage"].append(memory_after)
            
            await asyncio.sleep(0.1)  # Controlled delay
        
        total_time = time.time() - start_time
        baseline_metrics["throughput"] = len(baseline_metrics["response_times"]) / total_time
        
        # Analyze baseline performance
        if baseline_metrics["response_times"]:
            avg_response_time = statistics.mean(baseline_metrics["response_times"])
            p95_response_time = statistics.quantiles(baseline_metrics["response_times"], n=20)[18] if len(baseline_metrics["response_times"]) >= 20 else max(baseline_metrics["response_times"])
            avg_memory = statistics.mean(baseline_metrics["memory_usage"])
            
            # Single worker baseline assertions
            assert avg_response_time < 500.0, f"Single worker avg response time should be < 500ms, got {avg_response_time:.2f}ms"
            assert p95_response_time < 1000.0, f"Single worker P95 response time should be < 1s, got {p95_response_time:.2f}ms"
            assert baseline_metrics["throughput"] >= 1.0, f"Single worker throughput should be >= 1 RPS, got {baseline_metrics['throughput']:.2f}"
            
            logger.info(f"Single worker baseline - Avg: {avg_response_time:.2f}ms, P95: {p95_response_time:.2f}ms, RPS: {baseline_metrics['throughput']:.2f}, Memory: {avg_memory:.2f}MB")
        else:
            pytest.fail("No successful requests in single worker baseline test")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_server_multi_worker_comparison_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """PERF_SERVER_MULTI_WORKER_001: Test multi-worker performance comparison"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Simulate multi-worker scenario with concurrent requests
        concurrent_users = [5, 10, 15, 20]
        worker_performance = {}
        
        for user_count in concurrent_users:
            async def concurrent_user(user_id: int):
                user_times = []
                for i in range(3):  # Each user makes 3 requests
                    start_time = time.perf_counter()
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                    end_time = time.perf_counter()
                    
                    if response.status_code == 200:
                        user_times.append((end_time - start_time) * 1000)
                    
                    await asyncio.sleep(0.05)
                
                return user_times
            
            # Execute concurrent requests
            start_time = time.time()
            tasks = [concurrent_user(i) for i in range(user_count)]
            results = await asyncio.gather(*tasks)
            total_time = time.time() - start_time
            
            # Aggregate results
            all_times = [time for user_times in results for time in user_times]
            
            if all_times:
                worker_performance[user_count] = {
                    "avg_time": statistics.mean(all_times),
                    "p95_time": statistics.quantiles(all_times, n=20)[18] if len(all_times) >= 20 else max(all_times),
                    "throughput": len(all_times) / total_time,
                    "total_requests": len(all_times)
                }
            
            await asyncio.sleep(1)  # Brief pause between test phases
        
        # Analyze multi-worker performance scaling
        for user_count, performance in worker_performance.items():
            logger.info(f"{user_count} concurrent users - Avg: {performance['avg_time']:.2f}ms, P95: {performance['p95_time']:.2f}ms, RPS: {performance['throughput']:.2f}")
            
            # Multi-worker performance assertions
            assert performance["avg_time"] < 2000.0, f"{user_count} users avg time should be < 2s, got {performance['avg_time']:.2f}ms"
            assert performance["throughput"] >= 1.0, f"{user_count} users throughput should be >= 1 RPS, got {performance['throughput']:.2f}"
        
        # Verify scaling characteristics
        if len(worker_performance) >= 2:
            low_load = worker_performance[min(worker_performance.keys())]
            high_load = worker_performance[max(worker_performance.keys())]
            
            # Response time should not degrade excessively under load
            degradation_ratio = high_load["avg_time"] / low_load["avg_time"]
            assert degradation_ratio <= 5.0, f"Response time degradation should be <= 5x, got {degradation_ratio:.2f}x"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_server_async_handling_efficiency_001(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """PERF_SERVER_ASYNC_001: Test async request handling efficiency"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test async efficiency with mixed endpoints
        async def async_request_batch(batch_id: int):
            batch_times = []
            endpoints = [
                ("/api/v1/models", "GET", None),
                ("/api/v1/chat/completions", "POST", {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Async test {batch_id}"}],
                    "max_tokens": 20
                })
            ]
            
            for endpoint, method, data in endpoints:
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, method, endpoint, auth_headers, data
                )
                end_time = time.perf_counter()
                
                if response.status_code == 200:
                    batch_times.append((end_time - start_time) * 1000)
                
                await asyncio.sleep(0.01)
            
            return batch_times
        
        # Execute multiple async batches concurrently
        num_batches = 8
        start_time = time.time()
        
        tasks = [async_request_batch(i) for i in range(num_batches)]
        results = await asyncio.gather(*tasks)
        
        total_time = time.time() - start_time
        
        # Analyze async handling efficiency
        all_times = [time for batch_times in results for time in batch_times]
        
        if all_times:
            avg_async_time = statistics.mean(all_times)
            async_throughput = len(all_times) / total_time
            
            # Async handling should be efficient
            assert avg_async_time < 3000.0, f"Async handling avg time should be < 3s, got {avg_async_time:.2f}ms"
            assert async_throughput >= 2.0, f"Async throughput should be >= 2 RPS, got {async_throughput:.2f}"
            
            logger.info(f"Async handling efficiency - Avg: {avg_async_time:.2f}ms, RPS: {async_throughput:.2f} across {num_batches} concurrent batches")
        else:
            pytest.fail("No successful async requests recorded")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_server_timeout_configuration_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """PERF_SERVER_TIMEOUT_001: Test timeout configuration impact"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test timeout behavior with various request types
        timeout_scenarios = [
            {
                "name": "quick_request",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "data": None,
                "expected_time": 1000.0  # Should complete well under timeout
            },
            {
                "name": "standard_request",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Timeout test standard"}],
                    "max_tokens": 30
                },
                "expected_time": 5000.0  # Should complete within reasonable time
            },
            {
                "name": "larger_request",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Timeout test with a longer prompt to test how the system handles requests that might take more time to process"}],
                    "max_tokens": 100
                },
                "expected_time": 10000.0  # Should complete but may take longer
            }
        ]
        
        timeout_results = {}
        
        for scenario in timeout_scenarios:
            start_time = time.perf_counter()
            
            try:
                response = await make_request(
                    http_client, scenario["method"], scenario["endpoint"],
                    auth_headers, scenario["data"]
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                
                timeout_results[scenario["name"]] = {
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "completed": True
                }
                
                # Verify timeout handling
                assert response_time < scenario["expected_time"], f"{scenario['name']} should complete within {scenario['expected_time']}ms, took {response_time:.2f}ms"
                
            except asyncio.TimeoutError:
                end_time = time.perf_counter()
                timeout_results[scenario["name"]] = {
                    "status_code": 408,
                    "response_time": (end_time - start_time) * 1000,
                    "completed": False
                }
                logger.info(f"{scenario['name']} timed out as expected")
            
            await asyncio.sleep(0.1)
        
        # Analyze timeout configuration effectiveness
        for scenario_name, result in timeout_results.items():
            logger.info(f"Timeout test {scenario_name} - Status: {result['status_code']}, Time: {result['response_time']:.2f}ms, Completed: {result['completed']}")
            
            # Quick requests should never timeout
            if scenario_name == "quick_request":
                assert result["completed"], "Quick requests should always complete"
                assert result["response_time"] < 1000.0, f"Quick request should be < 1s, got {result['response_time']:.2f}ms"


class TestUvicornServerPerformance:
    """Test Uvicorn ASGI server performance"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_uvicorn_startup_shutdown_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """PERF_UVICORN_STARTUP_001: Test application startup/shutdown performance"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Measure application responsiveness (proxy for startup performance)
        startup_tests = []
        
        # Test rapid successive requests to verify server readiness
        for i in range(5):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                startup_tests.append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        if startup_tests:
            avg_startup_time = statistics.mean(startup_tests)
            first_request_time = startup_tests[0]
            
            # Server should be responsive quickly
            assert avg_startup_time < 1000.0, f"Average startup response should be < 1s, got {avg_startup_time:.2f}ms"
            assert first_request_time < 2000.0, f"First request should be < 2s, got {first_request_time:.2f}ms"
            
            logger.info(f"Startup performance - First request: {first_request_time:.2f}ms, Average: {avg_startup_time:.2f}ms")
        else:
            pytest.fail("No successful startup tests recorded")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_uvicorn_connection_handling_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_UVICORN_CONNECTION_001: Test connection handling performance"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test connection handling with burst requests
        connection_metrics = {
            "burst_response_times": [],
            "sustained_response_times": []
        }
        
        # Burst test - rapid requests
        burst_size = 10
        for i in range(burst_size):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                connection_metrics["burst_response_times"].append((end_time - start_time) * 1000)
        
        # Brief pause between tests
        await asyncio.sleep(1)
        
        # Sustained test - steady requests
        sustained_size = 15
        for i in range(sustained_size):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                connection_metrics["sustained_response_times"].append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.2)  # Sustained rhythm
        
        # Analyze connection handling
        for test_type, times in connection_metrics.items():
            if times:
                avg_time = statistics.mean(times)
                logger.info(f"{test_type} - Avg: {avg_time:.2f}ms over {len(times)} requests")
                
                # Connection handling should be efficient
                assert avg_time < 1000.0, f"{test_type} should be < 1s avg, got {avg_time:.2f}ms"
        
        # Burst should not significantly degrade sustained performance
        if connection_metrics["burst_response_times"] and connection_metrics["sustained_response_times"]:
            burst_avg = statistics.mean(connection_metrics["burst_response_times"])
            sustained_avg = statistics.mean(connection_metrics["sustained_response_times"])
            
            ratio = sustained_avg / burst_avg if burst_avg > 0 else 1.0
            
            # Sustained performance should not be significantly worse than burst
            assert ratio <= 3.0, f"Sustained/burst ratio should be <= 3.0, got {ratio:.2f}"


class TestMiddlewarePerformance:
    """Test middleware stack performance impact"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_middleware_stack_overhead_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """PERF_MIDDLEWARE_STACK_001: Test middleware stack overhead"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test middleware overhead with different request types
        middleware_tests = [
            {
                "name": "simple_get",
                "method": "GET",
                "endpoint": "/api/v1/models",
                "data": None
            },
            {
                "name": "authenticated_post",
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Middleware test"}],
                    "max_tokens": 15
                }
            }
        ]
        
        middleware_results = {}
        
        for test in middleware_tests:
            test_times = []
            
            for i in range(10):
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, test["method"], test["endpoint"],
                    auth_headers, test["data"]
                )
                end_time = time.perf_counter()
                
                if response.status_code == 200:
                    test_times.append((end_time - start_time) * 1000)
                
                await asyncio.sleep(0.05)
            
            if test_times:
                middleware_results[test["name"]] = {
                    "avg_time": statistics.mean(test_times),
                    "min_time": min(test_times),
                    "max_time": max(test_times),
                    "request_count": len(test_times)
                }
        
        # Analyze middleware overhead
        for test_name, results in middleware_results.items():
            logger.info(f"{test_name} middleware overhead - Avg: {results['avg_time']:.2f}ms, Range: {results['min_time']:.2f}-{results['max_time']:.2f}ms")
            
            # Middleware overhead should be reasonable
            if test_name == "simple_get":
                assert results["avg_time"] < 500.0, f"Simple GET middleware overhead should be < 500ms, got {results['avg_time']:.2f}ms"
            else:  # authenticated_post
                assert results["avg_time"] < 5000.0, f"Authenticated POST middleware overhead should be < 5s, got {results['avg_time']:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_middleware_auth_overhead_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """PERF_MIDDLEWARE_AUTH_001: Test authentication middleware overhead"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test auth middleware with valid credentials
        auth_times = []
        
        for i in range(15):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                auth_times.append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.05)
        
        # Test invalid auth (should be rejected quickly)
        invalid_auth_times = []
        invalid_headers = {"Authorization": "Bearer invalid_test_key"}
        
        for i in range(5):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                invalid_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            if response.status_code == 401:  # Expected unauthorized
                invalid_auth_times.append((end_time - start_time) * 1000)
        
        # Analyze auth middleware performance
        if auth_times:
            avg_auth_time = statistics.mean(auth_times)
            logger.info(f"Valid auth middleware - Avg: {avg_auth_time:.2f}ms over {len(auth_times)} requests")
            
            # Valid auth should be processed efficiently
            assert avg_auth_time < 1000.0, f"Valid auth should be < 1s, got {avg_auth_time:.2f}ms"
        
        if invalid_auth_times:
            avg_invalid_time = statistics.mean(invalid_auth_times)
            logger.info(f"Invalid auth rejection - Avg: {avg_invalid_time:.2f}ms over {len(invalid_auth_times)} requests")
            
            # Invalid auth should be rejected quickly
            assert avg_invalid_time < 500.0, f"Invalid auth rejection should be < 500ms, got {avg_invalid_time:.2f}ms"


class TestEnhancedApplicationPerformance:
    """Enhanced application server performance scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_dependency_injection_optimization_001(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """PERF_DEP_INJECTION_001: Test dependency injection optimization"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test dependency injection overhead with different endpoints
        injection_scenarios = [
            {
                "name": "models_endpoint",
                "method": "GET",
                "endpoint": "/api/v1/models",
                "data": None
            },
            {
                "name": "chat_endpoint",
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "DI optimization test"}],
                    "max_tokens": 20
                }
            }
        ]
        
        injection_performance = {}
        
        for scenario in injection_scenarios:
            times = []
            
            # Warm up dependencies
            for _ in range(3):
                await make_request(
                    http_client, scenario["method"], scenario["endpoint"],
                    auth_headers, scenario["data"]
                )
            
            # Measure dependency injection overhead
            for i in range(10):
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, scenario["method"], scenario["endpoint"],
                    auth_headers, scenario["data"]
                )
                end_time = time.perf_counter()
                
                if response.status_code == 200:
                    times.append((end_time - start_time) * 1000)
                
                await asyncio.sleep(0.02)
            
            if times:
                injection_performance[scenario["name"]] = {
                    "avg_time": statistics.mean(times),
                    "min_time": min(times),
                    "max_time": max(times)
                }
        
        # Analyze dependency injection optimization
        for scenario_name, performance in injection_performance.items():
            logger.info(f"{scenario_name} DI overhead - Avg: {performance['avg_time']:.2f}ms, Range: {performance['min_time']:.2f}-{performance['max_time']:.2f}ms")
            
            # Dependency injection should be optimized
            if scenario_name == "models_endpoint":
                assert performance["avg_time"] < 200.0, f"Models endpoint DI should be < 200ms, got {performance['avg_time']:.2f}ms"
            else:  # chat_endpoint
                assert performance["avg_time"] < 3000.0, f"Chat endpoint DI should be < 3s, got {performance['avg_time']:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_resource_contention_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """PERF_RESOURCE_CONTENTION_001: Test resource contention under load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test resource contention with concurrent mixed workload
        async def resource_contention_user(user_id: int, duration: int):
            """Simulate user creating resource contention"""
            end_time = time.time() + duration
            user_metrics = {"requests": 0, "response_times": [], "errors": 0}
            
            while time.time() < end_time:
                # Mix of endpoints to create resource contention
                endpoint_choice = user_id % 3
                
                if endpoint_choice == 0:
                    method, endpoint, data = "GET", "/api/v1/models", None
                elif endpoint_choice == 1:
                    method = "POST"
                    endpoint = "/api/v1/chat/completions"
                    data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Contention test user {user_id}"}],
                        "max_tokens": 15
                    }
                else:
                    if config.get_embedding_model(0):
                        method = "POST"
                        endpoint = "/api/v1/embeddings"
                        data = {
                            "model": config.get_embedding_model(0),
                            "input": f"Contention test user {user_id}"
                        }
                    else:
                        continue
                
                start_time = time.perf_counter()
                try:
                    response = await make_request(
                        http_client, method, endpoint, auth_headers, data
                    )
                    end_time_req = time.perf_counter()
                    
                    user_metrics["requests"] += 1
                    if response.status_code == 200:
                        user_metrics["response_times"].append((end_time_req - start_time) * 1000)
                    else:
                        user_metrics["errors"] += 1
                        
                except Exception:
                    user_metrics["errors"] += 1
                
                await asyncio.sleep(0.1)  # Brief delay
            
            return user_metrics
        
        # Execute resource contention test
        concurrent_users = 8
        test_duration = 15  # seconds
        
        tasks = [resource_contention_user(i, test_duration) for i in range(concurrent_users)]
        results = await asyncio.gather(*tasks)
        
        # Analyze resource contention impact
        total_requests = sum(result["requests"] for result in results)
        total_errors = sum(result["errors"] for result in results)
        all_response_times = [time for result in results for time in result["response_times"]]
        
        error_rate = total_errors / (total_requests + total_errors) if (total_requests + total_errors) > 0 else 0
        
        if all_response_times:
            avg_contention_time = statistics.mean(all_response_times)
            p95_contention_time = statistics.quantiles(all_response_times, n=20)[18] if len(all_response_times) >= 20 else max(all_response_times)
            
            # Resource contention should be managed effectively
            assert error_rate <= 0.20, f"Error rate under contention should be <= 20%, got {error_rate:.2%}"
            assert avg_contention_time < 5000.0, f"Avg response time under contention should be < 5s, got {avg_contention_time:.2f}ms"
            
            logger.info(f"Resource contention test - {total_requests} requests, {error_rate:.2%} error rate, Avg: {avg_contention_time:.2f}ms, P95: {p95_contention_time:.2f}ms")
        else:
            pytest.fail("No successful requests during resource contention test")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_app_lifecycle_shutdown_graceful_005(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """PERF_APP_LIFECYCLE_SHUTDOWN_GRACEFUL_005: Test graceful shutdown performance"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test graceful shutdown behavior under load
        # Note: This is a simulation since we can't actually shutdown the test server
        
        shutdown_simulation_metrics = {
            "active_requests": [],
            "response_times": [],
            "completion_rates": [],
            "graceful_handling": []
        }
        
        # Simulate conditions leading to graceful shutdown
        shutdown_scenarios = [
            {"name": "normal_load", "concurrent": 5, "duration": 10},
            {"name": "high_load", "concurrent": 15, "duration": 8},
            {"name": "burst_load", "concurrent": 25, "duration": 5}
        ]
        
        for scenario in shutdown_scenarios:
            scenario_metrics = {
                "requests_started": 0,
                "requests_completed": 0,
                "response_times": [],
                "errors": 0
            }
            
            async def graceful_shutdown_request(req_id: int):
                """Simulate request during graceful shutdown"""
                try:
                    scenario_metrics["requests_started"] += 1
                    
                    start_time = time.perf_counter()
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Graceful shutdown test {scenario['name']} request {req_id}"}],
                            "max_tokens": 50
                        }
                    )
                    end_time = time.perf_counter()
                    
                    response_time = (end_time - start_time) * 1000
                    
                    if response.status_code == 200:
                        scenario_metrics["requests_completed"] += 1
                        scenario_metrics["response_times"].append(response_time)
                    else:
                        scenario_metrics["errors"] += 1
                    
                    return {
                        "completed": response.status_code == 200,
                        "response_time": response_time,
                        "status_code": response.status_code
                    }
                    
                except Exception as e:
                    scenario_metrics["errors"] += 1
                    return {
                        "completed": False,
                        "response_time": 0,
                        "error": str(e)
                    }
            
            # Execute scenario requests
            tasks = [graceful_shutdown_request(i) for i in range(scenario["concurrent"])]
            
            # Wait for requests with timeout to simulate shutdown pressure
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=scenario["duration"] + 5  # Allow extra time for completion
                )
            except asyncio.TimeoutError:
                logger.warning(f"Timeout during graceful shutdown simulation for {scenario['name']}")
                results = []
            
            # Calculate completion rate
            completion_rate = scenario_metrics["requests_completed"] / scenario_metrics["requests_started"] if scenario_metrics["requests_started"] > 0 else 0
            
            avg_response_time = statistics.mean(scenario_metrics["response_times"]) if scenario_metrics["response_times"] else 0
            
            # Assess graceful handling
            graceful_score = completion_rate * 100  # Percentage of requests completed successfully
            
            shutdown_simulation_metrics["active_requests"].append(scenario_metrics["requests_started"])
            shutdown_simulation_metrics["response_times"].extend(scenario_metrics["response_times"])
            shutdown_simulation_metrics["completion_rates"].append(completion_rate)
            shutdown_simulation_metrics["graceful_handling"].append(graceful_score)
            
            logger.info(f"Graceful shutdown simulation {scenario['name']} - "
                       f"Started: {scenario_metrics['requests_started']}, "
                       f"Completed: {scenario_metrics['requests_completed']}, "
                       f"Completion rate: {completion_rate:.2%}, "
                       f"Avg response time: {avg_response_time:.2f}ms, "
                       f"Graceful score: {graceful_score:.1f}")
            
            # Graceful shutdown should maintain reasonable completion rates
            assert completion_rate >= 0.7, f"Graceful shutdown should complete >= 70% of requests for {scenario['name']}, got {completion_rate:.2%}"
            
            if scenario_metrics["response_times"]:
                assert avg_response_time <= 8000.0, f"Response times should remain reasonable during shutdown for {scenario['name']}, got {avg_response_time:.2f}ms"
            
            await asyncio.sleep(1)  # Brief pause between scenarios
        
        # Overall graceful shutdown assessment
        overall_completion_rate = statistics.mean(shutdown_simulation_metrics["completion_rates"])
        overall_graceful_score = statistics.mean(shutdown_simulation_metrics["graceful_handling"])
        
        logger.info(f"Overall graceful shutdown performance - "
                   f"Avg completion rate: {overall_completion_rate:.2%}, "
                   f"Avg graceful score: {overall_graceful_score:.1f}")
        
        # Validate overall graceful shutdown behavior
        assert overall_completion_rate >= 0.75, f"Overall graceful shutdown completion rate should be >= 75%, got {overall_completion_rate:.2%}"
        assert overall_graceful_score >= 75.0, f"Overall graceful shutdown score should be >= 75, got {overall_graceful_score:.1f}"
        
        logger.info("Graceful shutdown performance test completed successfully")