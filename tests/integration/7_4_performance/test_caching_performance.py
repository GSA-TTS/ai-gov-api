# Section 7.4 - Caching Performance & Configuration Testing
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_ Caching Performance & Configuration.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List
from dataclasses import dataclass
import gc
import sys
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class CachePerformanceResult:
    """Cache performance test result data structure"""
    test_name: str
    cache_hits: int
    cache_misses: int
    hit_rate: float
    avg_cache_hit_time: float
    avg_cache_miss_time: float
    total_requests: int
    cache_overhead: float


class TestApplicationSettingsCache:
    """Test @lru_cache performance for application settings"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cache_settings_hit_latency_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_CACHE_SETTINGS_HIT_001: Test settings cache hit latency"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Warm up cache by making several requests
        warmup_requests = 5
        for i in range(warmup_requests):
            await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            await asyncio.sleep(0.1)
        
        # Measure cache hit performance
        cache_hit_times = []
        total_requests = 20
        
        for i in range(total_requests):
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            assert response.status_code == 200, f"Request {i+1} should succeed"
            cache_hit_times.append((end_time - start_time) * 1000)  # Convert to milliseconds
            
            await asyncio.sleep(0.05)  # Small delay between requests
        
        # Analyze cache hit performance
        avg_hit_time = statistics.mean(cache_hit_times)
        p95_hit_time = statistics.quantiles(cache_hit_times, n=20)[18] if len(cache_hit_times) >= 20 else max(cache_hit_times)
        
        # Cache hits should be significantly faster
        assert avg_hit_time < 50.0, f"Average cache hit time should be < 50ms, got {avg_hit_time:.2f}ms"
        assert p95_hit_time < 100.0, f"P95 cache hit time should be < 100ms, got {p95_hit_time:.2f}ms"
        
        logger.info(f"Cache hit performance - Avg: {avg_hit_time:.2f}ms, P95: {p95_hit_time:.2f}ms")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cache_settings_miss_latency_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_CACHE_SETTINGS_MISS_001: Test settings cache miss latency"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Force cache misses by varying request parameters
        cache_miss_times = []
        endpoints_to_test = [
            "/api/v1/models",
            "/api/v1/chat/completions",
            "/api/v1/embeddings"
        ]
        
        for endpoint in endpoints_to_test:
            start_time = time.perf_counter()
            
            if endpoint == "/api/v1/models":
                response = await make_request(
                    http_client, "GET", endpoint, auth_headers, track_cost=False
                )
            elif endpoint == "/api/v1/chat/completions":
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Cache miss test"}],
                    "max_tokens": 10
                }
                response = await make_request(
                    http_client, "POST", endpoint, auth_headers, request_data
                )
            else:  # embeddings
                if config.get_embedding_model(0):
                    request_data = {
                        "model": config.get_embedding_model(0),
                        "input": "Cache miss test"
                    }
                    embedding_headers = auth_headers.copy()
                    response = await make_request(
                        http_client, "POST", endpoint, embedding_headers, request_data
                    )
                else:
                    continue
            
            end_time = time.perf_counter()
            
            if response.status_code in [200, 422]:  # Accept both success and validation errors
                cache_miss_times.append((end_time - start_time) * 1000)
        
        if cache_miss_times:
            avg_miss_time = statistics.mean(cache_miss_times)
            logger.info(f"Cache miss performance - Avg: {avg_miss_time:.2f}ms")
            
            # Cache misses will be slower but should still be reasonable
            assert avg_miss_time < 5000.0, f"Average cache miss time should be < 5s, got {avg_miss_time:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cache_concurrent_access_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """PERF_CACHE_CONCURRENT_001: Test cache performance under concurrent access"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        async def concurrent_cache_access(user_id: int, num_requests: int):
            """Simulate concurrent cache access"""
            times = []
            for i in range(num_requests):
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
                end_time = time.perf_counter()
                
                if response.status_code == 200:
                    times.append((end_time - start_time) * 1000)
                
                await asyncio.sleep(0.01)  # Small delay
            
            return times
        
        # Test concurrent access
        concurrent_users = 10
        requests_per_user = 5
        
        # Warm up cache first
        await make_request(http_client, "GET", "/api/v1/models", auth_headers, track_cost=False)
        
        # Execute concurrent cache access
        tasks = [concurrent_cache_access(i, requests_per_user) for i in range(concurrent_users)]
        results = await asyncio.gather(*tasks)
        
        # Analyze concurrent performance
        all_times = [time for user_times in results for time in user_times]
        
        if all_times:
            avg_concurrent_time = statistics.mean(all_times)
            p95_concurrent_time = statistics.quantiles(all_times, n=20)[18] if len(all_times) >= 20 else max(all_times)
            
            # Concurrent cache access should maintain good performance
            assert avg_concurrent_time < 100.0, f"Concurrent cache avg time should be < 100ms, got {avg_concurrent_time:.2f}ms"
            assert p95_concurrent_time < 200.0, f"Concurrent cache P95 time should be < 200ms, got {p95_concurrent_time:.2f}ms"
            
            logger.info(f"Concurrent cache access - Avg: {avg_concurrent_time:.2f}ms, P95: {p95_concurrent_time:.2f}ms")
        else:
            pytest.fail("No successful concurrent cache accesses recorded")


class TestProviderBackendInstanceCaching:
    """Test provider backend instance caching and reuse"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cache_provider_instance_reuse_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """PERF_CACHE_PROVIDER_REUSE_001: Test provider instance reuse effectiveness"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test same model multiple times to verify instance reuse
        model_name = config.get_chat_model(0)
        instance_reuse_times = []
        
        for i in range(10):
            request_data = {
                "model": model_name,
                "messages": [{"role": "user", "content": f"Provider instance test {i}"}],
                "max_tokens": 20
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                instance_reuse_times.append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.1)
        
        if instance_reuse_times:
            avg_reuse_time = statistics.mean(instance_reuse_times)
            
            # After first few requests, provider instance reuse should improve performance
            if len(instance_reuse_times) >= 5:
                early_times = instance_reuse_times[:3]
                later_times = instance_reuse_times[3:]
                
                avg_early = statistics.mean(early_times)
                avg_later = statistics.mean(later_times)
                
                # Later requests should benefit from instance reuse
                improvement_ratio = avg_early / avg_later if avg_later > 0 else 1.0
                logger.info(f"Provider instance reuse - Early: {avg_early:.2f}ms, Later: {avg_later:.2f}ms, Improvement: {improvement_ratio:.2f}x")
                
                # Should see some improvement from instance reuse
                assert improvement_ratio >= 0.9, f"Instance reuse should maintain or improve performance, got {improvement_ratio:.2f}x"
    
    @pytest.mark.performance 
    @pytest.mark.asyncio
    async def test_perf_cache_provider_multi_model_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_CACHE_PROVIDER_MULTI_001: Test caching with multiple models"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test multiple models to verify separate instance caching
        available_models = config.CHAT_MODELS[:3]  # Test up to 3 models
        
        if len(available_models) < 2:
            pytest.skip("Need at least 2 models for multi-model cache testing")
        
        model_performance = {}
        
        for model in available_models:
            model_times = []
            
            for i in range(5):
                request_data = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Multi-model cache test {i}"}],
                    "max_tokens": 20
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                if response.status_code == 200:
                    model_times.append((end_time - start_time) * 1000)
                
                await asyncio.sleep(0.1)
            
            if model_times:
                model_performance[model] = {
                    "avg_time": statistics.mean(model_times),
                    "request_count": len(model_times)
                }
        
        # Verify each model maintains reasonable performance
        for model, perf_data in model_performance.items():
            assert perf_data["avg_time"] < 10000.0, f"Model {model} avg time should be < 10s, got {perf_data['avg_time']:.2f}ms"
            logger.info(f"Model {model} performance - Avg: {perf_data['avg_time']:.2f}ms over {perf_data['request_count']} requests")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cache_provider_memory_overhead_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """PERF_CACHE_PROVIDER_MEMORY_001: Test memory overhead of provider caching"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Measure memory before provider usage
        gc.collect()  # Force garbage collection
        initial_memory = self._get_memory_usage()
        
        # Make multiple requests to trigger provider instance creation
        for i in range(20):
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Memory overhead test {i}"}],
                "max_tokens": 15
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            if i % 5 == 0:  # Log progress every 5 requests
                logger.info(f"Memory overhead test - Completed {i+1}/20 requests")
            
            await asyncio.sleep(0.05)
        
        # Measure memory after provider usage
        gc.collect()
        final_memory = self._get_memory_usage()
        
        memory_increase = final_memory - initial_memory
        memory_increase_mb = memory_increase / (1024 * 1024)
        
        logger.info(f"Provider caching memory overhead: {memory_increase_mb:.2f} MB")
        
        # Memory overhead should be reasonable for provider caching
        assert memory_increase_mb < 500.0, f"Provider caching memory overhead should be < 500MB, got {memory_increase_mb:.2f}MB"
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return process.memory_info().rss
        except ImportError:
            # Fallback if psutil not available
            import resource
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024  # Convert to bytes


class TestEnhancedCachingPerformance:
    """Enhanced caching performance scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cache_multi_level_hierarchy_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_CACHE_MULTI_LEVEL_001: Test multi-level cache hierarchy optimization"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test L1 cache (application level) vs L2 cache (provider level)
        cache_levels = {
            "L1": [],  # Application settings cache hits
            "L2": [],  # Provider instance cache hits
        }
        
        # Warm up both cache levels
        for i in range(3):
            await make_request(http_client, "GET", "/api/v1/models", auth_headers, track_cost=False)
            
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Cache warmup"}],
                "max_tokens": 10
            }
            await make_request(http_client, "POST", "/api/v1/chat/completions", auth_headers, request_data)
        
        # Test L1 cache performance (rapid identical requests)
        for i in range(10):
            start_time = time.perf_counter()
            response = await make_request(http_client, "GET", "/api/v1/models", auth_headers, track_cost=False)
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                cache_levels["L1"].append((end_time - start_time) * 1000)
        
        # Test L2 cache performance (provider instance reuse)
        for i in range(10):
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"L2 cache test {i}"}],
                "max_tokens": 10
            }
            
            start_time = time.perf_counter()
            response = await make_request(http_client, "POST", "/api/v1/chat/completions", auth_headers, request_data)
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                cache_levels["L2"].append((end_time - start_time) * 1000)
        
        # Analyze multi-level cache performance
        for level, times in cache_levels.items():
            if times:
                avg_time = statistics.mean(times)
                logger.info(f"{level} cache performance - Avg: {avg_time:.2f}ms")
                
                if level == "L1":
                    assert avg_time < 50.0, f"L1 cache should be < 50ms, got {avg_time:.2f}ms"
                else:  # L2
                    assert avg_time < 5000.0, f"L2 cache should be < 5s, got {avg_time:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cache_adaptive_management_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """PERF_CACHE_ADAPTIVE_001: Test adaptive cache management under varying loads"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Simulate varying load patterns
        load_patterns = [
            {"name": "low_load", "concurrent_users": 2, "requests_per_user": 3},
            {"name": "medium_load", "concurrent_users": 5, "requests_per_user": 4},
            {"name": "high_load", "concurrent_users": 10, "requests_per_user": 2},
        ]
        
        pattern_performance = {}
        
        for pattern in load_patterns:
            async def user_requests(user_id: int, num_requests: int):
                times = []
                for i in range(num_requests):
                    start_time = time.perf_counter()
                    response = await make_request(
                        http_client, "GET", "/api/v1/models", auth_headers, track_cost=False
                    )
                    end_time = time.perf_counter()
                    
                    if response.status_code == 200:
                        times.append((end_time - start_time) * 1000)
                    
                    await asyncio.sleep(0.1)
                return times
            
            # Execute load pattern
            tasks = [user_requests(i, pattern["requests_per_user"]) for i in range(pattern["concurrent_users"])]
            results = await asyncio.gather(*tasks)
            
            all_times = [time for user_times in results for time in user_times]
            
            if all_times:
                pattern_performance[pattern["name"]] = {
                    "avg_time": statistics.mean(all_times),
                    "total_requests": len(all_times)
                }
            
            await asyncio.sleep(1)  # Brief pause between patterns
        
        # Verify adaptive performance
        for pattern_name, perf_data in pattern_performance.items():
            logger.info(f"{pattern_name} - Avg: {perf_data['avg_time']:.2f}ms over {perf_data['total_requests']} requests")
            
            # Cache should adapt to maintain reasonable performance under all loads
            assert perf_data["avg_time"] < 200.0, f"{pattern_name} should maintain < 200ms avg, got {perf_data['avg_time']:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cache_warming_strategies_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """PERF_CACHE_WARMING_001: Test cache warming strategy effectiveness"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test cold cache performance (first request)
        cold_cache_times = []
        
        # Measure cold cache performance
        start_time = time.perf_counter()
        response = await make_request(http_client, "GET", "/api/v1/models", auth_headers, track_cost=False)
        end_time = time.perf_counter()
        
        if response.status_code == 200:
            cold_cache_times.append((end_time - start_time) * 1000)
        
        # Perform cache warming (multiple requests to warm up caches)
        warming_requests = 5
        warming_times = []
        
        for i in range(warming_requests):
            start_time = time.perf_counter()
            response = await make_request(http_client, "GET", "/api/v1/models", auth_headers, track_cost=False)
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                warming_times.append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.05)
        
        # Test warm cache performance
        warm_cache_times = []
        
        for i in range(10):
            start_time = time.perf_counter()
            response = await make_request(http_client, "GET", "/api/v1/models", auth_headers, track_cost=False)
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                warm_cache_times.append((end_time - start_time) * 1000)
            
            await asyncio.sleep(0.02)
        
        # Analyze cache warming effectiveness
        if cold_cache_times and warm_cache_times:
            avg_cold = statistics.mean(cold_cache_times)
            avg_warm = statistics.mean(warm_cache_times)
            
            improvement_ratio = avg_cold / avg_warm if avg_warm > 0 else 1.0
            
            logger.info(f"Cache warming - Cold: {avg_cold:.2f}ms, Warm: {avg_warm:.2f}ms, Improvement: {improvement_ratio:.2f}x")
            
            # Cache warming should provide measurable improvement
            assert improvement_ratio >= 1.0, f"Cache warming should improve or maintain performance, got {improvement_ratio:.2f}x"
            assert avg_warm < 100.0, f"Warm cache should be < 100ms, got {avg_warm:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cache_invalidation_high_load_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """PERF_CACHE_INVALIDATION_001: Cache invalidation performance under high load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Simulate cache invalidation under high concurrent load
        concurrent_requests = 20
        requests_per_task = 5
        
        async def cache_stress_task(task_id: int):
            """Stress test cache with concurrent requests"""
            task_results = []
            
            for i in range(requests_per_task):
                # Alternate between different operations to stress cache
                if i % 3 == 0:
                    # Models request (cached)
                    start_time = time.perf_counter()
                    response = await make_request(http_client, "GET", "/api/v1/models", auth_headers, track_cost=False)
                    end_time = time.perf_counter()
                    
                    task_results.append({
                        "operation": "models",
                        "response_time": (end_time - start_time) * 1000,
                        "status": response.status_code,
                        "task_id": task_id
                    })
                
                elif i % 3 == 1:
                    # Chat request (provider cache)
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Cache stress test task {task_id} request {i}"}],
                        "max_tokens": 10
                    }
                    
                    start_time = time.perf_counter()
                    response = await make_request(http_client, "POST", "/api/v1/chat/completions", auth_headers, request_data)
                    end_time = time.perf_counter()
                    
                    task_results.append({
                        "operation": "chat",
                        "response_time": (end_time - start_time) * 1000,
                        "status": response.status_code,
                        "task_id": task_id
                    })
                
                else:
                    # Embedding request (if available)
                    embedding_models = config.get_embedding_models()
                    if embedding_models:
                        request_data = {
                            "model": embedding_models[0],
                            "input": f"Cache stress embedding test task {task_id} request {i}"
                        }
                        
                        start_time = time.perf_counter()
                        response = await make_request(http_client, "POST", "/api/v1/embeddings", auth_headers, request_data)
                        end_time = time.perf_counter()
                        
                        task_results.append({
                            "operation": "embedding",
                            "response_time": (end_time - start_time) * 1000,
                            "status": response.status_code,
                            "task_id": task_id
                        })
                
                # Small delay to prevent overwhelming
                await asyncio.sleep(0.01)
            
            return task_results
        
        # Execute concurrent cache stress test
        start_time = time.perf_counter()
        tasks = [cache_stress_task(i) for i in range(concurrent_requests)]
        results = await asyncio.gather(*tasks)
        total_duration = time.perf_counter() - start_time
        
        # Analyze cache invalidation performance
        all_results = [result for task_results in results for result in task_results]
        successful_results = [r for r in all_results if r["status"] == 200]
        
        if successful_results:
            operations = {}
            for result in successful_results:
                op = result["operation"]
                if op not in operations:
                    operations[op] = []
                operations[op].append(result["response_time"])
            
            # Validate cache performance under load
            for operation, times in operations.items():
                avg_time = statistics.mean(times)
                p95_time = statistics.quantiles(times, n=20)[18] if len(times) >= 20 else max(times)
                
                logger.info(f"Cache under load - {operation}: avg={avg_time:.2f}ms, p95={p95_time:.2f}ms, count={len(times)}")
                
                # Cache should maintain reasonable performance under load
                if operation == "models":
                    assert avg_time <= 50.0, f"Models cache under load should be <= 50ms, got {avg_time:.2f}ms"
                elif operation == "chat":
                    assert avg_time <= 5000.0, f"Chat cache under load should be <= 5s, got {avg_time:.2f}ms"
                elif operation == "embedding":
                    assert avg_time <= 3000.0, f"Embedding cache under load should be <= 3s, got {avg_time:.2f}ms"
            
            # Overall success rate should be high
            success_rate = len(successful_results) / len(all_results)
            assert success_rate >= 0.95, f"Cache under load success rate should be >= 95%, got {success_rate:.2%}"
        
        logger.info(f"Cache invalidation under high load test completed: {len(all_results)} total requests in {total_duration:.2f}s")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cross_provider_cache_efficiency_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """PERF_CROSS_PROVIDER_001: Cross-provider cache efficiency optimization"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test cache efficiency across different providers
        chat_models = config.get_chat_models() or ["test_model"]
        
        if len(chat_models) < 2:
            pytest.skip("Multiple models required for cross-provider cache testing")
        
        provider_cache_results = {}
        
        # Test each provider's cache performance
        for i, model in enumerate(chat_models[:3]):  # Limit to 3 models
            provider_results = []
            
            # Warm up cache for this provider
            warmup_data = {
                "model": model,
                "messages": [{"role": "user", "content": f"Cache warmup for {model}"}],
                "max_tokens": 10
            }
            
            for warmup in range(3):
                await make_request(http_client, "POST", "/api/v1/chat/completions", auth_headers, warmup_data)
            
            # Test cache performance for this provider
            for test_req in range(10):
                request_data = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Cross-provider cache test {test_req}"}],
                    "max_tokens": 20
                }
                
                start_time = time.perf_counter()
                response = await make_request(http_client, "POST", "/api/v1/chat/completions", auth_headers, request_data)
                end_time = time.perf_counter()
                
                if response.status_code == 200:
                    provider_results.append({
                        "model": model,
                        "response_time": (end_time - start_time) * 1000,
                        "test_request": test_req
                    })
                
                await asyncio.sleep(0.05)
            
            provider_cache_results[model] = provider_results
        
        # Analyze cross-provider cache efficiency
        for model, results in provider_cache_results.items():
            if results:
                response_times = [r["response_time"] for r in results]
                avg_time = statistics.mean(response_times)
                std_dev = statistics.stdev(response_times) if len(response_times) > 1 else 0
                
                logger.info(f"Cross-provider cache - {model}: avg={avg_time:.2f}ms, std={std_dev:.2f}ms, count={len(results)}")
                
                # Each provider should have consistent cache performance
                assert avg_time <= 8000.0, f"Provider {model} cache should be <= 8s, got {avg_time:.2f}ms"
                assert std_dev <= avg_time * 0.5, f"Provider {model} cache should have low variance, std={std_dev:.2f}ms"
        
        # Compare efficiency across providers
        avg_times = {model: statistics.mean([r["response_time"] for r in results]) 
                    for model, results in provider_cache_results.items() if results}
        
        if len(avg_times) >= 2:
            min_avg = min(avg_times.values())
            max_avg = max(avg_times.values())
            efficiency_ratio = max_avg / min_avg if min_avg > 0 else 1.0
            
            logger.info(f"Cross-provider efficiency ratio: {efficiency_ratio:.2f}x (min: {min_avg:.2f}ms, max: {max_avg:.2f}ms)")
            
            # Efficiency variance across providers should be reasonable
            assert efficiency_ratio <= 5.0, f"Cross-provider efficiency should be within 5x, got {efficiency_ratio:.2f}x"
        
        logger.info("Cross-provider cache efficiency test completed successfully")