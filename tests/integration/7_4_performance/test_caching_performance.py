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