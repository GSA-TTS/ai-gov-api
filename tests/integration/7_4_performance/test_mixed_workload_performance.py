# Section 7.4 - Mixed Workload Performance
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_Mixed Workload Performance.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import random
import json
import psutil
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class MixedWorkloadResult:
    """Mixed workload test result data structure"""
    test_name: str
    total_requests: int
    request_type_breakdown: Dict[str, int]
    avg_response_times: Dict[str, float]
    error_rates: Dict[str, float]
    overall_throughput: float
    resource_utilization: Dict[str, float]
    success: bool


class TestAPIGatewayMixedLoad:
    """Test API Gateway / Load Balancer performance under mixed load"""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_mixed_gateway_std_load_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """PERF_MIXED_GATEWAY_STD_LOAD_001: Standard production-like mixed workload"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Define standard mixed workload distribution
        workload_mix = {
            "chat_nonstream": 0.60,  # 60% non-streaming chat
            "chat_stream": 0.10,     # 10% streaming chat  
            "embeddings": 0.25,      # 25% embeddings
            "models": 0.05           # 5% models list
        }
        
        mixed_load_metrics = {
            "request_counts": {key: 0 for key in workload_mix.keys()},
            "response_times": {key: [] for key in workload_mix.keys()},
            "error_counts": {key: 0 for key in workload_mix.keys()},
            "successful_requests": 0,
            "total_requests": 0
        }
        
        # Run mixed workload test
        test_duration = 900  # 15 minutes
        start_time = time.time()
        
        async def mixed_workload_user(user_id: int):
            """Simulate a user generating mixed workload"""
            user_metrics = {
                "requests": 0,
                "successes": 0,
                "response_times": {}
            }
            
            while (time.time() - start_time) < test_duration:
                # Select request type based on distribution
                rand_val = random.random()
                cumulative = 0
                selected_type = None
                
                for req_type, probability in workload_mix.items():
                    cumulative += probability
                    if rand_val <= cumulative:
                        selected_type = req_type
                        break
                
                if not selected_type:
                    selected_type = "chat_nonstream"  # Fallback
                
                req_start = time.perf_counter()
                success = False
                
                try:
                    if selected_type == "chat_nonstream":
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, {
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": f"Mixed workload test {user_id}"}],
                                "max_tokens": 50,
                                "stream": False
                            }
                        )
                        success = response.status_code == 200
                        
                    elif selected_type == "chat_stream":
                        async with http_client.stream(
                            "POST", "/api/v1/chat/completions",
                            headers=auth_headers,
                            json={
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": f"Streaming test {user_id}"}],
                                "max_tokens": 30,
                                "stream": True
                            },
                            timeout=30.0
                        ) as response:
                            success = response.status_code == 200
                            if success:
                                # Consume stream partially
                                chunk_count = 0
                                async for line in response.aiter_lines():
                                    if line.startswith("data: "):
                                        chunk_count += 1
                                        if chunk_count >= 5:  # Consume a few chunks
                                            break
                    
                    elif selected_type == "embeddings":
                        embedding_model = config.get_embedding_model(0)
                        if embedding_model:
                            response = await make_request(
                                http_client, "POST", "/api/v1/embeddings",
                                auth_headers, {
                                    "model": embedding_model,
                                    "input": f"Mixed workload embedding test {user_id}"
                                }
                            )
                            success = response.status_code == 200
                        else:
                            continue
                    
                    elif selected_type == "models":
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            auth_headers, track_cost=False
                        )
                        success = response.status_code == 200
                
                except Exception as e:
                    logger.warning(f"Mixed workload request failed: {e}")
                    success = False
                
                req_end = time.perf_counter()
                response_time = (req_end - req_start) * 1000
                
                # Record metrics
                user_metrics["requests"] += 1
                if success:
                    user_metrics["successes"] += 1
                
                if selected_type not in user_metrics["response_times"]:
                    user_metrics["response_times"][selected_type] = []
                user_metrics["response_times"][selected_type].append(response_time)
                
                # Brief delay to simulate realistic user behavior
                await asyncio.sleep(random.uniform(0.1, 0.5))
            
            return user_metrics
        
        # Execute mixed workload with multiple concurrent users
        concurrent_users = 20
        user_tasks = [mixed_workload_user(i) for i in range(concurrent_users)]
        user_results = await asyncio.gather(*user_tasks, return_exceptions=True)
        
        # Aggregate results
        for result in user_results:
            if isinstance(result, dict):
                mixed_load_metrics["total_requests"] += result["requests"]
                mixed_load_metrics["successful_requests"] += result["successes"]
                
                for req_type, times in result["response_times"].items():
                    mixed_load_metrics["request_counts"][req_type] += len(times)
                    mixed_load_metrics["response_times"][req_type].extend(times)
        
        # Analyze mixed workload performance
        total_test_time = time.time() - start_time
        overall_throughput = mixed_load_metrics["total_requests"] / total_test_time
        overall_success_rate = mixed_load_metrics["successful_requests"] / mixed_load_metrics["total_requests"] if mixed_load_metrics["total_requests"] > 0 else 0
        
        logger.info(f"Mixed workload gateway test - "
                   f"Total requests: {mixed_load_metrics['total_requests']}, "
                   f"Overall throughput: {overall_throughput:.2f} RPS, "
                   f"Success rate: {overall_success_rate:.2%}")
        
        # Analyze per-request-type performance
        for req_type, times in mixed_load_metrics["response_times"].items():
            if times:
                avg_time = statistics.mean(times)
                p95_time = statistics.quantiles(times, n=20)[18] if len(times) >= 20 else max(times)
                request_count = len(times)
                
                logger.info(f"{req_type} - Count: {request_count}, Avg: {avg_time:.2f}ms, P95: {p95_time:.2f}ms")
                
                # Verify performance targets per request type
                if req_type == "models":
                    assert avg_time < 500.0, f"Models requests should be fast, got {avg_time:.2f}ms"
                elif req_type in ["chat_nonstream", "chat_stream"]:
                    assert avg_time < 10000.0, f"Chat requests should be reasonable, got {avg_time:.2f}ms"
                elif req_type == "embeddings":
                    assert avg_time < 3000.0, f"Embedding requests should be efficient, got {avg_time:.2f}ms"
        
        # Verify overall system performance under mixed load
        assert overall_success_rate >= 0.95, f"Overall success rate should be high, got {overall_success_rate:.2%}"
        assert overall_throughput >= 5.0, f"Overall throughput should be reasonable, got {overall_throughput:.2f} RPS"


class TestFastAPIServerMixedLoad:
    """Test FastAPI application server performance under mixed load"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mixed_fastapi_worker_efficiency_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """PERF_MIXED_FASTAPI_WORKER_EFFICIENCY_001: FastAPI worker efficiency under mixed concurrent load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test FastAPI worker efficiency with mixed workload
        process = psutil.Process(os.getpid())
        
        fastapi_metrics = {
            "initial_memory": process.memory_info().rss / (1024 * 1024),
            "peak_memory": 0,
            "cpu_samples": [],
            "response_time_samples": [],
            "request_type_performance": {},
            "successful_requests": 0,
            "failed_requests": 0
        }
        
        # Mixed request types with different resource characteristics
        request_types = [
            {
                "name": "lightweight_chat",
                "weight": 0.4,
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Quick test"}],
                    "max_tokens": 20
                }
            },
            {
                "name": "heavy_chat",
                "weight": 0.3,
                "method": "POST", 
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Write a detailed explanation of quantum computing and its applications in cryptography and optimization"}],
                    "max_tokens": 200
                }
            },
            {
                "name": "embeddings",
                "weight": 0.2,
                "method": "POST",
                "endpoint": "/api/v1/embeddings", 
                "data": {
                    "model": config.get_embedding_model(0) if config.get_embedding_model(0) else None,
                    "input": "FastAPI worker efficiency test"
                }
            },
            {
                "name": "models",
                "weight": 0.1,
                "method": "GET",
                "endpoint": "/api/v1/models",
                "data": None
            }
        ]
        
        # Filter out requests that can't be made (e.g., no embedding model)
        valid_request_types = [rt for rt in request_types if rt["data"] is None or rt["data"].get("model") is not None]
        
        async def fastapi_worker_test():
            """Test FastAPI worker efficiency"""
            for i in range(100):  # Extended test
                # Select request type based on weights
                rand_val = random.random()
                cumulative = 0
                selected_request = None
                
                for req_type in valid_request_types:
                    cumulative += req_type["weight"]
                    if rand_val <= cumulative:
                        selected_request = req_type
                        break
                
                if not selected_request:
                    selected_request = valid_request_types[0]
                
                # Monitor system resources
                cpu_before = process.cpu_percent()
                memory_before = process.memory_info().rss / (1024 * 1024)
                
                # Execute request
                start_time = time.perf_counter()
                
                try:
                    if selected_request["name"] == "embeddings" and selected_request["data"]["model"] is None:
                        continue
                    
                    response = await make_request(
                        http_client, 
                        selected_request["method"],
                        selected_request["endpoint"],
                        auth_headers,
                        selected_request["data"]
                    )
                    
                    end_time = time.perf_counter()
                    
                    # Monitor system resources after
                    cpu_after = process.cpu_percent()
                    memory_after = process.memory_info().rss / (1024 * 1024)
                    
                    response_time = (end_time - start_time) * 1000
                    
                    # Record metrics
                    if selected_request["name"] not in fastapi_metrics["request_type_performance"]:
                        fastapi_metrics["request_type_performance"][selected_request["name"]] = {
                            "response_times": [],
                            "success_count": 0,
                            "error_count": 0
                        }
                    
                    req_metrics = fastapi_metrics["request_type_performance"][selected_request["name"]]
                    
                    if response.status_code == 200:
                        req_metrics["response_times"].append(response_time)
                        req_metrics["success_count"] += 1
                        fastapi_metrics["successful_requests"] += 1
                    else:
                        req_metrics["error_count"] += 1
                        fastapi_metrics["failed_requests"] += 1
                    
                    # System resource tracking
                    fastapi_metrics["cpu_samples"].append(max(cpu_after - cpu_before, 0))
                    fastapi_metrics["peak_memory"] = max(fastapi_metrics["peak_memory"], memory_after)
                    fastapi_metrics["response_time_samples"].append(response_time)
                
                except Exception as e:
                    fastapi_metrics["failed_requests"] += 1
                    logger.warning(f"FastAPI worker test request failed: {e}")
                
                await asyncio.sleep(0.05)  # Moderate pace
        
        # Run FastAPI worker efficiency test
        await fastapi_worker_test()
        
        # Analyze FastAPI worker performance
        final_memory = process.memory_info().rss / (1024 * 1024)
        memory_growth = final_memory - fastapi_metrics["initial_memory"]
        avg_cpu = statistics.mean(fastapi_metrics["cpu_samples"]) if fastapi_metrics["cpu_samples"] else 0
        
        success_rate = fastapi_metrics["successful_requests"] / (fastapi_metrics["successful_requests"] + fastapi_metrics["failed_requests"]) if (fastapi_metrics["successful_requests"] + fastapi_metrics["failed_requests"]) > 0 else 0
        
        logger.info(f"FastAPI worker efficiency - "
                   f"Success rate: {success_rate:.2%}, "
                   f"Memory growth: {memory_growth:.2f}MB, "
                   f"Avg CPU: {avg_cpu:.2f}%")
        
        # Analyze per-request-type performance
        for req_type, metrics in fastapi_metrics["request_type_performance"].items():
            if metrics["response_times"]:
                avg_time = statistics.mean(metrics["response_times"])
                success_rate_type = metrics["success_count"] / (metrics["success_count"] + metrics["error_count"]) if (metrics["success_count"] + metrics["error_count"]) > 0 else 0
                
                logger.info(f"FastAPI {req_type} - Avg: {avg_time:.2f}ms, Success: {success_rate_type:.2%}")
        
        # Verify FastAPI worker efficiency
        assert success_rate >= 0.90, f"FastAPI worker success rate should be high, got {success_rate:.2%}"
        assert memory_growth <= 100.0, f"FastAPI worker memory growth should be reasonable, got {memory_growth:.2f}MB"
        assert avg_cpu <= 50.0, f"FastAPI worker CPU usage should be efficient, got {avg_cpu:.2f}%"


class TestSharedResourceContention:
    """Test shared resource contention under mixed load"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mixed_resource_db_auth_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """PERF_MIXED_RESOURCE_DB_AUTH_001: Database authentication performance under mixed high-volume load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test database auth performance under mixed load
        db_auth_metrics = {
            "auth_response_times": [],
            "concurrent_request_times": [],
            "successful_auths": 0,
            "failed_auths": 0,
            "db_contention_indicators": []
        }
        
        async def high_volume_mixed_user(user_id: int):
            """Simulate high-volume user creating auth load"""
            user_results = {
                "auth_times": [],
                "successful_requests": 0,
                "failed_requests": 0
            }
            
            # Mix of request types, all requiring authentication
            request_sequence = [
                ("GET", "/api/v1/models", None),
                ("POST", "/api/v1/chat/completions", {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Auth test {user_id}"}],
                    "max_tokens": 25
                })
            ]
            
            # Add embedding request if available
            if config.get_embedding_model(0):
                request_sequence.append(("POST", "/api/v1/embeddings", {
                    "model": config.get_embedding_model(0),
                    "input": f"Auth test {user_id}"
                }))
            
            for cycle in range(15):  # Multiple cycles per user
                for method, endpoint, data in request_sequence:
                    start_time = time.perf_counter()
                    
                    try:
                        response = await make_request(
                            http_client, method, endpoint, auth_headers, data
                        )
                        
                        end_time = time.perf_counter()
                        auth_time = (end_time - start_time) * 1000
                        
                        user_results["auth_times"].append(auth_time)
                        
                        if response.status_code == 200:
                            user_results["successful_requests"] += 1
                        else:
                            user_results["failed_requests"] += 1
                    
                    except Exception as e:
                        user_results["failed_requests"] += 1
                    
                    await asyncio.sleep(0.02)  # High frequency
            
            return user_results
        
        # Execute high-volume concurrent authentication load
        concurrent_users = 25  # High concurrency to test DB auth
        auth_tasks = [high_volume_mixed_user(i) for i in range(concurrent_users)]
        auth_results = await asyncio.gather(*auth_tasks, return_exceptions=True)
        
        # Aggregate authentication performance metrics
        for result in auth_results:
            if isinstance(result, dict):
                db_auth_metrics["auth_response_times"].extend(result["auth_times"])
                db_auth_metrics["successful_auths"] += result["successful_requests"]
                db_auth_metrics["failed_auths"] += result["failed_requests"]
        
        # Analyze database authentication performance
        if db_auth_metrics["auth_response_times"]:
            avg_auth_time = statistics.mean(db_auth_metrics["auth_response_times"])
            p95_auth_time = statistics.quantiles(db_auth_metrics["auth_response_times"], n=20)[18] if len(db_auth_metrics["auth_response_times"]) >= 20 else max(db_auth_metrics["auth_response_times"])
            auth_success_rate = db_auth_metrics["successful_auths"] / (db_auth_metrics["successful_auths"] + db_auth_metrics["failed_auths"]) if (db_auth_metrics["successful_auths"] + db_auth_metrics["failed_auths"]) > 0 else 0
            
            logger.info(f"DB auth under mixed load - "
                       f"Avg auth time: {avg_auth_time:.2f}ms, "
                       f"P95 auth time: {p95_auth_time:.2f}ms, "
                       f"Auth success rate: {auth_success_rate:.2%}")
            
            # Verify database authentication performance under load
            assert avg_auth_time < 200.0, f"Average auth time should be fast under load, got {avg_auth_time:.2f}ms"
            assert p95_auth_time < 500.0, f"P95 auth time should be reasonable, got {p95_auth_time:.2f}ms"
            assert auth_success_rate >= 0.98, f"Auth success rate should be very high, got {auth_success_rate:.2%}"
        else:
            pytest.fail("No authentication timing data collected")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mixed_resource_config_cache_003(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_MIXED_RESOURCE_CONFIG_CACHE_003: Configuration cache performance under diverse model requests"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test configuration cache with diverse model requests
        config_cache_metrics = {
            "cache_response_times": [],
            "model_variety_performance": {},
            "cache_hit_indicators": [],
            "successful_requests": 0,
            "cache_miss_requests": 0
        }
        
        # Test with various model configurations
        available_models = config.CHAT_MODELS[:3] if len(config.CHAT_MODELS) >= 3 else config.CHAT_MODELS
        embedding_model = config.get_embedding_model(0)
        
        # Create diverse model request patterns
        model_request_patterns = []
        
        for model in available_models:
            model_request_patterns.extend([
                ("chat", model, {
                    "model": model,
                    "messages": [{"role": "user", "content": "Config cache test"}],
                    "max_tokens": 30
                }),
                ("chat_stream", model, {
                    "model": model,
                    "messages": [{"role": "user", "content": "Config cache stream test"}],
                    "max_tokens": 20,
                    "stream": True
                })
            ])
        
        if embedding_model:
            model_request_patterns.append(("embedding", embedding_model, {
                "model": embedding_model,
                "input": "Config cache embedding test"
            }))
        
        # Add some invalid model requests to test cache miss behavior
        model_request_patterns.append(("invalid_chat", "invalid_model_config_test", {
            "model": "invalid_model_config_test",
            "messages": [{"role": "user", "content": "Invalid model test"}],
            "max_tokens": 10
        }))
        
        # Execute diverse model configuration requests
        for cycle in range(20):  # Multiple cycles to test cache behavior
            for req_type, model, data in model_request_patterns:
                start_time = time.perf_counter()
                
                try:
                    if req_type == "chat":
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, data
                        )
                    elif req_type == "chat_stream":
                        async with http_client.stream(
                            "POST", "/api/v1/chat/completions",
                            headers=auth_headers,
                            json=data,
                            timeout=30.0
                        ) as response:
                            if response.status_code == 200:
                                # Consume a few chunks
                                chunk_count = 0
                                async for line in response.aiter_lines():
                                    if line.startswith("data: "):
                                        chunk_count += 1
                                        if chunk_count >= 3:
                                            break
                    elif req_type == "embedding":
                        response = await make_request(
                            http_client, "POST", "/api/v1/embeddings",
                            auth_headers, data
                        )
                    elif req_type == "invalid_chat":
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, data
                        )
                    
                    end_time = time.perf_counter()
                    response_time = (end_time - start_time) * 1000
                    
                    # Track model-specific performance
                    if model not in config_cache_metrics["model_variety_performance"]:
                        config_cache_metrics["model_variety_performance"][model] = {
                            "response_times": [],
                            "success_count": 0,
                            "error_count": 0
                        }
                    
                    model_metrics = config_cache_metrics["model_variety_performance"][model]
                    model_metrics["response_times"].append(response_time)
                    
                    if response.status_code == 200:
                        model_metrics["success_count"] += 1
                        config_cache_metrics["successful_requests"] += 1
                    elif response.status_code in [400, 422] and req_type == "invalid_chat":
                        # Expected failure for invalid model
                        config_cache_metrics["cache_miss_requests"] += 1
                    else:
                        model_metrics["error_count"] += 1
                    
                    config_cache_metrics["cache_response_times"].append(response_time)
                
                except Exception as e:
                    logger.warning(f"Config cache test failed for {model}: {e}")
                
                await asyncio.sleep(0.03)
        
        # Analyze configuration cache performance
        if config_cache_metrics["cache_response_times"]:
            avg_cache_time = statistics.mean(config_cache_metrics["cache_response_times"])
            cache_time_consistency = statistics.stdev(config_cache_metrics["cache_response_times"]) if len(config_cache_metrics["cache_response_times"]) > 1 else 0
            
            logger.info(f"Config cache performance - "
                       f"Avg response time: {avg_cache_time:.2f}ms, "
                       f"Time consistency (stddev): {cache_time_consistency:.2f}ms")
            
            # Analyze per-model cache performance
            for model, metrics in config_cache_metrics["model_variety_performance"].items():
                if metrics["response_times"]:
                    model_avg = statistics.mean(metrics["response_times"])
                    model_success_rate = metrics["success_count"] / (metrics["success_count"] + metrics["error_count"]) if (metrics["success_count"] + metrics["error_count"]) > 0 else 0
                    
                    logger.info(f"Model {model} cache - Avg: {model_avg:.2f}ms, Success: {model_success_rate:.2%}")
            
            # Verify configuration cache efficiency
            assert avg_cache_time < 5000.0, f"Config cache should not add significant overhead, got {avg_cache_time:.2f}ms"
            assert cache_time_consistency <= 2000.0, f"Config cache performance should be consistent, got {cache_time_consistency:.2f}ms stddev"
        else:
            pytest.fail("No configuration cache timing data collected")


class TestProviderInteractionMixedLoad:
    """Test provider interaction logic under mixed load"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mixed_provider_concurrency_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_MIXED_PROVIDER_CONCURRENCY_001: Concurrent multi-provider interactions"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test concurrent interactions across multiple providers
        provider_metrics = {
            "provider_performance": {},
            "cross_provider_interference": [],
            "total_successful_requests": 0,
            "total_failed_requests": 0
        }
        
        # Identify available models/providers
        available_models = config.CHAT_MODELS[:4] if len(config.CHAT_MODELS) >= 4 else config.CHAT_MODELS
        embedding_model = config.get_embedding_model(0)
        
        # Group models by provider (simplified - we'll test them as separate entities)
        provider_groups = {}
        for i, model in enumerate(available_models):
            provider_key = f"provider_{i % 2}"  # Alternate between two provider groups
            if provider_key not in provider_groups:
                provider_groups[provider_key] = []
            provider_groups[provider_key].append(model)
        
        async def provider_load_test(provider_key: str, models: List[str]):
            """Test load for a specific provider group"""
            provider_results = {
                "response_times": [],
                "successful_requests": 0,
                "failed_requests": 0,
                "model_performance": {}
            }
            
            for cycle in range(25):  # Multiple requests per provider
                # Rotate through models in this provider group
                model = models[cycle % len(models)]
                
                if model not in provider_results["model_performance"]:
                    provider_results["model_performance"][model] = {
                        "times": [],
                        "successes": 0,
                        "errors": 0
                    }
                
                start_time = time.perf_counter()
                
                try:
                    # Alternate between chat and embedding requests
                    if cycle % 3 == 0 and embedding_model:
                        response = await make_request(
                            http_client, "POST", "/api/v1/embeddings",
                            auth_headers, {
                                "model": embedding_model,
                                "input": f"Provider {provider_key} embedding test {cycle}"
                            }
                        )
                    else:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, {
                                "model": model,
                                "messages": [{"role": "user", "content": f"Provider {provider_key} test {cycle}"}],
                                "max_tokens": 40
                            }
                        )
                    
                    end_time = time.perf_counter()
                    response_time = (end_time - start_time) * 1000
                    
                    provider_results["response_times"].append(response_time)
                    provider_results["model_performance"][model]["times"].append(response_time)
                    
                    if response.status_code == 200:
                        provider_results["successful_requests"] += 1
                        provider_results["model_performance"][model]["successes"] += 1
                    else:
                        provider_results["failed_requests"] += 1
                        provider_results["model_performance"][model]["errors"] += 1
                
                except Exception as e:
                    provider_results["failed_requests"] += 1
                    logger.warning(f"Provider {provider_key} request failed: {e}")
                
                await asyncio.sleep(0.05)  # Moderate frequency
            
            return provider_key, provider_results
        
        # Execute concurrent provider load tests
        provider_tasks = [provider_load_test(key, models) for key, models in provider_groups.items()]
        provider_results = await asyncio.gather(*provider_tasks, return_exceptions=True)
        
        # Aggregate provider performance metrics
        for result in provider_results:
            if isinstance(result, tuple) and len(result) == 2:
                provider_key, metrics = result
                provider_metrics["provider_performance"][provider_key] = metrics
                provider_metrics["total_successful_requests"] += metrics["successful_requests"]
                provider_metrics["total_failed_requests"] += metrics["failed_requests"]
        
        # Analyze multi-provider performance
        overall_success_rate = provider_metrics["total_successful_requests"] / (provider_metrics["total_successful_requests"] + provider_metrics["total_failed_requests"]) if (provider_metrics["total_successful_requests"] + provider_metrics["total_failed_requests"]) > 0 else 0
        
        logger.info(f"Multi-provider concurrency - "
                   f"Overall success rate: {overall_success_rate:.2%}, "
                   f"Providers tested: {len(provider_metrics['provider_performance'])}")
        
        # Analyze per-provider performance
        provider_performance_comparison = {}
        
        for provider_key, metrics in provider_metrics["provider_performance"].items():
            if metrics["response_times"]:
                avg_time = statistics.mean(metrics["response_times"])
                success_rate = metrics["successful_requests"] / (metrics["successful_requests"] + metrics["failed_requests"]) if (metrics["successful_requests"] + metrics["failed_requests"]) > 0 else 0
                
                provider_performance_comparison[provider_key] = {
                    "avg_time": avg_time,
                    "success_rate": success_rate
                }
                
                logger.info(f"Provider {provider_key} - "
                           f"Avg time: {avg_time:.2f}ms, "
                           f"Success rate: {success_rate:.2%}")
                
                # Verify individual provider performance
                assert avg_time < 10000.0, f"Provider {provider_key} should perform reasonably, got {avg_time:.2f}ms"
                assert success_rate >= 0.85, f"Provider {provider_key} success rate should be good, got {success_rate:.2%}"
        
        # Verify no significant cross-provider interference
        if len(provider_performance_comparison) >= 2:
            performance_values = [p["avg_time"] for p in provider_performance_comparison.values()]
            performance_variance = statistics.stdev(performance_values) if len(performance_values) > 1 else 0
            
            logger.info(f"Cross-provider performance variance: {performance_variance:.2f}ms")
            
            # Performance should be relatively consistent across providers
            assert performance_variance <= 2000.0, f"Cross-provider performance variance should be reasonable, got {performance_variance:.2f}ms"
        
        # Verify overall multi-provider system performance
        assert overall_success_rate >= 0.90, f"Overall multi-provider success rate should be high, got {overall_success_rate:.2%}"


class TestEnhancedMixedWorkloadScenarios:
    """Enhanced mixed workload testing scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_mixed_dynamic_adaptation_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """PERF_MIXED_DYNAMIC_ADAPTATION_001: Dynamic workload pattern adaptation"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test system adaptation to changing workload patterns
        adaptation_metrics = {
            "pattern_phases": {},
            "transition_performance": [],
            "overall_adaptation_score": 0
        }
        
        # Define different workload patterns
        workload_patterns = [
            {
                "name": "morning_chat_heavy",
                "duration": 120,  # 2 minutes per pattern
                "distribution": {"chat": 0.70, "embeddings": 0.20, "models": 0.10},
                "intensity": 0.8
            },
            {
                "name": "afternoon_embedding_heavy", 
                "duration": 120,
                "distribution": {"chat": 0.30, "embeddings": 0.60, "models": 0.10},
                "intensity": 0.9
            },
            {
                "name": "evening_mixed_light",
                "duration": 120,
                "distribution": {"chat": 0.40, "embeddings": 0.40, "models": 0.20},
                "intensity": 0.5
            }
        ]
        
        async def execute_workload_pattern(pattern: Dict[str, Any]):
            """Execute a specific workload pattern"""
            pattern_results = {
                "requests_by_type": {key: 0 for key in pattern["distribution"].keys()},
                "response_times_by_type": {key: [] for key in pattern["distribution"].keys()},
                "successful_requests": 0,
                "failed_requests": 0,
                "adaptation_indicators": []
            }
            
            pattern_start = time.time()
            request_count = 0
            
            while (time.time() - pattern_start) < pattern["duration"]:
                # Select request type based on pattern distribution
                rand_val = random.random()
                cumulative = 0
                selected_type = None
                
                for req_type, probability in pattern["distribution"].items():
                    cumulative += probability
                    if rand_val <= cumulative:
                        selected_type = req_type
                        break
                
                if not selected_type:
                    selected_type = list(pattern["distribution"].keys())[0]
                
                start_time = time.perf_counter()
                
                try:
                    if selected_type == "chat":
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, {
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": f"Dynamic pattern {pattern['name']} test {request_count}"}],
                                "max_tokens": 50
                            }
                        )
                    elif selected_type == "embeddings":
                        embedding_model = config.get_embedding_model(0)
                        if embedding_model:
                            response = await make_request(
                                http_client, "POST", "/api/v1/embeddings",
                                auth_headers, {
                                    "model": embedding_model,
                                    "input": f"Dynamic pattern {pattern['name']} embedding {request_count}"
                                }
                            )
                        else:
                            continue
                    elif selected_type == "models":
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            auth_headers, track_cost=False
                        )
                    
                    end_time = time.perf_counter()
                    response_time = (end_time - start_time) * 1000
                    
                    pattern_results["requests_by_type"][selected_type] += 1
                    pattern_results["response_times_by_type"][selected_type].append(response_time)
                    
                    if response.status_code == 200:
                        pattern_results["successful_requests"] += 1
                    else:
                        pattern_results["failed_requests"] += 1
                    
                    request_count += 1
                
                except Exception as e:
                    pattern_results["failed_requests"] += 1
                    logger.warning(f"Dynamic adaptation test failed: {e}")
                
                # Adjust request frequency based on pattern intensity
                sleep_time = (1.0 - pattern["intensity"]) * 0.1
                await asyncio.sleep(sleep_time)
            
            return pattern_results
        
        # Execute workload patterns sequentially to test adaptation
        for pattern in workload_patterns:
            logger.info(f"Starting workload pattern: {pattern['name']}")
            
            pattern_start_time = time.time()
            pattern_results = await execute_workload_pattern(pattern)
            pattern_end_time = time.time()
            
            # Analyze pattern performance
            total_pattern_requests = pattern_results["successful_requests"] + pattern_results["failed_requests"]
            pattern_success_rate = pattern_results["successful_requests"] / total_pattern_requests if total_pattern_requests > 0 else 0
            pattern_throughput = total_pattern_requests / (pattern_end_time - pattern_start_time)
            
            # Calculate adaptation metrics
            adaptation_score = 0
            for req_type, times in pattern_results["response_times_by_type"].items():
                if times:
                    avg_time = statistics.mean(times)
                    expected_weight = pattern["distribution"][req_type]
                    actual_weight = len(times) / total_pattern_requests if total_pattern_requests > 0 else 0
                    
                    # Score based on performance and distribution accuracy
                    distribution_accuracy = 1.0 - abs(expected_weight - actual_weight)
                    performance_score = 1.0 if avg_time < 5000.0 else (5000.0 / avg_time)
                    adaptation_score += (distribution_accuracy * performance_score * expected_weight)
            
            adaptation_metrics["pattern_phases"][pattern["name"]] = {
                "success_rate": pattern_success_rate,
                "throughput": pattern_throughput,
                "adaptation_score": adaptation_score,
                "request_distribution": {k: len(v) for k, v in pattern_results["response_times_by_type"].items()}
            }
            
            logger.info(f"Pattern {pattern['name']} - "
                       f"Success rate: {pattern_success_rate:.2%}, "
                       f"Throughput: {pattern_throughput:.2f} RPS, "
                       f"Adaptation score: {adaptation_score:.3f}")
            
            # Brief transition period between patterns
            await asyncio.sleep(5)
        
        # Analyze overall dynamic adaptation performance
        overall_adaptation_score = statistics.mean([p["adaptation_score"] for p in adaptation_metrics["pattern_phases"].values()])
        overall_success_rate = statistics.mean([p["success_rate"] for p in adaptation_metrics["pattern_phases"].values()])
        
        logger.info(f"Dynamic adaptation overall - "
                   f"Adaptation score: {overall_adaptation_score:.3f}, "
                   f"Overall success rate: {overall_success_rate:.2%}")
        
        # Verify dynamic adaptation effectiveness
        assert overall_adaptation_score >= 0.7, f"Dynamic adaptation should be effective, got {overall_adaptation_score:.3f}"
        assert overall_success_rate >= 0.90, f"Success rate should remain high during adaptation, got {overall_success_rate:.2%}"
        
        # Verify each pattern performed adequately
        for pattern_name, metrics in adaptation_metrics["pattern_phases"].items():
            assert metrics["success_rate"] >= 0.85, f"Pattern {pattern_name} success rate should be good, got {metrics['success_rate']:.2%}"
            assert metrics["adaptation_score"] >= 0.6, f"Pattern {pattern_name} adaptation should be reasonable, got {metrics['adaptation_score']:.3f}"