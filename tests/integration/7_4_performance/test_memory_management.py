# Section 7.4 - Memory Management & Resource Leaks
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_Memory Management & Resource Leaks.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import gc
import psutil
import os
import json
import tracemalloc
from unittest.mock import patch

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class MemoryLeakTestResult:
    """Memory leak test result data structure"""
    test_name: str
    initial_memory_mb: float
    peak_memory_mb: float
    final_memory_mb: float
    memory_growth_mb: float
    total_requests: int
    gc_collections: int
    success: bool


class TestMemoryLeakDetection:
    """Test memory leak detection patterns"""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_mem_leak_endurance_load_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """PERF_MEM_LEAK_ENDURANCE_LOAD_001: Detect memory leaks under sustained endurance load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Enable memory tracing for detailed analysis
        tracemalloc.start()
        
        # Get baseline memory usage
        process = psutil.Process(os.getpid())
        gc.collect()  # Force garbage collection
        await asyncio.sleep(0.5)  # Allow GC to complete
        
        initial_memory = process.memory_info().rss / (1024 * 1024)  # MB
        initial_snapshot = tracemalloc.take_snapshot()
        
        endurance_metrics = {
            "memory_samples": [],
            "successful_requests": 0,
            "failed_requests": 0,
            "gc_collection_count": 0,
            "response_times": []
        }
        
        # Run endurance test for sustained period
        endurance_duration = 300  # 5 minutes of requests
        start_time = time.time()
        request_count = 0
        
        while (time.time() - start_time) < endurance_duration:
            # Mix of different request types to stress memory
            request_type = request_count % 3
            
            try:
                req_start = time.perf_counter()
                
                if request_type == 0:
                    # Simple GET request
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                elif request_type == 1:
                    # Chat completion request
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Endurance test {request_count}"}],
                            "max_tokens": 50
                        }
                    )
                else:
                    # Embedding request (if available)
                    embedding_model = config.get_embedding_model(0)
                    if embedding_model:
                        response = await make_request(
                            http_client, "POST", "/api/v1/embeddings",
                            auth_headers, {
                                "model": embedding_model,
                                "input": f"Endurance test {request_count}"
                            }
                        )
                    else:
                        continue
                
                req_end = time.perf_counter()
                endurance_metrics["response_times"].append((req_end - req_start) * 1000)
                
                if response.status_code == 200:
                    endurance_metrics["successful_requests"] += 1
                else:
                    endurance_metrics["failed_requests"] += 1
                
                request_count += 1
                
                # Sample memory every 50 requests
                if request_count % 50 == 0:
                    current_memory = process.memory_info().rss / (1024 * 1024)
                    endurance_metrics["memory_samples"].append({
                        "request_count": request_count,
                        "memory_mb": current_memory,
                        "timestamp": time.time() - start_time
                    })
                    
                    # Force periodic garbage collection
                    collected = gc.collect()
                    endurance_metrics["gc_collection_count"] += collected
                
                # Brief delay to prevent overwhelming
                await asyncio.sleep(0.02)
                
            except Exception as e:
                endurance_metrics["failed_requests"] += 1
                logger.warning(f"Endurance request {request_count} failed: {e}")
        
        # Final memory measurement
        gc.collect()
        await asyncio.sleep(1)  # Allow final GC
        final_memory = process.memory_info().rss / (1024 * 1024)
        final_snapshot = tracemalloc.take_snapshot()
        
        # Analyze memory leak behavior
        memory_growth = final_memory - initial_memory
        peak_memory = max(sample["memory_mb"] for sample in endurance_metrics["memory_samples"]) if endurance_metrics["memory_samples"] else final_memory
        
        # Calculate memory growth trend
        if len(endurance_metrics["memory_samples"]) >= 2:
            early_samples = endurance_metrics["memory_samples"][:3]
            late_samples = endurance_metrics["memory_samples"][-3:]
            
            early_avg = statistics.mean(sample["memory_mb"] for sample in early_samples)
            late_avg = statistics.mean(sample["memory_mb"] for sample in late_samples)
            
            trend_growth = late_avg - early_avg
        else:
            trend_growth = memory_growth
        
        avg_response_time = statistics.mean(endurance_metrics["response_times"]) if endurance_metrics["response_times"] else 0
        success_rate = endurance_metrics["successful_requests"] / (endurance_metrics["successful_requests"] + endurance_metrics["failed_requests"]) if (endurance_metrics["successful_requests"] + endurance_metrics["failed_requests"]) > 0 else 0
        
        logger.info(f"Endurance memory leak test - "
                   f"Initial: {initial_memory:.2f}MB, "
                   f"Peak: {peak_memory:.2f}MB, "
                   f"Final: {final_memory:.2f}MB, "
                   f"Growth: {memory_growth:.2f}MB, "
                   f"Trend growth: {trend_growth:.2f}MB, "
                   f"Requests: {endurance_metrics['successful_requests']}, "
                   f"Success rate: {success_rate:.2%}")
        
        # Clean up memory tracing
        tracemalloc.stop()
        
        # Verify no significant memory leaks
        assert memory_growth <= 200.0, f"Memory growth should be reasonable for endurance test, got {memory_growth:.2f}MB"
        assert trend_growth <= 100.0, f"Memory trend growth should be minimal, got {trend_growth:.2f}MB"
        assert success_rate >= 0.95, f"Success rate should remain high during endurance test, got {success_rate:.2%}"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mem_leak_streaming_connections_002(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """PERF_MEM_LEAK_STREAMING_CONNECTIONS_002: Test memory leaks from streaming connections"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test streaming connection memory management
        process = psutil.Process(os.getpid())
        gc.collect()
        initial_memory = process.memory_info().rss / (1024 * 1024)
        
        streaming_metrics = {
            "completed_streams": 0,
            "terminated_streams": 0,
            "memory_samples": [],
            "connection_errors": 0
        }
        
        # Test completed streams
        for i in range(20):
            try:
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Streaming memory test {i}"}],
                    "max_tokens": 50,
                    "stream": True
                }
                
                async with http_client.stream(
                    "POST",
                    "/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request_data,
                    timeout=30.0
                ) as response:
                    
                    if response.status_code == 200:
                        content_received = False
                        async for line in response.aiter_lines():
                            if line.startswith("data: "):
                                data_str = line[6:].strip()
                                if data_str == "[DONE]":
                                    break
                                
                                try:
                                    chunk_data = json.loads(data_str)
                                    if "choices" in chunk_data:
                                        content_received = True
                                except json.JSONDecodeError:
                                    continue
                        
                        if content_received:
                            streaming_metrics["completed_streams"] += 1
                
                # Sample memory every 5 streams
                if i % 5 == 0:
                    current_memory = process.memory_info().rss / (1024 * 1024)
                    streaming_metrics["memory_samples"].append(current_memory)
            
            except Exception as e:
                streaming_metrics["connection_errors"] += 1
                logger.warning(f"Streaming test {i} failed: {e}")
            
            await asyncio.sleep(0.1)
        
        # Test prematurely terminated streams
        for i in range(15):
            try:
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Terminated stream test {i}"}],
                    "max_tokens": 100,
                    "stream": True
                }
                
                async with http_client.stream(
                    "POST",
                    "/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request_data,
                    timeout=30.0
                ) as response:
                    
                    if response.status_code == 200:
                        chunk_count = 0
                        async for line in response.aiter_lines():
                            if line.startswith("data: "):
                                chunk_count += 1
                                # Terminate after receiving a few chunks
                                if chunk_count >= 3:
                                    streaming_metrics["terminated_streams"] += 1
                                    break
            
            except Exception as e:
                streaming_metrics["connection_errors"] += 1
            
            await asyncio.sleep(0.05)
        
        # Final memory check
        gc.collect()
        await asyncio.sleep(1)
        final_memory = process.memory_info().rss / (1024 * 1024)
        memory_growth = final_memory - initial_memory
        
        logger.info(f"Streaming memory leak test - "
                   f"Completed streams: {streaming_metrics['completed_streams']}, "
                   f"Terminated streams: {streaming_metrics['terminated_streams']}, "
                   f"Memory growth: {memory_growth:.2f}MB")
        
        # Verify streaming doesn't cause memory leaks
        assert memory_growth <= 50.0, f"Streaming should not cause significant memory growth, got {memory_growth:.2f}MB"
        assert streaming_metrics["completed_streams"] >= 15, f"Most streams should complete successfully"
        assert streaming_metrics["terminated_streams"] >= 10, f"Terminated streams should be handled properly"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mem_leak_provider_sdk_clients_004(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """PERF_MEM_LEAK_PROVIDER_SDK_CLIENTS_004: Test provider SDK client memory management"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test provider SDK memory management
        process = psutil.Process(os.getpid())
        gc.collect()
        initial_memory = process.memory_info().rss / (1024 * 1024)
        
        provider_metrics = {
            "requests_per_model": {},
            "memory_samples": [],
            "successful_requests": 0,
            "failed_requests": 0
        }
        
        # Test multiple models/providers if available
        available_models = config.CHAT_MODELS[:3] if len(config.CHAT_MODELS) >= 3 else config.CHAT_MODELS
        
        for cycle in range(10):  # Multiple cycles to test SDK client reuse
            for model in available_models:
                model_key = f"model_{model}"
                if model_key not in provider_metrics["requests_per_model"]:
                    provider_metrics["requests_per_model"][model_key] = 0
                
                try:
                    request_data = {
                        "model": model,
                        "messages": [{"role": "user", "content": f"Provider SDK test cycle {cycle}"}],
                        "max_tokens": 30
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    if response.status_code == 200:
                        provider_metrics["successful_requests"] += 1
                        provider_metrics["requests_per_model"][model_key] += 1
                    else:
                        provider_metrics["failed_requests"] += 1
                
                except Exception as e:
                    provider_metrics["failed_requests"] += 1
                    logger.warning(f"Provider SDK test failed for {model}: {e}")
                
                await asyncio.sleep(0.05)
            
            # Sample memory every cycle
            current_memory = process.memory_info().rss / (1024 * 1024)
            provider_metrics["memory_samples"].append({
                "cycle": cycle,
                "memory_mb": current_memory
            })
            
            # Force garbage collection periodically
            if cycle % 3 == 0:
                gc.collect()
            
            await asyncio.sleep(0.1)
        
        # Final memory check
        gc.collect()
        await asyncio.sleep(1)
        final_memory = process.memory_info().rss / (1024 * 1024)
        memory_growth = final_memory - initial_memory
        
        # Analyze memory stability across provider SDK usage
        if len(provider_metrics["memory_samples"]) >= 2:
            memory_values = [sample["memory_mb"] for sample in provider_metrics["memory_samples"]]
            memory_stability = statistics.stdev(memory_values) if len(memory_values) > 1 else 0
        else:
            memory_stability = 0
        
        success_rate = provider_metrics["successful_requests"] / (provider_metrics["successful_requests"] + provider_metrics["failed_requests"]) if (provider_metrics["successful_requests"] + provider_metrics["failed_requests"]) > 0 else 0
        
        logger.info(f"Provider SDK memory test - "
                   f"Memory growth: {memory_growth:.2f}MB, "
                   f"Memory stability: {memory_stability:.2f}MB, "
                   f"Success rate: {success_rate:.2%}, "
                   f"Models tested: {len(provider_metrics['requests_per_model'])}")
        
        # Verify provider SDK memory management
        assert memory_growth <= 75.0, f"Provider SDK should not cause excessive memory growth, got {memory_growth:.2f}MB"
        assert memory_stability <= 30.0, f"Memory usage should be stable across provider calls, got {memory_stability:.2f}MB stddev"
        assert success_rate >= 0.85, f"Provider SDK calls should be reliable, got {success_rate:.2%}"


class TestLargePayloadHandling:
    """Test memory usage with large payloads"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mem_payload_chat_large_prompt_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """PERF_MEM_PAYLOAD_CHAT_LARGE_PROMPT_001: Test memory usage with large chat prompts"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test memory handling with increasingly large prompts
        process = psutil.Process(os.getpid())
        gc.collect()
        baseline_memory = process.memory_info().rss / (1024 * 1024)
        
        large_prompt_tests = [
            {
                "name": "medium_prompt",
                "size_kb": 5,
                "repeat_count": 3
            },
            {
                "name": "large_prompt", 
                "size_kb": 20,
                "repeat_count": 2
            },
            {
                "name": "very_large_prompt",
                "size_kb": 50,
                "repeat_count": 1
            }
        ]
        
        payload_results = {}
        
        for test_case in large_prompt_tests:
            case_metrics = {
                "peak_memory": baseline_memory,
                "memory_samples": [],
                "successful_requests": 0,
                "failed_requests": 0,
                "response_times": []
            }
            
            # Create large prompt
            base_text = "This is a comprehensive analysis of artificial intelligence and machine learning technologies. " * 50
            large_prompt = base_text * (test_case["size_kb"] * 1024 // len(base_text))
            
            for i in range(test_case["repeat_count"]):
                memory_before = process.memory_info().rss / (1024 * 1024)
                
                try:
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": large_prompt}],
                        "max_tokens": 50  # Keep response small to focus on prompt processing
                    }
                    
                    start_time = time.perf_counter()
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    end_time = time.perf_counter()
                    
                    memory_after = process.memory_info().rss / (1024 * 1024)
                    response_time = (end_time - start_time) * 1000
                    
                    case_metrics["memory_samples"].append({
                        "before": memory_before,
                        "after": memory_after,
                        "peak": max(memory_before, memory_after)
                    })
                    
                    case_metrics["peak_memory"] = max(case_metrics["peak_memory"], memory_after)
                    case_metrics["response_times"].append(response_time)
                    
                    if response.status_code == 200:
                        case_metrics["successful_requests"] += 1
                    else:
                        case_metrics["failed_requests"] += 1
                        if response.status_code in [400, 422]:
                            logger.info(f"Large prompt may have exceeded model limits: {response.status_code}")
                
                except Exception as e:
                    case_metrics["failed_requests"] += 1
                    logger.warning(f"Large prompt test failed: {e}")
                
                # Force GC after each large request
                gc.collect()
                await asyncio.sleep(1)
            
            payload_results[test_case["name"]] = case_metrics
        
        # Analyze large payload memory usage
        for test_name, metrics in payload_results.items():
            if metrics["memory_samples"]:
                max_memory_spike = max(sample["peak"] - sample["before"] for sample in metrics["memory_samples"])
                avg_response_time = statistics.mean(metrics["response_times"]) if metrics["response_times"] else 0
                
                logger.info(f"{test_name} - "
                           f"Max memory spike: {max_memory_spike:.2f}MB, "
                           f"Avg response time: {avg_response_time:.2f}ms, "
                           f"Successful: {metrics['successful_requests']}")
                
                # Verify memory spikes are reasonable for large payloads
                assert max_memory_spike <= 500.0, f"{test_name} memory spike should be manageable, got {max_memory_spike:.2f}MB"
        
        # Verify memory returns to baseline
        gc.collect()
        await asyncio.sleep(2)
        final_memory = process.memory_info().rss / (1024 * 1024)
        memory_retention = final_memory - baseline_memory
        
        assert memory_retention <= 100.0, f"Memory should return near baseline after large payloads, retained {memory_retention:.2f}MB"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mem_payload_embed_large_batch_003(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """PERF_MEM_PAYLOAD_EMBED_LARGE_BATCH_003: Test memory usage with large embedding batches"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Skip if no embedding model available
        embedding_model = config.get_embedding_model(0)
        if not embedding_model:
            pytest.skip("No embedding model configured")
        
        # Test large embedding batch memory usage
        process = psutil.Process(os.getpid())
        gc.collect()
        baseline_memory = process.memory_info().rss / (1024 * 1024)
        
        batch_sizes = [50, 100, 200]
        batch_results = {}
        
        base_texts = [
            "Advanced artificial intelligence research and development",
            "Machine learning algorithms and neural network architectures", 
            "Natural language processing and computational linguistics",
            "Computer vision and image recognition technologies",
            "Data science and statistical analysis methodologies"
        ]
        
        for batch_size in batch_sizes:
            batch_metrics = {
                "memory_before": 0,
                "memory_peak": 0, 
                "memory_after": 0,
                "successful_batches": 0,
                "response_times": []
            }
            
            # Create large batch
            batch_texts = []
            for i in range(batch_size):
                text = f"{base_texts[i % len(base_texts)]} - item {i}"
                batch_texts.append(text)
            
            memory_before = process.memory_info().rss / (1024 * 1024)
            batch_metrics["memory_before"] = memory_before
            
            try:
                request_data = {
                    "model": embedding_model,
                    "input": batch_texts
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/embeddings",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                memory_after = process.memory_info().rss / (1024 * 1024)
                batch_metrics["memory_after"] = memory_after
                batch_metrics["memory_peak"] = max(memory_before, memory_after)
                
                response_time = (end_time - start_time) * 1000
                batch_metrics["response_times"].append(response_time)
                
                if response.status_code == 200:
                    batch_metrics["successful_batches"] += 1
                    logger.info(f"Batch size {batch_size} completed successfully")
                else:
                    logger.warning(f"Batch size {batch_size} failed with status {response.status_code}")
            
            except Exception as e:
                logger.warning(f"Large embedding batch {batch_size} failed: {e}")
            
            batch_results[batch_size] = batch_metrics
            
            # Clean up between batches
            gc.collect()
            await asyncio.sleep(2)
        
        # Analyze embedding batch memory usage
        for batch_size, metrics in batch_results.items():
            memory_growth = metrics["memory_after"] - metrics["memory_before"]
            
            logger.info(f"Embedding batch {batch_size} - "
                       f"Memory growth: {memory_growth:.2f}MB, "
                       f"Success: {metrics['successful_batches']}")
            
            if metrics["successful_batches"] > 0:
                # Memory growth should be proportional but reasonable
                memory_per_item = memory_growth / batch_size if batch_size > 0 else 0
                assert memory_per_item <= 5.0, f"Memory per embedding item should be reasonable, got {memory_per_item:.2f}MB"
        
        # Verify memory cleanup after large batches
        gc.collect()
        await asyncio.sleep(2)
        final_memory = process.memory_info().rss / (1024 * 1024)
        total_retention = final_memory - baseline_memory
        
        assert total_retention <= 150.0, f"Memory should be cleaned up after large batches, retained {total_retention:.2f}MB"


class TestGarbageCollectionImpact:
    """Test garbage collection behavior and performance impact"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mem_gc_behavior_load_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """PERF_MEM_GC_BEHAVIOR_LOAD_001: Test garbage collection behavior under sustained load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Monitor GC behavior under sustained load
        gc_metrics = {
            "gc_collections_before": gc.get_count(),
            "gc_collections_after": None,
            "response_times": [],
            "gc_impact_samples": [],
            "successful_requests": 0
        }
        
        # Enable GC debugging
        gc.set_debug(gc.DEBUG_STATS)
        
        # Generate sustained load to trigger GC
        for i in range(100):
            # Force some object creation/destruction
            temp_data = [f"GC test object {j}" for j in range(100)]
            
            gc_before = sum(gc.get_count())
            start_time = time.perf_counter()
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"GC test {i}"}],
                    "max_tokens": 30
                }
            )
            
            end_time = time.perf_counter()
            gc_after = sum(gc.get_count())
            
            response_time = (end_time - start_time) * 1000
            
            if response.status_code == 200:
                gc_metrics["response_times"].append(response_time)
                gc_metrics["successful_requests"] += 1
                
                # Track GC impact
                gc_delta = gc_after - gc_before
                gc_metrics["gc_impact_samples"].append({
                    "response_time": response_time,
                    "gc_delta": gc_delta,
                    "request_id": i
                })
            
            # Deliberately create temporary objects
            del temp_data
            
            # Periodic forced GC to observe impact
            if i % 20 == 0:
                gc_start = time.perf_counter()
                collected = gc.collect()
                gc_time = (time.perf_counter() - gc_start) * 1000
                
                logger.info(f"Forced GC at request {i}: collected {collected} objects in {gc_time:.2f}ms")
            
            await asyncio.sleep(0.02)
        
        gc_metrics["gc_collections_after"] = gc.get_count()
        
        # Analyze GC impact on performance
        if gc_metrics["response_times"]:
            avg_response_time = statistics.mean(gc_metrics["response_times"])
            p95_response_time = statistics.quantiles(gc_metrics["response_times"], n=20)[18] if len(gc_metrics["response_times"]) >= 20 else max(gc_metrics["response_times"])
            
            # Look for correlation between GC activity and response time
            high_gc_responses = [sample["response_time"] for sample in gc_metrics["gc_impact_samples"] if abs(sample["gc_delta"]) > 10]
            low_gc_responses = [sample["response_time"] for sample in gc_metrics["gc_impact_samples"] if abs(sample["gc_delta"]) <= 10]
            
            high_gc_avg = statistics.mean(high_gc_responses) if high_gc_responses else 0
            low_gc_avg = statistics.mean(low_gc_responses) if low_gc_responses else 0
            
            logger.info(f"GC behavior under load - "
                       f"Avg response: {avg_response_time:.2f}ms, "
                       f"P95 response: {p95_response_time:.2f}ms, "
                       f"High GC activity avg: {high_gc_avg:.2f}ms, "
                       f"Low GC activity avg: {low_gc_avg:.2f}ms")
            
            # Verify GC doesn't cause excessive performance degradation
            assert avg_response_time < 5000.0, f"Average response time should be reasonable despite GC, got {avg_response_time:.2f}ms"
            assert p95_response_time < 10000.0, f"P95 response time should handle GC impact, got {p95_response_time:.2f}ms"
            
            # GC impact should be reasonable
            if high_gc_avg > 0 and low_gc_avg > 0:
                gc_impact_ratio = high_gc_avg / low_gc_avg
                assert gc_impact_ratio <= 3.0, f"GC impact on response time should be limited, got {gc_impact_ratio:.2f}x"
        
        # Disable GC debugging
        gc.set_debug(0)


class TestEnhancedMemoryManagement:
    """Enhanced memory management testing scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mem_automated_profiling_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """PERF_MEM_AUTOMATED_PROFILING_001: Automated memory profiling and trend analysis"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Automated memory profiling
        tracemalloc.start(10)  # Track top 10 allocations
        
        process = psutil.Process(os.getpid())
        profiling_metrics = {
            "memory_trend": [],
            "allocation_patterns": [],
            "peak_allocations": [],
            "successful_requests": 0
        }
        
        baseline_memory = process.memory_info().rss / (1024 * 1024)
        
        # Profile memory during normal operations
        for i in range(50):
            snapshot_before = tracemalloc.take_snapshot()
            memory_before = process.memory_info().rss / (1024 * 1024)
            
            # Mixed workload
            if i % 3 == 0:
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
            else:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Memory profiling test {i}"}],
                        "max_tokens": 40
                    }
                )
            
            memory_after = process.memory_info().rss / (1024 * 1024)
            snapshot_after = tracemalloc.take_snapshot()
            
            if response.status_code == 200:
                profiling_metrics["successful_requests"] += 1
            
            # Track memory trend
            profiling_metrics["memory_trend"].append({
                "request_id": i,
                "memory_before": memory_before,
                "memory_after": memory_after,
                "memory_delta": memory_after - memory_before
            })
            
            # Track allocation patterns
            top_stats = snapshot_after.compare_to(snapshot_before, 'lineno')
            if top_stats:
                total_size_diff = sum(stat.size_diff for stat in top_stats[:5])
                profiling_metrics["allocation_patterns"].append({
                    "request_id": i,
                    "total_allocation_diff": total_size_diff,
                    "top_allocations": len([s for s in top_stats if s.size_diff > 0])
                })
            
            await asyncio.sleep(0.05)
        
        # Analyze memory profiling results
        memory_deltas = [trend["memory_delta"] for trend in profiling_metrics["memory_trend"]]
        avg_memory_delta = statistics.mean(memory_deltas)
        memory_trend_slope = (profiling_metrics["memory_trend"][-1]["memory_after"] - 
                             profiling_metrics["memory_trend"][0]["memory_before"]) / len(profiling_metrics["memory_trend"])
        
        final_memory = process.memory_info().rss / (1024 * 1024)
        total_memory_change = final_memory - baseline_memory
        
        logger.info(f"Automated memory profiling - "
                   f"Avg memory delta: {avg_memory_delta:.3f}MB, "
                   f"Memory trend slope: {memory_trend_slope:.3f}MB/request, "
                   f"Total change: {total_memory_change:.2f}MB")
        
        tracemalloc.stop()
        
        # Verify memory profiling shows healthy patterns
        assert abs(avg_memory_delta) <= 5.0, f"Average memory delta should be small, got {avg_memory_delta:.3f}MB"
        assert abs(memory_trend_slope) <= 1.0, f"Memory trend should be stable, got {memory_trend_slope:.3f}MB/request"
        assert abs(total_memory_change) <= 100.0, f"Total memory change should be reasonable, got {total_memory_change:.2f}MB"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mem_realtime_leak_detection_006(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_MEM_REALTIME_LEAK_DETECTION_006: Real-time memory leak detection"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Real-time leak detection simulation
        process = psutil.Process(os.getpid())
        
        leak_detection_metrics = {
            "memory_snapshots": [],
            "leak_alerts": [],
            "growth_rate_samples": [],
            "successful_requests": 0
        }
        
        baseline_memory = process.memory_info().rss / (1024 * 1024)
        window_size = 10  # Rolling window for leak detection
        
        for i in range(60):  # Extended test for leak detection
            memory_before = process.memory_info().rss / (1024 * 1024)
            
            # Generate requests
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Leak detection test {i}"}],
                    "max_tokens": 35
                }
            )
            
            memory_after = process.memory_info().rss / (1024 * 1024)
            
            if response.status_code == 200:
                leak_detection_metrics["successful_requests"] += 1
            
            # Record memory snapshot
            leak_detection_metrics["memory_snapshots"].append({
                "request_id": i,
                "memory": memory_after,
                "timestamp": time.time()
            })
            
            # Real-time leak detection (sliding window analysis)
            if len(leak_detection_metrics["memory_snapshots"]) >= window_size:
                recent_snapshots = leak_detection_metrics["memory_snapshots"][-window_size:]
                memory_values = [s["memory"] for s in recent_snapshots]
                
                # Calculate growth rate
                if len(memory_values) >= 2:
                    growth_rate = (memory_values[-1] - memory_values[0]) / len(memory_values)
                    leak_detection_metrics["growth_rate_samples"].append(growth_rate)
                    
                    # Leak detection threshold
                    if growth_rate > 2.0:  # More than 2MB growth per request over window
                        leak_detection_metrics["leak_alerts"].append({
                            "request_id": i,
                            "growth_rate": growth_rate,
                            "window_start": memory_values[0],
                            "window_end": memory_values[-1]
                        })
            
            # Periodic GC to ensure leaks aren't just delayed cleanup
            if i % 15 == 0:
                gc.collect()
            
            await asyncio.sleep(0.02)
        
        # Analyze real-time leak detection results
        final_memory = process.memory_info().rss / (1024 * 1024)
        total_growth = final_memory - baseline_memory
        
        avg_growth_rate = statistics.mean(leak_detection_metrics["growth_rate_samples"]) if leak_detection_metrics["growth_rate_samples"] else 0
        leak_alert_count = len(leak_detection_metrics["leak_alerts"])
        
        logger.info(f"Real-time leak detection - "
                   f"Total growth: {total_growth:.2f}MB, "
                   f"Avg growth rate: {avg_growth_rate:.3f}MB/request, "
                   f"Leak alerts: {leak_alert_count}")
        
        # Verify leak detection effectiveness
        assert total_growth <= 150.0, f"Total memory growth should be reasonable, got {total_growth:.2f}MB"
        assert leak_alert_count <= 3, f"Leak alerts should be rare in healthy system, got {leak_alert_count}"
        assert abs(avg_growth_rate) <= 1.0, f"Average growth rate should be minimal, got {avg_growth_rate:.3f}MB/request"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mem_gc_tuning_validation_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """PERF_MEM_GC_TUNING_001: Advanced garbage collection tuning validation"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test different GC tuning scenarios
        gc_tuning_scenarios = [
            {
                "name": "default_gc",
                "thresholds": None,  # Use default
                "description": "Default GC settings"
            },
            {
                "name": "aggressive_gc",
                "thresholds": (500, 10, 10),  # More aggressive collection
                "description": "Aggressive GC for low latency"
            },
            {
                "name": "conservative_gc", 
                "thresholds": (2000, 20, 20),  # Less frequent collection
                "description": "Conservative GC for throughput"
            }
        ]
        
        gc_results = {}
        
        for scenario in gc_tuning_scenarios:
            # Save current GC settings
            original_thresholds = gc.get_threshold()
            
            # Apply scenario GC settings
            if scenario["thresholds"]:
                gc.set_threshold(*scenario["thresholds"])
            
            scenario_metrics = {
                "memory_samples": [],
                "gc_collections": [],
                "response_times": [],
                "successful_requests": 0
            }
            
            process = psutil.Process(os.getpid())
            gc.collect()  # Start clean
            
            # Run test workload with this GC configuration
            for i in range(30):
                gc_before = sum(gc.get_count())
                memory_before = process.memory_info().rss / (1024 * 1024)
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"GC tuning test {scenario['name']} request {i}"}],
                        "max_tokens": 40
                    }
                )
                end_time = time.perf_counter()
                
                memory_after = process.memory_info().rss / (1024 * 1024)
                gc_after = sum(gc.get_count())
                
                response_time = (end_time - start_time) * 1000
                
                if response.status_code == 200:
                    scenario_metrics["successful_requests"] += 1
                    scenario_metrics["response_times"].append(response_time)
                
                scenario_metrics["memory_samples"].append({
                    "before": memory_before,
                    "after": memory_after,
                    "delta": memory_after - memory_before
                })
                
                scenario_metrics["gc_collections"].append({
                    "before": gc_before,
                    "after": gc_after,
                    "delta": gc_after - gc_before
                })
                
                # Create some temporary objects to trigger GC
                temp_objects = [f"gc_test_object_{j}" for j in range(50)]
                del temp_objects
                
                await asyncio.sleep(0.03)
            
            # Restore original GC settings
            gc.set_threshold(*original_thresholds)
            
            # Analyze scenario results
            if scenario_metrics["response_times"]:
                avg_response_time = statistics.mean(scenario_metrics["response_times"])
                memory_deltas = [sample["delta"] for sample in scenario_metrics["memory_samples"]]
                avg_memory_delta = statistics.mean(memory_deltas)
                gc_activity = sum(abs(gc["delta"]) for gc in scenario_metrics["gc_collections"])
                
                gc_results[scenario["name"]] = {
                    "avg_response_time": avg_response_time,
                    "avg_memory_delta": avg_memory_delta,
                    "total_gc_activity": gc_activity,
                    "successful_requests": scenario_metrics["successful_requests"],
                    "description": scenario["description"]
                }
                
                logger.info(f"GC tuning {scenario['name']} - "
                           f"Avg response: {avg_response_time:.2f}ms, "
                           f"Avg memory delta: {avg_memory_delta:.3f}MB, "
                           f"GC activity: {gc_activity}")
        
        # Compare GC tuning effectiveness
        for scenario_name, results in gc_results.items():
            # All scenarios should maintain reasonable performance
            assert results["avg_response_time"] <= 8000.0, f"GC scenario {scenario_name} response time should be reasonable"
            assert abs(results["avg_memory_delta"]) <= 10.0, f"GC scenario {scenario_name} memory delta should be controlled"
            assert results["successful_requests"] >= 25, f"GC scenario {scenario_name} should have high success rate"
        
        # Analyze relative performance of different GC configurations
        if len(gc_results) >= 2:
            response_times = {name: results["avg_response_time"] for name, results in gc_results.items()}
            best_response_time = min(response_times.values())
            worst_response_time = max(response_times.values())
            
            gc_tuning_effectiveness = worst_response_time / best_response_time if best_response_time > 0 else 1.0
            
            logger.info(f"GC tuning effectiveness - Best: {best_response_time:.2f}ms, "
                       f"Worst: {worst_response_time:.2f}ms, "
                       f"Ratio: {gc_tuning_effectiveness:.2f}x")
            
            # GC tuning should show measurable impact
            assert gc_tuning_effectiveness <= 5.0, f"GC tuning should have bounded impact, got {gc_tuning_effectiveness:.2f}x"
        
        logger.info("Advanced GC tuning validation completed")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mem_fragmentation_sustained_load_001(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """PERF_MEM_FRAGMENTATION_001: Memory fragmentation analysis under sustained load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Monitor memory fragmentation during sustained load
        process = psutil.Process(os.getpid())
        
        fragmentation_metrics = {
            "virtual_memory_samples": [],
            "resident_memory_samples": [],
            "allocation_patterns": [],
            "fragmentation_indicators": [],
            "successful_requests": 0
        }
        
        gc.collect()
        baseline_vms = process.memory_info().vms / (1024 * 1024)
        baseline_rss = process.memory_info().rss / (1024 * 1024)
        
        # Sustained load with varied allocation patterns
        allocation_patterns = [
            {"size": "small", "tokens": 20, "requests": 15},
            {"size": "medium", "tokens": 100, "requests": 10},
            {"size": "large", "tokens": 300, "requests": 5},
            {"size": "mixed", "tokens": None, "requests": 20}  # Variable sizes
        ]
        
        for pattern in allocation_patterns:
            pattern_metrics = {
                "pattern_name": pattern["size"],
                "memory_growth": [],
                "fragmentation_ratio": [],
                "response_times": []
            }
            
            for i in range(pattern["requests"]):
                memory_before = process.memory_info()
                vms_before = memory_before.vms / (1024 * 1024)
                rss_before = memory_before.rss / (1024 * 1024)
                
                # Create request with specific allocation pattern
                if pattern["size"] == "mixed":
                    max_tokens = [10, 50, 150, 250][i % 4]
                else:
                    max_tokens = pattern["tokens"]
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Fragmentation test {pattern['size']} pattern request {i}"}],
                        "max_tokens": max_tokens
                    }
                )
                end_time = time.perf_counter()
                
                memory_after = process.memory_info()
                vms_after = memory_after.vms / (1024 * 1024)
                rss_after = memory_after.rss / (1024 * 1024)
                
                if response.status_code == 200:
                    fragmentation_metrics["successful_requests"] += 1
                    pattern_metrics["response_times"].append((end_time - start_time) * 1000)
                
                # Track memory allocation patterns
                vms_growth = vms_after - vms_before
                rss_growth = rss_after - rss_before
                
                # Fragmentation indicator: VMS growth vs RSS growth
                fragmentation_ratio = vms_growth / rss_growth if rss_growth > 0 else 1.0
                
                pattern_metrics["memory_growth"].append({
                    "vms_growth": vms_growth,
                    "rss_growth": rss_growth,
                    "request_id": i
                })
                
                pattern_metrics["fragmentation_ratio"].append(fragmentation_ratio)
                
                # Store detailed samples
                fragmentation_metrics["virtual_memory_samples"].append(vms_after)
                fragmentation_metrics["resident_memory_samples"].append(rss_after)
                fragmentation_metrics["fragmentation_indicators"].append({
                    "pattern": pattern["size"],
                    "fragmentation_ratio": fragmentation_ratio,
                    "vms_total": vms_after,
                    "rss_total": rss_after
                })
                
                await asyncio.sleep(0.02)
            
            # Analyze pattern-specific fragmentation
            if pattern_metrics["fragmentation_ratio"]:
                avg_fragmentation = statistics.mean(pattern_metrics["fragmentation_ratio"])
                avg_response_time = statistics.mean(pattern_metrics["response_times"]) if pattern_metrics["response_times"] else 0
                
                logger.info(f"Memory fragmentation {pattern['size']} pattern - "
                           f"Avg fragmentation ratio: {avg_fragmentation:.2f}, "
                           f"Avg response time: {avg_response_time:.2f}ms")
                
                # Fragmentation should be reasonable for each pattern
                assert avg_fragmentation <= 3.0, f"Fragmentation ratio for {pattern['size']} should be reasonable, got {avg_fragmentation:.2f}"
            
            # Force GC between patterns to see fragmentation persistence
            gc.collect()
            await asyncio.sleep(0.5)
        
        # Overall fragmentation analysis
        final_vms = process.memory_info().vms / (1024 * 1024)
        final_rss = process.memory_info().rss / (1024 * 1024)
        
        total_vms_growth = final_vms - baseline_vms
        total_rss_growth = final_rss - baseline_rss
        overall_fragmentation = total_vms_growth / total_rss_growth if total_rss_growth > 0 else 1.0
        
        # Calculate fragmentation trend
        if len(fragmentation_metrics["fragmentation_indicators"]) >= 2:
            early_fragmentation = statistics.mean([f["fragmentation_ratio"] 
                                                  for f in fragmentation_metrics["fragmentation_indicators"][:10]])
            late_fragmentation = statistics.mean([f["fragmentation_ratio"] 
                                                 for f in fragmentation_metrics["fragmentation_indicators"][-10:]])
            fragmentation_trend = late_fragmentation - early_fragmentation
        else:
            fragmentation_trend = 0
        
        logger.info(f"Memory fragmentation analysis - "
                   f"Overall ratio: {overall_fragmentation:.2f}, "
                   f"Trend: {fragmentation_trend:.3f}, "
                   f"VMS growth: {total_vms_growth:.2f}MB, "
                   f"RSS growth: {total_rss_growth:.2f}MB")
        
        # Verify fragmentation is under control
        assert overall_fragmentation <= 4.0, f"Overall fragmentation should be manageable, got {overall_fragmentation:.2f}"
        assert abs(fragmentation_trend) <= 1.0, f"Fragmentation trend should be stable, got {fragmentation_trend:.3f}"
        assert total_vms_growth <= 500.0, f"VMS growth should be reasonable, got {total_vms_growth:.2f}MB"
        
        logger.info("Memory fragmentation analysis completed")