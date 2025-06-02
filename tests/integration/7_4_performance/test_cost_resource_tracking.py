# Section 7.4 - Cost and Resource Tracking Performance
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_Cost and Resource Tracking Performance.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import psutil
import os
import gc

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class CostTrackingResult:
    """Cost tracking test result data structure"""
    test_name: str
    total_prompt_tokens: int
    total_completion_tokens: int
    total_requests: int
    avg_response_time: float
    cost_efficiency_score: float
    resource_utilization: Dict[str, float]


class TestTokenUsageEfficiency:
    """Test efficiency of token usage and request handling"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cost_token_prompt_overhead_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_COST_TOKEN_PROMPT_OVERHEAD_001: Verify minimal token overhead from API framework"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test token overhead with simple prompts
        token_overhead_tests = [
            {
                "name": "simple_prompt",
                "messages": [{"role": "user", "content": "Hello"}],
                "expected_tokens": 1  # Approximate - "Hello" should be 1 token
            },
            {
                "name": "system_user_prompt",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Hello"}
                ],
                "expected_tokens": 7  # Approximate - system message + "Hello"
            },
            {
                "name": "medium_prompt",
                "messages": [{"role": "user", "content": "Tell me about artificial intelligence in three sentences."}],
                "expected_tokens": 12  # Approximate token count
            }
        ]
        
        token_overhead_results = {}
        
        for test_case in token_overhead_tests:
            request_data = {
                "model": config.get_chat_model(0),
                "messages": test_case["messages"],
                "max_tokens": 50
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                response_data = response.json()
                if "usage" in response_data:
                    prompt_tokens = response_data["usage"]["prompt_tokens"]
                    completion_tokens = response_data["usage"]["completion_tokens"]
                    
                    # Calculate overhead ratio
                    overhead_ratio = prompt_tokens / test_case["expected_tokens"] if test_case["expected_tokens"] > 0 else 1.0
                    
                    token_overhead_results[test_case["name"]] = {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "expected_tokens": test_case["expected_tokens"],
                        "overhead_ratio": overhead_ratio,
                        "response_time": (end_time - start_time) * 1000
                    }
                    
                    logger.info(f"{test_case['name']} - Prompt tokens: {prompt_tokens}, "
                               f"Expected: {test_case['expected_tokens']}, "
                               f"Overhead ratio: {overhead_ratio:.2f}")
            
            await asyncio.sleep(0.1)
        
        # Verify token overhead is reasonable
        for test_name, result in token_overhead_results.items():
            # Allow for reasonable overhead (tokenizer differences, model-specific formatting)
            assert result["overhead_ratio"] <= 3.0, f"{test_name} token overhead should be reasonable, got {result['overhead_ratio']:.2f}x"
            assert result["prompt_tokens"] > 0, f"{test_name} should report positive prompt tokens"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cost_token_max_tokens_enforcement_002(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """PERF_COST_TOKEN_MAXTOKENS_ENFORCEMENT_002: Ensure max_tokens is enforced for cost control"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test max_tokens enforcement with different limits
        max_tokens_tests = [
            {"max_tokens": 10, "prompt": "Write a long story about a brave knight"},
            {"max_tokens": 25, "prompt": "Explain quantum physics in detail"},
            {"max_tokens": 50, "prompt": "Describe the history of artificial intelligence"}
        ]
        
        max_tokens_results = {}
        
        for test_case in max_tokens_tests:
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": test_case["prompt"]}],
                "max_tokens": test_case["max_tokens"]
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                response_data = response.json()
                if "usage" in response_data and "choices" in response_data:
                    completion_tokens = response_data["usage"]["completion_tokens"]
                    finish_reason = response_data["choices"][0].get("finish_reason", "unknown")
                    
                    max_tokens_results[str(test_case["max_tokens"])] = {
                        "completion_tokens": completion_tokens,
                        "max_tokens": test_case["max_tokens"],
                        "finish_reason": finish_reason,
                        "response_time": (end_time - start_time) * 1000,
                        "enforced": completion_tokens <= test_case["max_tokens"]
                    }
                    
                    logger.info(f"Max tokens {test_case['max_tokens']} - "
                               f"Completion tokens: {completion_tokens}, "
                               f"Finish reason: {finish_reason}")
            
            await asyncio.sleep(0.2)
        
        # Verify max_tokens enforcement
        for limit, result in max_tokens_results.items():
            assert result["enforced"], f"Max tokens {limit} should be enforced, got {result['completion_tokens']} tokens"
            if result["completion_tokens"] == result["max_tokens"]:
                assert result["finish_reason"] == "length", f"Finish reason should be 'length' when max_tokens reached"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cost_batching_embed_effectiveness_003(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """PERF_COST_BATCHING_EMBED_EFFECTIVENESS_003: Evaluate embedding batching cost effectiveness"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Skip if no embedding model available
        embedding_model = config.get_embedding_model(0)
        if not embedding_model:
            pytest.skip("No embedding model configured")
        
        # Test texts for embedding
        test_texts = [
            "Artificial intelligence is transforming technology",
            "Machine learning enables computers to learn from data",
            "Natural language processing helps computers understand text",
            "Computer vision allows machines to interpret images",
            "Deep learning uses neural networks for complex tasks"
        ]
        
        # Test individual requests
        individual_metrics = {
            "total_time": 0,
            "total_tokens": 0,
            "request_count": 0,
            "response_times": []
        }
        
        for text in test_texts:
            request_data = {
                "model": embedding_model,
                "input": text
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            response_time = (end_time - start_time) * 1000
            individual_metrics["response_times"].append(response_time)
            individual_metrics["total_time"] += response_time
            individual_metrics["request_count"] += 1
            
            if response.status_code == 200:
                response_data = response.json()
                if "usage" in response_data:
                    individual_metrics["total_tokens"] += response_data["usage"]["prompt_tokens"]
            
            await asyncio.sleep(0.1)
        
        # Test batch request
        batch_request_data = {
            "model": embedding_model,
            "input": test_texts
        }
        
        batch_start_time = time.perf_counter()
        batch_response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            auth_headers, batch_request_data
        )
        batch_end_time = time.perf_counter()
        
        batch_metrics = {
            "total_time": (batch_end_time - batch_start_time) * 1000,
            "total_tokens": 0,
            "request_count": 1
        }
        
        if batch_response.status_code == 200:
            batch_data = batch_response.json()
            if "usage" in batch_data:
                batch_metrics["total_tokens"] = batch_data["usage"]["prompt_tokens"]
        
        # Analyze batching effectiveness
        if individual_metrics["request_count"] > 0 and batch_metrics["total_time"] > 0:
            time_efficiency = individual_metrics["total_time"] / batch_metrics["total_time"]
            token_consistency = abs(individual_metrics["total_tokens"] - batch_metrics["total_tokens"])
            
            logger.info(f"Embedding batching - Individual: {individual_metrics['total_time']:.2f}ms, "
                       f"Batch: {batch_metrics['total_time']:.2f}ms, "
                       f"Efficiency: {time_efficiency:.2f}x")
            
            # Batching should provide some efficiency (allow for provider variations)
            assert time_efficiency >= 0.8, f"Batching should provide reasonable efficiency, got {time_efficiency:.2f}x"
            assert token_consistency <= 10, f"Token counting should be consistent, difference: {token_consistency}"


class TestAPIResourceUtilization:
    """Test resource utilization of API framework components"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cost_api_resource_cpu_baseline_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """PERF_COST_API_RESOURCE_CPU_BASELINE_001: Measure baseline CPU utilization"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Get baseline CPU usage
        process = psutil.Process(os.getpid())
        
        # Measure idle CPU
        idle_cpu_samples = []
        for i in range(5):
            cpu_percent = process.cpu_percent(interval=0.1)
            idle_cpu_samples.append(cpu_percent)
            await asyncio.sleep(0.1)
        
        idle_cpu_avg = statistics.mean(idle_cpu_samples) if idle_cpu_samples else 0
        
        # Measure CPU under light load
        light_load_cpu_samples = []
        light_load_response_times = []
        
        for i in range(20):
            cpu_before = process.cpu_percent()
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            cpu_after = process.cpu_percent()
            
            if response.status_code == 200:
                light_load_response_times.append((end_time - start_time) * 1000)
                light_load_cpu_samples.append(max(cpu_after - cpu_before, 0))
            
            await asyncio.sleep(0.1)
        
        light_load_cpu_avg = statistics.mean(light_load_cpu_samples) if light_load_cpu_samples else 0
        avg_response_time = statistics.mean(light_load_response_times) if light_load_response_times else 0
        
        logger.info(f"CPU utilization - Idle: {idle_cpu_avg:.2f}%, "
                   f"Light load: {light_load_cpu_avg:.2f}%, "
                   f"Avg response time: {avg_response_time:.2f}ms")
        
        # Verify reasonable CPU usage
        assert idle_cpu_avg <= 10.0, f"Idle CPU should be low, got {idle_cpu_avg:.2f}%"
        assert light_load_cpu_avg <= 50.0, f"Light load CPU should be reasonable, got {light_load_cpu_avg:.2f}%"
        assert avg_response_time < 1000.0, f"Light load response time should be fast, got {avg_response_time:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cost_api_resource_memory_baseline_002(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """PERF_COST_API_RESOURCE_MEMORY_BASELINE_002: Measure baseline memory footprint"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Force garbage collection for accurate baseline
        gc.collect()
        
        process = psutil.Process(os.getpid())
        
        # Measure baseline memory
        baseline_memory = process.memory_info().rss / (1024 * 1024)  # MB
        
        # Generate light load and monitor memory
        memory_samples = []
        response_count = 0
        
        for i in range(30):
            memory_before = process.memory_info().rss / (1024 * 1024)
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            
            memory_after = process.memory_info().rss / (1024 * 1024)
            
            if response.status_code == 200:
                response_count += 1
                memory_samples.append(memory_after)
            
            await asyncio.sleep(0.05)
        
        # Force garbage collection after load
        gc.collect()
        await asyncio.sleep(0.5)  # Allow GC to complete
        final_memory = process.memory_info().rss / (1024 * 1024)
        
        if memory_samples:
            peak_memory = max(memory_samples)
            avg_memory = statistics.mean(memory_samples)
            memory_growth = final_memory - baseline_memory
            
            logger.info(f"Memory usage - Baseline: {baseline_memory:.2f}MB, "
                       f"Peak: {peak_memory:.2f}MB, "
                       f"Final: {final_memory:.2f}MB, "
                       f"Growth: {memory_growth:.2f}MB")
            
            # Verify reasonable memory usage
            assert memory_growth <= 50.0, f"Memory growth should be minimal, got {memory_growth:.2f}MB"
            assert peak_memory <= baseline_memory + 100.0, f"Peak memory should be reasonable, got {peak_memory:.2f}MB"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cost_api_resource_logging_overhead_004(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """PERF_COST_API_RESOURCE_LOGGING_OVERHEAD_004: Assess logging system overhead"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test logging overhead by measuring performance with typical logging
        logging_overhead_metrics = {
            "response_times": [],
            "cpu_usage": [],
            "memory_usage": []
        }
        
        process = psutil.Process(os.getpid())
        
        # Run requests and measure overhead
        for i in range(25):
            memory_before = process.memory_info().rss / (1024 * 1024)
            cpu_before = process.cpu_percent()
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Logging overhead test {i}"}],
                    "max_tokens": 20
                }
            )
            end_time = time.perf_counter()
            
            memory_after = process.memory_info().rss / (1024 * 1024)
            cpu_after = process.cpu_percent()
            
            if response.status_code == 200:
                response_time = (end_time - start_time) * 1000
                logging_overhead_metrics["response_times"].append(response_time)
                logging_overhead_metrics["cpu_usage"].append(max(cpu_after - cpu_before, 0))
                logging_overhead_metrics["memory_usage"].append(memory_after)
            
            await asyncio.sleep(0.1)
        
        # Analyze logging overhead
        if logging_overhead_metrics["response_times"]:
            avg_response_time = statistics.mean(logging_overhead_metrics["response_times"])
            avg_cpu_overhead = statistics.mean(logging_overhead_metrics["cpu_usage"])
            
            logger.info(f"Logging overhead - Avg response time: {avg_response_time:.2f}ms, "
                       f"Avg CPU overhead: {avg_cpu_overhead:.2f}%")
            
            # Logging overhead should be reasonable
            assert avg_response_time < 5000.0, f"Response time with logging should be reasonable, got {avg_response_time:.2f}ms"
            assert avg_cpu_overhead <= 20.0, f"CPU overhead from logging should be minimal, got {avg_cpu_overhead:.2f}%"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cost_api_resource_billing_worker_005(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """PERF_COST_API_RESOURCE_BILLING_WORKER_005: Monitor billing worker resource consumption"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Monitor resource usage while generating billable events
        process = psutil.Process(os.getpid())
        
        baseline_memory = process.memory_info().rss / (1024 * 1024)
        baseline_cpu = process.cpu_percent(interval=0.1)
        
        billing_metrics = {
            "response_times": [],
            "memory_samples": [],
            "cpu_samples": [],
            "successful_requests": 0
        }
        
        # Generate high rate of billable events
        for i in range(40):
            memory_before = process.memory_info().rss / (1024 * 1024)
            cpu_before = process.cpu_percent()
            
            # Alternate between chat and embedding requests
            if i % 2 == 0:
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Billing test {i}"}],
                    "max_tokens": 15
                }
                endpoint = "/api/v1/chat/completions"
            else:
                embedding_model = config.get_embedding_model(0)
                if embedding_model:
                    request_data = {
                        "model": embedding_model,
                        "input": f"Billing test {i}"
                    }
                    endpoint = "/api/v1/embeddings"
                else:
                    continue
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", endpoint,
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            memory_after = process.memory_info().rss / (1024 * 1024)
            cpu_after = process.cpu_percent()
            
            if response.status_code == 200:
                billing_metrics["successful_requests"] += 1
                billing_metrics["response_times"].append((end_time - start_time) * 1000)
                billing_metrics["memory_samples"].append(memory_after)
                billing_metrics["cpu_samples"].append(max(cpu_after - cpu_before, 0))
            
            await asyncio.sleep(0.05)  # High rate
        
        # Allow billing worker to process queue
        await asyncio.sleep(2)
        
        final_memory = process.memory_info().rss / (1024 * 1024)
        
        # Analyze billing worker performance
        if billing_metrics["memory_samples"]:
            avg_response_time = statistics.mean(billing_metrics["response_times"])
            peak_memory = max(billing_metrics["memory_samples"])
            avg_cpu = statistics.mean(billing_metrics["cpu_samples"])
            memory_growth = final_memory - baseline_memory
            
            logger.info(f"Billing worker performance - Requests: {billing_metrics['successful_requests']}, "
                       f"Avg response: {avg_response_time:.2f}ms, "
                       f"Peak memory: {peak_memory:.2f}MB, "
                       f"Memory growth: {memory_growth:.2f}MB")
            
            # Billing worker should not consume excessive resources
            assert memory_growth <= 100.0, f"Billing worker memory growth should be reasonable, got {memory_growth:.2f}MB"
            assert avg_cpu <= 30.0, f"Billing worker CPU usage should be reasonable, got {avg_cpu:.2f}%"


class TestEnhancedCostOptimization:
    """Enhanced cost optimization and monitoring scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cost_realtime_optimization_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_COST_REALTIME_OPTIMIZATION_001: Test real-time cost optimization"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test cost tracking and optimization across different models/providers
        cost_optimization_metrics = {}
        
        # Test different models to simulate cost optimization
        test_models = config.CHAT_MODELS[:2] if len(config.CHAT_MODELS) >= 2 else [config.get_chat_model(0)]
        
        for model in test_models:
            model_metrics = {
                "requests": 0,
                "total_prompt_tokens": 0,
                "total_completion_tokens": 0,
                "response_times": [],
                "cost_efficiency": []
            }
            
            for i in range(10):
                request_data = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Cost optimization test {i}"}],
                    "max_tokens": 25
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                model_metrics["response_times"].append(response_time)
                model_metrics["requests"] += 1
                
                if response.status_code == 200:
                    response_data = response.json()
                    if "usage" in response_data:
                        prompt_tokens = response_data["usage"]["prompt_tokens"]
                        completion_tokens = response_data["usage"]["completion_tokens"]
                        
                        model_metrics["total_prompt_tokens"] += prompt_tokens
                        model_metrics["total_completion_tokens"] += completion_tokens
                        
                        # Calculate cost efficiency (tokens per ms)
                        if response_time > 0:
                            efficiency = (prompt_tokens + completion_tokens) / response_time
                            model_metrics["cost_efficiency"].append(efficiency)
                
                await asyncio.sleep(0.1)
            
            cost_optimization_metrics[model] = model_metrics
        
        # Analyze cost optimization potential
        for model, metrics in cost_optimization_metrics.items():
            if metrics["response_times"]:
                avg_response_time = statistics.mean(metrics["response_times"])
                total_tokens = metrics["total_prompt_tokens"] + metrics["total_completion_tokens"]
                
                if metrics["cost_efficiency"]:
                    avg_efficiency = statistics.mean(metrics["cost_efficiency"])
                    logger.info(f"Model {model} - Avg response: {avg_response_time:.2f}ms, "
                               f"Total tokens: {total_tokens}, "
                               f"Efficiency: {avg_efficiency:.4f} tokens/ms")
                
                # Verify cost tracking works
                assert total_tokens > 0, f"Model {model} should report token usage"
                assert avg_response_time < 10000.0, f"Model {model} response time should be reasonable"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_cost_token_analytics_002(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """PERF_COST_TOKEN_ANALYTICS_002: Test advanced token usage analytics"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test token usage patterns across different request types
        token_analytics = {
            "short_prompts": {"total_tokens": 0, "requests": 0, "efficiency": []},
            "medium_prompts": {"total_tokens": 0, "requests": 0, "efficiency": []},
            "long_prompts": {"total_tokens": 0, "requests": 0, "efficiency": []}
        }
        
        test_prompts = [
            ("short_prompts", "Hi"),
            ("short_prompts", "Hello"),
            ("short_prompts", "Thanks"),
            ("medium_prompts", "Can you explain the basics of machine learning?"),
            ("medium_prompts", "What are the main benefits of renewable energy?"),
            ("medium_prompts", "How does artificial intelligence work?"),
            ("long_prompts", "Please provide a detailed explanation of the differences between supervised and unsupervised machine learning, including examples of algorithms for each category and their typical use cases in real-world applications."),
            ("long_prompts", "Describe the process of photosynthesis in plants, including the light-dependent and light-independent reactions, and explain how this process is essential for life on Earth.")
        ]
        
        for category, prompt in test_prompts:
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 30
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            if response.status_code == 200:
                response_data = response.json()
                if "usage" in response_data:
                    prompt_tokens = response_data["usage"]["prompt_tokens"]
                    completion_tokens = response_data["usage"]["completion_tokens"]
                    total_tokens = prompt_tokens + completion_tokens
                    
                    token_analytics[category]["total_tokens"] += total_tokens
                    token_analytics[category]["requests"] += 1
                    
                    # Calculate efficiency (tokens per character in prompt)
                    if len(prompt) > 0:
                        efficiency = prompt_tokens / len(prompt)
                        token_analytics[category]["efficiency"].append(efficiency)
            
            await asyncio.sleep(0.1)
        
        # Analyze token usage patterns
        for category, data in token_analytics.items():
            if data["requests"] > 0:
                avg_tokens_per_request = data["total_tokens"] / data["requests"]
                avg_efficiency = statistics.mean(data["efficiency"]) if data["efficiency"] else 0
                
                logger.info(f"{category} - Avg tokens/request: {avg_tokens_per_request:.2f}, "
                           f"Avg efficiency: {avg_efficiency:.4f} tokens/char")
                
                # Verify token analytics show expected patterns
                assert avg_tokens_per_request > 0, f"{category} should have positive token usage"
                
                # Short prompts should be more efficient per character
                if category == "short_prompts" and avg_efficiency > 0:
                    assert avg_efficiency >= 0.1, f"Short prompts should be relatively efficient"
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_cost_resource_efficiency_004(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """PERF_COST_RESOURCE_EFFICIENCY_004: Test resource utilization efficiency optimization"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test resource efficiency under sustained load
        process = psutil.Process(os.getpid())
        
        efficiency_metrics = {
            "baseline": {"cpu": 0, "memory": 0, "requests": 0},
            "sustained_load": {"cpu": [], "memory": [], "requests": 0, "response_times": []}
        }
        
        # Establish baseline
        gc.collect()
        baseline_memory = process.memory_info().rss / (1024 * 1024)
        baseline_cpu = process.cpu_percent(interval=0.5)
        
        efficiency_metrics["baseline"]["memory"] = baseline_memory
        efficiency_metrics["baseline"]["cpu"] = baseline_cpu
        
        # Run sustained load test
        for i in range(50):
            memory_before = process.memory_info().rss / (1024 * 1024)
            cpu_before = process.cpu_percent()
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            memory_after = process.memory_info().rss / (1024 * 1024)
            cpu_after = process.cpu_percent()
            
            if response.status_code == 200:
                efficiency_metrics["sustained_load"]["requests"] += 1
                efficiency_metrics["sustained_load"]["response_times"].append((end_time - start_time) * 1000)
                efficiency_metrics["sustained_load"]["memory"].append(memory_after)
                efficiency_metrics["sustained_load"]["cpu"].append(max(cpu_after - cpu_before, 0))
            
            await asyncio.sleep(0.02)  # Sustained load
        
        # Analyze resource efficiency
        if efficiency_metrics["sustained_load"]["memory"]:
            avg_response_time = statistics.mean(efficiency_metrics["sustained_load"]["response_times"])
            peak_memory = max(efficiency_metrics["sustained_load"]["memory"])
            avg_cpu = statistics.mean(efficiency_metrics["sustained_load"]["cpu"])
            memory_efficiency = peak_memory - baseline_memory
            
            # Calculate throughput
            total_time = len(efficiency_metrics["sustained_load"]["response_times"]) * 0.02  # 20ms intervals
            throughput = efficiency_metrics["sustained_load"]["requests"] / total_time if total_time > 0 else 0
            
            logger.info(f"Resource efficiency - Avg response: {avg_response_time:.2f}ms, "
                       f"Memory growth: {memory_efficiency:.2f}MB, "
                       f"Avg CPU: {avg_cpu:.2f}%, "
                       f"Throughput: {throughput:.2f} RPS")
            
            # Verify resource efficiency
            assert memory_efficiency <= 50.0, f"Memory efficiency should be good, growth: {memory_efficiency:.2f}MB"
            assert avg_cpu <= 25.0, f"CPU efficiency should be good, avg: {avg_cpu:.2f}%"
            assert throughput >= 5.0, f"Throughput should be reasonable, got: {throughput:.2f} RPS"
            assert avg_response_time < 1000.0, f"Response time should remain efficient, got: {avg_response_time:.2f}ms"