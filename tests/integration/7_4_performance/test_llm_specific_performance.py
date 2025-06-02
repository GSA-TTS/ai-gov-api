# Section 7.4 - LLM-Specific Performance Metrics
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_LLM-Specific Performance Metrics.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json
import re

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class LLMPerformanceResult:
    """LLM performance test result data structure"""
    test_name: str
    ttft_ms: Optional[float]
    total_response_time: float
    tokens_per_second: Optional[float]
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    success: bool
    model_name: str


class TestTimeToFirstToken:
    """Test Time to First Token (TTFT) for streaming responses"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_ttft_chat_stream_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """PERF_LLM_TTFT_CHAT_STREAM_001: Measure TTFT for streaming chat completions under normal load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test TTFT for streaming responses
        ttft_metrics = {
            "ttft_times": [],
            "total_response_times": [],
            "successful_streams": 0,
            "failed_streams": 0
        }
        
        num_requests = 20
        model = config.get_chat_model(0)
        
        for i in range(num_requests):
            request_data = {
                "model": model,
                "messages": [{"role": "user", "content": "Tell me a short story"}],
                "max_tokens": 100,
                "stream": True
            }
            
            start_time = time.perf_counter()
            first_token_time = None
            total_content = ""
            
            try:
                async with http_client.stream(
                    "POST", 
                    "/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request_data,
                    timeout=30.0
                ) as response:
                    
                    if response.status_code == 200:
                        async for line in response.aiter_lines():
                            if line.startswith("data: "):
                                data_str = line[6:].strip()
                                if data_str == "[DONE]":
                                    break
                                
                                try:
                                    chunk_data = json.loads(data_str)
                                    if "choices" in chunk_data and len(chunk_data["choices"]) > 0:
                                        delta = chunk_data["choices"][0].get("delta", {})
                                        content = delta.get("content", "")
                                        
                                        if content and first_token_time is None:
                                            first_token_time = time.perf_counter()
                                            ttft_ms = (first_token_time - start_time) * 1000
                                            ttft_metrics["ttft_times"].append(ttft_ms)
                                        
                                        total_content += content
                                except json.JSONDecodeError:
                                    continue
                        
                        end_time = time.perf_counter()
                        total_response_time = (end_time - start_time) * 1000
                        ttft_metrics["total_response_times"].append(total_response_time)
                        ttft_metrics["successful_streams"] += 1
                    else:
                        ttft_metrics["failed_streams"] += 1
            
            except Exception as e:
                logger.warning(f"Streaming request {i} failed: {e}")
                ttft_metrics["failed_streams"] += 1
            
            await asyncio.sleep(0.1)
        
        # Analyze TTFT performance
        if ttft_metrics["ttft_times"]:
            avg_ttft = statistics.mean(ttft_metrics["ttft_times"])
            p95_ttft = statistics.quantiles(ttft_metrics["ttft_times"], n=20)[18] if len(ttft_metrics["ttft_times"]) >= 20 else max(ttft_metrics["ttft_times"])
            success_rate = ttft_metrics["successful_streams"] / num_requests
            
            logger.info(f"TTFT streaming performance - "
                       f"Avg TTFT: {avg_ttft:.2f}ms, "
                       f"P95 TTFT: {p95_ttft:.2f}ms, "
                       f"Success rate: {success_rate:.2%}")
            
            # Verify TTFT meets performance targets
            assert avg_ttft < 2000.0, f"Average TTFT should be reasonable, got {avg_ttft:.2f}ms"
            assert p95_ttft < 5000.0, f"P95 TTFT should meet SLA, got {p95_ttft:.2f}ms"
            assert success_rate >= 0.90, f"Stream success rate should be high, got {success_rate:.2%}"
        else:
            pytest.fail("No successful TTFT measurements recorded")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_ttft_provider_compare_002(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """PERF_LLM_TTFT_CHAT_STREAM_PROVIDER_COMPARE_002: Compare TTFT across different providers"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test TTFT across different models/providers
        available_models = config.CHAT_MODELS[:2] if len(config.CHAT_MODELS) >= 2 else [config.get_chat_model(0)]
        provider_ttft_results = {}
        
        for model in available_models:
            model_metrics = {
                "ttft_times": [],
                "successful_requests": 0,
                "failed_requests": 0
            }
            
            for i in range(10):  # Smaller sample per model
                request_data = {
                    "model": model,
                    "messages": [{"role": "user", "content": "Hello, how are you?"}],
                    "max_tokens": 50,
                    "stream": True
                }
                
                start_time = time.perf_counter()
                first_token_time = None
                
                try:
                    async with http_client.stream(
                        "POST",
                        "/api/v1/chat/completions",
                        headers=auth_headers,
                        json=request_data,
                        timeout=30.0
                    ) as response:
                        
                        if response.status_code == 200:
                            async for line in response.aiter_lines():
                                if line.startswith("data: "):
                                    data_str = line[6:].strip()
                                    if data_str == "[DONE]":
                                        break
                                    
                                    try:
                                        chunk_data = json.loads(data_str)
                                        if "choices" in chunk_data and len(chunk_data["choices"]) > 0:
                                            delta = chunk_data["choices"][0].get("delta", {})
                                            content = delta.get("content", "")
                                            
                                            if content and first_token_time is None:
                                                first_token_time = time.perf_counter()
                                                ttft_ms = (first_token_time - start_time) * 1000
                                                model_metrics["ttft_times"].append(ttft_ms)
                                                break
                                    except json.JSONDecodeError:
                                        continue
                            
                            model_metrics["successful_requests"] += 1
                        else:
                            model_metrics["failed_requests"] += 1
                
                except Exception as e:
                    model_metrics["failed_requests"] += 1
                
                await asyncio.sleep(0.1)
            
            provider_ttft_results[model] = model_metrics
        
        # Analyze provider TTFT comparison
        for model, metrics in provider_ttft_results.items():
            if metrics["ttft_times"]:
                avg_ttft = statistics.mean(metrics["ttft_times"])
                success_rate = metrics["successful_requests"] / (metrics["successful_requests"] + metrics["failed_requests"])
                
                logger.info(f"Model {model} TTFT - "
                           f"Avg: {avg_ttft:.2f}ms, "
                           f"Success rate: {success_rate:.2%}")
                
                # Verify each model meets TTFT targets
                assert avg_ttft < 3000.0, f"Model {model} TTFT should be reasonable, got {avg_ttft:.2f}ms"
                assert success_rate >= 0.80, f"Model {model} success rate should be good, got {success_rate:.2%}"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_ttft_prompt_size_impact_003(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_LLM_TTFT_CHAT_STREAM_PROMPT_SIZE_IMPACT_003: Evaluate prompt size impact on TTFT"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test TTFT with different prompt sizes
        prompt_size_tests = [
            {
                "name": "short_prompt",
                "prompt": "Hi",
                "expected_ttft": 2000.0  # ms
            },
            {
                "name": "medium_prompt", 
                "prompt": "Please explain the concept of artificial intelligence and its applications in modern technology. How does machine learning differ from traditional programming approaches?",
                "expected_ttft": 3000.0  # ms
            },
            {
                "name": "long_prompt",
                "prompt": "I need a comprehensive analysis of the impact of artificial intelligence on various industries including healthcare, finance, education, and transportation. Please discuss the current applications, benefits, challenges, and future prospects for each sector. Additionally, address the ethical considerations and potential societal implications of widespread AI adoption across these industries.",
                "expected_ttft": 5000.0  # ms
            }
        ]
        
        prompt_size_results = {}
        
        for test_case in prompt_size_tests:
            case_metrics = {
                "ttft_times": [],
                "successful_requests": 0
            }
            
            for i in range(8):  # Fewer requests for longer prompts
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": test_case["prompt"]}],
                    "max_tokens": 100,
                    "stream": True
                }
                
                start_time = time.perf_counter()
                first_token_time = None
                
                try:
                    async with http_client.stream(
                        "POST",
                        "/api/v1/chat/completions", 
                        headers=auth_headers,
                        json=request_data,
                        timeout=45.0
                    ) as response:
                        
                        if response.status_code == 200:
                            async for line in response.aiter_lines():
                                if line.startswith("data: "):
                                    data_str = line[6:].strip()
                                    if data_str == "[DONE]":
                                        break
                                    
                                    try:
                                        chunk_data = json.loads(data_str)
                                        if "choices" in chunk_data and len(chunk_data["choices"]) > 0:
                                            delta = chunk_data["choices"][0].get("delta", {})
                                            content = delta.get("content", "")
                                            
                                            if content and first_token_time is None:
                                                first_token_time = time.perf_counter()
                                                ttft_ms = (first_token_time - start_time) * 1000
                                                case_metrics["ttft_times"].append(ttft_ms)
                                                break
                                    except json.JSONDecodeError:
                                        continue
                            
                            case_metrics["successful_requests"] += 1
                
                except Exception as e:
                    logger.warning(f"Request failed for {test_case['name']}: {e}")
                
                await asyncio.sleep(0.2)
            
            prompt_size_results[test_case["name"]] = case_metrics
        
        # Analyze prompt size impact on TTFT
        for test_name, test_case in zip(prompt_size_results.keys(), prompt_size_tests):
            metrics = prompt_size_results[test_name]
            
            if metrics["ttft_times"]:
                avg_ttft = statistics.mean(metrics["ttft_times"])
                
                logger.info(f"{test_name} TTFT - Avg: {avg_ttft:.2f}ms")
                
                # Verify TTFT scales reasonably with prompt size
                assert avg_ttft < test_case["expected_ttft"], f"{test_name} TTFT should be within expected range, got {avg_ttft:.2f}ms"


class TestTokenGenerationThroughput:
    """Test token generation throughput for streaming and non-streaming responses"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_throughput_chat_stream_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_LLM_THROUGHPUT_CHAT_STREAM_001: Measure token generation throughput for streaming"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test streaming token throughput
        throughput_metrics = {
            "token_throughputs": [],
            "successful_streams": 0,
            "total_tokens_generated": 0,
            "total_generation_time": 0
        }
        
        num_requests = 15
        
        for i in range(num_requests):
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Tell me a detailed story about a brave knight, about 200 words"}],
                "max_tokens": 300,
                "stream": True
            }
            
            start_time = time.perf_counter()
            first_content_time = None
            last_content_time = None
            total_tokens = 0
            total_content = ""
            
            try:
                async with http_client.stream(
                    "POST",
                    "/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request_data,
                    timeout=60.0
                ) as response:
                    
                    if response.status_code == 200:
                        async for line in response.aiter_lines():
                            if line.startswith("data: "):
                                data_str = line[6:].strip()
                                if data_str == "[DONE]":
                                    break
                                
                                try:
                                    chunk_data = json.loads(data_str)
                                    if "choices" in chunk_data and len(chunk_data["choices"]) > 0:
                                        delta = chunk_data["choices"][0].get("delta", {})
                                        content = delta.get("content", "")
                                        
                                        if content:
                                            current_time = time.perf_counter()
                                            if first_content_time is None:
                                                first_content_time = current_time
                                            last_content_time = current_time
                                            total_content += content
                                            
                                            # Rough token estimation (4 chars per token average)
                                            total_tokens = len(total_content) // 4
                                except json.JSONDecodeError:
                                    continue
                        
                        if first_content_time and last_content_time and total_tokens > 0:
                            generation_time = last_content_time - first_content_time
                            if generation_time > 0:
                                tokens_per_second = total_tokens / generation_time
                                throughput_metrics["token_throughputs"].append(tokens_per_second)
                                throughput_metrics["total_tokens_generated"] += total_tokens
                                throughput_metrics["total_generation_time"] += generation_time
                        
                        throughput_metrics["successful_streams"] += 1
            
            except Exception as e:
                logger.warning(f"Throughput test {i} failed: {e}")
            
            await asyncio.sleep(0.1)
        
        # Analyze token generation throughput
        if throughput_metrics["token_throughputs"]:
            avg_throughput = statistics.mean(throughput_metrics["token_throughputs"])
            median_throughput = statistics.median(throughput_metrics["token_throughputs"])
            success_rate = throughput_metrics["successful_streams"] / num_requests
            
            logger.info(f"Streaming token throughput - "
                       f"Avg: {avg_throughput:.2f} tokens/sec, "
                       f"Median: {median_throughput:.2f} tokens/sec, "
                       f"Success rate: {success_rate:.2%}")
            
            # Verify token throughput meets targets
            assert avg_throughput >= 5.0, f"Average throughput should be reasonable, got {avg_throughput:.2f} tokens/sec"
            assert success_rate >= 0.80, f"Success rate should be high, got {success_rate:.2%}"
        else:
            pytest.fail("No successful throughput measurements recorded")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_throughput_chat_nonstream_002(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """PERF_LLM_THROUGHPUT_CHAT_NONSTREAM_002: Measure effective throughput for non-streaming"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test non-streaming effective throughput
        nonstream_metrics = {
            "effective_throughputs": [],
            "response_times": [],
            "successful_requests": 0,
            "token_data": []
        }
        
        for i in range(12):
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Write a detailed explanation of machine learning, about 150 words"}],
                "max_tokens": 200,
                "stream": False
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            response_time = (end_time - start_time) * 1000
            
            if response.status_code == 200:
                response_data = response.json()
                if "usage" in response_data:
                    completion_tokens = response_data["usage"]["completion_tokens"]
                    
                    # Calculate effective throughput
                    response_time_seconds = response_time / 1000
                    effective_throughput = completion_tokens / response_time_seconds if response_time_seconds > 0 else 0
                    
                    nonstream_metrics["effective_throughputs"].append(effective_throughput)
                    nonstream_metrics["response_times"].append(response_time)
                    nonstream_metrics["token_data"].append({
                        "completion_tokens": completion_tokens,
                        "response_time": response_time
                    })
                
                nonstream_metrics["successful_requests"] += 1
            
            await asyncio.sleep(0.1)
        
        # Analyze non-streaming effective throughput
        if nonstream_metrics["effective_throughputs"]:
            avg_effective_throughput = statistics.mean(nonstream_metrics["effective_throughputs"])
            avg_response_time = statistics.mean(nonstream_metrics["response_times"])
            success_rate = nonstream_metrics["successful_requests"] / 12
            
            logger.info(f"Non-streaming effective throughput - "
                       f"Avg: {avg_effective_throughput:.2f} tokens/sec, "
                       f"Avg response time: {avg_response_time:.2f}ms, "
                       f"Success rate: {success_rate:.2%}")
            
            # Verify non-streaming throughput
            assert avg_effective_throughput >= 2.0, f"Effective throughput should be reasonable, got {avg_effective_throughput:.2f} tokens/sec"
            assert avg_response_time < 30000.0, f"Response time should be reasonable, got {avg_response_time:.2f}ms"
            assert success_rate >= 0.90, f"Success rate should be high, got {success_rate:.2%}"


class TestContextWindowPerformance:
    """Test context window performance with varying prompt sizes"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_context_window_chat_latency_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """PERF_LLM_CONTEXT_WINDOW_CHAT_LATENCY_001: Test latency vs prompt size (context window utilization)"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test context window performance with different prompt sizes
        context_window_tests = [
            {
                "name": "small_context",
                "prompt_base": "Explain artificial intelligence",
                "repeat_factor": 1,
                "expected_max_time": 10000.0  # 10s
            },
            {
                "name": "medium_context", 
                "prompt_base": "Please provide a comprehensive analysis of machine learning algorithms, their applications, and implementation details. Include examples and use cases for each type of algorithm.",
                "repeat_factor": 5,
                "expected_max_time": 20000.0  # 20s
            },
            {
                "name": "large_context",
                "prompt_base": "Analyze the complete history of artificial intelligence, including all major breakthroughs, key researchers, technological developments, current applications across industries, ethical considerations, future prospects, and societal implications. Provide detailed examples and case studies for each area discussed.",
                "repeat_factor": 10,
                "expected_max_time": 30000.0  # 30s
            }
        ]
        
        context_results = {}
        
        for test_case in context_window_tests:
            case_metrics = {
                "response_times": [],
                "successful_requests": 0,
                "prompt_tokens": [],
                "completion_tokens": []
            }
            
            # Create prompt of appropriate size
            full_prompt = " ".join([test_case["prompt_base"]] * test_case["repeat_factor"])
            
            for i in range(5):  # Fewer requests for larger contexts
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": full_prompt}],
                    "max_tokens": 50,  # Keep completion small to isolate prompt processing
                    "stream": False
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                
                if response.status_code == 200:
                    response_data = response.json()
                    if "usage" in response_data:
                        case_metrics["prompt_tokens"].append(response_data["usage"]["prompt_tokens"])
                        case_metrics["completion_tokens"].append(response_data["usage"]["completion_tokens"])
                    
                    case_metrics["response_times"].append(response_time)
                    case_metrics["successful_requests"] += 1
                elif response.status_code in [400, 422]:
                    # May exceed context window - expected for large contexts
                    logger.info(f"{test_case['name']} request may have exceeded context window")
                
                await asyncio.sleep(0.2)
            
            context_results[test_case["name"]] = case_metrics
        
        # Analyze context window performance
        for test_name, test_case in zip(context_results.keys(), context_window_tests):
            metrics = context_results[test_name]
            
            if metrics["response_times"]:
                avg_response_time = statistics.mean(metrics["response_times"])
                avg_prompt_tokens = statistics.mean(metrics["prompt_tokens"]) if metrics["prompt_tokens"] else 0
                
                logger.info(f"{test_name} - "
                           f"Avg response: {avg_response_time:.2f}ms, "
                           f"Avg prompt tokens: {avg_prompt_tokens:.0f}")
                
                # Verify context window performance
                assert avg_response_time < test_case["expected_max_time"], f"{test_name} should complete within time limit, got {avg_response_time:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_context_window_embed_latency_002(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """PERF_LLM_CONTEXT_WINDOW_EMBED_LATENCY_002: Test embedding performance vs input text size"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Skip if no embedding model available
        embedding_model = config.get_embedding_model(0)
        if not embedding_model:
            pytest.skip("No embedding model configured")
        
        # Test embedding context window performance
        embedding_context_tests = [
            {
                "name": "short_text",
                "text": "Machine learning is a subset of artificial intelligence.",
                "expected_max_time": 2000.0  # 2s
            },
            {
                "name": "medium_text",
                "text": " ".join([
                    "Machine learning is a rapidly evolving field that encompasses various algorithms and techniques.",
                    "It enables computers to learn and make decisions from data without being explicitly programmed.",
                    "Applications include natural language processing, computer vision, recommendation systems, and predictive analytics.",
                    "Deep learning, a subset of machine learning, uses neural networks to model complex patterns in data."
                ] * 10),
                "expected_max_time": 5000.0  # 5s
            },
            {
                "name": "long_text", 
                "text": " ".join([
                    "Artificial intelligence and machine learning have revolutionized numerous industries and applications.",
                    "From healthcare diagnostics to autonomous vehicles, from financial fraud detection to personalized recommendations,",
                    "these technologies are transforming how we interact with data and make decisions.",
                    "The field continues to advance with new architectures, algorithms, and computational approaches."
                ] * 25),
                "expected_max_time": 10000.0  # 10s
            }
        ]
        
        embedding_results = {}
        
        for test_case in embedding_context_tests:
            case_metrics = {
                "response_times": [],
                "successful_requests": 0
            }
            
            for i in range(8):
                request_data = {
                    "model": embedding_model,
                    "input": test_case["text"]
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/embeddings",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                
                if response.status_code == 200:
                    case_metrics["response_times"].append(response_time)
                    case_metrics["successful_requests"] += 1
                elif response.status_code in [400, 422]:
                    logger.info(f"Embedding {test_case['name']} may have exceeded input limits")
                
                await asyncio.sleep(0.1)
            
            embedding_results[test_case["name"]] = case_metrics
        
        # Analyze embedding context performance
        for test_name, test_case in zip(embedding_results.keys(), embedding_context_tests):
            metrics = embedding_results[test_name]
            
            if metrics["response_times"]:
                avg_response_time = statistics.mean(metrics["response_times"])
                success_rate = metrics["successful_requests"] / 8
                
                logger.info(f"Embedding {test_name} - "
                           f"Avg response: {avg_response_time:.2f}ms, "
                           f"Success rate: {success_rate:.2%}")
                
                # Verify embedding context performance
                assert avg_response_time < test_case["expected_max_time"], f"Embedding {test_name} should complete within time limit, got {avg_response_time:.2f}ms"
                assert success_rate >= 0.75, f"Embedding {test_name} success rate should be good, got {success_rate:.2%}"


class TestStreamingResponseLatency:
    """Test streaming response latency and inter-chunk timing"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_stream_latency_interchunk_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """PERF_LLM_STREAM_LATENCY_INTERCHUNK_001: Measure inter-chunk latency in streaming responses"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test inter-chunk latency for streaming responses
        interchunk_metrics = {
            "all_interchunk_times": [],
            "stream_consistency_scores": [],
            "successful_streams": 0
        }
        
        for i in range(10):
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Write a detailed story about space exploration, at least 100 words"}],
                "max_tokens": 150,
                "stream": True
            }
            
            chunk_times = []
            content_chunks = 0
            
            try:
                async with http_client.stream(
                    "POST",
                    "/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request_data,
                    timeout=45.0
                ) as response:
                    
                    if response.status_code == 200:
                        last_content_time = None
                        
                        async for line in response.aiter_lines():
                            if line.startswith("data: "):
                                data_str = line[6:].strip()
                                if data_str == "[DONE]":
                                    break
                                
                                try:
                                    chunk_data = json.loads(data_str)
                                    if "choices" in chunk_data and len(chunk_data["choices"]) > 0:
                                        delta = chunk_data["choices"][0].get("delta", {})
                                        content = delta.get("content", "")
                                        
                                        if content:
                                            current_time = time.perf_counter()
                                            content_chunks += 1
                                            
                                            if last_content_time is not None:
                                                interchunk_time = (current_time - last_content_time) * 1000
                                                chunk_times.append(interchunk_time)
                                            
                                            last_content_time = current_time
                                except json.JSONDecodeError:
                                    continue
                        
                        if chunk_times and content_chunks >= 5:  # Need meaningful number of chunks
                            interchunk_metrics["all_interchunk_times"].extend(chunk_times)
                            
                            # Calculate consistency score (lower std dev = more consistent)
                            if len(chunk_times) > 1:
                                chunk_std = statistics.stdev(chunk_times)
                                chunk_mean = statistics.mean(chunk_times)
                                consistency_score = chunk_std / chunk_mean if chunk_mean > 0 else 1.0
                                interchunk_metrics["stream_consistency_scores"].append(consistency_score)
                            
                            interchunk_metrics["successful_streams"] += 1
            
            except Exception as e:
                logger.warning(f"Inter-chunk test {i} failed: {e}")
            
            await asyncio.sleep(0.1)
        
        # Analyze inter-chunk latency
        if interchunk_metrics["all_interchunk_times"]:
            avg_interchunk = statistics.mean(interchunk_metrics["all_interchunk_times"])
            p95_interchunk = statistics.quantiles(interchunk_metrics["all_interchunk_times"], n=20)[18] if len(interchunk_metrics["all_interchunk_times"]) >= 20 else max(interchunk_metrics["all_interchunk_times"])
            avg_consistency = statistics.mean(interchunk_metrics["stream_consistency_scores"]) if interchunk_metrics["stream_consistency_scores"] else 0
            
            logger.info(f"Inter-chunk latency - "
                       f"Avg: {avg_interchunk:.2f}ms, "
                       f"P95: {p95_interchunk:.2f}ms, "
                       f"Consistency score: {avg_consistency:.3f}")
            
            # Verify inter-chunk latency performance
            assert avg_interchunk < 500.0, f"Average inter-chunk latency should be low, got {avg_interchunk:.2f}ms"
            assert p95_interchunk < 1000.0, f"P95 inter-chunk latency should be reasonable, got {p95_interchunk:.2f}ms"
            assert avg_consistency <= 2.0, f"Streaming should be consistent, got consistency score {avg_consistency:.3f}"
        else:
            pytest.fail("No successful inter-chunk measurements recorded")


class TestEmbeddingPerformance:
    """Test embedding generation performance"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_embedding_single_latency_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """PERF_LLM_EMBEDDING_SINGLE_LATENCY_001: Test single embedding generation latency"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Skip if no embedding model available
        embedding_model = config.get_embedding_model(0)
        if not embedding_model:
            pytest.skip("No embedding model configured")
        
        # Test single embedding latency
        embedding_metrics = {
            "response_times": [],
            "successful_requests": 0,
            "failed_requests": 0
        }
        
        test_texts = [
            "Artificial intelligence is transforming technology",
            "Machine learning enables computers to learn from data",
            "Natural language processing helps computers understand text",
            "Computer vision allows machines to interpret images",
            "Deep learning uses neural networks for complex tasks"
        ]
        
        for text in test_texts * 4:  # 20 total requests
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
            
            if response.status_code == 200:
                embedding_metrics["response_times"].append(response_time)
                embedding_metrics["successful_requests"] += 1
            else:
                embedding_metrics["failed_requests"] += 1
            
            await asyncio.sleep(0.05)
        
        # Analyze single embedding performance
        if embedding_metrics["response_times"]:
            avg_response_time = statistics.mean(embedding_metrics["response_times"])
            p95_response_time = statistics.quantiles(embedding_metrics["response_times"], n=20)[18] if len(embedding_metrics["response_times"]) >= 20 else max(embedding_metrics["response_times"])
            success_rate = embedding_metrics["successful_requests"] / (embedding_metrics["successful_requests"] + embedding_metrics["failed_requests"])
            
            logger.info(f"Single embedding performance - "
                       f"Avg: {avg_response_time:.2f}ms, "
                       f"P95: {p95_response_time:.2f}ms, "
                       f"Success rate: {success_rate:.2%}")
            
            # Verify single embedding performance
            assert avg_response_time < 2000.0, f"Average embedding time should be fast, got {avg_response_time:.2f}ms"
            assert p95_response_time < 5000.0, f"P95 embedding time should be reasonable, got {p95_response_time:.2f}ms"
            assert success_rate >= 0.95, f"Embedding success rate should be high, got {success_rate:.2%}"
        else:
            pytest.fail("No successful embedding measurements recorded")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_llm_embedding_batch_throughput_002(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """PERF_LLM_EMBEDDING_BATCH_THROUGHPUT_002: Test batch embedding throughput"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Skip if no embedding model available
        embedding_model = config.get_embedding_model(0)
        if not embedding_model:
            pytest.skip("No embedding model configured")
        
        # Test batch embedding throughput
        batch_sizes = [5, 10, 20]
        batch_results = {}
        
        base_texts = [
            "Technology is advancing rapidly",
            "Artificial intelligence helps solve complex problems", 
            "Data science extracts insights from information",
            "Software engineering builds reliable systems",
            "Cloud computing provides scalable infrastructure"
        ]
        
        for batch_size in batch_sizes:
            batch_metrics = {
                "response_times": [],
                "throughputs": [],
                "successful_batches": 0
            }
            
            for i in range(5):  # 5 batches per size
                # Create batch of texts
                batch_texts = [f"{text} - batch {i}" for text in base_texts[:batch_size]]
                
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
                
                response_time = (end_time - start_time) * 1000
                
                if response.status_code == 200:
                    batch_metrics["response_times"].append(response_time)
                    
                    # Calculate throughput (embeddings per second)
                    response_time_seconds = response_time / 1000
                    throughput = batch_size / response_time_seconds if response_time_seconds > 0 else 0
                    batch_metrics["throughputs"].append(throughput)
                    batch_metrics["successful_batches"] += 1
                
                await asyncio.sleep(0.2)
            
            batch_results[batch_size] = batch_metrics
        
        # Analyze batch embedding throughput
        for batch_size, metrics in batch_results.items():
            if metrics["throughputs"]:
                avg_throughput = statistics.mean(metrics["throughputs"])
                avg_response_time = statistics.mean(metrics["response_times"])
                success_rate = metrics["successful_batches"] / 5
                
                logger.info(f"Batch size {batch_size} - "
                           f"Avg throughput: {avg_throughput:.2f} embeddings/sec, "
                           f"Avg response: {avg_response_time:.2f}ms, "
                           f"Success rate: {success_rate:.2%}")
                
                # Verify batch embedding performance
                assert avg_throughput >= 1.0, f"Batch {batch_size} throughput should be reasonable, got {avg_throughput:.2f} embeddings/sec"
                assert success_rate >= 0.80, f"Batch {batch_size} success rate should be good, got {success_rate:.2%}"
        
        # Verify that larger batches provide better throughput efficiency
        if len(batch_results) >= 2:
            smallest_batch = min(batch_results.keys())
            largest_batch = max(batch_results.keys())
            
            if (batch_results[smallest_batch]["throughputs"] and 
                batch_results[largest_batch]["throughputs"]):
                
                small_throughput = statistics.mean(batch_results[smallest_batch]["throughputs"])
                large_throughput = statistics.mean(batch_results[largest_batch]["throughputs"])
                
                # Larger batches should generally be more efficient
                efficiency_ratio = large_throughput / small_throughput if small_throughput > 0 else 1.0
                logger.info(f"Batch efficiency ratio (large/small): {efficiency_ratio:.2f}x")


class TestEnhancedLLMPerformanceScenarios:
    """Enhanced LLM performance testing scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_llm_comprehensive_profiling_011(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_LLM_COMPREHENSIVE_PROFILING_011: Comprehensive LLM performance profiling"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Comprehensive performance profiling across different request types
        profiling_results = {
            "chat_streaming": {"response_times": [], "ttft_times": [], "throughputs": []},
            "chat_non_streaming": {"response_times": [], "effective_throughputs": []},
            "embeddings": {"response_times": [], "throughputs": []}
        }
        
        # Test chat streaming performance
        for i in range(8):
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Comprehensive test {i}: Explain quantum computing"}],
                "max_tokens": 100,
                "stream": True
            }
            
            start_time = time.perf_counter()
            first_token_time = None
            total_tokens = 0
            
            try:
                async with http_client.stream(
                    "POST",
                    "/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request_data,
                    timeout=30.0
                ) as response:
                    
                    if response.status_code == 200:
                        content = ""
                        async for line in response.aiter_lines():
                            if line.startswith("data: "):
                                data_str = line[6:].strip()
                                if data_str == "[DONE]":
                                    break
                                
                                try:
                                    chunk_data = json.loads(data_str)
                                    if "choices" in chunk_data and len(chunk_data["choices"]) > 0:
                                        delta = chunk_data["choices"][0].get("delta", {})
                                        chunk_content = delta.get("content", "")
                                        
                                        if chunk_content:
                                            if first_token_time is None:
                                                first_token_time = time.perf_counter()
                                            content += chunk_content
                                except json.JSONDecodeError:
                                    continue
                        
                        end_time = time.perf_counter()
                        total_time = (end_time - start_time) * 1000
                        profiling_results["chat_streaming"]["response_times"].append(total_time)
                        
                        if first_token_time:
                            ttft = (first_token_time - start_time) * 1000
                            profiling_results["chat_streaming"]["ttft_times"].append(ttft)
                        
                        # Estimate tokens and throughput
                        total_tokens = len(content) // 4  # Rough estimation
                        if total_time > 0:
                            throughput = total_tokens / (total_time / 1000)
                            profiling_results["chat_streaming"]["throughputs"].append(throughput)
            
            except Exception as e:
                logger.warning(f"Streaming profiling test {i} failed: {e}")
            
            await asyncio.sleep(0.1)
        
        # Test chat non-streaming performance
        for i in range(6):
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Non-streaming test {i}: Describe machine learning"}],
                "max_tokens": 80,
                "stream": False
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            response_time = (end_time - start_time) * 1000
            
            if response.status_code == 200:
                profiling_results["chat_non_streaming"]["response_times"].append(response_time)
                
                response_data = response.json()
                if "usage" in response_data:
                    completion_tokens = response_data["usage"]["completion_tokens"]
                    effective_throughput = completion_tokens / (response_time / 1000) if response_time > 0 else 0
                    profiling_results["chat_non_streaming"]["effective_throughputs"].append(effective_throughput)
            
            await asyncio.sleep(0.1)
        
        # Test embedding performance (if available)
        embedding_model = config.get_embedding_model(0)
        if embedding_model:
            for i in range(6):
                request_data = {
                    "model": embedding_model,
                    "input": f"Embedding profiling test {i}: Advanced artificial intelligence concepts"
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/embeddings",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                
                if response.status_code == 200:
                    profiling_results["embeddings"]["response_times"].append(response_time)
                    # Embedding throughput is 1 embedding per response time
                    throughput = 1000 / response_time if response_time > 0 else 0
                    profiling_results["embeddings"]["throughputs"].append(throughput)
                
                await asyncio.sleep(0.05)
        
        # Analyze comprehensive profiling results
        for test_type, metrics in profiling_results.items():
            if metrics.get("response_times"):
                avg_response_time = statistics.mean(metrics["response_times"])
                logger.info(f"{test_type} profiling - Avg response: {avg_response_time:.2f}ms")
                
                if metrics.get("ttft_times"):
                    avg_ttft = statistics.mean(metrics["ttft_times"])
                    logger.info(f"{test_type} - Avg TTFT: {avg_ttft:.2f}ms")
                
                if metrics.get("throughputs") or metrics.get("effective_throughputs"):
                    throughput_key = "throughputs" if "throughputs" in metrics else "effective_throughputs"
                    avg_throughput = statistics.mean(metrics[throughput_key])
                    logger.info(f"{test_type} - Avg throughput: {avg_throughput:.2f} tokens/sec")
                
                # Verify comprehensive performance targets
                if test_type == "chat_streaming":
                    assert avg_response_time < 30000.0, f"Streaming response time should be reasonable, got {avg_response_time:.2f}ms"
                elif test_type == "chat_non_streaming":
                    assert avg_response_time < 20000.0, f"Non-streaming response time should be reasonable, got {avg_response_time:.2f}ms"
                elif test_type == "embeddings":
                    assert avg_response_time < 5000.0, f"Embedding response time should be fast, got {avg_response_time:.2f}ms"