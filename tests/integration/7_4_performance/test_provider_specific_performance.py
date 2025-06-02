# Section 7.4 - Provider-Specific Performance Testing
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_Provider-Specific Performance Testing.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class ProviderPerformanceResult:
    """Provider performance test result data structure"""
    test_name: str
    provider_name: str
    model_name: str
    avg_response_time: float
    p95_response_time: float
    ttft_ms: Optional[float]
    tokens_per_second: Optional[float]
    success_rate: float
    error_count: int
    total_requests: int


class TestBedrockPerformanceBaseline:
    """Test Bedrock performance baseline metrics"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_bedrock_chat_latency_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """PERF_PROV_BEDROCK_CHAT_LATENCY_001: Measure baseline latency for Bedrock chat completions"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Identify Bedrock models (models containing 'claude' or 'bedrock' - provider-specific heuristic)
        bedrock_models = [model for model in config.CHAT_MODELS 
                         if any(keyword in model.lower() for keyword in ['claude', 'bedrock', 'anthropic'])]
        
        if not bedrock_models:
            pytest.skip("No Bedrock-specific models identified")
        
        bedrock_model = bedrock_models[0]
        
        bedrock_metrics = {
            "non_streaming": {
                "response_times": [],
                "successful_requests": 0,
                "failed_requests": 0,
                "token_data": []
            },
            "streaming": {
                "response_times": [],
                "ttft_times": [],
                "successful_requests": 0,
                "failed_requests": 0,
                "token_throughputs": []
            }
        }
        
        # Test non-streaming baseline
        logger.info(f"Testing Bedrock non-streaming baseline with model: {bedrock_model}")
        for i in range(25):
            request_data = {
                "model": bedrock_model,
                "messages": [{"role": "user", "content": "Explain artificial intelligence briefly"}],
                "max_tokens": 100,
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
                bedrock_metrics["non_streaming"]["response_times"].append(response_time)
                bedrock_metrics["non_streaming"]["successful_requests"] += 1
                
                response_data = response.json()
                if "usage" in response_data:
                    bedrock_metrics["non_streaming"]["token_data"].append({
                        "prompt_tokens": response_data["usage"]["prompt_tokens"],
                        "completion_tokens": response_data["usage"]["completion_tokens"],
                        "response_time": response_time
                    })
            else:
                bedrock_metrics["non_streaming"]["failed_requests"] += 1
            
            await asyncio.sleep(0.1)
        
        # Test streaming baseline
        logger.info(f"Testing Bedrock streaming baseline with model: {bedrock_model}")
        for i in range(20):
            request_data = {
                "model": bedrock_model,
                "messages": [{"role": "user", "content": "Tell me about machine learning"}],
                "max_tokens": 100,
                "stream": True
            }
            
            start_time = time.perf_counter()
            first_token_time = None
            content_received = ""
            
            try:
                async with http_client.stream(
                    "POST", "/api/v1/chat/completions",
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
                                            bedrock_metrics["streaming"]["ttft_times"].append(ttft_ms)
                                        
                                        content_received += content
                                except json.JSONDecodeError:
                                    continue
                        
                        end_time = time.perf_counter()
                        total_response_time = (end_time - start_time) * 1000
                        bedrock_metrics["streaming"]["response_times"].append(total_response_time)
                        bedrock_metrics["streaming"]["successful_requests"] += 1
                        
                        # Calculate token throughput
                        if first_token_time and content_received:
                            total_tokens = len(content_received) // 4  # Rough estimation
                            generation_time = (end_time - first_token_time)
                            if generation_time > 0:
                                throughput = total_tokens / generation_time
                                bedrock_metrics["streaming"]["token_throughputs"].append(throughput)
                    else:
                        bedrock_metrics["streaming"]["failed_requests"] += 1
            
            except Exception as e:
                bedrock_metrics["streaming"]["failed_requests"] += 1
                logger.warning(f"Bedrock streaming test {i} failed: {e}")
            
            await asyncio.sleep(0.1)
        
        # Analyze Bedrock performance baseline
        # Non-streaming analysis
        if bedrock_metrics["non_streaming"]["response_times"]:
            non_stream_avg = statistics.mean(bedrock_metrics["non_streaming"]["response_times"])
            non_stream_p95 = statistics.quantiles(bedrock_metrics["non_streaming"]["response_times"], n=20)[18] if len(bedrock_metrics["non_streaming"]["response_times"]) >= 20 else max(bedrock_metrics["non_streaming"]["response_times"])
            non_stream_success_rate = bedrock_metrics["non_streaming"]["successful_requests"] / (bedrock_metrics["non_streaming"]["successful_requests"] + bedrock_metrics["non_streaming"]["failed_requests"])
            
            logger.info(f"Bedrock non-streaming baseline - "
                       f"Avg: {non_stream_avg:.2f}ms, "
                       f"P95: {non_stream_p95:.2f}ms, "
                       f"Success rate: {non_stream_success_rate:.2%}")
            
            # Verify Bedrock non-streaming performance
            assert non_stream_avg < 15000.0, f"Bedrock average response time should be reasonable, got {non_stream_avg:.2f}ms"
            assert non_stream_p95 < 25000.0, f"Bedrock P95 response time should meet SLA, got {non_stream_p95:.2f}ms"
            assert non_stream_success_rate >= 0.90, f"Bedrock success rate should be high, got {non_stream_success_rate:.2%}"
        
        # Streaming analysis
        if bedrock_metrics["streaming"]["ttft_times"]:
            stream_avg_ttft = statistics.mean(bedrock_metrics["streaming"]["ttft_times"])
            stream_p95_ttft = statistics.quantiles(bedrock_metrics["streaming"]["ttft_times"], n=20)[18] if len(bedrock_metrics["streaming"]["ttft_times"]) >= 20 else max(bedrock_metrics["streaming"]["ttft_times"])
            stream_success_rate = bedrock_metrics["streaming"]["successful_requests"] / (bedrock_metrics["streaming"]["successful_requests"] + bedrock_metrics["streaming"]["failed_requests"])
            
            logger.info(f"Bedrock streaming baseline - "
                       f"Avg TTFT: {stream_avg_ttft:.2f}ms, "
                       f"P95 TTFT: {stream_p95_ttft:.2f}ms, "
                       f"Success rate: {stream_success_rate:.2%}")
            
            # Verify Bedrock streaming performance
            assert stream_avg_ttft < 3000.0, f"Bedrock average TTFT should be fast, got {stream_avg_ttft:.2f}ms"
            assert stream_p95_ttft < 6000.0, f"Bedrock P95 TTFT should meet SLA, got {stream_p95_ttft:.2f}ms"
            assert stream_success_rate >= 0.85, f"Bedrock streaming success rate should be good, got {stream_success_rate:.2%}"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_bedrock_embed_latency_002(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_PROV_BEDROCK_EMBED_LATENCY_002: Measure baseline latency for Bedrock embeddings"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Identify Bedrock embedding models
        bedrock_embed_models = [model for model in config.EMBEDDING_MODELS 
                               if any(keyword in model.lower() for keyword in ['cohere', 'bedrock'])]
        
        if not bedrock_embed_models:
            pytest.skip("No Bedrock-specific embedding models identified")
        
        bedrock_embed_model = bedrock_embed_models[0]
        
        bedrock_embed_metrics = {
            "single_embeddings": {
                "response_times": [],
                "successful_requests": 0,
                "failed_requests": 0
            },
            "batch_embeddings": {
                "response_times": [],
                "throughputs": [],
                "successful_batches": 0,
                "failed_batches": 0
            }
        }
        
        # Test single embedding latency
        test_texts = [
            "Artificial intelligence transforms technology",
            "Machine learning enables data-driven decisions",
            "Natural language processing understands text",
            "Computer vision interprets visual information",
            "Deep learning models complex patterns"
        ]
        
        for text in test_texts * 4:  # 20 total requests
            request_data = {
                "model": bedrock_embed_model,
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
                bedrock_embed_metrics["single_embeddings"]["response_times"].append(response_time)
                bedrock_embed_metrics["single_embeddings"]["successful_requests"] += 1
            else:
                bedrock_embed_metrics["single_embeddings"]["failed_requests"] += 1
            
            await asyncio.sleep(0.05)
        
        # Test batch embedding throughput
        batch_sizes = [3, 5, 8]
        for batch_size in batch_sizes:
            for i in range(3):  # 3 batches per size
                batch_texts = [f"{text} - batch {i}" for text in test_texts[:batch_size]]
                
                request_data = {
                    "model": bedrock_embed_model,
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
                    bedrock_embed_metrics["batch_embeddings"]["response_times"].append(response_time)
                    
                    # Calculate throughput
                    throughput = batch_size / (response_time / 1000) if response_time > 0 else 0
                    bedrock_embed_metrics["batch_embeddings"]["throughputs"].append(throughput)
                    bedrock_embed_metrics["batch_embeddings"]["successful_batches"] += 1
                else:
                    bedrock_embed_metrics["batch_embeddings"]["failed_batches"] += 1
                
                await asyncio.sleep(0.2)
        
        # Analyze Bedrock embedding performance
        if bedrock_embed_metrics["single_embeddings"]["response_times"]:
            single_avg = statistics.mean(bedrock_embed_metrics["single_embeddings"]["response_times"])
            single_p95 = statistics.quantiles(bedrock_embed_metrics["single_embeddings"]["response_times"], n=20)[18] if len(bedrock_embed_metrics["single_embeddings"]["response_times"]) >= 20 else max(bedrock_embed_metrics["single_embeddings"]["response_times"])
            single_success_rate = bedrock_embed_metrics["single_embeddings"]["successful_requests"] / (bedrock_embed_metrics["single_embeddings"]["successful_requests"] + bedrock_embed_metrics["single_embeddings"]["failed_requests"])
            
            logger.info(f"Bedrock single embedding baseline - "
                       f"Avg: {single_avg:.2f}ms, "
                       f"P95: {single_p95:.2f}ms, "
                       f"Success rate: {single_success_rate:.2%}")
            
            # Verify Bedrock embedding performance
            assert single_avg < 3000.0, f"Bedrock single embedding should be fast, got {single_avg:.2f}ms"
            assert single_p95 < 6000.0, f"Bedrock P95 embedding time should be reasonable, got {single_p95:.2f}ms"
            assert single_success_rate >= 0.90, f"Bedrock embedding success rate should be high, got {single_success_rate:.2%}"
        
        if bedrock_embed_metrics["batch_embeddings"]["throughputs"]:
            batch_avg_throughput = statistics.mean(bedrock_embed_metrics["batch_embeddings"]["throughputs"])
            batch_success_rate = bedrock_embed_metrics["batch_embeddings"]["successful_batches"] / (bedrock_embed_metrics["batch_embeddings"]["successful_batches"] + bedrock_embed_metrics["batch_embeddings"]["failed_batches"])
            
            logger.info(f"Bedrock batch embedding baseline - "
                       f"Avg throughput: {batch_avg_throughput:.2f} embeddings/sec, "
                       f"Success rate: {batch_success_rate:.2%}")
            
            # Verify Bedrock batch embedding efficiency
            assert batch_avg_throughput >= 2.0, f"Bedrock batch throughput should be efficient, got {batch_avg_throughput:.2f} embeddings/sec"
            assert batch_success_rate >= 0.85, f"Bedrock batch success rate should be good, got {batch_success_rate:.2%}"


class TestVertexAIPerformanceBaseline:
    """Test Vertex AI performance baseline metrics"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_vertexai_chat_latency_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """PERF_PROV_VERTEXAI_CHAT_LATENCY_001: Measure baseline latency for Vertex AI chat completions"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Identify Vertex AI models (models containing 'gemini' or 'vertexai' - provider-specific heuristic)
        vertexai_models = [model for model in config.CHAT_MODELS 
                          if any(keyword in model.lower() for keyword in ['gemini', 'vertex', 'google'])]
        
        if not vertexai_models:
            pytest.skip("No Vertex AI-specific models identified")
        
        vertexai_model = vertexai_models[0]
        
        vertexai_metrics = {
            "non_streaming": {
                "response_times": [],
                "successful_requests": 0,
                "failed_requests": 0,
                "token_data": []
            },
            "streaming": {
                "response_times": [],
                "ttft_times": [],
                "successful_requests": 0,
                "failed_requests": 0,
                "token_throughputs": []
            }
        }
        
        # Test non-streaming baseline
        logger.info(f"Testing Vertex AI non-streaming baseline with model: {vertexai_model}")
        for i in range(25):
            request_data = {
                "model": vertexai_model,
                "messages": [{"role": "user", "content": "Explain machine learning concepts"}],
                "max_tokens": 100,
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
                vertexai_metrics["non_streaming"]["response_times"].append(response_time)
                vertexai_metrics["non_streaming"]["successful_requests"] += 1
                
                response_data = response.json()
                if "usage" in response_data:
                    vertexai_metrics["non_streaming"]["token_data"].append({
                        "prompt_tokens": response_data["usage"]["prompt_tokens"],
                        "completion_tokens": response_data["usage"]["completion_tokens"],
                        "response_time": response_time
                    })
            else:
                vertexai_metrics["non_streaming"]["failed_requests"] += 1
            
            await asyncio.sleep(0.1)
        
        # Test streaming baseline
        logger.info(f"Testing Vertex AI streaming baseline with model: {vertexai_model}")
        for i in range(20):
            request_data = {
                "model": vertexai_model,
                "messages": [{"role": "user", "content": "Describe neural networks"}],
                "max_tokens": 100,
                "stream": True
            }
            
            start_time = time.perf_counter()
            first_token_time = None
            content_received = ""
            
            try:
                async with http_client.stream(
                    "POST", "/api/v1/chat/completions",
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
                                            vertexai_metrics["streaming"]["ttft_times"].append(ttft_ms)
                                        
                                        content_received += content
                                except json.JSONDecodeError:
                                    continue
                        
                        end_time = time.perf_counter()
                        total_response_time = (end_time - start_time) * 1000
                        vertexai_metrics["streaming"]["response_times"].append(total_response_time)
                        vertexai_metrics["streaming"]["successful_requests"] += 1
                        
                        # Calculate token throughput
                        if first_token_time and content_received:
                            total_tokens = len(content_received) // 4  # Rough estimation
                            generation_time = (end_time - first_token_time)
                            if generation_time > 0:
                                throughput = total_tokens / generation_time
                                vertexai_metrics["streaming"]["token_throughputs"].append(throughput)
                    else:
                        vertexai_metrics["streaming"]["failed_requests"] += 1
            
            except Exception as e:
                vertexai_metrics["streaming"]["failed_requests"] += 1
                logger.warning(f"Vertex AI streaming test {i} failed: {e}")
            
            await asyncio.sleep(0.1)
        
        # Analyze Vertex AI performance baseline
        # Non-streaming analysis
        if vertexai_metrics["non_streaming"]["response_times"]:
            non_stream_avg = statistics.mean(vertexai_metrics["non_streaming"]["response_times"])
            non_stream_p95 = statistics.quantiles(vertexai_metrics["non_streaming"]["response_times"], n=20)[18] if len(vertexai_metrics["non_streaming"]["response_times"]) >= 20 else max(vertexai_metrics["non_streaming"]["response_times"])
            non_stream_success_rate = vertexai_metrics["non_streaming"]["successful_requests"] / (vertexai_metrics["non_streaming"]["successful_requests"] + vertexai_metrics["non_streaming"]["failed_requests"])
            
            logger.info(f"Vertex AI non-streaming baseline - "
                       f"Avg: {non_stream_avg:.2f}ms, "
                       f"P95: {non_stream_p95:.2f}ms, "
                       f"Success rate: {non_stream_success_rate:.2%}")
            
            # Verify Vertex AI non-streaming performance
            assert non_stream_avg < 15000.0, f"Vertex AI average response time should be reasonable, got {non_stream_avg:.2f}ms"
            assert non_stream_p95 < 25000.0, f"Vertex AI P95 response time should meet SLA, got {non_stream_p95:.2f}ms"
            assert non_stream_success_rate >= 0.90, f"Vertex AI success rate should be high, got {non_stream_success_rate:.2%}"
        
        # Streaming analysis
        if vertexai_metrics["streaming"]["ttft_times"]:
            stream_avg_ttft = statistics.mean(vertexai_metrics["streaming"]["ttft_times"])
            stream_p95_ttft = statistics.quantiles(vertexai_metrics["streaming"]["ttft_times"], n=20)[18] if len(vertexai_metrics["streaming"]["ttft_times"]) >= 20 else max(vertexai_metrics["streaming"]["ttft_times"])
            stream_success_rate = vertexai_metrics["streaming"]["successful_requests"] / (vertexai_metrics["streaming"]["successful_requests"] + vertexai_metrics["streaming"]["failed_requests"])
            
            logger.info(f"Vertex AI streaming baseline - "
                       f"Avg TTFT: {stream_avg_ttft:.2f}ms, "
                       f"P95 TTFT: {stream_p95_ttft:.2f}ms, "
                       f"Success rate: {stream_success_rate:.2%}")
            
            # Verify Vertex AI streaming performance
            assert stream_avg_ttft < 3000.0, f"Vertex AI average TTFT should be fast, got {stream_avg_ttft:.2f}ms"
            assert stream_p95_ttft < 6000.0, f"Vertex AI P95 TTFT should meet SLA, got {stream_p95_ttft:.2f}ms"
            assert stream_success_rate >= 0.85, f"Vertex AI streaming success rate should be good, got {stream_success_rate:.2%}"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_vertexai_embed_latency_002(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_PROV_VERTEXAI_EMBED_LATENCY_002: Measure baseline latency for Vertex AI embeddings"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Identify Vertex AI embedding models
        vertexai_embed_models = [model for model in config.EMBEDDING_MODELS 
                                if any(keyword in model.lower() for keyword in ['text-embedding', 'vertex', 'google'])]
        
        if not vertexai_embed_models:
            pytest.skip("No Vertex AI-specific embedding models identified")
        
        vertexai_embed_model = vertexai_embed_models[0]
        
        vertexai_embed_metrics = {
            "single_embeddings": {
                "response_times": [],
                "successful_requests": 0,
                "failed_requests": 0
            },
            "batch_embeddings": {
                "response_times": [],
                "throughputs": [],
                "successful_batches": 0,
                "failed_batches": 0
            }
        }
        
        # Test single embedding latency
        test_texts = [
            "Advanced machine learning algorithms",
            "Deep neural network architectures",
            "Natural language understanding systems",
            "Computer vision pattern recognition",
            "Reinforcement learning strategies"
        ]
        
        for text in test_texts * 4:  # 20 total requests
            request_data = {
                "model": vertexai_embed_model,
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
                vertexai_embed_metrics["single_embeddings"]["response_times"].append(response_time)
                vertexai_embed_metrics["single_embeddings"]["successful_requests"] += 1
            else:
                vertexai_embed_metrics["single_embeddings"]["failed_requests"] += 1
            
            await asyncio.sleep(0.05)
        
        # Test batch embedding throughput
        batch_sizes = [3, 5, 8]
        for batch_size in batch_sizes:
            for i in range(3):  # 3 batches per size
                batch_texts = [f"{text} - batch {i}" for text in test_texts[:batch_size]]
                
                request_data = {
                    "model": vertexai_embed_model,
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
                    vertexai_embed_metrics["batch_embeddings"]["response_times"].append(response_time)
                    
                    # Calculate throughput
                    throughput = batch_size / (response_time / 1000) if response_time > 0 else 0
                    vertexai_embed_metrics["batch_embeddings"]["throughputs"].append(throughput)
                    vertexai_embed_metrics["batch_embeddings"]["successful_batches"] += 1
                else:
                    vertexai_embed_metrics["batch_embeddings"]["failed_batches"] += 1
                
                await asyncio.sleep(0.2)
        
        # Analyze Vertex AI embedding performance
        if vertexai_embed_metrics["single_embeddings"]["response_times"]:
            single_avg = statistics.mean(vertexai_embed_metrics["single_embeddings"]["response_times"])
            single_p95 = statistics.quantiles(vertexai_embed_metrics["single_embeddings"]["response_times"], n=20)[18] if len(vertexai_embed_metrics["single_embeddings"]["response_times"]) >= 20 else max(vertexai_embed_metrics["single_embeddings"]["response_times"])
            single_success_rate = vertexai_embed_metrics["single_embeddings"]["successful_requests"] / (vertexai_embed_metrics["single_embeddings"]["successful_requests"] + vertexai_embed_metrics["single_embeddings"]["failed_requests"])
            
            logger.info(f"Vertex AI single embedding baseline - "
                       f"Avg: {single_avg:.2f}ms, "
                       f"P95: {single_p95:.2f}ms, "
                       f"Success rate: {single_success_rate:.2%}")
            
            # Verify Vertex AI embedding performance
            assert single_avg < 3000.0, f"Vertex AI single embedding should be fast, got {single_avg:.2f}ms"
            assert single_p95 < 6000.0, f"Vertex AI P95 embedding time should be reasonable, got {single_p95:.2f}ms"
            assert single_success_rate >= 0.90, f"Vertex AI embedding success rate should be high, got {single_success_rate:.2%}"
        
        if vertexai_embed_metrics["batch_embeddings"]["throughputs"]:
            batch_avg_throughput = statistics.mean(vertexai_embed_metrics["batch_embeddings"]["throughputs"])
            batch_success_rate = vertexai_embed_metrics["batch_embeddings"]["successful_batches"] / (vertexai_embed_metrics["batch_embeddings"]["successful_batches"] + vertexai_embed_metrics["batch_embeddings"]["failed_batches"])
            
            logger.info(f"Vertex AI batch embedding baseline - "
                       f"Avg throughput: {batch_avg_throughput:.2f} embeddings/sec, "
                       f"Success rate: {batch_success_rate:.2%}")
            
            # Verify Vertex AI batch embedding efficiency
            assert batch_avg_throughput >= 2.0, f"Vertex AI batch throughput should be efficient, got {batch_avg_throughput:.2f} embeddings/sec"
            assert batch_success_rate >= 0.85, f"Vertex AI batch success rate should be good, got {batch_success_rate:.2%}"


class TestProviderPerformanceComparison:
    """Test cross-provider performance comparison"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_comprehensive_comparison_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """PERF_PROV_COMPREHENSIVE_COMPARISON_001: Comprehensive performance comparison across providers"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Organize models by provider heuristics
        provider_models = {
            "bedrock": [model for model in config.CHAT_MODELS[:3] 
                       if any(keyword in model.lower() for keyword in ['claude', 'bedrock', 'anthropic'])],
            "vertexai": [model for model in config.CHAT_MODELS[:3] 
                        if any(keyword in model.lower() for keyword in ['gemini', 'vertex', 'google'])],
            "other": [model for model in config.CHAT_MODELS[:3] 
                     if not any(keyword in model.lower() for keyword in ['claude', 'bedrock', 'anthropic', 'gemini', 'vertex', 'google'])]
        }
        
        # Remove empty provider groups
        provider_models = {k: v for k, v in provider_models.items() if v}
        
        if len(provider_models) < 2:
            pytest.skip("Need at least 2 different providers for comparison")
        
        comparison_results = {}
        
        # Standardized test scenarios
        test_scenarios = [
            {
                "name": "short_prompt",
                "prompt": "Hi there",
                "max_tokens": 50,
                "expected_time": 5000.0
            },
            {
                "name": "medium_prompt",
                "prompt": "Explain the basics of machine learning and its applications in modern technology",
                "max_tokens": 100,
                "expected_time": 10000.0
            },
            {
                "name": "long_prompt",
                "prompt": "Provide a comprehensive analysis of artificial intelligence, including its history, current applications, future prospects, and potential impact on society. Discuss the ethical considerations and challenges that come with AI development.",
                "max_tokens": 150,
                "expected_time": 15000.0
            }
        ]
        
        # Test each provider with standardized scenarios
        for provider_name, models in provider_models.items():
            provider_results = {}
            
            for scenario in test_scenarios:
                scenario_metrics = {
                    "response_times": [],
                    "successful_requests": 0,
                    "failed_requests": 0
                }
                
                # Use first available model for this provider
                test_model = models[0]
                
                for i in range(8):  # 8 requests per scenario
                    request_data = {
                        "model": test_model,
                        "messages": [{"role": "user", "content": scenario["prompt"]}],
                        "max_tokens": scenario["max_tokens"],
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
                        scenario_metrics["response_times"].append(response_time)
                        scenario_metrics["successful_requests"] += 1
                    else:
                        scenario_metrics["failed_requests"] += 1
                    
                    await asyncio.sleep(0.1)
                
                provider_results[scenario["name"]] = scenario_metrics
            
            comparison_results[provider_name] = provider_results
        
        # Analyze comprehensive comparison results
        for provider_name, provider_data in comparison_results.items():
            logger.info(f"Provider {provider_name} performance comparison:")
            
            for scenario_name, metrics in provider_data.items():
                if metrics["response_times"]:
                    avg_time = statistics.mean(metrics["response_times"])
                    success_rate = metrics["successful_requests"] / (metrics["successful_requests"] + metrics["failed_requests"])
                    
                    logger.info(f"  {scenario_name} - Avg: {avg_time:.2f}ms, Success: {success_rate:.2%}")
                    
                    # Verify each provider meets basic performance targets
                    scenario_config = next(s for s in test_scenarios if s["name"] == scenario_name)
                    assert avg_time < scenario_config["expected_time"], f"Provider {provider_name} {scenario_name} should meet time target, got {avg_time:.2f}ms"
                    assert success_rate >= 0.75, f"Provider {provider_name} {scenario_name} success rate should be reasonable, got {success_rate:.2%}"
        
        # Cross-provider statistical comparison
        if len(comparison_results) >= 2:
            for scenario_name in test_scenarios[0]["name"]:  # Use first scenario for comparison
                scenario_name = test_scenarios[0]["name"]
                provider_avg_times = {}
                
                for provider_name, provider_data in comparison_results.items():
                    if scenario_name in provider_data and provider_data[scenario_name]["response_times"]:
                        avg_time = statistics.mean(provider_data[scenario_name]["response_times"])
                        provider_avg_times[provider_name] = avg_time
                
                if len(provider_avg_times) >= 2:
                    fastest_provider = min(provider_avg_times, key=provider_avg_times.get)
                    slowest_provider = max(provider_avg_times, key=provider_avg_times.get)
                    
                    performance_ratio = provider_avg_times[slowest_provider] / provider_avg_times[fastest_provider]
                    
                    logger.info(f"Cross-provider comparison for {scenario_name}: "
                               f"Fastest: {fastest_provider} ({provider_avg_times[fastest_provider]:.2f}ms), "
                               f"Slowest: {slowest_provider} ({provider_avg_times[slowest_provider]:.2f}ms), "
                               f"Ratio: {performance_ratio:.2f}x")
                    
                    # Performance difference should be reasonable (not more than 5x)
                    assert performance_ratio <= 5.0, f"Provider performance difference should be reasonable, got {performance_ratio:.2f}x"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_consistency_validation_005(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_PROV_CONSISTENCY_VALIDATION_005: Validate response consistency across providers"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test identical prompts across different providers
        available_models = config.CHAT_MODELS[:4] if len(config.CHAT_MODELS) >= 4 else config.CHAT_MODELS
        
        if len(available_models) < 2:
            pytest.skip("Need at least 2 models for consistency validation")
        
        consistency_metrics = {
            "model_performance": {},
            "response_quality_indicators": [],
            "format_compliance": {}
        }
        
        # Standardized prompts for consistency testing
        test_prompts = [
            "What is artificial intelligence?",
            "Explain machine learning in simple terms",
            "List three applications of neural networks"
        ]
        
        for model in available_models[:3]:  # Test up to 3 models
            model_metrics = {
                "response_times": [],
                "successful_requests": 0,
                "response_lengths": [],
                "format_compliance_score": 0
            }
            
            for prompt in test_prompts:
                request_data = {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 100,
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
                    model_metrics["response_times"].append(response_time)
                    model_metrics["successful_requests"] += 1
                    
                    response_data = response.json()
                    if "choices" in response_data and len(response_data["choices"]) > 0:
                        content = response_data["choices"][0]["message"]["content"]
                        model_metrics["response_lengths"].append(len(content))
                        
                        # Basic format compliance check
                        format_score = 1.0
                        if not content.strip():
                            format_score -= 0.5
                        if len(content) < 10:
                            format_score -= 0.3
                        
                        model_metrics["format_compliance_score"] += format_score
                
                await asyncio.sleep(0.1)
            
            consistency_metrics["model_performance"][model] = model_metrics
        
        # Analyze consistency across providers
        for model, metrics in consistency_metrics["model_performance"].items():
            if metrics["response_times"]:
                avg_response_time = statistics.mean(metrics["response_times"])
                avg_response_length = statistics.mean(metrics["response_lengths"]) if metrics["response_lengths"] else 0
                success_rate = metrics["successful_requests"] / len(test_prompts)
                avg_format_compliance = metrics["format_compliance_score"] / len(test_prompts) if len(test_prompts) > 0 else 0
                
                logger.info(f"Model {model} consistency - "
                           f"Avg response: {avg_response_time:.2f}ms, "
                           f"Avg length: {avg_response_length:.0f} chars, "
                           f"Success rate: {success_rate:.2%}, "
                           f"Format compliance: {avg_format_compliance:.3f}")
                
                # Verify consistency standards
                assert avg_response_time < 20000.0, f"Model {model} should maintain reasonable response times, got {avg_response_time:.2f}ms"
                assert success_rate >= 0.80, f"Model {model} should have high success rate, got {success_rate:.2%}"
                assert avg_format_compliance >= 0.7, f"Model {model} should have good format compliance, got {avg_format_compliance:.3f}"
        
        # Cross-model consistency analysis
        response_time_values = []
        response_length_values = []
        
        for metrics in consistency_metrics["model_performance"].values():
            if metrics["response_times"]:
                response_time_values.append(statistics.mean(metrics["response_times"]))
            if metrics["response_lengths"]:
                response_length_values.append(statistics.mean(metrics["response_lengths"]))
        
        if len(response_time_values) >= 2:
            response_time_consistency = statistics.stdev(response_time_values) / statistics.mean(response_time_values) if statistics.mean(response_time_values) > 0 else 1.0
            logger.info(f"Cross-model response time consistency: {response_time_consistency:.3f}")
            
            # Response time consistency should be reasonable
            assert response_time_consistency <= 1.0, f"Response time consistency across models should be reasonable, got {response_time_consistency:.3f}"


class TestProviderThrottlingAndQuotaBehavior:
    """Test provider-specific throttling and quota behavior"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_bedrock_throttling_behavior_003(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """PERF_PROV_BEDROCK_THROTTLING_BEHAVIOR_003: Test Bedrock throttling behavior under high load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Identify Bedrock models
        bedrock_models = [model for model in config.CHAT_MODELS 
                         if any(keyword in model.lower() for keyword in ['claude', 'bedrock', 'anthropic'])]
        
        if not bedrock_models:
            pytest.skip("No Bedrock-specific models identified")
        
        bedrock_model = bedrock_models[0]
        
        throttling_metrics = {
            "response_codes": {},
            "response_times": [],
            "throttling_events": [],
            "successful_requests": 0,
            "failed_requests": 0
        }
        
        # Generate high-frequency requests to potentially trigger throttling
        rapid_fire_requests = 40
        
        for i in range(rapid_fire_requests):
            request_data = {
                "model": bedrock_model,
                "messages": [{"role": "user", "content": f"Throttling test {i}"}],
                "max_tokens": 30,
                "stream": False
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            response_time = (end_time - start_time) * 1000
            status_code = response.status_code
            
            # Track response codes
            if status_code not in throttling_metrics["response_codes"]:
                throttling_metrics["response_codes"][status_code] = 0
            throttling_metrics["response_codes"][status_code] += 1
            
            if status_code == 200:
                throttling_metrics["response_times"].append(response_time)
                throttling_metrics["successful_requests"] += 1
            elif status_code == 429:
                # Throttling detected
                throttling_metrics["throttling_events"].append({
                    "request_id": i,
                    "response_time": response_time,
                    "retry_after": response.headers.get("Retry-After")
                })
                throttling_metrics["failed_requests"] += 1
            else:
                throttling_metrics["failed_requests"] += 1
            
            # Minimal delay to maintain high frequency
            await asyncio.sleep(0.02)
        
        # Analyze throttling behavior
        success_rate = throttling_metrics["successful_requests"] / rapid_fire_requests
        throttling_rate = len(throttling_metrics["throttling_events"]) / rapid_fire_requests
        
        logger.info(f"Bedrock throttling test - "
                   f"Success rate: {success_rate:.2%}, "
                   f"Throttling rate: {throttling_rate:.2%}, "
                   f"Response codes: {throttling_metrics['response_codes']}")
        
        if throttling_metrics["throttling_events"]:
            avg_throttling_response_time = statistics.mean([event["response_time"] for event in throttling_metrics["throttling_events"]])
            retry_after_headers = [event["retry_after"] for event in throttling_metrics["throttling_events"] if event["retry_after"]]
            
            logger.info(f"Throttling events: {len(throttling_metrics['throttling_events'])}, "
                       f"Avg throttling response time: {avg_throttling_response_time:.2f}ms, "
                       f"Retry-After headers: {len(retry_after_headers)}")
        
        # Verify throttling behavior is handled properly
        # System should remain stable even under high load
        assert success_rate >= 0.30, f"Some requests should succeed even under high load, got {success_rate:.2%}"
        
        # If throttling occurs, it should be properly indicated
        if throttling_rate > 0:
            assert 429 in throttling_metrics["response_codes"], "Throttling should be indicated with 429 status code"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_vertexai_quota_behavior_003(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """PERF_PROV_VERTEXAI_QUOTA_BEHAVIOR_003: Test Vertex AI quota behavior under high load"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Identify Vertex AI models
        vertexai_models = [model for model in config.CHAT_MODELS 
                          if any(keyword in model.lower() for keyword in ['gemini', 'vertex', 'google'])]
        
        if not vertexai_models:
            pytest.skip("No Vertex AI-specific models identified")
        
        vertexai_model = vertexai_models[0]
        
        quota_metrics = {
            "response_codes": {},
            "response_times": [],
            "quota_events": [],
            "successful_requests": 0,
            "failed_requests": 0
        }
        
        # Generate high-frequency requests to potentially trigger quota limits
        rapid_fire_requests = 40
        
        for i in range(rapid_fire_requests):
            request_data = {
                "model": vertexai_model,
                "messages": [{"role": "user", "content": f"Quota test {i}"}],
                "max_tokens": 30,
                "stream": False
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            end_time = time.perf_counter()
            
            response_time = (end_time - start_time) * 1000
            status_code = response.status_code
            
            # Track response codes
            if status_code not in quota_metrics["response_codes"]:
                quota_metrics["response_codes"][status_code] = 0
            quota_metrics["response_codes"][status_code] += 1
            
            if status_code == 200:
                quota_metrics["response_times"].append(response_time)
                quota_metrics["successful_requests"] += 1
            elif status_code == 429:
                # Quota exceeded detected
                quota_metrics["quota_events"].append({
                    "request_id": i,
                    "response_time": response_time,
                    "retry_after": response.headers.get("Retry-After")
                })
                quota_metrics["failed_requests"] += 1
            else:
                quota_metrics["failed_requests"] += 1
            
            # Minimal delay to maintain high frequency
            await asyncio.sleep(0.02)
        
        # Analyze quota behavior
        success_rate = quota_metrics["successful_requests"] / rapid_fire_requests
        quota_exceeded_rate = len(quota_metrics["quota_events"]) / rapid_fire_requests
        
        logger.info(f"Vertex AI quota test - "
                   f"Success rate: {success_rate:.2%}, "
                   f"Quota exceeded rate: {quota_exceeded_rate:.2%}, "
                   f"Response codes: {quota_metrics['response_codes']}")
        
        if quota_metrics["quota_events"]:
            avg_quota_response_time = statistics.mean([event["response_time"] for event in quota_metrics["quota_events"]])
            retry_after_headers = [event["retry_after"] for event in quota_metrics["quota_events"] if event["retry_after"]]
            
            logger.info(f"Quota exceeded events: {len(quota_metrics['quota_events'])}, "
                       f"Avg quota response time: {avg_quota_response_time:.2f}ms, "
                       f"Retry-After headers: {len(retry_after_headers)}")
        
        # Verify quota behavior is handled properly
        # System should remain stable even under high load
        assert success_rate >= 0.30, f"Some requests should succeed even under high load, got {success_rate:.2%}"
        
        # If quota is exceeded, it should be properly indicated
        if quota_exceeded_rate > 0:
            assert 429 in quota_metrics["response_codes"], "Quota exceeded should be indicated with 429 status code"


class TestEnhancedProviderPerformanceScenarios:
    """Enhanced provider performance testing scenarios"""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_dynamic_load_balancing_002(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """PERF_PROV_DYNAMIC_LOAD_BALANCING_002: Test dynamic load balancing across providers"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Simulate dynamic load balancing by testing multiple models
        available_models = config.CHAT_MODELS[:4] if len(config.CHAT_MODELS) >= 4 else config.CHAT_MODELS
        
        if len(available_models) < 2:
            pytest.skip("Need at least 2 models for load balancing simulation")
        
        load_balancing_metrics = {
            "model_performance": {},
            "load_distribution": {},
            "rebalancing_indicators": []
        }
        
        # Simulate load balancing by rotating between models
        total_requests = 60
        requests_per_cycle = 10
        
        for cycle in range(total_requests // requests_per_cycle):
            # Select model for this cycle (simulating load balancing decision)
            model = available_models[cycle % len(available_models)]
            
            if model not in load_balancing_metrics["model_performance"]:
                load_balancing_metrics["model_performance"][model] = {
                    "response_times": [],
                    "successful_requests": 0,
                    "failed_requests": 0,
                    "load_cycles": 0
                }
            
            if model not in load_balancing_metrics["load_distribution"]:
                load_balancing_metrics["load_distribution"][model] = 0
            
            cycle_start = time.time()
            cycle_response_times = []
            
            for i in range(requests_per_cycle):
                request_data = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Load balancing test cycle {cycle} request {i}"}],
                    "max_tokens": 50,
                    "stream": False
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                cycle_response_times.append(response_time)
                
                if response.status_code == 200:
                    load_balancing_metrics["model_performance"][model]["response_times"].append(response_time)
                    load_balancing_metrics["model_performance"][model]["successful_requests"] += 1
                else:
                    load_balancing_metrics["model_performance"][model]["failed_requests"] += 1
                
                await asyncio.sleep(0.05)
            
            cycle_end = time.time()
            load_balancing_metrics["model_performance"][model]["load_cycles"] += 1
            load_balancing_metrics["load_distribution"][model] += requests_per_cycle
            
            # Simulate rebalancing decision based on performance
            if cycle_response_times:
                cycle_avg_time = statistics.mean(cycle_response_times)
                if cycle_avg_time > 10000.0:  # If cycle is slow, note for rebalancing
                    load_balancing_metrics["rebalancing_indicators"].append({
                        "cycle": cycle,
                        "model": model,
                        "avg_response_time": cycle_avg_time,
                        "reason": "high_latency"
                    })
        
        # Analyze load balancing effectiveness
        total_requests_distributed = sum(load_balancing_metrics["load_distribution"].values())
        
        logger.info(f"Dynamic load balancing test - Total requests: {total_requests_distributed}")
        
        for model, metrics in load_balancing_metrics["model_performance"].items():
            if metrics["response_times"]:
                avg_response_time = statistics.mean(metrics["response_times"])
                success_rate = metrics["successful_requests"] / (metrics["successful_requests"] + metrics["failed_requests"])
                load_share = load_balancing_metrics["load_distribution"][model] / total_requests_distributed
                
                logger.info(f"Model {model} - "
                           f"Avg response: {avg_response_time:.2f}ms, "
                           f"Success rate: {success_rate:.2%}, "
                           f"Load share: {load_share:.2%}")
                
                # Verify load balancing effectiveness
                assert avg_response_time < 20000.0, f"Load balanced model {model} should maintain reasonable performance, got {avg_response_time:.2f}ms"
                assert success_rate >= 0.80, f"Load balanced model {model} should maintain high success rate, got {success_rate:.2%}"
        
        # Analyze load distribution
        load_shares = list(load_balancing_metrics["load_distribution"].values())
        if len(load_shares) >= 2:
            load_distribution_balance = statistics.stdev(load_shares) / statistics.mean(load_shares) if statistics.mean(load_shares) > 0 else 1.0
            
            logger.info(f"Load distribution balance: {load_distribution_balance:.3f}, "
                       f"Rebalancing events: {len(load_balancing_metrics['rebalancing_indicators'])}")
            
            # Load should be reasonably distributed
            assert load_distribution_balance <= 1.0, f"Load distribution should be reasonable, got {load_distribution_balance:.3f}"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_optimization_strategies_003(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """PERF_PROV_OPTIMIZATION_STRATEGIES_003: Test provider-specific optimization strategies"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test optimization strategies for different model types
        available_models = config.CHAT_MODELS[:3] if len(config.CHAT_MODELS) >= 3 else config.CHAT_MODELS
        
        optimization_results = {}
        
        # Define optimization strategies to test
        optimization_strategies = [
            {
                "name": "baseline",
                "max_tokens": 50,
                "stream": False,
                "optimization": "none"
            },
            {
                "name": "streaming_optimization",
                "max_tokens": 50,
                "stream": True,
                "optimization": "streaming"
            },
            {
                "name": "token_optimization",
                "max_tokens": 30,  # Reduced tokens for faster response
                "stream": False,
                "optimization": "reduced_tokens"
            }
        ]
        
        for model in available_models:
            model_optimizations = {}
            
            for strategy in optimization_strategies:
                strategy_metrics = {
                    "response_times": [],
                    "successful_requests": 0,
                    "optimization_effectiveness": 0
                }
                
                for i in range(8):  # 8 requests per strategy
                    request_data = {
                        "model": model,
                        "messages": [{"role": "user", "content": f"Optimization test {strategy['name']} {i}"}],
                        "max_tokens": strategy["max_tokens"],
                        "stream": strategy["stream"]
                    }
                    
                    start_time = time.perf_counter()
                    
                    if strategy["stream"]:
                        # Streaming optimization
                        try:
                            async with http_client.stream(
                                "POST", "/api/v1/chat/completions",
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
                                                if "choices" in chunk_data and len(chunk_data["choices"]) > 0:
                                                    delta = chunk_data["choices"][0].get("delta", {})
                                                    if delta.get("content"):
                                                        content_received = True
                                                        break  # Optimize by stopping after first content
                                            except json.JSONDecodeError:
                                                continue
                                    
                                    if content_received:
                                        strategy_metrics["successful_requests"] += 1
                        except Exception:
                            pass
                    else:
                        # Non-streaming optimization
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request_data
                        )
                        
                        if response.status_code == 200:
                            strategy_metrics["successful_requests"] += 1
                    
                    end_time = time.perf_counter()
                    response_time = (end_time - start_time) * 1000
                    strategy_metrics["response_times"].append(response_time)
                    
                    await asyncio.sleep(0.05)
                
                model_optimizations[strategy["name"]] = strategy_metrics
            
            optimization_results[model] = model_optimizations
        
        # Analyze optimization effectiveness
        for model, optimizations in optimization_results.items():
            logger.info(f"Optimization strategies for model {model}:")
            
            baseline_avg = None
            if "baseline" in optimizations and optimizations["baseline"]["response_times"]:
                baseline_avg = statistics.mean(optimizations["baseline"]["response_times"])
                logger.info(f"  Baseline avg: {baseline_avg:.2f}ms")
            
            for strategy_name, metrics in optimizations.items():
                if metrics["response_times"]:
                    avg_response_time = statistics.mean(metrics["response_times"])
                    success_rate = metrics["successful_requests"] / 8
                    
                    optimization_gain = 0
                    if baseline_avg and baseline_avg > 0 and strategy_name != "baseline":
                        optimization_gain = (baseline_avg - avg_response_time) / baseline_avg
                    
                    logger.info(f"  {strategy_name} - "
                               f"Avg: {avg_response_time:.2f}ms, "
                               f"Success: {success_rate:.2%}, "
                               f"Gain: {optimization_gain:.2%}")
                    
                    # Verify optimization effectiveness
                    assert avg_response_time < 15000.0, f"Optimized {strategy_name} should maintain reasonable performance, got {avg_response_time:.2f}ms"
                    assert success_rate >= 0.75, f"Optimized {strategy_name} should maintain good success rate, got {success_rate:.2%}"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_prov_error_recovery_006(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """PERF_PROV_ERROR_RECOVERY_006: Test provider error handling and recovery performance"""
        if not config.ENABLE_PERFORMANCE_TESTS:
            pytest.skip("Performance tests disabled")
        
        # Test error recovery mechanisms
        available_models = config.CHAT_MODELS[:2] if len(config.CHAT_MODELS) >= 2 else config.CHAT_MODELS
        
        error_recovery_metrics = {
            "error_scenarios": {},
            "recovery_times": [],
            "error_detection_times": []
        }
        
        # Define error scenarios to test
        error_scenarios = [
            {
                "name": "invalid_model",
                "model": "invalid_model_test_error_recovery",
                "expected_error": 400
            },
            {
                "name": "excessive_tokens",
                "model": available_models[0],
                "max_tokens": 100000,  # Likely to cause error
                "expected_error": 400
            },
            {
                "name": "empty_prompt",
                "model": available_models[0],
                "content": "",
                "expected_error": 400
            }
        ]
        
        for scenario in error_scenarios:
            scenario_metrics = {
                "error_detection_times": [],
                "response_codes": {},
                "recovery_attempts": 0
            }
            
            for i in range(5):  # 5 attempts per error scenario
                # Construct request that should cause error
                if scenario["name"] == "invalid_model":
                    request_data = {
                        "model": scenario["model"],
                        "messages": [{"role": "user", "content": "Test error recovery"}],
                        "max_tokens": 50
                    }
                elif scenario["name"] == "excessive_tokens":
                    request_data = {
                        "model": scenario["model"],
                        "messages": [{"role": "user", "content": "Test error recovery"}],
                        "max_tokens": scenario["max_tokens"]
                    }
                elif scenario["name"] == "empty_prompt":
                    request_data = {
                        "model": scenario["model"],
                        "messages": [{"role": "user", "content": scenario["content"]}],
                        "max_tokens": 50
                    }
                
                error_detection_start = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                error_detection_end = time.perf_counter()
                
                error_detection_time = (error_detection_end - error_detection_start) * 1000
                scenario_metrics["error_detection_times"].append(error_detection_time)
                
                status_code = response.status_code
                if status_code not in scenario_metrics["response_codes"]:
                    scenario_metrics["response_codes"][status_code] = 0
                scenario_metrics["response_codes"][status_code] += 1
                
                # Test recovery by making a valid request after error
                if status_code != 200:
                    recovery_start = time.perf_counter()
                    
                    valid_request_data = {
                        "model": available_models[0],
                        "messages": [{"role": "user", "content": "Recovery test"}],
                        "max_tokens": 30
                    }
                    
                    recovery_response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, valid_request_data
                    )
                    
                    recovery_end = time.perf_counter()
                    recovery_time = (recovery_end - recovery_start) * 1000
                    
                    if recovery_response.status_code == 200:
                        error_recovery_metrics["recovery_times"].append(recovery_time)
                        scenario_metrics["recovery_attempts"] += 1
                
                await asyncio.sleep(0.1)
            
            error_recovery_metrics["error_scenarios"][scenario["name"]] = scenario_metrics
        
        # Analyze error recovery performance
        for scenario_name, metrics in error_recovery_metrics["error_scenarios"].items():
            if metrics["error_detection_times"]:
                avg_detection_time = statistics.mean(metrics["error_detection_times"])
                dominant_response_code = max(metrics["response_codes"], key=metrics["response_codes"].get)
                
                logger.info(f"Error scenario {scenario_name} - "
                           f"Avg detection time: {avg_detection_time:.2f}ms, "
                           f"Dominant response code: {dominant_response_code}, "
                           f"Recovery attempts: {metrics['recovery_attempts']}")
                
                # Verify error detection is fast
                assert avg_detection_time < 10000.0, f"Error detection for {scenario_name} should be fast, got {avg_detection_time:.2f}ms"
                
                # Verify appropriate error codes are returned
                assert dominant_response_code in [400, 422, 500], f"Error scenario {scenario_name} should return appropriate error code, got {dominant_response_code}"
        
        # Analyze overall recovery performance
        if error_recovery_metrics["recovery_times"]:
            avg_recovery_time = statistics.mean(error_recovery_metrics["recovery_times"])
            recovery_success_rate = len(error_recovery_metrics["recovery_times"]) / (len(error_scenarios) * 5)
            
            logger.info(f"Error recovery performance - "
                       f"Avg recovery time: {avg_recovery_time:.2f}ms, "
                       f"Recovery success rate: {recovery_success_rate:.2%}")
            
            # Verify recovery performance
            assert avg_recovery_time < 10000.0, f"Error recovery should be fast, got {avg_recovery_time:.2f}ms"
            assert recovery_success_rate >= 0.80, f"Error recovery should be reliable, got {recovery_success_rate:.2%}"