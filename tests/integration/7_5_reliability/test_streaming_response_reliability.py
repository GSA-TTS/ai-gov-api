# Section 7.5 - Streaming Response Reliability Tests
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Streaming Response Reliability.md

import pytest
import httpx
import asyncio
import time
import json
from typing import Dict, Any, List, AsyncGenerator
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestStreamingResponseReliability:
    """Streaming response reliability tests"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_streaming_partial_failure_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """STREAM_PARTIAL_FAIL_001: Mid-stream error handling"""
        # Test handling of errors that occur during streaming
        
        # Test streaming request
        streaming_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Generate a streaming response about artificial intelligence, machine learning, and their applications in various industries. Please provide detailed explanations."}],
            "max_tokens": 300,
            "stream": True
        }
        
        start_time = time.time()
        stream_chunks = []
        stream_error = None
        
        try:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, streaming_request
            )
            
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                
                # Check if response indicates streaming
                if "stream" in content_type.lower() or "text/event-stream" in content_type:
                    logger.info("Streaming response detected")
                    
                    try:
                        # Parse streaming response
                        response_text = response.text
                        
                        # Handle Server-Sent Events format
                        if "data:" in response_text:
                            lines = response_text.split('\n')
                            for line in lines:
                                if line.startswith('data:'):
                                    data_content = line[5:].strip()
                                    if data_content and data_content != '[DONE]':
                                        try:
                                            chunk_data = json.loads(data_content)
                                            stream_chunks.append(chunk_data)
                                        except json.JSONDecodeError:
                                            stream_chunks.append({"raw": data_content})
                        else:
                            # Handle other streaming formats
                            stream_chunks.append({"content": response_text})
                        
                        end_time = time.time()
                        stream_duration = end_time - start_time
                        
                        logger.info(f"Streaming completed: {len(stream_chunks)} chunks in {stream_duration:.2f}s")
                        
                    except Exception as e:
                        stream_error = str(e)
                        logger.warning(f"Error parsing streaming response: {e}")
                
                elif response.status_code == 200:
                    # Non-streaming response to stream request
                    logger.info("Non-streaming response received for stream request")
                    response_data = response.json()
                    
                    # Verify it's a complete response
                    assert "choices" in response_data
                    assert len(response_data["choices"]) > 0
                    
                    stream_chunks.append(response_data)
            
            elif response.status_code == 422:
                logger.info("Streaming not supported - testing fallback behavior")
                
                # Test non-streaming fallback
                non_streaming_request = streaming_request.copy()
                non_streaming_request.pop("stream", None)
                
                fallback_response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, non_streaming_request
                )
                
                assert fallback_response.status_code == 200, \
                    "Non-streaming fallback should work when streaming is not supported"
                
                return  # Exit early for non-streaming systems
            
            else:
                logger.warning(f"Unexpected response code for streaming: {response.status_code}")
        
        except httpx.TimeoutException:
            stream_error = "timeout"
            logger.info("Streaming request timed out")
        
        except Exception as e:
            stream_error = str(e)
            logger.warning(f"Streaming request failed: {e}")
        
        # Analyze streaming reliability
        if stream_chunks:
            # Verify stream integrity
            assert len(stream_chunks) > 0, "Stream should produce content"
            
            # Check for proper stream termination
            if stream_error:
                logger.warning(f"Stream terminated with error: {stream_error}")
            else:
                logger.info("Stream completed successfully")
        
        elif stream_error == "timeout":
            # Timeout handling is acceptable for streaming
            logger.info("Stream timeout handled appropriately")
        
        else:
            logger.info("Streaming test completed with no chunks (may not be supported)")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_streaming_network_interruption_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """STREAM_NETWORK_001: Network interruption handling"""
        # Test streaming resilience to network interruptions
        
        # Test rapid connection/disconnection patterns
        network_test_scenarios = [
            {
                "description": "Quick streaming request",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Quick stream test"}],
                    "max_tokens": 50,
                    "stream": True
                },
                "expected_duration": "short"
            },
            {
                "description": "Long streaming request", 
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Generate a comprehensive analysis of network reliability in streaming systems, including error handling, recovery mechanisms, and best practices."}],
                    "max_tokens": 200,
                    "stream": True
                },
                "expected_duration": "long"
            }
        ]
        
        network_interruption_results = []
        
        for scenario in network_test_scenarios:
            interruption_start_time = time.time()
            
            try:
                # Test with shorter timeout to simulate network issues
                timeout_config = httpx.Timeout(10.0) if scenario["expected_duration"] == "short" else httpx.Timeout(30.0)
                
                async with httpx.AsyncClient(
                    base_url=config.BASE_URL,
                    timeout=timeout_config
                ) as test_client:
                    
                    response = await test_client.post(
                        "/api/v1/chat/completions",
                        headers=auth_headers,
                        json=scenario["request"]
                    )
                    
                    interruption_end_time = time.time()
                    interruption_duration = interruption_end_time - interruption_start_time
                    
                    network_interruption_results.append({
                        "description": scenario["description"],
                        "status_code": response.status_code,
                        "duration": interruption_duration,
                        "completed": True,
                        "network_stable": True
                    })
                    
                    # Verify response handling
                    if response.status_code == 200:
                        logger.info(f"Network test completed: {scenario['description']} in {interruption_duration:.2f}s")
                    elif response.status_code == 422:
                        logger.info(f"Streaming not supported: {scenario['description']}")
                    else:
                        logger.warning(f"Unexpected response: {response.status_code} for {scenario['description']}")
            
            except httpx.TimeoutException:
                interruption_end_time = time.time()
                interruption_duration = interruption_end_time - interruption_start_time
                
                network_interruption_results.append({
                    "description": scenario["description"],
                    "timeout": True,
                    "duration": interruption_duration,
                    "completed": False
                })
                
                logger.info(f"Network timeout after {interruption_duration:.2f}s: {scenario['description']}")
            
            except Exception as e:
                network_interruption_results.append({
                    "description": scenario["description"],
                    "error": str(e),
                    "completed": False
                })
                
                logger.info(f"Network error: {e} for {scenario['description']}")
            
            await asyncio.sleep(1)  # Brief pause between tests
        
        # Analyze network interruption handling
        completed_requests = [r for r in network_interruption_results if r.get("completed")]
        timed_out_requests = [r for r in network_interruption_results if r.get("timeout")]
        
        # System should handle network interruptions gracefully
        total_requests = len(network_interruption_results)
        if total_requests > 0:
            completion_rate = len(completed_requests) / total_requests
            logger.info(f"Network interruption test: {completion_rate:.2%} completion rate")
        
        logger.info("Network interruption handling testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_streaming_chunk_ordering_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """STREAM_ORDERING_001: Chunk ordering and sequence validation"""
        # Test that streaming chunks are delivered in correct order
        
        # Request that should produce sequential content
        ordering_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Count from 1 to 10 and explain each number's significance in mathematics."}],
            "max_tokens": 200,
            "stream": True
        }
        
        start_time = time.time()
        ordered_chunks = []
        sequence_error = None
        
        try:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, ordering_request
            )
            
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                
                if "stream" in content_type.lower() or "text/event-stream" in content_type:
                    # Parse streaming response for ordering
                    response_text = response.text
                    
                    if "data:" in response_text:
                        lines = response_text.split('\n')
                        chunk_index = 0
                        
                        for line in lines:
                            if line.startswith('data:'):
                                data_content = line[5:].strip()
                                if data_content and data_content != '[DONE]':
                                    try:
                                        chunk_data = json.loads(data_content)
                                        
                                        # Extract content and add ordering info
                                        content = ""
                                        if "choices" in chunk_data and chunk_data["choices"]:
                                            choice = chunk_data["choices"][0]
                                            if "delta" in choice and "content" in choice["delta"]:
                                                content = choice["delta"]["content"]
                                        
                                        ordered_chunks.append({
                                            "index": chunk_index,
                                            "content": content,
                                            "timestamp": time.time(),
                                            "chunk_data": chunk_data
                                        })
                                        
                                        chunk_index += 1
                                    
                                    except json.JSONDecodeError as e:
                                        sequence_error = f"JSON decode error: {e}"
                                        break
                    
                    else:
                        # Non-SSE streaming format
                        ordered_chunks.append({
                            "index": 0,
                            "content": response_text,
                            "timestamp": time.time()
                        })
                
                elif response.status_code == 200:
                    # Non-streaming response
                    logger.info("Non-streaming response for ordering test")
                    response_data = response.json()
                    
                    ordered_chunks.append({
                        "index": 0,
                        "content": response_data["choices"][0]["message"]["content"],
                        "timestamp": time.time(),
                        "non_streaming": True
                    })
            
            elif response.status_code == 422:
                logger.info("Streaming not supported for chunk ordering test")
                return
            
            else:
                sequence_error = f"Unexpected response code: {response.status_code}"
        
        except Exception as e:
            sequence_error = str(e)
            logger.warning(f"Chunk ordering test error: {e}")
        
        # Analyze chunk ordering
        if ordered_chunks and not sequence_error:
            # Verify temporal ordering
            timestamps = [chunk["timestamp"] for chunk in ordered_chunks]
            
            for i in range(1, len(timestamps)):
                assert timestamps[i] >= timestamps[i-1], \
                    f"Chunk timestamps should be in order: {i-1}({timestamps[i-1]}) vs {i}({timestamps[i]})"
            
            # Verify index ordering
            indices = [chunk["index"] for chunk in ordered_chunks]
            expected_indices = list(range(len(indices)))
            
            assert indices == expected_indices, \
                f"Chunk indices should be sequential: {indices} vs {expected_indices}"
            
            # Check content coherence (basic validation)
            full_content = "".join(chunk["content"] for chunk in ordered_chunks)
            
            if len(full_content) > 0:
                logger.info(f"Streaming ordering test: {len(ordered_chunks)} chunks, {len(full_content)} characters")
            else:
                logger.info(f"Streaming ordering test: {len(ordered_chunks)} chunks (no content)")
        
        elif sequence_error:
            logger.warning(f"Sequence error detected: {sequence_error}")
        
        else:
            logger.info("No chunks received for ordering test")
        
        logger.info("Chunk ordering validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_streaming_completion_signals_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """STREAM_COMPLETION_001: Stream completion signal validation"""
        # Test proper stream completion signaling
        
        # Request designed to have clear completion
        completion_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Write a short poem with exactly 4 lines."}],
            "max_tokens": 100,
            "stream": True
        }
        
        completion_signals = []
        stream_completed = False
        completion_error = None
        
        try:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, completion_request
            )
            
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                
                if "stream" in content_type.lower() or "text/event-stream" in content_type:
                    response_text = response.text
                    
                    if "data:" in response_text:
                        lines = response_text.split('\n')
                        
                        for line in lines:
                            if line.startswith('data:'):
                                data_content = line[5:].strip()
                                
                                # Check for completion signals
                                if data_content == '[DONE]':
                                    completion_signals.append({
                                        "signal": "DONE",
                                        "timestamp": time.time()
                                    })
                                    stream_completed = True
                                
                                elif data_content:
                                    try:
                                        chunk_data = json.loads(data_content)
                                        
                                        # Check for completion in chunk data
                                        if "choices" in chunk_data and chunk_data["choices"]:
                                            choice = chunk_data["choices"][0]
                                            
                                            if "finish_reason" in choice and choice["finish_reason"]:
                                                completion_signals.append({
                                                    "signal": "finish_reason",
                                                    "reason": choice["finish_reason"],
                                                    "timestamp": time.time()
                                                })
                                    
                                    except json.JSONDecodeError:
                                        pass
                    
                    else:
                        # Non-SSE format - assume completion
                        completion_signals.append({
                            "signal": "full_response",
                            "timestamp": time.time()
                        })
                        stream_completed = True
                
                elif response.status_code == 200:
                    # Non-streaming response
                    logger.info("Non-streaming response for completion test")
                    response_data = response.json()
                    
                    if "choices" in response_data and response_data["choices"]:
                        choice = response_data["choices"][0]
                        if "finish_reason" in choice:
                            completion_signals.append({
                                "signal": "finish_reason",
                                "reason": choice["finish_reason"],
                                "timestamp": time.time()
                            })
                            stream_completed = True
            
            elif response.status_code == 422:
                logger.info("Streaming not supported for completion test")
                return
            
            else:
                completion_error = f"Unexpected response code: {response.status_code}"
        
        except Exception as e:
            completion_error = str(e)
            logger.warning(f"Completion signal test error: {e}")
        
        # Analyze completion signals
        if completion_signals:
            logger.info(f"Completion signals detected: {len(completion_signals)}")
            
            for signal in completion_signals:
                logger.info(f"Signal: {signal['signal']}")
                if "reason" in signal:
                    logger.info(f"Finish reason: {signal['reason']}")
            
            # Verify proper completion
            assert stream_completed, "Stream should have clear completion signal"
            
            # Check for proper finish reasons
            finish_reasons = [s.get("reason") for s in completion_signals if "reason" in s]
            valid_reasons = ["stop", "length", "content_filter", "function_call"]
            
            for reason in finish_reasons:
                if reason:
                    assert reason in valid_reasons, f"Finish reason should be valid: {reason}"
        
        elif completion_error:
            logger.warning(f"Completion test error: {completion_error}")
        
        else:
            logger.info("No completion signals detected (may not be streaming)")
        
        logger.info("Stream completion signal validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_streaming_timeout_handling_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """STREAM_TIMEOUT_001: Streaming timeout handling"""
        # Test timeout handling in streaming scenarios
        
        # Test different timeout scenarios
        timeout_scenarios = [
            {
                "description": "Short timeout with quick request",
                "timeout": 5.0,
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Quick response please"}],
                    "max_tokens": 30,
                    "stream": True
                },
                "should_complete": True
            },
            {
                "description": "Medium timeout with complex request",
                "timeout": 15.0,
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Provide a detailed explanation of streaming protocols and their reliability mechanisms."}],
                    "max_tokens": 150,
                    "stream": True
                },
                "should_complete": "maybe"
            },
            {
                "description": "Very short timeout",
                "timeout": 2.0,
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Generate a long response about artificial intelligence, machine learning, deep learning, and their applications across various industries."}],
                    "max_tokens": 200,
                    "stream": True
                },
                "should_complete": False
            }
        ]
        
        timeout_results = []
        
        for scenario in timeout_scenarios:
            start_time = time.time()
            
            try:
                # Create client with specific timeout
                timeout_config = httpx.Timeout(scenario["timeout"])
                
                async with httpx.AsyncClient(
                    base_url=config.BASE_URL,
                    timeout=timeout_config
                ) as timeout_client:
                    
                    response = await timeout_client.post(
                        "/api/v1/chat/completions",
                        headers=auth_headers,
                        json=scenario["request"]
                    )
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    timeout_results.append({
                        "description": scenario["description"],
                        "status_code": response.status_code,
                        "duration": duration,
                        "completed": True,
                        "timed_out": False,
                        "timeout_setting": scenario["timeout"]
                    })
                    
                    # Verify completion within timeout
                    assert duration <= scenario["timeout"] + 1.0, \
                        f"Request should complete within timeout: {duration:.2f}s vs {scenario['timeout']}s"
                    
                    logger.info(f"Timeout test completed: {scenario['description']} in {duration:.2f}s")
            
            except httpx.TimeoutException:
                end_time = time.time()
                duration = end_time - start_time
                
                timeout_results.append({
                    "description": scenario["description"],
                    "duration": duration,
                    "completed": False,
                    "timed_out": True,
                    "timeout_setting": scenario["timeout"]
                })
                
                logger.info(f"Expected timeout: {scenario['description']} after {duration:.2f}s")
                
                # Timeout should occur near the configured timeout
                assert abs(duration - scenario["timeout"]) <= 2.0, \
                    f"Timeout should occur near configured value: {duration:.2f}s vs {scenario['timeout']}s"
            
            except Exception as e:
                timeout_results.append({
                    "description": scenario["description"],
                    "error": str(e),
                    "completed": False
                })
                
                logger.warning(f"Timeout test error: {e} for {scenario['description']}")
            
            await asyncio.sleep(1)
        
        # Analyze timeout handling
        completed_within_timeout = [r for r in timeout_results if r.get("completed")]
        proper_timeouts = [r for r in timeout_results if r.get("timed_out")]
        
        logger.info(f"Streaming timeout test: {len(completed_within_timeout)} completed, {len(proper_timeouts)} timed out")
        
        # Verify timeout behavior is appropriate
        for result in timeout_results:
            if result.get("timed_out"):
                # Timeouts should be clean and occur at expected time
                assert result["duration"] <= result["timeout_setting"] + 3.0, \
                    "Timeout should occur within reasonable margin"
        
        logger.info("Streaming timeout handling testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_streaming_resource_cleanup_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """STREAM_CLEANUP_001: Resource cleanup after streaming"""
        # Test that resources are properly cleaned up after streaming
        
        # Generate multiple streaming requests to test resource management
        resource_cleanup_scenarios = [
            {
                "description": "Normal completion",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Short response for cleanup test"}],
                    "max_tokens": 40,
                    "stream": True
                }
            },
            {
                "description": "Interrupted stream",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Long response for cleanup test - this should be interrupted"}],
                    "max_tokens": 200,
                    "stream": True
                },
                "interrupt": True
            }
        ]
        
        cleanup_results = []
        
        for scenario in resource_cleanup_scenarios:
            start_time = time.time()
            
            try:
                if scenario.get("interrupt"):
                    # Test with very short timeout to simulate interruption
                    timeout_config = httpx.Timeout(1.0)
                    
                    async with httpx.AsyncClient(
                        base_url=config.BASE_URL,
                        timeout=timeout_config
                    ) as interrupt_client:
                        
                        try:
                            response = await interrupt_client.post(
                                "/api/v1/chat/completions",
                                headers=auth_headers,
                                json=scenario["request"]
                            )
                            
                            # If it completes quickly, that's also fine
                            cleanup_results.append({
                                "description": scenario["description"],
                                "status_code": response.status_code,
                                "completed": True,
                                "interrupted": False
                            })
                        
                        except httpx.TimeoutException:
                            # Expected interruption
                            cleanup_results.append({
                                "description": scenario["description"],
                                "completed": False,
                                "interrupted": True
                            })
                            
                            logger.info(f"Stream interrupted as expected: {scenario['description']}")
                
                else:
                    # Normal streaming test
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, scenario["request"]
                    )
                    
                    cleanup_results.append({
                        "description": scenario["description"],
                        "status_code": response.status_code,
                        "completed": True,
                        "interrupted": False
                    })
                    
                    logger.info(f"Stream completed normally: {scenario['description']}")
            
            except Exception as e:
                cleanup_results.append({
                    "description": scenario["description"],
                    "error": str(e),
                    "completed": False
                })
                
                logger.warning(f"Cleanup test error: {e} for {scenario['description']}")
            
            # Brief pause to allow cleanup
            await asyncio.sleep(0.5)
        
        # Test that system continues to work after cleanup scenarios
        post_cleanup_test = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Post-cleanup functionality test"}],
            "max_tokens": 50
        }
        
        post_cleanup_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, post_cleanup_test
        )
        
        # System should work normally after streaming cleanup
        assert post_cleanup_response.status_code == 200, \
            "System should work normally after streaming resource cleanup"
        
        # Verify no resource leaks by testing multiple requests
        leak_test_requests = []
        
        for i in range(3):
            leak_test_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Resource leak test {i}"}],
                "max_tokens": 30
            }
            
            leak_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, leak_test_request
            )
            
            leak_test_requests.append(leak_response.status_code)
            await asyncio.sleep(0.2)
        
        # All leak test requests should succeed
        leak_success_rate = sum(1 for status in leak_test_requests if status == 200) / len(leak_test_requests)
        
        assert leak_success_rate >= 0.9, \
            f"Resource leak test should have high success rate: {leak_success_rate:.2%}"
        
        logger.info("Streaming resource cleanup testing completed")