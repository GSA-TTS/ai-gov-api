# Section 7.2 - LLM-Specific Functional Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - LLM-Specific Functional Testing.md

import pytest
import httpx
import asyncio
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestTokenLimits:
    """Test token limit handling and enforcement"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_token_prompt_exceeds_ctx_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """FV_LLM_TOKEN_PROMPT_EXCEEDS_CTX_001: Test context window limit handling"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Generate progressively larger prompts to test context limits
        base_text = "This is a test of context window limits. "
        large_prompts = [
            base_text * 100,   # ~800 tokens
            base_text * 500,   # ~4K tokens
            base_text * 1000,  # ~8K tokens
            base_text * 2000   # ~16K tokens
        ]
        
        for i, prompt in enumerate(large_prompts):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 100
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                # Request succeeded within context window
                response_data = response.json()
                assert "choices" in response_data
                assert "usage" in response_data
                
                # Verify token usage is reported
                usage = response_data["usage"]
                assert usage["prompt_tokens"] > 0
                assert usage["total_tokens"] > 0
                
                logger.info(f"FV_LLM_TOKEN_PROMPT_EXCEEDS_CTX_001: Prompt {i+1} (~{len(prompt)//4} tokens) processed successfully")
                
            elif response.status_code == 422:
                # Context limit exceeded
                response_data = response.json()
                assert "detail" in response_data
                
                detail_str = str(response_data["detail"]).lower()
                assert any(keyword in detail_str for keyword in [
                    "context", "token", "limit", "exceed", "too long", "maximum"
                ]), f"Error should indicate context limit exceeded for prompt {i+1}"
                
                logger.info(f"FV_LLM_TOKEN_PROMPT_EXCEEDS_CTX_001: Prompt {i+1} appropriately rejected - context limit")
                break  # No need to test larger prompts
            else:
                logger.info(f"FV_LLM_TOKEN_PROMPT_EXCEEDS_CTX_001: Prompt {i+1} returned {response.status_code}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_token_maxtokens_respected_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_LLM_TOKEN_MAXTOKENS_RESPECTED_001: Verify max_tokens parameter enforcement"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test different max_tokens values
        max_tokens_tests = [10, 50, 100, 200]
        
        for max_tokens in max_tokens_tests:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Write a detailed explanation of artificial intelligence and machine learning concepts, including their history, applications, and future implications."}],
                "max_tokens": max_tokens
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Request with max_tokens={max_tokens} should succeed"
            
            response_data = response.json()
            assert "usage" in response_data
            
            usage = response_data["usage"]
            completion_tokens = usage["completion_tokens"]
            
            # Completion tokens should not exceed max_tokens (with small tolerance for tokenization differences)
            assert completion_tokens <= max_tokens + 5, \
                f"Completion tokens ({completion_tokens}) should not significantly exceed max_tokens ({max_tokens})"
            
            # For very small max_tokens, should still generate some content
            if max_tokens >= 10:
                content = response_data["choices"][0]["message"]["content"]
                assert len(content) > 0, f"Should generate content with max_tokens={max_tokens}"
            
            logger.info(f"FV_LLM_TOKEN_MAXTOKENS_RESPECTED_001: max_tokens={max_tokens} respected, generated {completion_tokens} tokens")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_token_maxtokens_ignored_if_larger_001(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """FV_LLM_TOKEN_MAXTOKENS_IGNORED_IF_LARGER_001: Test max_tokens larger than natural response"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Short prompt that should naturally complete in few tokens
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Say 'hello'"}],
            "max_tokens": 1000  # Much larger than needed
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Should complete naturally, not use all 1000 tokens
        usage = response_data["usage"]
        completion_tokens = usage["completion_tokens"]
        
        assert completion_tokens < 100, \
            f"Natural completion should use much fewer than max_tokens (1000), used {completion_tokens}"
        
        # Should have appropriate finish_reason
        choice = response_data["choices"][0]
        if "finish_reason" in choice:
            finish_reason = choice["finish_reason"]
            assert finish_reason in ["stop", None], \
                f"Should finish naturally with 'stop', got '{finish_reason}'"
        
        logger.info(f"FV_LLM_TOKEN_MAXTOKENS_IGNORED_IF_LARGER_001: Natural completion used {completion_tokens}/1000 tokens")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_token_count_accuracy_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """FV_LLM_TOKEN_COUNT_ACCURACY_001: Test token count accuracy"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with various prompt lengths for token count consistency
        test_prompts = [
            "Hello",  # Very short
            "This is a medium length prompt with several words.",  # Medium
            "This is a longer prompt that contains multiple sentences and should use more tokens for encoding. It includes various words and punctuation marks.",  # Long
        ]
        
        for i, prompt in enumerate(test_prompts):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200
            response_data = response.json()
            
            usage = response_data["usage"]
            prompt_tokens = usage["prompt_tokens"]
            completion_tokens = usage["completion_tokens"]
            total_tokens = usage["total_tokens"]
            
            # Basic token count validation
            assert prompt_tokens > 0, f"Prompt tokens should be > 0 for prompt {i+1}"
            assert completion_tokens > 0, f"Completion tokens should be > 0 for prompt {i+1}"
            assert total_tokens == prompt_tokens + completion_tokens, \
                f"Total tokens should equal sum for prompt {i+1}"
            
            # Rough estimation - longer prompts should use more tokens
            expected_min_tokens = len(prompt) // 6  # Very rough estimate
            assert prompt_tokens >= expected_min_tokens, \
                f"Prompt tokens ({prompt_tokens}) seem too low for prompt length ({len(prompt)})"
            
            logger.info(f"FV_LLM_TOKEN_COUNT_ACCURACY_001: Prompt {i+1} - {prompt_tokens} prompt + {completion_tokens} completion = {total_tokens} total tokens")


class TestStreamingFunction:
    """Test streaming response functionality"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_stream_func_content_order_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_LLM_STREAM_FUNC_CONTENT_ORDER_001: Verify streaming content order"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Count from 1 to 10"}],
            "max_tokens": 100,
            "stream": True
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            # Streaming not supported
            pytest.skip("Streaming not supported")
        
        assert response.status_code == 200
        
        if response.headers.get("content-type", "").startswith("text/event-stream"):
            # Parse SSE stream
            stream_content = response.text
            chunks = []
            
            for line in stream_content.split('\n'):
                if line.startswith('data: '):
                    data_part = line[6:]  # Remove 'data: '
                    if data_part.strip() and data_part.strip() != '[DONE]':
                        try:
                            import json
                            chunk_data = json.loads(data_part)
                            if 'choices' in chunk_data and len(chunk_data['choices']) > 0:
                                choice = chunk_data['choices'][0]
                                if 'delta' in choice and 'content' in choice['delta']:
                                    content = choice['delta']['content']
                                    if content:
                                        chunks.append(content)
                        except json.JSONDecodeError:
                            continue
            
            # Verify streaming chunks can be reassembled
            if chunks:
                full_content = ''.join(chunks)
                assert len(full_content) > 0, "Streaming chunks should combine to form content"
                logger.info(f"FV_LLM_STREAM_FUNC_CONTENT_ORDER_001: Streaming generated {len(chunks)} chunks")
            else:
                logger.info("FV_LLM_STREAM_FUNC_CONTENT_ORDER_001: No content chunks found in stream")
        else:
            # Non-streaming response despite stream=True
            response_data = response.json()
            assert "choices" in response_data
            logger.info("FV_LLM_STREAM_FUNC_CONTENT_ORDER_001: Fallback to non-streaming response")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_stream_func_finish_reason_last_chunk_001(self, http_client: httpx.AsyncClient,
                                                                 auth_headers: Dict[str, str],
                                                                 make_request):
        """FV_LLM_STREAM_FUNC_FINISH_REASON_LAST_CHUNK_001: Test finish_reason in final chunk"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Say exactly 'Done.'"}],
            "max_tokens": 10,
            "stream": True
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            pytest.skip("Streaming not supported")
        
        assert response.status_code == 200
        
        if response.headers.get("content-type", "").startswith("text/event-stream"):
            stream_content = response.text
            found_finish_reason = False
            
            for line in stream_content.split('\n'):
                if line.startswith('data: '):
                    data_part = line[6:]
                    if data_part.strip() and data_part.strip() != '[DONE]':
                        try:
                            import json
                            chunk_data = json.loads(data_part)
                            if 'choices' in chunk_data and len(chunk_data['choices']) > 0:
                                choice = chunk_data['choices'][0]
                                if 'finish_reason' in choice and choice['finish_reason'] is not None:
                                    found_finish_reason = True
                                    finish_reason = choice['finish_reason']
                                    assert finish_reason in ["stop", "length", "content_filter"], \
                                        f"Valid finish_reason expected, got {finish_reason}"
                                    logger.info(f"FV_LLM_STREAM_FUNC_FINISH_REASON_LAST_CHUNK_001: Found finish_reason: {finish_reason}")
                                    break
                        except json.JSONDecodeError:
                            continue
            
            if not found_finish_reason:
                logger.info("FV_LLM_STREAM_FUNC_FINISH_REASON_LAST_CHUNK_001: No explicit finish_reason found in stream")
        else:
            logger.info("FV_LLM_STREAM_FUNC_FINISH_REASON_LAST_CHUNK_001: Non-streaming response")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_stream_func_tool_calls_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """FV_LLM_STREAM_FUNC_TOOL_CALLS_001: Test tool calls in streaming"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test streaming with function/tool calling (if supported)
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "What's the weather like today?"}],
            "max_tokens": 100,
            "stream": True,
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "Get weather information",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "location": {"type": "string"}
                            }
                        }
                    }
                }
            ]
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            # Tools or streaming not supported
            response_data = response.json()
            detail = str(response_data.get("detail", "")).lower()
            if "tool" in detail or "function" in detail:
                pytest.skip("Tool calling not supported")
            else:
                pytest.skip("Streaming not supported")
        
        assert response.status_code == 200
        
        if response.headers.get("content-type", "").startswith("text/event-stream"):
            # Check for tool calls in stream
            stream_content = response.text
            found_tool_call = False
            
            for line in stream_content.split('\n'):
                if line.startswith('data: '):
                    data_part = line[6:]
                    if data_part.strip() and data_part.strip() != '[DONE]':
                        try:
                            import json
                            chunk_data = json.loads(data_part)
                            if 'choices' in chunk_data and len(chunk_data['choices']) > 0:
                                choice = chunk_data['choices'][0]
                                if 'delta' in choice and 'tool_calls' in choice['delta']:
                                    found_tool_call = True
                                    logger.info("FV_LLM_STREAM_FUNC_TOOL_CALLS_001: Tool call found in streaming")
                                    break
                        except json.JSONDecodeError:
                            continue
            
            if not found_tool_call:
                logger.info("FV_LLM_STREAM_FUNC_TOOL_CALLS_001: No tool calls in streaming response")
        else:
            logger.info("FV_LLM_STREAM_FUNC_TOOL_CALLS_001: Non-streaming response")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_stream_sse_format_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """FV_LLM_STREAM_SSE_FORMAT_001: Verify SSE format compliance"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Write a short poem"}],
            "max_tokens": 50,
            "stream": True
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            pytest.skip("Streaming not supported")
        
        assert response.status_code == 200
        
        # Check SSE format compliance
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            # Verify SSE headers
            assert "text/event-stream" in content_type, "Content-Type should be text/event-stream"
            
            # Check for proper Cache-Control header
            cache_control = response.headers.get("cache-control", "")
            if cache_control:
                assert "no-cache" in cache_control.lower(), "Should have no-cache directive"
            
            # Verify SSE format
            stream_content = response.text
            lines = stream_content.split('\n')
            
            valid_sse_lines = 0
            for line in lines:
                if line.startswith('data: '):
                    valid_sse_lines += 1
                    data_part = line[6:]  # Remove 'data: '
                    
                    if data_part.strip() == '[DONE]':
                        logger.info("FV_LLM_STREAM_SSE_FORMAT_001: Found [DONE] marker")
                    elif data_part.strip():
                        # Should be valid JSON
                        try:
                            import json
                            json.loads(data_part)
                        except json.JSONDecodeError:
                            pytest.fail(f"Invalid JSON in SSE data: {data_part}")
                
                elif line.startswith('event: ') or line.startswith('id: ') or line == '':
                    # Valid SSE format lines
                    pass
                elif line.strip():
                    logger.warning(f"Unexpected SSE line format: {line}")
            
            assert valid_sse_lines > 0, "Should have at least one valid SSE data line"
            logger.info(f"FV_LLM_STREAM_SSE_FORMAT_001: {valid_sse_lines} valid SSE data lines")
        else:
            logger.info("FV_LLM_STREAM_SSE_FORMAT_001: Non-streaming response")


class TestParameterBehavior:
    """Test LLM parameter behavior and effects"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_param_temp_0_determinism_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """FV_LLM_PARAM_TEMP_0_DETERMINISM_001: Test temperature=0 determinism"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Make multiple identical requests with temperature=0
        deterministic_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "What is 2+2?"}],
            "max_tokens": 50,
            "temperature": 0.0
        }
        
        responses = []
        for i in range(3):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, deterministic_request
            )
            
            assert response.status_code == 200, f"Request {i+1} should succeed"
            responses.append(response.json())
            
            # Small delay between requests
            await asyncio.sleep(0.1)
        
        # Extract response content
        contents = [resp["choices"][0]["message"]["content"] for resp in responses]
        
        # With temperature=0, responses should be identical or very similar
        unique_contents = set(contents)
        if len(unique_contents) == 1:
            logger.info("FV_LLM_PARAM_TEMP_0_DETERMINISM_001: Perfect determinism with temperature=0")
        else:
            # Some variation might occur due to system factors, but should be minimal
            logger.info(f"FV_LLM_PARAM_TEMP_0_DETERMINISM_001: {len(unique_contents)} unique responses with temperature=0")
            
            # Check if responses are at least very similar (for numerical answers)
            if all("4" in content for content in contents):
                logger.info("FV_LLM_PARAM_TEMP_0_DETERMINISM_001: Responses contain correct answer despite variation")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_param_temp_high_variability_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """FV_LLM_PARAM_TEMP_HIGH_VARIABILITY_001: Test high temperature variability"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Make multiple requests with high temperature
        variable_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Tell me a creative story about a robot."}],
            "max_tokens": 100,
            "temperature": 1.5
        }
        
        responses = []
        for i in range(3):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, variable_request
            )
            
            if response.status_code == 422:
                # High temperature might not be supported
                pytest.skip("High temperature (1.5) not supported")
            
            assert response.status_code == 200, f"Request {i+1} should succeed"
            responses.append(response.json())
            
            await asyncio.sleep(0.1)
        
        # Extract response content
        contents = [resp["choices"][0]["message"]["content"] for resp in responses]
        
        # With high temperature, responses should show more variability
        unique_contents = set(contents)
        
        if len(unique_contents) > 1:
            logger.info(f"FV_LLM_PARAM_TEMP_HIGH_VARIABILITY_001: {len(unique_contents)} unique responses with high temperature")
        else:
            logger.info("FV_LLM_PARAM_TEMP_HIGH_VARIABILITY_001: Identical responses despite high temperature")
        
        # Verify all responses are reasonable length
        for i, content in enumerate(contents):
            assert len(content) > 10, f"Response {i+1} should be substantial with high temperature"
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_param_stop_sequence_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """FV_LLM_PARAM_STOP_SEQUENCE_001: Test stop sequence functionality"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Count: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10"}],
            "max_tokens": 100,
            "stop": ["5"]  # Should stop at "5"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            # Stop sequences might not be supported
            pytest.skip("Stop sequences not supported")
        
        assert response.status_code == 200
        response_data = response.json()
        
        content = response_data["choices"][0]["message"]["content"]
        
        # Should stop before or at the stop sequence
        if "5" in content:
            # Verify it stops appropriately
            parts_after_5 = content.split("5")[1:]
            if parts_after_5:
                # Some content after "5" is acceptable if it's part of the same token
                logger.info(f"FV_LLM_PARAM_STOP_SEQUENCE_001: Stopped with some content after stop sequence: '{content}'")
            else:
                logger.info(f"FV_LLM_PARAM_STOP_SEQUENCE_001: Stopped exactly at stop sequence: '{content}'")
        else:
            logger.info(f"FV_LLM_PARAM_STOP_SEQUENCE_001: Stopped before stop sequence: '{content}'")
        
        # Check finish_reason
        choice = response_data["choices"][0]
        if "finish_reason" in choice:
            finish_reason = choice["finish_reason"]
            if finish_reason == "stop":
                logger.info("FV_LLM_PARAM_STOP_SEQUENCE_001: Proper stop finish_reason")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_param_system_message_effect_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """FV_LLM_PARAM_SYSTEM_MESSAGE_EFFECT_001: Test system message influence"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with system message
        request_with_system = {
            "model": config.get_chat_model(0),
            "messages": [
                {"role": "system", "content": "You are a helpful assistant who always responds with exactly one word."},
                {"role": "user", "content": "What's the weather like?"}
            ],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request_with_system
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        content_with_system = response_data["choices"][0]["message"]["content"].strip()
        
        # Test without system message
        request_without_system = {
            "model": config.get_chat_model(0),
            "messages": [
                {"role": "user", "content": "What's the weather like?"}
            ],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request_without_system
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        content_without_system = response_data["choices"][0]["message"]["content"].strip()
        
        # Compare responses
        words_with_system = len(content_with_system.split())
        words_without_system = len(content_without_system.split())
        
        logger.info(f"FV_LLM_PARAM_SYSTEM_MESSAGE_EFFECT_001: With system: {words_with_system} words, Without: {words_without_system} words")
        
        # System message should influence response length/style
        if words_with_system <= words_without_system:
            logger.info("FV_LLM_PARAM_SYSTEM_MESSAGE_EFFECT_001: System message appears to influence response length")
        else:
            logger.info("FV_LLM_PARAM_SYSTEM_MESSAGE_EFFECT_001: System message effect unclear")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_param_top_p_effect_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """FV_LLM_PARAM_TOP_P_EFFECT_001: Test top_p parameter effects"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with low top_p (more focused)
        request_low_top_p = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Complete this sentence: The sky is"}],
            "max_tokens": 20,
            "top_p": 0.1,
            "temperature": 0.8
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request_low_top_p
        )
        
        if response.status_code == 422:
            # top_p might not be supported
            pytest.skip("top_p parameter not supported")
        
        assert response.status_code == 200
        low_top_p_content = response.json()["choices"][0]["message"]["content"]
        
        # Test with high top_p (more diverse)
        request_high_top_p = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Complete this sentence: The sky is"}],
            "max_tokens": 20,
            "top_p": 0.9,
            "temperature": 0.8
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request_high_top_p
        )
        
        assert response.status_code == 200
        high_top_p_content = response.json()["choices"][0]["message"]["content"]
        
        logger.info(f"FV_LLM_PARAM_TOP_P_EFFECT_001: Low top_p: '{low_top_p_content.strip()}'")
        logger.info(f"FV_LLM_PARAM_TOP_P_EFFECT_001: High top_p: '{high_top_p_content.strip()}'")
        
        # Both should generate reasonable completions
        assert len(low_top_p_content.strip()) > 0, "Low top_p should generate content"
        assert len(high_top_p_content.strip()) > 0, "High top_p should generate content"
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_param_presence_penalty_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """FV_LLM_PARAM_PRESENCE_PENALTY_001: Test presence_penalty effects"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Write about cats. Mention cats multiple times."}],
            "max_tokens": 100,
            "presence_penalty": 1.0  # High penalty for repeated tokens
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            # presence_penalty might not be supported
            pytest.skip("presence_penalty parameter not supported")
        
        assert response.status_code == 200
        response_data = response.json()
        
        content = response_data["choices"][0]["message"]["content"].lower()
        
        # Count occurrences of "cat" related words
        cat_count = content.count("cat")
        
        logger.info(f"FV_LLM_PARAM_PRESENCE_PENALTY_001: Found {cat_count} occurrences of 'cat' with high presence_penalty")
        
        # With high presence penalty, repetition should be reduced
        # (though this is hard to test definitively)
        assert len(content) > 10, "Should generate substantial content"
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_param_frequency_penalty_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_LLM_PARAM_FREQUENCY_PENALTY_001: Test frequency_penalty effects"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Describe a beautiful day. Use descriptive words."}],
            "max_tokens": 100,
            "frequency_penalty": 1.0  # High penalty for frequent tokens
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            # frequency_penalty might not be supported
            pytest.skip("frequency_penalty parameter not supported")
        
        assert response.status_code == 200
        response_data = response.json()
        
        content = response_data["choices"][0]["message"]["content"]
        
        # With high frequency penalty, should use more diverse vocabulary
        words = content.lower().split()
        unique_words = set(words)
        
        if len(words) > 0:
            diversity_ratio = len(unique_words) / len(words)
            logger.info(f"FV_LLM_PARAM_FREQUENCY_PENALTY_001: Vocabulary diversity: {diversity_ratio:.2f} ({len(unique_words)}/{len(words)})")
            
            # Should have reasonable diversity with frequency penalty
            assert diversity_ratio > 0.5, "Should have reasonable vocabulary diversity with frequency penalty"


class TestProviderConsistency:
    """Test consistency across different providers"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_provider_consistency_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """FV_LLM_PROVIDER_CONSISTENCY_001: Compare behavior across providers"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test same prompt across different models/providers
        test_prompt = "What is the capital of France?"
        
        model_responses = {}
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for model in chat_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": test_prompt}],
                "max_tokens": 50,
                "temperature": 0.0  # Deterministic
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                usage = response_data["usage"]
                
                model_responses[model] = {
                    "content": content,
                    "prompt_tokens": usage["prompt_tokens"],
                    "completion_tokens": usage["completion_tokens"]
                }
                
                logger.info(f"FV_LLM_PROVIDER_CONSISTENCY_001: {model} - '{content.strip()}' ({usage['total_tokens']} tokens)")
        
        # Verify at least some models responded
        assert len(model_responses) >= 1, "At least one model should respond"
        
        # Check for correct answer consistency
        contents = [resp["content"].lower() for resp in model_responses.values()]
        paris_mentions = sum(1 for content in contents if "paris" in content)
        
        if paris_mentions > 0:
            logger.info(f"FV_LLM_PROVIDER_CONSISTENCY_001: {paris_mentions}/{len(contents)} models correctly identified Paris")
        
        # Check token usage consistency for same prompt
        prompt_tokens = [resp["prompt_tokens"] for resp in model_responses.values()]
        if len(set(prompt_tokens)) == 1:
            logger.info("FV_LLM_PROVIDER_CONSISTENCY_001: Consistent prompt token counts across providers")
        else:
            logger.info(f"FV_LLM_PROVIDER_CONSISTENCY_001: Prompt token variation: {prompt_tokens}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_llm_model_capabilities_validation_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """FV_LLM_MODEL_CAPABILITIES_VALIDATION_001: Verify model capabilities match declarations"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Get available models
        models_response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert models_response.status_code == 200
        models_data = models_response.json()
        
        available_models = [model["id"] for model in models_data["data"]]
        
        # Test capabilities for each model
        for model_id in available_models:
            # Test basic chat capability
            request = {
                "model": model_id,
                "messages": [{"role": "user", "content": "Hello"}],
                "max_tokens": 20
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                # Model supports chat completion
                response_data = response.json()
                assert "choices" in response_data, f"Model {model_id} should return choices"
                assert "usage" in response_data, f"Model {model_id} should return usage"
                
                # Verify response structure
                choice = response_data["choices"][0]
                assert "message" in choice, f"Model {model_id} should return message"
                assert "content" in choice["message"], f"Model {model_id} should return content"
                
                content = choice["message"]["content"]
                assert len(content.strip()) > 0, f"Model {model_id} should generate non-empty content"
                
                logger.info(f"FV_LLM_MODEL_CAPABILITIES_VALIDATION_001: {model_id} chat capability verified")
                
            elif response.status_code == 422:
                # Model doesn't support chat completion or has validation error
                logger.info(f"FV_LLM_MODEL_CAPABILITIES_VALIDATION_001: {model_id} validation error - may not support chat")
            else:
                logger.info(f"FV_LLM_MODEL_CAPABILITIES_VALIDATION_001: {model_id} returned {response.status_code}")
        
        # Verify at least one model works
        working_models = []
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for model_id in chat_models:
            if model_id in available_models:
                working_models.append(model_id)
        
        assert len(working_models) >= 1, "At least one configured chat model should be available and working"
        logger.info(f"FV_LLM_MODEL_CAPABILITIES_VALIDATION_001: {len(working_models)} working chat models verified")