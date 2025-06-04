# Section 7.2 - Edge Case Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Edge Case Testing.md

import pytest
import httpx
import base64
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestEmptyNullInputs:
    """Test handling of empty and null inputs"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_empty_chat_content_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """FV_EDGE_EMPTY_CHAT_CONTENT_001: Test empty message content"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        empty_content_requests = [
            # Completely empty string
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": ""}],
                "max_tokens": 50
            },
            # Only whitespace
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "   "}],
                "max_tokens": 50
            },
            # Multiple empty messages
            {
                "model": config.get_chat_model(0),
                "messages": [
                    {"role": "user", "content": ""},
                    {"role": "assistant", "content": ""},
                    {"role": "user", "content": ""}
                ],
                "max_tokens": 50
            }
        ]
        
        for i, request in enumerate(empty_content_requests):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should be rejected with validation error
            assert response.status_code == 422, f"Empty content request {i+1} should be rejected"
            
            response_data = response.json()
            assert "detail" in response_data
            
            # Error should indicate content validation issue
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in [
                "content", "empty", "required", "validation", "invalid"
            ]), f"Error should indicate content issue for request {i+1}"
            
            logger.info(f"FV_EDGE_EMPTY_CHAT_CONTENT_001: Empty content request {i+1} properly rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_empty_embed_input_str_001(self, http_client: httpx.AsyncClient,
                                                    embedding_auth_headers: Dict[str, str],
                                                    make_request):
        """FV_EDGE_EMPTY_EMBED_INPUT_STR_001: Test empty embedding input string"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        empty_input_requests = [
            # Empty string
            {
                "model": config.get_embedding_model(0),
                "input": ""
            },
            # Only whitespace
            {
                "model": config.get_embedding_model(0),
                "input": "   "
            },
            # Tab and newline characters
            {
                "model": config.get_embedding_model(0),
                "input": "\t\n"
            }
        ]
        
        for i, request in enumerate(empty_input_requests):
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request, track_cost=False
            )
            
            # Should be rejected with validation error
            assert response.status_code == 422, f"Empty embedding input {i+1} should be rejected"
            
            response_data = response.json()
            assert "detail" in response_data
            
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in [
                "input", "empty", "required", "validation", "invalid"
            ]), f"Error should indicate input issue for request {i+1}"
            
            logger.info(f"FV_EDGE_EMPTY_EMBED_INPUT_STR_001: Empty embedding input {i+1} properly rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_empty_embed_input_list_001(self, http_client: httpx.AsyncClient,
                                                     embedding_auth_headers: Dict[str, str],
                                                     make_request):
        """FV_EDGE_EMPTY_EMBED_INPUT_LIST_001: Test empty string in embedding list"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        empty_list_requests = [
            # Empty list
            {
                "model": config.get_embedding_model(0),
                "input": []
            },
            # List with empty string
            {
                "model": config.get_embedding_model(0),
                "input": [""]
            },
            # Mixed list with empty strings
            {
                "model": config.get_embedding_model(0),
                "input": ["Valid text", "", "More text"]
            }
        ]
        
        for i, request in enumerate(empty_list_requests):
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request, track_cost=False
            )
            
            # Should be rejected with validation error
            assert response.status_code == 422, f"Empty list input {i+1} should be rejected"
            
            response_data = response.json()
            assert "detail" in response_data
            
            logger.info(f"FV_EDGE_EMPTY_EMBED_INPUT_LIST_001: Empty list input {i+1} properly rejected")


class TestUnicodeSpecialCharacters:
    """Test Unicode and special character handling"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_unicode_chat_prompt_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """FV_EDGE_UNICODE_CHAT_PROMPT_001: Test Unicode characters in chat prompts"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        unicode_prompts = [
            # Emoji
            "Hello! 😊 Can you help me? 🤔",
            # Chinese characters
            "你好，请问你会说中文吗？",
            # Arabic
            "مرحبا، كيف حالك؟",
            # Math symbols
            "Calculate: ∑(n=1 to ∞) 1/n² = π²/6",
            # Special punctuation
            "What's the meaning of \"life\"? It's quite… complex!",
            # Mixed Unicode
            "Café naïve résumé 北京 🌟 ∞ →"
        ]
        
        for i, prompt in enumerate(unicode_prompts):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Unicode prompt {i+1} should be processed successfully"
            
            response_data = response.json()
            assert "choices" in response_data
            assert len(response_data["choices"]) > 0
            
            # Response should contain valid content
            content = response_data["choices"][0]["message"]["content"]
            assert len(content) > 0, f"Unicode prompt {i+1} should generate non-empty response"
            
            logger.info(f"FV_EDGE_UNICODE_CHAT_PROMPT_001: Unicode prompt {i+1} processed successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_unicode_embed_input_001(self, http_client: httpx.AsyncClient,
                                                  embedding_auth_headers: Dict[str, str],
                                                  make_request):
        """FV_EDGE_UNICODE_EMBED_INPUT_001: Test Unicode in embedding inputs"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        unicode_inputs = [
            "Café résumé naïve",
            "北京欢迎你",
            "математика и физика",
            "🌟⭐✨💫🔥",
            "α + β = γ ∞"
        ]
        
        for i, input_text in enumerate(unicode_inputs):
            request = {
                "model": config.get_embedding_model(0),
                "input": input_text
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request
            )
            
            assert response.status_code == 200, f"Unicode embedding input {i+1} should be processed"
            
            response_data = response.json()
            assert "data" in response_data
            assert len(response_data["data"]) > 0
            assert "embedding" in response_data["data"][0]
            
            embedding = response_data["data"][0]["embedding"]
            assert isinstance(embedding, list), "Embedding should be a list"
            assert len(embedding) > 0, "Embedding should not be empty"
            
            logger.info(f"FV_EDGE_UNICODE_EMBED_INPUT_001: Unicode embedding {i+1} processed successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_unicode_rtl_chat_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """FV_EDGE_UNICODE_RTL_CHAT_001: Test Right-to-Left text"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        rtl_prompts = [
            # Arabic
            "كيف حالك اليوم؟ أرجو أن تكون بخير",
            # Hebrew
            "שלום, איך שלומך היום?",
            # Mixed RTL and LTR
            "Hello مرحبا world עולם 123"
        ]
        
        for i, prompt in enumerate(rtl_prompts):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"RTL prompt {i+1} should be processed"
            
            response_data = response.json()
            content = response_data["choices"][0]["message"]["content"]
            assert len(content) > 0, f"RTL prompt {i+1} should generate response"
            
            logger.info(f"FV_EDGE_UNICODE_RTL_CHAT_001: RTL prompt {i+1} processed successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_unicode_control_chars_chat_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """FV_EDGE_UNICODE_CONTROL_CHARS_CHAT_001: Test control characters"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        control_char_prompts = [
            # Tab and newline
            "Line 1\nLine 2\tTabbed text",
            # Carriage return
            "Text with\rcarriage return",
            # Zero-width characters (should be handled gracefully)
            "Text\u200Bwith\u200Czero\u200Dwidth\u2060chars",
            # Form feed and vertical tab
            "Text\fwith\vspecial\nwhitespace"
        ]
        
        for i, prompt in enumerate(control_char_prompts):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            # Should either succeed or be rejected gracefully
            assert response.status_code in [200, 422], f"Control chars prompt {i+1} should be handled gracefully"
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                assert len(content) > 0, f"Control chars prompt {i+1} should generate response"
            
            logger.info(f"FV_EDGE_UNICODE_CONTROL_CHARS_CHAT_001: Control chars prompt {i+1} handled")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_unicode_multimodal_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 multimodal_fixtures,
                                                 make_request):
        """FV_EDGE_UNICODE_MULTIMODAL_001: Test Unicode in multimodal content"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Get test image
        test_image = multimodal_fixtures.get_test_image_base64()
        
        unicode_multimodal_requests = [
            {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "这张图片显示什么？"},  # Chinese
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:image/jpeg;base64,{test_image}"}
                            }
                        ]
                    }
                ],
                "max_tokens": 100
            },
            {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Describe this image 🖼️ in detail"},  # Emoji
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:image/jpeg;base64,{test_image}"}
                            }
                        ]
                    }
                ],
                "max_tokens": 100
            }
        ]
        
        for i, request in enumerate(unicode_multimodal_requests):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 422:
                # Multimodal not supported
                pytest.skip("Multimodal content not supported")
            
            assert response.status_code == 200, f"Unicode multimodal request {i+1} should be processed"
            
            response_data = response.json()
            content = response_data["choices"][0]["message"]["content"]
            assert len(content) > 0, f"Unicode multimodal request {i+1} should generate response"
            
            logger.info(f"FV_EDGE_UNICODE_MULTIMODAL_001: Unicode multimodal request {i+1} processed")


class TestLargePayloads:
    """Test handling of large payloads and size limits"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_large_chat_prompt_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """FV_EDGE_LARGE_CHAT_PROMPT_001: Test very long prompts"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Generate increasingly large prompts
        large_prompts = [
            # 1K characters
            "A" * 1000,
            # 5K characters
            "B" * 5000,
            # 10K characters
            "C" * 10000,
            # Very large - 50K characters
            "D" * 50000
        ]
        
        for i, prompt in enumerate(large_prompts):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            # Should either succeed or be rejected with appropriate error
            if response.status_code == 200:
                response_data = response.json()
                assert "choices" in response_data
                logger.info(f"FV_EDGE_LARGE_CHAT_PROMPT_001: Large prompt {i+1} ({len(prompt)} chars) processed")
            elif response.status_code == 422:
                # Context length exceeded or validation error
                response_data = response.json()
                assert "detail" in response_data
                logger.info(f"FV_EDGE_LARGE_CHAT_PROMPT_001: Large prompt {i+1} appropriately rejected")
            elif response.status_code == 413:
                # Payload too large
                logger.info(f"FV_EDGE_LARGE_CHAT_PROMPT_001: Large prompt {i+1} rejected - payload too large")
            else:
                pytest.fail(f"Unexpected status code {response.status_code} for large prompt {i+1}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_large_chat_num_messages_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """FV_EDGE_LARGE_CHAT_NUM_MESSAGES_001: Test many messages in array"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with increasing number of messages
        message_counts = [10, 50, 100]
        
        for count in message_counts:
            # Generate conversation with many messages
            messages = []
            for i in range(count):
                if i % 2 == 0:
                    messages.append({"role": "user", "content": f"User message {i+1}"})
                else:
                    messages.append({"role": "assistant", "content": f"Assistant response {i}"})
            
            request = {
                "model": config.get_chat_model(0),
                "messages": messages,
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            # Should handle gracefully
            if response.status_code == 200:
                logger.info(f"FV_EDGE_LARGE_CHAT_NUM_MESSAGES_001: {count} messages processed successfully")
            elif response.status_code == 422:
                logger.info(f"FV_EDGE_LARGE_CHAT_NUM_MESSAGES_001: {count} messages appropriately rejected")
            else:
                logger.info(f"FV_EDGE_LARGE_CHAT_NUM_MESSAGES_001: {count} messages returned {response.status_code}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_large_embed_input_batch_001(self, http_client: httpx.AsyncClient,
                                                      embedding_auth_headers: Dict[str, str],
                                                      make_request):
        """FV_EDGE_LARGE_EMBED_INPUT_BATCH_001: Test large embedding batches"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with increasing batch sizes
        batch_sizes = [5, 20, 50]
        
        for batch_size in batch_sizes:
            # Generate batch of inputs
            inputs = [f"Embedding text number {i+1} for batch processing" for i in range(batch_size)]
            
            request = {
                "model": config.get_embedding_model(0),
                "input": inputs
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request
            )
            
            if response.status_code == 200:
                response_data = response.json()
                assert "data" in response_data
                assert len(response_data["data"]) == batch_size
                logger.info(f"FV_EDGE_LARGE_EMBED_INPUT_BATCH_001: Batch of {batch_size} embeddings processed")
            elif response.status_code == 422:
                logger.info(f"FV_EDGE_LARGE_EMBED_INPUT_BATCH_001: Batch of {batch_size} appropriately rejected")
            else:
                logger.info(f"FV_EDGE_LARGE_EMBED_INPUT_BATCH_001: Batch of {batch_size} returned {response.status_code}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_large_request_size_limit_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_EDGE_LARGE_REQUEST_SIZE_LIMIT_001: Test request size limits"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Create extremely large request (beyond reasonable limits)
        very_large_content = "X" * 100000  # 100K characters
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": very_large_content}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        # Should be rejected with appropriate error
        assert response.status_code in [413, 422, 400], "Very large request should be rejected"
        
        if response.status_code == 413:
            logger.info("FV_EDGE_LARGE_REQUEST_SIZE_LIMIT_001: Request properly rejected - payload too large")
        elif response.status_code == 422:
            response_data = response.json()
            assert "detail" in response_data
            logger.info("FV_EDGE_LARGE_REQUEST_SIZE_LIMIT_001: Request properly rejected - validation error")
        else:
            logger.info(f"FV_EDGE_LARGE_REQUEST_SIZE_LIMIT_001: Request rejected with status {response.status_code}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_large_multimodal_image_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     multimodal_fixtures,
                                                     make_request):
        """FV_EDGE_LARGE_MULTIMODAL_IMAGE_001: Test oversized images"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Create oversized image data (simulate large image)
        large_image_data = base64.b64encode(b"X" * 50000).decode()  # 50KB of data
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Describe this large image"},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{large_image_data}"}
                        }
                    ]
                }
            ],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        # Should handle gracefully
        if response.status_code == 422:
            # Either multimodal not supported or image too large
            response_data = response.json()
            detail_str = str(response_data.get("detail", "")).lower()
            if "image" in detail_str or "multimodal" in detail_str or "size" in detail_str:
                logger.info("FV_EDGE_LARGE_MULTIMODAL_IMAGE_001: Large image appropriately rejected")
            else:
                pytest.skip("Multimodal content not supported")
        elif response.status_code == 413:
            logger.info("FV_EDGE_LARGE_MULTIMODAL_IMAGE_001: Large image rejected - payload too large")
        elif response.status_code == 200:
            logger.info("FV_EDGE_LARGE_MULTIMODAL_IMAGE_001: Large image processed successfully")
        else:
            logger.info(f"FV_EDGE_LARGE_MULTIMODAL_IMAGE_001: Large image returned {response.status_code}")


class TestConcurrentRequests:
    """Test concurrent request handling edge cases"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_concurrent_chat_same_key_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_EDGE_CONCURRENT_CHAT_SAME_KEY_001: Test concurrent chat requests with same key"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        import asyncio
        
        async def concurrent_chat_request(request_id: int):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Concurrent chat request {request_id}"}],
                "max_tokens": 50
            }
            
            return await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
        
        # Create 8 concurrent requests with same API key
        tasks = [concurrent_chat_request(i) for i in range(8)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        successful_responses = 0
        rate_limited_responses = 0
        error_responses = 0
        
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                error_responses += 1
                logger.warning(f"Concurrent chat request {i} failed: {response}")
            elif hasattr(response, 'status_code'):
                if response.status_code == 200:
                    successful_responses += 1
                elif response.status_code == 429:
                    rate_limited_responses += 1
                else:
                    error_responses += 1
                    logger.info(f"Concurrent chat request {i} returned {response.status_code}")
        
        # Some requests should succeed, rate limiting is acceptable
        total_handled = successful_responses + rate_limited_responses
        assert total_handled >= 4, f"At least 4 requests should be handled (success or rate limit), got {total_handled}"
        
        logger.info(f"FV_EDGE_CONCURRENT_CHAT_SAME_KEY_001: {successful_responses} successful, {rate_limited_responses} rate limited, {error_responses} errors")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_concurrent_embed_same_key_001(self, http_client: httpx.AsyncClient,
                                                        embedding_auth_headers: Dict[str, str],
                                                        make_request):
        """FV_EDGE_CONCURRENT_EMBED_SAME_KEY_001: Test concurrent embedding requests"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        import asyncio
        
        async def concurrent_embed_request(request_id: int):
            request = {
                "model": config.get_embedding_model(0),
                "input": f"Concurrent embedding request {request_id}"
            }
            
            return await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request
            )
        
        # Create 6 concurrent embedding requests
        tasks = [concurrent_embed_request(i) for i in range(6)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        successful_responses = 0
        handled_responses = 0
        
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.warning(f"Concurrent embed request {i} failed: {response}")
            elif hasattr(response, 'status_code'):
                handled_responses += 1
                if response.status_code == 200:
                    successful_responses += 1
                    # Verify embedding response
                    response_data = response.json()
                    assert "data" in response_data
                    assert len(response_data["data"]) > 0
                    assert "embedding" in response_data["data"][0]
        
        assert handled_responses >= 3, f"At least 3 requests should be handled, got {handled_responses}"
        
        logger.info(f"FV_EDGE_CONCURRENT_EMBED_SAME_KEY_001: {successful_responses}/{handled_responses} concurrent embedding requests successful")


class TestMalformedData:
    """Test handling of malformed request data"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_malformed_message_role_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_EDGE_MALFORMED_MESSAGE_ROLE_001: Test invalid message roles"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        malformed_role_requests = [
            # Invalid role
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "invalid_role", "content": "Test invalid role"}],
                "max_tokens": 50
            },
            # Missing role
            {
                "model": config.get_chat_model(0),
                "messages": [{"content": "Test missing role"}],
                "max_tokens": 50
            },
            # Null role
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": None, "content": "Test null role"}],
                "max_tokens": 50
            },
            # Empty role
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "", "content": "Test empty role"}],
                "max_tokens": 50
            }
        ]
        
        for i, request in enumerate(malformed_role_requests):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            assert response.status_code == 422, f"Malformed role request {i+1} should be rejected"
            
            response_data = response.json()
            assert "detail" in response_data
            
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in [
                "role", "invalid", "required", "validation"
            ]), f"Error should indicate role validation issue for request {i+1}"
            
            logger.info(f"FV_EDGE_MALFORMED_MESSAGE_ROLE_001: Malformed role request {i+1} properly rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_malformed_choice_index_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_EDGE_MALFORMED_CHOICE_INDEX_001: Test choice indexing with n>1"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with n parameter > 1 (multiple choices)
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Generate multiple responses"}],
            "max_tokens": 50,
            "n": 3  # Request 3 choices
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 200:
            response_data = response.json()
            assert "choices" in response_data
            
            # Should have 3 choices
            choices = response_data["choices"]
            assert len(choices) == 3, "Should return 3 choices when n=3"
            
            # Each choice should have correct index
            for i, choice in enumerate(choices):
                assert "index" in choice, f"Choice {i} should have index"
                assert choice["index"] == i, f"Choice {i} should have index {i}"
                assert "message" in choice, f"Choice {i} should have message"
                assert "content" in choice["message"], f"Choice {i} should have content"
            
            logger.info("FV_EDGE_MALFORMED_CHOICE_INDEX_001: Multiple choices with correct indexing")
        elif response.status_code == 422:
            # n > 1 not supported
            response_data = response.json()
            detail_str = str(response_data.get("detail", "")).lower()
            if "n" in detail_str or "choice" in detail_str or "multiple" in detail_str:
                logger.info("FV_EDGE_MALFORMED_CHOICE_INDEX_001: Multiple choices not supported")
            else:
                pytest.fail("Unexpected validation error for n parameter")
        else:
            pytest.fail(f"Unexpected status code {response.status_code} for n parameter test")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_malformed_multimodal_data_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """FV_EDGE_MALFORMED_MULTIMODAL_DATA_001: Test malformed image data URIs"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        malformed_multimodal_requests = [
            # Invalid base64 data
            {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Describe this image"},
                            {
                                "type": "image_url",
                                "image_url": {"url": "data:image/jpeg;base64,invalid_base64_data!!!"}
                            }
                        ]
                    }
                ],
                "max_tokens": 100
            },
            # Missing data URI prefix
            {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Describe this image"},
                            {
                                "type": "image_url",
                                "image_url": {"url": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="}
                            }
                        ]
                    }
                ],
                "max_tokens": 100
            },
            # Empty image URL
            {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Describe this image"},
                            {
                                "type": "image_url",
                                "image_url": {"url": ""}
                            }
                        ]
                    }
                ],
                "max_tokens": 100
            }
        ]
        
        for i, request in enumerate(malformed_multimodal_requests):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should be rejected with validation error
            assert response.status_code == 422, f"Malformed multimodal request {i+1} should be rejected"
            
            response_data = response.json()
            assert "detail" in response_data
            
            logger.info(f"FV_EDGE_MALFORMED_MULTIMODAL_DATA_001: Malformed multimodal request {i+1} properly rejected")


class TestParameterEdgeCases:
    """Test edge cases in parameter values"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_param_max_tokens_zero_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """FV_EDGE_PARAM_MAX_TOKENS_ZERO_001: Test max_tokens=0"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test max_tokens zero"}],
            "max_tokens": 0
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request, track_cost=False
        )
        
        # Should be rejected
        assert response.status_code == 422, "max_tokens=0 should be rejected"
        
        response_data = response.json()
        assert "detail" in response_data
        
        detail_str = str(response_data["detail"]).lower()
        assert any(keyword in detail_str for keyword in [
            "max_tokens", "token", "greater", "positive", "validation"
        ]), "Error should indicate max_tokens validation issue"
        
        logger.info("FV_EDGE_PARAM_MAX_TOKENS_ZERO_001: max_tokens=0 properly rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_param_temperature_extreme_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """FV_EDGE_PARAM_TEMPERATURE_EXTREME_001: Test extreme temperature values"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        extreme_temps = [-1.0, 3.0, 100.0, -0.5]
        
        for temp in extreme_temps:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Test temperature {temp}"}],
                "max_tokens": 50,
                "temperature": temp
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should be rejected for out-of-range values
            assert response.status_code == 422, f"Temperature {temp} should be rejected"
            
            response_data = response.json()
            assert "detail" in response_data
            
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in [
                "temperature", "range", "between", "validation"
            ]), f"Error should indicate temperature validation issue for {temp}"
            
            logger.info(f"FV_EDGE_PARAM_TEMPERATURE_EXTREME_001: Temperature {temp} properly rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_edge_param_top_p_invalid_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """FV_EDGE_PARAM_TOP_P_INVALID_001: Test invalid top_p values"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        invalid_top_p_values = [-0.1, 1.5, 2.0, -1.0]
        
        for top_p in invalid_top_p_values:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Test top_p {top_p}"}],
                "max_tokens": 50,
                "top_p": top_p
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should be rejected for out-of-range values
            assert response.status_code == 422, f"top_p {top_p} should be rejected"
            
            response_data = response.json()
            assert "detail" in response_data
            
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in [
                "top_p", "range", "between", "validation", "0", "1"
            ]), f"Error should indicate top_p validation issue for {top_p}"
            
            logger.info(f"FV_EDGE_PARAM_TOP_P_INVALID_001: top_p {top_p} properly rejected")