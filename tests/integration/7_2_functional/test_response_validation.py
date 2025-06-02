# Section 7.2 - Response Validation Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Response Validation.md

import pytest
import httpx
import json
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestSuccessResponseValidation:
    """Test structure and content of successful responses"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_models_list_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """FV_RESP_MODELS_LIST_001: Test /models response structure"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Validate top-level structure
        assert "data" in response_data, "Response should contain 'data' field"
        assert isinstance(response_data["data"], list), "Data field should be a list"
        assert len(response_data["data"]) > 0, "Should return at least one model"
        
        # Validate optional fields
        if "object" in response_data:
            assert response_data["object"] == "list", "Object field should be 'list'"
        
        # Validate each model entry
        for i, model in enumerate(response_data["data"]):
            assert isinstance(model, dict), f"Model {i} should be a dictionary"
            
            # Required fields
            assert "id" in model, f"Model {i} should have 'id' field"
            assert "object" in model, f"Model {i} should have 'object' field"
            assert model["object"] == "model", f"Model {i} object should be 'model'"
            
            # Validate ID format
            model_id = model["id"]
            assert isinstance(model_id, str), f"Model {i} ID should be string"
            assert len(model_id) > 0, f"Model {i} ID should not be empty"
            
            # Optional fields validation
            if "created" in model:
                assert isinstance(model["created"], int), f"Model {i} created should be integer timestamp"
            
            if "owned_by" in model:
                assert isinstance(model["owned_by"], str), f"Model {i} owned_by should be string"
            
            logger.info(f"FV_RESP_MODELS_LIST_001: Model {i}: {model_id}")
        
        logger.info(f"FV_RESP_MODELS_LIST_001: Validated {len(response_data['data'])} models")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_chat_success_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """FV_RESP_CHAT_SUCCESS_001: Test chat completion response structure"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test chat response validation"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Required top-level fields
        required_fields = ["id", "object", "created", "model", "choices"]
        for field in required_fields:
            assert field in response_data, f"Response should contain '{field}' field"
        
        # Validate field types and values
        assert isinstance(response_data["id"], str), "ID should be string"
        assert len(response_data["id"]) > 0, "ID should not be empty"
        assert response_data["object"] == "chat.completion", "Object should be 'chat.completion'"
        assert isinstance(response_data["created"], int), "Created should be integer timestamp"
        assert isinstance(response_data["model"], str), "Model should be string"
        assert isinstance(response_data["choices"], list), "Choices should be list"
        assert len(response_data["choices"]) > 0, "Should have at least one choice"
        
        # Validate choices structure
        for i, choice in enumerate(response_data["choices"]):
            assert isinstance(choice, dict), f"Choice {i} should be dictionary"
            
            # Required choice fields
            choice_required = ["index", "message"]
            for field in choice_required:
                assert field in choice, f"Choice {i} should contain '{field}'"
            
            assert isinstance(choice["index"], int), f"Choice {i} index should be integer"
            assert choice["index"] == i, f"Choice {i} index should match position"
            
            # Validate message structure
            message = choice["message"]
            assert isinstance(message, dict), f"Choice {i} message should be dictionary"
            assert "role" in message, f"Choice {i} message should have role"
            assert "content" in message, f"Choice {i} message should have content"
            assert message["role"] == "assistant", f"Choice {i} message role should be 'assistant'"
            assert isinstance(message["content"], str), f"Choice {i} content should be string"
            
            # Optional choice fields
            if "finish_reason" in choice:
                valid_reasons = ["stop", "length", "content_filter", "tool_calls", "function_call"]
                assert choice["finish_reason"] in valid_reasons or choice["finish_reason"] is None, \
                    f"Choice {i} finish_reason should be valid"
        
        # Validate usage (if present)
        if "usage" in response_data:
            usage = response_data["usage"]
            assert isinstance(usage, dict), "Usage should be dictionary"
            
            usage_fields = ["prompt_tokens", "completion_tokens", "total_tokens"]
            for field in usage_fields:
                if field in usage:
                    assert isinstance(usage[field], int), f"Usage {field} should be integer"
                    assert usage[field] >= 0, f"Usage {field} should be non-negative"
            
            if all(field in usage for field in usage_fields):
                assert usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"], \
                    "Total tokens should equal sum of prompt and completion tokens"
        
        logger.info("FV_RESP_CHAT_SUCCESS_001: Chat completion response structure validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_chat_multimodal_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              multimodal_fixtures,
                                              make_request):
        """FV_RESP_CHAT_MULTIMODAL_001: Test multimodal response structure"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Get test image
        test_image = multimodal_fixtures.get_test_image_base64()
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Describe this image"},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{test_image}"}
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
        
        if response.status_code == 422:
            # Multimodal not supported
            pytest.skip("Multimodal content not supported")
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Should follow same structure as regular chat completion
        assert "choices" in response_data
        assert len(response_data["choices"]) > 0
        
        choice = response_data["choices"][0]
        assert "message" in choice
        message = choice["message"]
        assert "content" in message
        assert isinstance(message["content"], str)
        assert len(message["content"]) > 0, "Multimodal response should have content"
        
        # Usage should account for image processing
        if "usage" in response_data:
            usage = response_data["usage"]
            assert usage["prompt_tokens"] > 10, "Image processing should contribute to prompt tokens"
        
        logger.info("FV_RESP_CHAT_MULTIMODAL_001: Multimodal response structure validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_embed_success_001(self, http_client: httpx.AsyncClient,
                                            embedding_auth_headers: Dict[str, str],
                                            make_request):
        """FV_RESP_EMBED_SUCCESS_001: Test embedding response structure"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_embedding_model(0),
            "input": "Test embedding response validation"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Required top-level fields
        required_fields = ["object", "data", "model"]
        for field in required_fields:
            assert field in response_data, f"Response should contain '{field}' field"
        
        # Validate field types and values
        assert response_data["object"] == "list", "Object should be 'list'"
        assert isinstance(response_data["data"], list), "Data should be list"
        assert len(response_data["data"]) > 0, "Should have at least one embedding"
        assert isinstance(response_data["model"], str), "Model should be string"
        
        # Validate embedding data structure
        for i, embedding_obj in enumerate(response_data["data"]):
            assert isinstance(embedding_obj, dict), f"Embedding {i} should be dictionary"
            
            # Required embedding fields
            embedding_required = ["object", "embedding", "index"]
            for field in embedding_required:
                assert field in embedding_obj, f"Embedding {i} should contain '{field}'"
            
            assert embedding_obj["object"] == "embedding", f"Embedding {i} object should be 'embedding'"
            assert isinstance(embedding_obj["index"], int), f"Embedding {i} index should be integer"
            assert embedding_obj["index"] == i, f"Embedding {i} index should match position"
            
            # Validate embedding vector
            embedding = embedding_obj["embedding"]
            assert isinstance(embedding, list), f"Embedding {i} should be list of numbers"
            assert len(embedding) > 0, f"Embedding {i} should not be empty"
            
            # All values should be numbers
            for j, value in enumerate(embedding):
                assert isinstance(value, (int, float)), f"Embedding {i}[{j}] should be numeric"
                assert not (isinstance(value, float) and (value != value)), f"Embedding {i}[{j}] should not be NaN"
        
        # Validate usage (if present)
        if "usage" in response_data:
            usage = response_data["usage"]
            assert isinstance(usage, dict), "Usage should be dictionary"
            assert "prompt_tokens" in usage, "Usage should contain prompt_tokens"
            assert "total_tokens" in usage, "Usage should contain total_tokens"
            assert isinstance(usage["prompt_tokens"], int), "Prompt tokens should be integer"
            assert isinstance(usage["total_tokens"], int), "Total tokens should be integer"
            assert usage["prompt_tokens"] > 0, "Prompt tokens should be positive"
            assert usage["total_tokens"] >= usage["prompt_tokens"], "Total should be >= prompt tokens"
        
        logger.info(f"FV_RESP_EMBED_SUCCESS_001: Embedding response with {len(response_data['data'])} embeddings validated")


class TestErrorResponseValidation:
    """Test structure and content of error responses"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_error_generic_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """FV_RESP_ERROR_GENERIC_001: Test generic error response structure"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Trigger generic error with invalid model
        request = {
            "model": "completely-invalid-model-name",
            "messages": [{"role": "user", "content": "Test error response"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request, track_cost=False
        )
        
        assert response.status_code == 422
        response_data = response.json()
        
        # Should contain detail field
        assert "detail" in response_data, "Error response should contain 'detail' field"
        
        detail = response_data["detail"]
        if isinstance(detail, str):
            assert len(detail) > 0, "Error detail should not be empty"
        elif isinstance(detail, list):
            # Pydantic validation errors format
            assert len(detail) > 0, "Error detail list should not be empty"
            for error in detail:
                assert isinstance(error, dict), "Error detail item should be dictionary"
                assert "msg" in error, "Error should have message"
        else:
            pytest.fail(f"Error detail should be string or list, got {type(detail)}")
        
        # Should not contain sensitive information
        response_text = json.dumps(response_data).lower()
        sensitive_terms = ["password", "secret", "key", "token", "internal", "traceback"]
        for term in sensitive_terms:
            assert term not in response_text, f"Error response should not contain '{term}'"
        
        logger.info("FV_RESP_ERROR_GENERIC_001: Generic error response structure validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_error_422_pydantic_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """FV_RESP_ERROR_422_PYDANTIC_001: Test Pydantic validation error structure"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Trigger Pydantic validation error
        request = {
            "model": config.get_chat_model(0),
            "messages": "not_an_array",  # Should be array
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request, track_cost=False
        )
        
        assert response.status_code == 422
        response_data = response.json()
        
        assert "detail" in response_data, "Validation error should contain 'detail'"
        
        detail = response_data["detail"]
        if isinstance(detail, list):
            # Pydantic validation error format
            for error in detail:
                assert isinstance(error, dict), "Validation error should be dictionary"
                
                # Standard Pydantic error fields
                if "type" in error:
                    assert isinstance(error["type"], str), "Error type should be string"
                if "msg" in error:
                    assert isinstance(error["msg"], str), "Error message should be string"
                if "loc" in error:
                    assert isinstance(error["loc"], list), "Error location should be list"
                
                logger.info(f"FV_RESP_ERROR_422_PYDANTIC_001: Validation error - {error.get('msg', 'No message')}")
        
        logger.info("FV_RESP_ERROR_422_PYDANTIC_001: Pydantic validation error structure validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_error_provider_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """FV_RESP_ERROR_PROVIDER_001: Test provider error response structure"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Trigger provider-level error with extreme parameters
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "A" * 50000}],  # Very long prompt
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request, track_cost=False
        )
        
        # Should be some kind of error response
        assert response.status_code >= 400, "Should return error status"
        
        if response.status_code in [422, 400, 413]:
            response_data = response.json()
            assert "detail" in response_data, "Provider error should contain 'detail'"
            
            # Should not expose provider-specific internal details
            response_text = json.dumps(response_data).lower()
            provider_internals = ["bedrock", "vertex", "openai", "boto3", "google", "anthropic"]
            
            # Some provider names might be acceptable in user-facing errors
            # but internal implementation details should not be exposed
            internal_details = ["exception", "traceback", "stacktrace", "internal", "debug"]
            for detail in internal_details:
                assert detail not in response_text, f"Should not expose internal detail: {detail}"
            
            logger.info(f"FV_RESP_ERROR_PROVIDER_001: Provider error (status {response.status_code}) properly formatted")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_error_authentication_001(self, http_client: httpx.AsyncClient,
                                                   make_request):
        """FV_RESP_ERROR_AUTHENTICATION_001: Test authentication error structure"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test with invalid API key
        invalid_headers = {"Authorization": "Bearer invalid_api_key_test"}
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            invalid_headers, track_cost=False
        )
        
        assert response.status_code == 401
        response_data = response.json()
        
        assert "detail" in response_data, "Authentication error should contain 'detail'"
        
        detail = response_data["detail"]
        assert isinstance(detail, str), "Authentication error detail should be string"
        assert len(detail) > 0, "Authentication error detail should not be empty"
        
        # Should indicate authentication issue
        detail_lower = detail.lower()
        auth_keywords = ["authentication", "unauthorized", "invalid", "api key", "token"]
        assert any(keyword in detail_lower for keyword in auth_keywords), \
            "Authentication error should indicate auth issue"
        
        # Should not expose sensitive details
        sensitive_terms = ["database", "query", "internal", "secret"]
        for term in sensitive_terms:
            assert term not in detail_lower, f"Should not expose sensitive term: {term}"
        
        logger.info("FV_RESP_ERROR_AUTHENTICATION_001: Authentication error structure validated")


class TestStreamingResponseValidation:
    """Test streaming response format and structure"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_stream_format_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """FV_RESP_STREAM_FORMAT_001: Test SSE format validation"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Count to 5"}],
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
        
        # Check headers
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            # Validate SSE format
            stream_content = response.text
            
            # Parse SSE stream
            lines = stream_content.split('\n')
            data_lines = []
            
            for line in lines:
                if line.startswith('data: '):
                    data_part = line[6:]  # Remove 'data: '
                    data_lines.append(data_part)
                elif line.strip() == '' or line.startswith('event: ') or line.startswith('id: '):
                    # Valid SSE format lines
                    pass
                elif line.strip():  # Non-empty, non-SSE line
                    logger.warning(f"Unexpected line in SSE stream: {line}")
            
            assert len(data_lines) > 0, "Should have at least one data line"
            
            # Validate data content
            valid_json_count = 0
            for data in data_lines:
                if data.strip() == '[DONE]':
                    logger.info("FV_RESP_STREAM_FORMAT_001: Found [DONE] marker")
                    continue
                
                if data.strip():
                    try:
                        chunk_data = json.loads(data)
                        valid_json_count += 1
                        
                        # Validate chunk structure
                        assert "object" in chunk_data, "Chunk should have object field"
                        assert chunk_data["object"] == "chat.completion.chunk", "Object should be chat.completion.chunk"
                        assert "choices" in chunk_data, "Chunk should have choices"
                        
                    except json.JSONDecodeError as e:
                        pytest.fail(f"Invalid JSON in stream data: {data} - {e}")
            
            assert valid_json_count > 0, "Should have at least one valid JSON chunk"
            logger.info(f"FV_RESP_STREAM_FORMAT_001: {valid_json_count} valid SSE chunks processed")
            
        else:
            logger.info("FV_RESP_STREAM_FORMAT_001: Non-streaming response despite stream=True")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_stream_chunk_schema_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """FV_RESP_STREAM_CHUNK_SCHEMA_001: Test streaming chunk schema"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Tell me about AI"}],
            "max_tokens": 30,
            "stream": True
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            pytest.skip("Streaming not supported")
        
        assert response.status_code == 200
        
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            stream_content = response.text
            
            chunks_processed = 0
            for line in stream_content.split('\n'):
                if line.startswith('data: '):
                    data_part = line[6:]
                    if data_part.strip() and data_part.strip() != '[DONE]':
                        try:
                            chunk_data = json.loads(data_part)
                            chunks_processed += 1
                            
                            # Validate required fields
                            assert "id" in chunk_data, "Chunk should have id"
                            assert "object" in chunk_data, "Chunk should have object"
                            assert "created" in chunk_data, "Chunk should have created"
                            assert "model" in chunk_data, "Chunk should have model"
                            assert "choices" in chunk_data, "Chunk should have choices"
                            
                            # Validate choices structure
                            for choice in chunk_data["choices"]:
                                assert "index" in choice, "Choice should have index"
                                assert "delta" in choice, "Choice should have delta"
                                
                                delta = choice["delta"]
                                assert isinstance(delta, dict), "Delta should be dictionary"
                                
                                # Delta may contain role, content, etc.
                                if "role" in delta:
                                    assert delta["role"] == "assistant", "Delta role should be assistant"
                                if "content" in delta:
                                    assert isinstance(delta["content"], str), "Delta content should be string"
                            
                        except json.JSONDecodeError:
                            pytest.fail(f"Invalid JSON in chunk: {data_part}")
            
            assert chunks_processed > 0, "Should process at least one chunk"
            logger.info(f"FV_RESP_STREAM_CHUNK_SCHEMA_001: {chunks_processed} chunks validated")
        else:
            logger.info("FV_RESP_STREAM_CHUNK_SCHEMA_001: Non-streaming response")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_stream_termination_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """FV_RESP_STREAM_TERMINATION_001: Test streaming termination"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Say 'hello'"}],
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
        
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            stream_content = response.text
            
            found_done = False
            found_finish_reason = False
            last_chunk = None
            
            for line in stream_content.split('\n'):
                if line.startswith('data: '):
                    data_part = line[6:]
                    
                    if data_part.strip() == '[DONE]':
                        found_done = True
                        logger.info("FV_RESP_STREAM_TERMINATION_001: Found [DONE] termination marker")
                    elif data_part.strip():
                        try:
                            chunk_data = json.loads(data_part)
                            last_chunk = chunk_data
                            
                            # Check for finish_reason in choices
                            for choice in chunk_data.get("choices", []):
                                if choice.get("finish_reason") is not None:
                                    found_finish_reason = True
                                    finish_reason = choice["finish_reason"]
                                    logger.info(f"FV_RESP_STREAM_TERMINATION_001: Found finish_reason: {finish_reason}")
                        except json.JSONDecodeError:
                            pass
            
            # Should have proper termination
            if found_done:
                logger.info("FV_RESP_STREAM_TERMINATION_001: Stream properly terminated with [DONE]")
            elif found_finish_reason:
                logger.info("FV_RESP_STREAM_TERMINATION_001: Stream properly terminated with finish_reason")
            else:
                logger.info("FV_RESP_STREAM_TERMINATION_001: Stream termination method unclear")
        else:
            logger.info("FV_RESP_STREAM_TERMINATION_001: Non-streaming response")


class TestUsageMetrics:
    """Test usage metrics in responses"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_usage_chat_nonstream_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """FV_RESP_USAGE_CHAT_NONSTREAM_001: Test chat usage metrics"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Explain machine learning in 50 words"}],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "usage" in response_data, "Chat response should include usage metrics"
        usage = response_data["usage"]
        
        # Required usage fields
        required_fields = ["prompt_tokens", "completion_tokens", "total_tokens"]
        for field in required_fields:
            assert field in usage, f"Usage should contain {field}"
            assert isinstance(usage[field], int), f"Usage {field} should be integer"
            assert usage[field] >= 0, f"Usage {field} should be non-negative"
        
        # Logical consistency
        assert usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"], \
            "Total tokens should equal sum of prompt and completion tokens"
        
        assert usage["prompt_tokens"] > 0, "Prompt tokens should be positive for non-empty prompt"
        assert usage["completion_tokens"] > 0, "Completion tokens should be positive for response"
        
        # Reasonable bounds
        assert usage["prompt_tokens"] < 10000, "Prompt tokens should be reasonable"
        assert usage["completion_tokens"] <= 100, "Completion tokens should not exceed max_tokens significantly"
        
        logger.info(f"FV_RESP_USAGE_CHAT_NONSTREAM_001: Usage - {usage['prompt_tokens']} prompt + {usage['completion_tokens']} completion = {usage['total_tokens']} total")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_usage_embed_001(self, http_client: httpx.AsyncClient,
                                          embedding_auth_headers: Dict[str, str],
                                          make_request):
        """FV_RESP_USAGE_EMBED_001: Test embedding usage metrics"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_embedding_model(0),
            "input": "This is a test sentence for embedding usage metrics validation"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "usage" in response_data, "Embedding response should include usage metrics"
        usage = response_data["usage"]
        
        # Required fields for embeddings
        assert "prompt_tokens" in usage, "Usage should contain prompt_tokens"
        assert "total_tokens" in usage, "Usage should contain total_tokens"
        
        assert isinstance(usage["prompt_tokens"], int), "Prompt tokens should be integer"
        assert isinstance(usage["total_tokens"], int), "Total tokens should be integer"
        
        assert usage["prompt_tokens"] > 0, "Prompt tokens should be positive"
        assert usage["total_tokens"] >= usage["prompt_tokens"], "Total should be >= prompt tokens"
        
        # For embeddings, completion_tokens is typically 0 or not present
        if "completion_tokens" in usage:
            assert usage["completion_tokens"] == 0, "Embedding completion_tokens should be 0"
            assert usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"]
        else:
            assert usage["total_tokens"] == usage["prompt_tokens"], "Total should equal prompt tokens for embeddings"
        
        logger.info(f"FV_RESP_USAGE_EMBED_001: Embedding usage - {usage['prompt_tokens']} prompt tokens, {usage['total_tokens']} total")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_usage_chat_stream_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """FV_RESP_USAGE_CHAT_STREAM_001: Test streaming usage metrics"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Count to 3"}],
            "max_tokens": 30,
            "stream": True
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            pytest.skip("Streaming not supported")
        
        assert response.status_code == 200
        
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            stream_content = response.text
            
            found_usage = False
            usage_data = None
            
            for line in stream_content.split('\n'):
                if line.startswith('data: '):
                    data_part = line[6:]
                    if data_part.strip() and data_part.strip() != '[DONE]':
                        try:
                            chunk_data = json.loads(data_part)
                            
                            # Look for usage in the chunk
                            if "usage" in chunk_data:
                                found_usage = True
                                usage_data = chunk_data["usage"]
                                break
                                
                        except json.JSONDecodeError:
                            continue
            
            if found_usage:
                # Validate usage metrics in streaming
                assert isinstance(usage_data, dict), "Usage should be dictionary"
                assert "prompt_tokens" in usage_data, "Streaming usage should contain prompt_tokens"
                assert "completion_tokens" in usage_data, "Streaming usage should contain completion_tokens"
                assert "total_tokens" in usage_data, "Streaming usage should contain total_tokens"
                
                assert usage_data["total_tokens"] == usage_data["prompt_tokens"] + usage_data["completion_tokens"]
                
                logger.info(f"FV_RESP_USAGE_CHAT_STREAM_001: Streaming usage found - {usage_data}")
            else:
                logger.info("FV_RESP_USAGE_CHAT_STREAM_001: No usage metrics found in streaming response")
        else:
            logger.info("FV_RESP_USAGE_CHAT_STREAM_001: Non-streaming response")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_usage_multimodal_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               multimodal_fixtures,
                                               make_request):
        """FV_RESP_USAGE_MULTIMODAL_001: Test multimodal usage metrics"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        test_image = multimodal_fixtures.get_test_image_base64()
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Describe this image briefly"},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{test_image}"}
                        }
                    ]
                }
            ],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            pytest.skip("Multimodal content not supported")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "usage" in response_data, "Multimodal response should include usage metrics"
        usage = response_data["usage"]
        
        # Should have higher prompt token count due to image processing
        assert usage["prompt_tokens"] > 20, "Multimodal prompt should use significant tokens for image processing"
        assert usage["completion_tokens"] > 0, "Should generate completion"
        assert usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"]
        
        logger.info(f"FV_RESP_USAGE_MULTIMODAL_001: Multimodal usage - {usage['prompt_tokens']} prompt + {usage['completion_tokens']} completion = {usage['total_tokens']} total")


class TestHTTPHeaders:
    """Test HTTP headers in responses"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_headers_chat_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """FV_RESP_HEADERS_CHAT_001: Test JSON response headers"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test headers"}],
            "max_tokens": 30
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        
        # Validate content-type
        content_type = response.headers.get("content-type", "")
        assert "application/json" in content_type, "Content-Type should be application/json"
        
        # Check for security headers
        security_headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": ["DENY", "SAMEORIGIN"],
        }
        
        for header, expected_values in security_headers.items():
            if header in response.headers:
                header_value = response.headers[header]
                if isinstance(expected_values, list):
                    assert header_value in expected_values, f"Header {header} should have valid value"
                else:
                    assert header_value == expected_values, f"Header {header} should be {expected_values}"
                logger.info(f"FV_RESP_HEADERS_CHAT_001: Security header {header}: {header_value}")
        
        # Should not have caching headers for dynamic content
        cache_control = response.headers.get("cache-control", "")
        if cache_control:
            assert "no-cache" in cache_control.lower() or "private" in cache_control.lower(), \
                "Dynamic content should not be cached"
        
        logger.info("FV_RESP_HEADERS_CHAT_001: JSON response headers validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_resp_headers_stream_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """FV_RESP_HEADERS_STREAM_001: Test streaming response headers"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test streaming headers"}],
            "max_tokens": 30,
            "stream": True
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            pytest.skip("Streaming not supported")
        
        assert response.status_code == 200
        
        # Check content-type for streaming
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            # Validate SSE headers
            assert "text/event-stream" in content_type, "Streaming should use text/event-stream"
            
            # Check cache control for streaming
            cache_control = response.headers.get("cache-control", "")
            if cache_control:
                assert "no-cache" in cache_control.lower(), "Streaming should not be cached"
            
            # Check for connection header
            connection = response.headers.get("connection", "")
            if connection:
                logger.info(f"FV_RESP_HEADERS_STREAM_001: Connection header: {connection}")
            
            logger.info("FV_RESP_HEADERS_STREAM_001: Streaming headers validated")
        else:
            logger.info("FV_RESP_HEADERS_STREAM_001: Non-streaming response despite stream=True")