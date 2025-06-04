# Section 7.2 - OpenAPI Schema Conformance Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Pre-runtime Protection Verification.md

import pytest
import httpx
import json
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestOpenAPISchemaCompliance:
    """Test OpenAI API schema compliance"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_models_response_schema_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """FV_OPENAPI_MODELS_RESPONSE_SCHEMA_001: Test /models response schema compliance"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Validate top-level structure according to OpenAI spec
        assert "object" in response_data, "Response should contain 'object' field"
        assert response_data["object"] == "list", "Object field should be 'list'"
        assert "data" in response_data, "Response should contain 'data' field"
        assert isinstance(response_data["data"], list), "Data field should be array"
        assert len(response_data["data"]) > 0, "Should return at least one model"
        
        # Validate each model object structure
        for i, model in enumerate(response_data["data"]):
            # Required fields per OpenAI spec
            assert "id" in model, f"Model {i} should have 'id' field"
            assert "object" in model, f"Model {i} should have 'object' field"
            assert model["object"] == "model", f"Model {i} object should be 'model'"
            
            # Field type validation
            assert isinstance(model["id"], str), f"Model {i} ID should be string"
            assert len(model["id"]) > 0, f"Model {i} ID should not be empty"
            
            # Optional fields validation
            if "created" in model:
                assert isinstance(model["created"], int), f"Model {i} created should be integer"
                assert model["created"] > 0, f"Model {i} created should be positive timestamp"
            
            if "owned_by" in model:
                assert isinstance(model["owned_by"], str), f"Model {i} owned_by should be string"
        
        logger.info(f"FV_OPENAPI_MODELS_RESPONSE_SCHEMA_001: Validated {len(response_data['data'])} models schema compliance")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_chat_completions_request_schema_001(self, http_client: httpx.AsyncClient,
                                                                 auth_headers: Dict[str, str],
                                                                 make_request):
        """FV_OPENAPI_CHAT_COMPLETIONS_REQUEST_SCHEMA_001: Test chat completions request schema"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test minimal required fields
        minimal_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test minimal schema"}]
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, minimal_request
        )
        
        assert response.status_code == 200, "Minimal request should succeed"
        
        # Test full schema with all optional fields
        full_request = {
            "model": config.get_chat_model(0),
            "messages": [
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": "Test full schema"}
            ],
            "max_tokens": 100,
            "temperature": 0.7,
            "top_p": 0.9,
            "n": 1,
            "stream": False,
            "stop": None,
            "presence_penalty": 0.0,
            "frequency_penalty": 0.0,
            "user": "test-user"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, full_request
        )
        
        # Should either succeed or reject with validation error for unsupported params
        assert response.status_code in [200, 422], "Full request should be handled appropriately"
        
        if response.status_code == 422:
            response_data = response.json()
            assert "detail" in response_data, "Validation error should have detail"
        
        logger.info("FV_OPENAPI_CHAT_COMPLETIONS_REQUEST_SCHEMA_001: Request schema compliance validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_chat_completions_response_schema_001(self, http_client: httpx.AsyncClient,
                                                                  auth_headers: Dict[str, str],
                                                                  make_request):
        """FV_OPENAPI_CHAT_COMPLETIONS_RESPONSE_SCHEMA_001: Test chat completions response schema"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test response schema compliance"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Validate top-level required fields
        required_fields = ["id", "object", "created", "model", "choices"]
        for field in required_fields:
            assert field in response_data, f"Response should contain '{field}' field"
        
        # Validate field types and values
        assert isinstance(response_data["id"], str), "ID should be string"
        assert len(response_data["id"]) > 0, "ID should not be empty"
        assert response_data["object"] == "chat.completion", "Object should be 'chat.completion'"
        assert isinstance(response_data["created"], int), "Created should be integer timestamp"
        assert isinstance(response_data["model"], str), "Model should be string"
        assert isinstance(response_data["choices"], list), "Choices should be array"
        assert len(response_data["choices"]) > 0, "Should have at least one choice"
        
        # Validate choices structure
        for i, choice in enumerate(response_data["choices"]):
            assert isinstance(choice, dict), f"Choice {i} should be object"
            assert "index" in choice, f"Choice {i} should have index"
            assert "message" in choice, f"Choice {i} should have message"
            
            assert isinstance(choice["index"], int), f"Choice {i} index should be integer"
            assert choice["index"] == i, f"Choice {i} index should match position"
            
            # Validate message structure
            message = choice["message"]
            assert isinstance(message, dict), f"Choice {i} message should be object"
            assert "role" in message, f"Choice {i} message should have role"
            assert "content" in message, f"Choice {i} message should have content"
            assert message["role"] == "assistant", f"Choice {i} role should be 'assistant'"
            assert isinstance(message["content"], str), f"Choice {i} content should be string"
            
            # Optional finish_reason field
            if "finish_reason" in choice:
                valid_reasons = ["stop", "length", "content_filter", "tool_calls", "function_call"]
                assert choice["finish_reason"] in valid_reasons or choice["finish_reason"] is None, \
                    f"Choice {i} finish_reason should be valid"
        
        # Validate usage (optional but should be present)
        if "usage" in response_data:
            usage = response_data["usage"]
            assert isinstance(usage, dict), "Usage should be object"
            
            usage_fields = ["prompt_tokens", "completion_tokens", "total_tokens"]
            for field in usage_fields:
                if field in usage:
                    assert isinstance(usage[field], int), f"Usage {field} should be integer"
                    assert usage[field] >= 0, f"Usage {field} should be non-negative"
        
        logger.info("FV_OPENAPI_CHAT_COMPLETIONS_RESPONSE_SCHEMA_001: Response schema compliance validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_embeddings_request_schema_001(self, http_client: httpx.AsyncClient,
                                                           embedding_auth_headers: Dict[str, str],
                                                           make_request):
        """FV_OPENAPI_EMBEDDINGS_REQUEST_SCHEMA_001: Test embeddings request schema"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test minimal required fields
        minimal_request = {
            "model": config.get_embedding_model(0),
            "input": "Test minimal embedding schema"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, minimal_request
        )
        
        assert response.status_code == 200, "Minimal embedding request should succeed"
        
        # Test with array input
        array_request = {
            "model": config.get_embedding_model(0),
            "input": ["First text", "Second text"]
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, array_request
        )
        
        # Should either succeed or be rejected if batch not supported
        assert response.status_code in [200, 422], "Array input should be handled appropriately"
        
        # Test with optional parameters
        full_request = {
            "model": config.get_embedding_model(0),
            "input": "Test full embedding schema",
            "encoding_format": "float",
            "user": "test-user"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, full_request
        )
        
        assert response.status_code in [200, 422], "Full embedding request should be handled"
        
        logger.info("FV_OPENAPI_EMBEDDINGS_REQUEST_SCHEMA_001: Embedding request schema compliance validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_embeddings_response_schema_001(self, http_client: httpx.AsyncClient,
                                                            embedding_auth_headers: Dict[str, str],
                                                            make_request):
        """FV_OPENAPI_EMBEDDINGS_RESPONSE_SCHEMA_001: Test embeddings response schema"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_embedding_model(0),
            "input": "Test embedding response schema compliance"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Validate top-level required fields
        required_fields = ["object", "data", "model"]
        for field in required_fields:
            assert field in response_data, f"Response should contain '{field}' field"
        
        # Validate field types and values
        assert response_data["object"] == "list", "Object should be 'list'"
        assert isinstance(response_data["data"], list), "Data should be array"
        assert len(response_data["data"]) > 0, "Should have at least one embedding"
        assert isinstance(response_data["model"], str), "Model should be string"
        
        # Validate embedding data structure
        for i, embedding_obj in enumerate(response_data["data"]):
            assert isinstance(embedding_obj, dict), f"Embedding {i} should be object"
            
            # Required embedding fields
            embedding_required = ["object", "embedding", "index"]
            for field in embedding_required:
                assert field in embedding_obj, f"Embedding {i} should contain '{field}'"
            
            assert embedding_obj["object"] == "embedding", f"Embedding {i} object should be 'embedding'"
            assert isinstance(embedding_obj["index"], int), f"Embedding {i} index should be integer"
            assert embedding_obj["index"] == i, f"Embedding {i} index should match position"
            
            # Validate embedding vector
            embedding = embedding_obj["embedding"]
            assert isinstance(embedding, list), f"Embedding {i} should be array of numbers"
            assert len(embedding) > 0, f"Embedding {i} should not be empty"
            
            # All values should be numbers
            for j, value in enumerate(embedding):
                assert isinstance(value, (int, float)), f"Embedding {i}[{j}] should be numeric"
                assert not (isinstance(value, float) and value != value), f"Embedding {i}[{j}] should not be NaN"
        
        # Validate usage (optional)
        if "usage" in response_data:
            usage = response_data["usage"]
            assert isinstance(usage, dict), "Usage should be object"
            assert "prompt_tokens" in usage, "Usage should contain prompt_tokens"
            assert "total_tokens" in usage, "Usage should contain total_tokens"
        
        logger.info("FV_OPENAPI_EMBEDDINGS_RESPONSE_SCHEMA_001: Embedding response schema compliance validated")


class TestHTTPStatusCodeCompliance:
    """Test HTTP status code compliance with OpenAI API"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_http_status_200_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """FV_OPENAPI_HTTP_STATUS_200_001: Test 200 OK responses"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test endpoints that should return 200
        success_endpoints = [
            {
                "method": "GET",
                "endpoint": "/api/v1/models",
                "data": None,
                "description": "Models listing"
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test 200 status"}],
                    "max_tokens": 50
                },
                "description": "Chat completion"
            }
        ]
        
        for endpoint_test in success_endpoints:
            response = await make_request(
                http_client, endpoint_test["method"], endpoint_test["endpoint"],
                auth_headers, endpoint_test["data"]
            )
            
            assert response.status_code == 200, f"{endpoint_test['description']} should return 200"
            
            # Verify response has valid JSON
            response_data = response.json()
            assert isinstance(response_data, dict), f"{endpoint_test['description']} should return JSON object"
            
            logger.info(f"FV_OPENAPI_HTTP_STATUS_200_001: {endpoint_test['description']} returned 200 OK")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_http_status_401_001(self, http_client: httpx.AsyncClient,
                                                  make_request):
        """FV_OPENAPI_HTTP_STATUS_401_001: Test 401 Unauthorized responses"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with invalid API key
        invalid_headers = {"Authorization": "Bearer invalid_key_test"}
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            invalid_headers, track_cost=False
        )
        
        assert response.status_code == 401, "Invalid API key should return 401"
        
        # Verify error response format
        response_data = response.json()
        assert "error" in response_data or "detail" in response_data, "401 response should contain error information"
        
        logger.info("FV_OPENAPI_HTTP_STATUS_401_001: 401 Unauthorized properly returned")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_http_status_422_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """FV_OPENAPI_HTTP_STATUS_422_001: Test 422 Validation Error responses"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test validation errors
        validation_errors = [
            # Missing required field
            {
                "model": config.get_chat_model(0),
                "max_tokens": 50,
                "description": "Missing messages field"
            },
            # Invalid field type
            {
                "model": config.get_chat_model(0),
                "messages": "not_an_array",
                "max_tokens": 50,
                "description": "Invalid messages type"
            },
            # Invalid parameter value
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": -1,
                "description": "Invalid max_tokens value"
            }
        ]
        
        for error_test in validation_errors:
            description = error_test.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, error_test, track_cost=False
            )
            
            assert response.status_code == 422, f"{description} should return 422"
            
            # Verify error response format
            response_data = response.json()
            assert "detail" in response_data, f"{description} should contain error detail"
            
            logger.info(f"FV_OPENAPI_HTTP_STATUS_422_001: {description} returned 422")


class TestContentTypeCompliance:
    """Test Content-Type header compliance"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_content_type_json_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """FV_OPENAPI_CONTENT_TYPE_JSON_001: Test JSON Content-Type responses"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test JSON content type"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        
        # Verify Content-Type header
        content_type = response.headers.get("content-type", "")
        assert "application/json" in content_type, f"Content-Type should be application/json, got {content_type}"
        
        # Verify response is valid JSON
        response_data = response.json()
        assert isinstance(response_data, dict), "Response should be valid JSON object"
        
        logger.info("FV_OPENAPI_CONTENT_TYPE_JSON_001: JSON Content-Type compliance validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_content_type_stream_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_OPENAPI_CONTENT_TYPE_STREAM_001: Test streaming Content-Type"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test streaming content type"}],
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
        
        # Check Content-Type for streaming
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            # SSE format
            assert "text/event-stream" in content_type, "Streaming should use text/event-stream"
            logger.info("FV_OPENAPI_CONTENT_TYPE_STREAM_001: SSE Content-Type compliance validated")
        else:
            # Fallback to regular JSON
            assert "application/json" in content_type, "Non-streaming fallback should use application/json"
            logger.info("FV_OPENAPI_CONTENT_TYPE_STREAM_001: Non-streaming fallback Content-Type validated")


class TestParameterValidationCompliance:
    """Test parameter validation compliance with OpenAI API"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_param_validation_ranges_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """FV_OPENAPI_PARAM_VALIDATION_RANGES_001: Test parameter range validation"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test parameter ranges according to OpenAI spec
        range_tests = [
            # Temperature validation
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test temperature"}],
                "max_tokens": 50,
                "temperature": -1.0,  # Invalid: should be >= 0
                "description": "Invalid temperature (negative)"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test temperature"}],
                "max_tokens": 50,
                "temperature": 3.0,  # Invalid: should be <= 2
                "description": "Invalid temperature (too high)"
            },
            # top_p validation
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test top_p"}],
                "max_tokens": 50,
                "top_p": -0.1,  # Invalid: should be >= 0
                "description": "Invalid top_p (negative)"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test top_p"}],
                "max_tokens": 50,
                "top_p": 1.1,  # Invalid: should be <= 1
                "description": "Invalid top_p (too high)"
            }
        ]
        
        for test_case in range_tests:
            description = test_case.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_case, track_cost=False
            )
            
            assert response.status_code == 422, f"{description} should return 422"
            
            response_data = response.json()
            assert "detail" in response_data, f"{description} should contain validation error"
            
            logger.info(f"FV_OPENAPI_PARAM_VALIDATION_RANGES_001: {description} properly validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_param_validation_types_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """FV_OPENAPI_PARAM_VALIDATION_TYPES_001: Test parameter type validation"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test parameter type validation
        type_tests = [
            # Wrong type for max_tokens
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test max_tokens type"}],
                "max_tokens": "fifty",  # Should be integer
                "description": "Invalid max_tokens type (string)"
            },
            # Wrong type for temperature
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test temperature type"}],
                "max_tokens": 50,
                "temperature": "0.7",  # Should be number
                "description": "Invalid temperature type (string)"
            },
            # Wrong type for stream
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test stream type"}],
                "max_tokens": 50,
                "stream": "true",  # Should be boolean
                "description": "Invalid stream type (string)"
            }
        ]
        
        for test_case in type_tests:
            description = test_case.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_case, track_cost=False
            )
            
            assert response.status_code == 422, f"{description} should return 422"
            
            response_data = response.json()
            assert "detail" in response_data, f"{description} should contain validation error"
            
            logger.info(f"FV_OPENAPI_PARAM_VALIDATION_TYPES_001: {description} properly validated")


class TestErrorResponseCompliance:
    """Test error response format compliance"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_error_response_format_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_OPENAPI_ERROR_RESPONSE_FORMAT_001: Test error response format compliance"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Trigger validation error
        invalid_request = {
            "model": config.get_chat_model(0),
            "messages": [],  # Empty messages array
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, invalid_request, track_cost=False
        )
        
        assert response.status_code == 422
        response_data = response.json()
        
        # Check error response structure
        # Should have either 'error' (OpenAI format) or 'detail' (FastAPI format)
        has_error_field = "error" in response_data
        has_detail_field = "detail" in response_data
        
        assert has_error_field or has_detail_field, "Error response should contain error information"
        
        if has_error_field:
            # OpenAI format
            error = response_data["error"]
            assert isinstance(error, dict), "Error should be object"
            assert "message" in error, "Error should have message"
            assert "type" in error, "Error should have type"
            
            logger.info("FV_OPENAPI_ERROR_RESPONSE_FORMAT_001: OpenAI error format compliance validated")
        
        if has_detail_field:
            # FastAPI format
            detail = response_data["detail"]
            assert detail is not None, "Detail should not be null"
            
            logger.info("FV_OPENAPI_ERROR_RESPONSE_FORMAT_001: FastAPI error format compliance validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_openapi_error_response_fields_001(self, http_client: httpx.AsyncClient,
                                                       make_request):
        """FV_OPENAPI_ERROR_RESPONSE_FIELDS_001: Test error response required fields"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test authentication error
        invalid_headers = {"Authorization": "Bearer invalid_key"}
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            invalid_headers, track_cost=False
        )
        
        assert response.status_code == 401
        response_data = response.json()
        
        # Should have error information
        assert "error" in response_data or "detail" in response_data, "401 response should contain error"
        
        # Check Content-Type is still JSON for errors
        content_type = response.headers.get("content-type", "")
        assert "application/json" in content_type, "Error responses should be JSON"
        
        logger.info("FV_OPENAPI_ERROR_RESPONSE_FIELDS_001: Error response fields compliance validated")