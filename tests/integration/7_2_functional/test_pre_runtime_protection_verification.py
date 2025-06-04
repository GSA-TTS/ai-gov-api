# Section 7.2 - Pre-runtime Protection Verification
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Pre-runtime Protection Verification.md

import pytest
import httpx
import json
import asyncio
from typing import Dict, Any, List, Optional

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestPreRuntimeProtectionVerification:
    """Pre-runtime Protection Verification - OpenAPI Schema Conformance Testing"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_openapi_accessibility_001(self, http_client: httpx.AsyncClient):
        """FV_PRP_OPENAPI_ACCESSIBILITY_001: Verify /openapi.json endpoint accessibility and validity"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test OpenAPI endpoint accessibility
        response = await http_client.get(f"{config.BASE_URL}/openapi.json")
        
        assert response.status_code == 200, "OpenAPI endpoint should be accessible"
        assert response.headers.get("content-type", "").startswith("application/json"), \
            "OpenAPI endpoint should return JSON"
        
        # Validate OpenAPI specification structure
        openapi_spec = response.json()
        
        # Verify required OpenAPI 3.x fields
        assert "openapi" in openapi_spec, "OpenAPI spec should have 'openapi' field"
        assert openapi_spec["openapi"].startswith("3."), "Should be OpenAPI 3.x specification"
        
        assert "info" in openapi_spec, "OpenAPI spec should have 'info' field"
        assert "paths" in openapi_spec, "OpenAPI spec should have 'paths' field"
        
        # Verify info section
        info = openapi_spec["info"]
        assert "title" in info, "Info should have title"
        assert "version" in info, "Info should have version"
        
        # Verify critical API endpoints are documented
        paths = openapi_spec["paths"]
        expected_endpoints = [
            "/api/v1/models",
            "/api/v1/chat/completions",
            "/api/v1/embeddings"
        ]
        
        for endpoint in expected_endpoints:
            assert endpoint in paths, f"Endpoint {endpoint} should be documented in OpenAPI spec"
        
        logger.info(f"FV_PRP_OPENAPI_ACCESSIBILITY_001: OpenAPI spec validated with {len(paths)} endpoints")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_param_chat_maxtokens_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """FV_PRP_PARAM_CHAT_MAXTOKENS_001: Verify max_tokens parameter is honored by backend"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test small max_tokens value
        small_tokens_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Write a long story about adventures in space"}],
            "max_tokens": 5
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, small_tokens_request
        )
        
        assert response.status_code == 200, "Small max_tokens request should succeed"
        response_data = response.json()
        
        # Verify max_tokens is respected
        if "usage" in response_data:
            completion_tokens = response_data["usage"].get("completion_tokens", 0)
            assert completion_tokens <= 5, f"Completion tokens ({completion_tokens}) should not exceed max_tokens (5)"
        
        # Check finish_reason indicates length limitation
        if "choices" in response_data and response_data["choices"]:
            finish_reason = response_data["choices"][0].get("finish_reason")
            if finish_reason:
                assert finish_reason in ["length", "stop"], f"Finish reason should be 'length' or 'stop', got '{finish_reason}'"
        
        logger.info("FV_PRP_PARAM_CHAT_MAXTOKENS_001: max_tokens parameter enforcement validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_resp_field_chat_usage_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """FV_PRP_RESP_FIELD_CHAT_USAGE_001: Verify usage.completion_tokens field presence and type"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test usage field validation"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify usage object exists and has correct structure
        assert "usage" in response_data, "Response should contain 'usage' object"
        usage = response_data["usage"]
        assert isinstance(usage, dict), "Usage should be an object"
        
        # Verify completion_tokens field
        assert "completion_tokens" in usage, "Usage should contain 'completion_tokens'"
        completion_tokens = usage["completion_tokens"]
        assert isinstance(completion_tokens, int), f"completion_tokens should be integer, got {type(completion_tokens)}"
        assert completion_tokens >= 0, f"completion_tokens should be non-negative, got {completion_tokens}"
        
        # Verify other required usage fields
        for field_name in ["prompt_tokens", "total_tokens"]:
            if field_name in usage:
                field_value = usage[field_name]
                assert isinstance(field_value, int), f"{field_name} should be integer"
                assert field_value >= 0, f"{field_name} should be non-negative"
        
        logger.info("FV_PRP_RESP_FIELD_CHAT_USAGE_001: Usage field structure and types validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_enum_chat_finishreason_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """FV_PRP_ENUM_CHAT_FINISHREASON_001: Verify finish_reason enum values compliance"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Valid finish_reason values according to OpenAI API spec
        valid_finish_reasons = ["stop", "length", "content_filter", "tool_calls", "function_call"]
        
        # Test scenarios to elicit different finish reasons
        test_scenarios = [
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Say 'hello' and stop."}],
                    "max_tokens": 100
                },
                "description": "Natural completion (should be 'stop')"
            },
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Write a very long story about space exploration"}],
                    "max_tokens": 3
                },
                "description": "Length limited completion (should be 'length')"
            }
        ]
        
        for scenario in test_scenarios:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario["request"]
            )
            
            assert response.status_code == 200, f"Request should succeed for {scenario['description']}"
            response_data = response.json()
            
            # Verify finish_reason enum compliance
            if "choices" in response_data and response_data["choices"]:
                for i, choice in enumerate(response_data["choices"]):
                    if "finish_reason" in choice:
                        finish_reason = choice["finish_reason"]
                        if finish_reason is not None:
                            assert finish_reason in valid_finish_reasons, \
                                f"Choice {i} finish_reason '{finish_reason}' not in valid enum: {valid_finish_reasons}"
                            logger.info(f"FV_PRP_ENUM_CHAT_FINISHREASON_001: {scenario['description']} -> {finish_reason}")
            
            await asyncio.sleep(0.2)
        
        logger.info("FV_PRP_ENUM_CHAT_FINISHREASON_001: finish_reason enum validation completed")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_endpoint_models_availability_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """FV_PRP_ENDPOINT_MODELS_AVAILABILITY_001: Verify /models endpoint availability and structure"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200, "/models endpoint should be available"
        response_data = response.json()
        
        # Verify response structure matches OpenAPI specification
        assert isinstance(response_data, dict), "Models response should be object"
        assert "object" in response_data, "Response should have 'object' field"
        assert response_data["object"] == "list", "Object field should be 'list'"
        assert "data" in response_data, "Response should have 'data' field"
        assert isinstance(response_data["data"], list), "Data field should be array"
        
        # Verify model objects structure
        for i, model in enumerate(response_data["data"]):
            assert isinstance(model, dict), f"Model {i} should be object"
            assert "id" in model, f"Model {i} should have 'id' field"
            assert "object" in model, f"Model {i} should have 'object' field"
            assert model["object"] == "model", f"Model {i} object should be 'model'"
            assert isinstance(model["id"], str), f"Model {i} id should be string"
            assert len(model["id"]) > 0, f"Model {i} id should not be empty"
        
        logger.info(f"FV_PRP_ENDPOINT_MODELS_AVAILABILITY_001: /models endpoint validated with {len(response_data['data'])} models")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_resp_status_code_auth_001(self, http_client: httpx.AsyncClient,
                                                   make_request):
        """FV_PRP_RESP_STATUS_CODE_AUTH_001: Verify 401 status for unauthenticated requests"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test unauthenticated request
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            {}, {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test unauthorized"}],
                "max_tokens": 50
            }, track_cost=False
        )
        
        assert response.status_code == 401, "Unauthenticated request should return 401"
        
        # Test invalid API key
        invalid_headers = {"Authorization": "Bearer sk-invalid-key-test"}
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            invalid_headers, {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test invalid key"}],
                "max_tokens": 50
            }, track_cost=False
        )
        
        assert response.status_code == 401, "Invalid API key should return 401"
        
        # Verify error response format
        response_data = response.json()
        assert "error" in response_data or "detail" in response_data, \
            "401 response should contain error information"
        
        logger.info("FV_PRP_RESP_STATUS_CODE_AUTH_001: Authentication error status codes validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_param_validation_constraint_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """FV_PRP_PARAM_VALIDATION_CONSTRAINT_001: Verify parameter constraint enforcement"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test various parameter constraint violations
        constraint_violations = [
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test negative temperature"}],
                    "temperature": -0.5,
                    "max_tokens": 50
                },
                "description": "Negative temperature (should be >= 0)"
            },
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test high temperature"}],
                    "temperature": 3.0,
                    "max_tokens": 50
                },
                "description": "Temperature too high (should be <= 2)"
            },
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test negative max_tokens"}],
                    "max_tokens": -10
                },
                "description": "Negative max_tokens (should be positive)"
            },
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test invalid top_p"}],
                    "top_p": 1.5,
                    "max_tokens": 50
                },
                "description": "top_p too high (should be <= 1)"
            },
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": ""}],  # Empty content
                    "max_tokens": 50
                },
                "description": "Empty message content (should be non-empty)"
            }
        ]
        
        for violation in constraint_violations:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, violation["request"], track_cost=False
            )
            
            assert response.status_code == 422, \
                f"{violation['description']} should return 422, got {response.status_code}"
            
            # Verify error response format
            response_data = response.json()
            assert "detail" in response_data, f"{violation['description']} should contain validation error details"
            
            # Verify error details are informative
            detail = response_data["detail"]
            assert detail is not None, "Error detail should not be null"
            
            logger.info(f"FV_PRP_PARAM_VALIDATION_CONSTRAINT_001: {violation['description']} properly rejected")
            
            await asyncio.sleep(0.1)
        
        logger.info("FV_PRP_PARAM_VALIDATION_CONSTRAINT_001: Parameter constraint validation completed")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_schema_version_consistency_001(self, http_client: httpx.AsyncClient):
        """FV_PRP_SCHEMA_VERSION_CONSISTENCY_001: Verify OpenAPI schema version consistency"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Fetch OpenAPI specification
        response = await http_client.get(f"{config.BASE_URL}/openapi.json")
        assert response.status_code == 200
        
        openapi_spec = response.json()
        
        # Verify OpenAPI version
        assert "openapi" in openapi_spec, "OpenAPI spec should specify version"
        openapi_version = openapi_spec["openapi"]
        assert openapi_version.startswith("3."), f"Should use OpenAPI 3.x, got {openapi_version}"
        
        # Verify API version in info
        assert "info" in openapi_spec, "OpenAPI spec should have info section"
        info = openapi_spec["info"]
        assert "version" in info, "Info should specify API version"
        api_version = info["version"]
        assert isinstance(api_version, str), "API version should be string"
        assert len(api_version) > 0, "API version should not be empty"
        
        # Verify versioned endpoints
        paths = openapi_spec.get("paths", {})
        versioned_endpoints = [path for path in paths.keys() if path.startswith("/api/v1")]
        assert len(versioned_endpoints) > 0, "Should have versioned API endpoints (/api/v1)"
        
        # Verify consistency in endpoint versioning
        for path in paths.keys():
            if path.startswith("/api/"):
                assert path.startswith("/api/v1"), f"API path {path} should use version prefix /api/v1"
        
        logger.info(f"FV_PRP_SCHEMA_VERSION_CONSISTENCY_001: Version consistency validated (OpenAPI {openapi_version}, API {api_version})")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_schema_completeness_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str]):
        """FV_PRP_SCHEMA_COMPLETENESS_001: Verify all endpoints are documented in OpenAPI"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Fetch OpenAPI specification
        response = await http_client.get(f"{config.BASE_URL}/openapi.json")
        assert response.status_code == 200
        
        openapi_spec = response.json()
        documented_paths = set(openapi_spec.get("paths", {}).keys())
        
        # Test accessibility of documented endpoints
        accessible_endpoints = []
        for path in documented_paths:
            if path.startswith("/api/v1"):
                # Test GET endpoints
                try:
                    test_response = await http_client.get(
                        f"{config.BASE_URL}{path}",
                        headers=auth_headers
                    )
                    if test_response.status_code in [200, 401, 405]:  # 405 = Method Not Allowed
                        accessible_endpoints.append(path)
                except:
                    pass  # Endpoint might require POST or specific parameters
                
                # Test POST endpoints for known API paths
                if path in ["/api/v1/chat/completions", "/api/v1/embeddings"]:
                    try:
                        test_response = await http_client.post(
                            f"{config.BASE_URL}{path}",
                            headers=auth_headers,
                            json={}  # Empty request to test endpoint existence
                        )
                        if test_response.status_code in [200, 422]:  # 422 = validation error
                            accessible_endpoints.append(path)
                    except:
                        pass
        
        # Verify critical endpoints are both documented and accessible
        critical_endpoints = ["/api/v1/models", "/api/v1/chat/completions", "/api/v1/embeddings"]
        for endpoint in critical_endpoints:
            assert endpoint in documented_paths, f"Critical endpoint {endpoint} should be documented"
            # Note: accessibility test is best-effort due to authentication/parameter requirements
        
        # Verify no obvious undocumented endpoints exist (basic check)
        # This is a simplified test - comprehensive route discovery would require app introspection
        common_paths_to_check = [
            "/api/v1/health",
            "/api/v1/status", 
            "/api/v1/admin",
            "/api/v2/models"  # Should not exist
        ]
        
        for test_path in common_paths_to_check:
            try:
                test_response = await http_client.get(f"{config.BASE_URL}{test_path}")
                if test_response.status_code == 200:
                    # If endpoint exists, it should be documented
                    assert test_path in documented_paths, \
                        f"Accessible endpoint {test_path} should be documented in OpenAPI spec"
            except:
                pass  # Endpoint doesn't exist, which is fine
        
        logger.info(f"FV_PRP_SCHEMA_COMPLETENESS_001: Schema completeness validated ({len(documented_paths)} documented paths)")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_response_content_type_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """FV_PRP_RESPONSE_CONTENT_TYPE_001: Verify correct Content-Type headers"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test JSON endpoints
        json_endpoints = [
            {
                "method": "GET",
                "endpoint": "/api/v1/models",
                "data": None,
                "description": "Models endpoint"
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test content type"}],
                    "max_tokens": 50
                },
                "description": "Chat completions endpoint"
            }
        ]
        
        for endpoint_test in json_endpoints:
            response = await make_request(
                http_client, endpoint_test["method"], endpoint_test["endpoint"],
                auth_headers, endpoint_test["data"]
            )
            
            assert response.status_code == 200, f"{endpoint_test['description']} should succeed"
            
            content_type = response.headers.get("content-type", "")
            assert "application/json" in content_type, \
                f"{endpoint_test['description']} should return application/json, got {content_type}"
            
            logger.info(f"FV_PRP_RESPONSE_CONTENT_TYPE_001: {endpoint_test['description']} Content-Type validated")
        
        # Test streaming endpoint if supported
        streaming_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test streaming content type"}],
            "max_tokens": 50,
            "stream": True
        }
        
        streaming_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, streaming_request
        )
        
        if streaming_response.status_code == 200:
            content_type = streaming_response.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                logger.info("FV_PRP_RESPONSE_CONTENT_TYPE_001: Streaming Content-Type (text/event-stream) validated")
            elif "application/json" in content_type:
                logger.info("FV_PRP_RESPONSE_CONTENT_TYPE_001: Non-streaming fallback Content-Type validated")
        elif streaming_response.status_code == 422:
            logger.info("FV_PRP_RESPONSE_CONTENT_TYPE_001: Streaming not supported, skipping stream test")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_error_response_format_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """FV_PRP_ERROR_RESPONSE_FORMAT_001: Verify error response format consistency"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test different error conditions
        error_scenarios = [
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "headers": {},  # No auth
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test"}]
                },
                "expected_status": 401,
                "description": "Authentication error"
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "headers": auth_headers,
                "data": {
                    "model": config.get_chat_model(0)
                    # Missing required 'messages' field
                },
                "expected_status": 422,
                "description": "Validation error"
            },
            {
                "method": "GET",
                "endpoint": "/api/v1/nonexistent",
                "headers": auth_headers,
                "data": None,
                "expected_status": 404,
                "description": "Not found error"
            }
        ]
        
        for scenario in error_scenarios:
            response = await make_request(
                http_client, scenario["method"], scenario["endpoint"],
                scenario["headers"], scenario["data"], track_cost=False
            )
            
            # Verify expected status code
            if response.status_code != scenario["expected_status"]:
                # Some scenarios might return different but valid error codes
                assert response.status_code >= 400, \
                    f"{scenario['description']} should return error status, got {response.status_code}"
            
            # Verify Content-Type is JSON for errors
            content_type = response.headers.get("content-type", "")
            assert "application/json" in content_type, \
                f"{scenario['description']} should return JSON error, got {content_type}"
            
            # Verify error response structure
            response_data = response.json()
            has_error_info = "error" in response_data or "detail" in response_data
            assert has_error_info, f"{scenario['description']} should contain error information"
            
            # Verify error doesn't leak sensitive information
            response_text = response.text.lower()
            sensitive_keywords = ["password", "secret", "key", "token", "internal", "stack trace"]
            for keyword in sensitive_keywords:
                assert keyword not in response_text, \
                    f"{scenario['description']} should not leak sensitive information: {keyword}"
            
            logger.info(f"FV_PRP_ERROR_RESPONSE_FORMAT_001: {scenario['description']} format validated")
            
            await asyncio.sleep(0.1)
        
        logger.info("FV_PRP_ERROR_RESPONSE_FORMAT_001: Error response format validation completed")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_prp_multimodal_schema_validation_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """FV_PRP_MULTIMODAL_SCHEMA_VALIDATION_001: Verify multimodal content schema validation"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test valid image data URI (small 1x1 PNG)
        valid_image_data_uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAGAWwmOFQAAAABJRU5ErkJggg=="
        
        multimodal_test_scenarios = [
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": "What do you see in this image?"},
                                {"type": "image_url", "image_url": {"url": valid_image_data_uri}}
                            ]
                        }
                    ],
                    "max_tokens": 100
                },
                "description": "Valid image data URI",
                "should_succeed": True
            },
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": "Test invalid image"},
                                {"type": "image_url", "image_url": {"url": "data:image/png;base64,invalid_base64_data"}}
                            ]
                        }
                    ],
                    "max_tokens": 100
                },
                "description": "Invalid image data URI",
                "should_succeed": False
            },
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": "Test malformed content"},
                                {"type": "invalid_type", "data": "invalid"}
                            ]
                        }
                    ],
                    "max_tokens": 100
                },
                "description": "Invalid content type",
                "should_succeed": False
            },
            {
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "image_url", "image_url": {"url": "https://example.com/nonexistent.jpg"}}
                            ]
                        }
                    ],
                    "max_tokens": 100
                },
                "description": "External image URL (may not be supported)",
                "should_succeed": "optional"
            }
        ]
        
        for scenario in multimodal_test_scenarios:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario["request"], track_cost=False
            )
            
            if scenario["should_succeed"] is True:
                # Should succeed or gracefully handle unsupported multimodal
                assert response.status_code in [200, 422], \
                    f"{scenario['description']} should succeed or be rejected appropriately"
                
                if response.status_code == 422:
                    logger.info(f"FV_PRP_MULTIMODAL_SCHEMA_VALIDATION_001: {scenario['description']} - multimodal not supported")
                else:
                    logger.info(f"FV_PRP_MULTIMODAL_SCHEMA_VALIDATION_001: {scenario['description']} - processed successfully")
            
            elif scenario["should_succeed"] is False:
                # Should be rejected with validation error
                assert response.status_code == 422, \
                    f"{scenario['description']} should return 422, got {response.status_code}"
                
                response_data = response.json()
                assert "detail" in response_data, \
                    f"{scenario['description']} should contain validation error details"
                
                logger.info(f"FV_PRP_MULTIMODAL_SCHEMA_VALIDATION_001: {scenario['description']} - properly rejected")
            
            elif scenario["should_succeed"] == "optional":
                # Either succeed or fail appropriately
                assert response.status_code in [200, 400, 422], \
                    f"{scenario['description']} should be handled appropriately"
                
                logger.info(f"FV_PRP_MULTIMODAL_SCHEMA_VALIDATION_001: {scenario['description']} - handled appropriately")
            
            await asyncio.sleep(0.2)
        
        logger.info("FV_PRP_MULTIMODAL_SCHEMA_VALIDATION_001: Multimodal schema validation completed")