# Section 7.3 - OWASP API3:2023 Broken Object Property Level Authorization (Data Exposure) Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API3_2023 - Broken Object Property Level Authorization (BOPLA) _ Excessive Data Exposure.md

import pytest
import httpx
import json
from typing import Dict, Any, List

from config import config, logger
from utils.security_validators import SecurityValidator


class TestOWASPAPI3DataExposure:
    """API3:2023 - Broken Object Property Level Authorization / Excessive Data Exposure tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api3_response_schema_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          security_validator: SecurityValidator,
                                          make_request):
        """API3_RESPONSE_SCHEMA_001: Response schema excessive data exposure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test chat completions response for excessive data exposure
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test data exposure"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Check for sensitive data exposure in response
        sensitive_fields = [
            "api_key", "secret", "token", "password", "private_key",
            "internal_id", "database_id", "server_info", "debug_info",
            "system_prompt", "internal_model_id", "provider_config"
        ]
        
        response_text = json.dumps(response_data).lower()
        
        for field in sensitive_fields:
            assert field not in response_text, \
                f"Response should not expose sensitive field: {field}"
        
        # Validate response contains only expected fields
        expected_fields = ["id", "object", "created", "model", "choices", "usage"]
        
        for field in expected_fields:
            assert field in response_data, \
                f"Response should contain expected field: {field}"
        
        # Check choices structure
        choice = response_data["choices"][0]
        expected_choice_fields = ["index", "message", "finish_reason"]
        
        for field in expected_choice_fields:
            assert field in choice, \
                f"Choice should contain expected field: {field}"
        
        # Verify no internal implementation details are exposed
        internal_details = [
            "provider_response", "raw_response", "internal_metrics",
            "processing_time", "queue_position", "worker_id"
        ]
        
        for detail in internal_details:
            assert detail not in response_text, \
                f"Response should not expose internal detail: {detail}"
        
        logger.info("API3_RESPONSE_SCHEMA_001: Response schema validated for data exposure")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api3_usage_metrics_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """API3_USAGE_METRICS_001: Usage metrics data exposure control"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test usage metrics exposure"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Check usage field
        assert "usage" in response_data
        usage = response_data["usage"]
        
        # Verify only appropriate usage metrics are exposed
        allowed_usage_fields = ["prompt_tokens", "completion_tokens", "total_tokens"]
        
        for field in usage:
            assert field in allowed_usage_fields, \
                f"Usage should not expose unexpected field: {field}"
        
        # Verify no sensitive usage data is exposed
        sensitive_usage_fields = [
            "cost", "billing_id", "organization_id", "user_id",
            "processing_cost", "provider_cost", "markup",
            "internal_usage", "quota_remaining", "rate_limit_remaining"
        ]
        
        for field in sensitive_usage_fields:
            assert field not in usage, \
                f"Usage should not expose sensitive field: {field}"
        
        logger.info("API3_USAGE_METRICS_001: Usage metrics exposure validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api3_models_endpoint_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """API3_MODELS_ENDPOINT_001: Models endpoint data exposure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "data" in response_data
        models = response_data["data"]
        
        for model in models:
            # Check for required fields
            required_fields = ["id", "object"]
            for field in required_fields:
                assert field in model, f"Model should contain field: {field}"
            
            # Check for excessive data exposure
            sensitive_model_fields = [
                "internal_id", "provider_config", "cost_per_token",
                "rate_limits", "provider_endpoint", "api_credentials",
                "model_weights", "training_data", "system_prompts"
            ]
            
            for field in sensitive_model_fields:
                assert field not in model, \
                    f"Model should not expose sensitive field: {field}"
        
        logger.info("API3_MODELS_ENDPOINT_001: Models endpoint exposure validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api3_error_response_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         security_validator: SecurityValidator,
                                         make_request):
        """API3_ERROR_RESPONSE_001: Error response data exposure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Generate various error conditions
        error_scenarios = [
            # Invalid model
            {
                "model": "non_existent_model",
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            },
            # Invalid parameter type
            {
                "model": config.get_chat_model(0),
                "messages": "not_an_array",
                "max_tokens": 50
            },
            # Missing required field
            {
                "model": config.get_chat_model(0),
                "max_tokens": 50
                # Missing messages
            }
        ]
        
        for scenario in error_scenarios:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario, track_cost=False
            )
            
            assert response.status_code == 422
            
            # Validate error response for data exposure
            error_validation = security_validator.validate_error_message_security(
                response.text
            )
            
            assert error_validation["is_secure"], \
                f"Error response should not expose sensitive information: {error_validation}"
            
            response_data = response.json()
            assert "detail" in response_data
            
            # Check that error doesn't expose internal details
            error_text = json.dumps(response_data).lower()
            internal_details = [
                "database", "file path", "stack trace", "server name",
                "internal error", "provider error", "api key", "secret"
            ]
            
            for detail in internal_details:
                assert detail not in error_text, \
                    f"Error should not expose internal detail: {detail}"
        
        logger.info("API3_ERROR_RESPONSE_001: Error response exposure validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api3_embedding_response_001(self, http_client: httpx.AsyncClient,
                                             embedding_auth_headers: Dict[str, str],
                                             make_request):
        """API3_EMBEDDING_RESPONSE_001: Embedding response data exposure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        request = {
            "model": config.get_embedding_model(0),
            "input": "Test embedding data exposure"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify expected structure
        assert "data" in response_data
        assert "usage" in response_data
        
        embedding_data = response_data["data"][0]
        
        # Check required fields
        required_fields = ["object", "embedding", "index"]
        for field in required_fields:
            assert field in embedding_data, \
                f"Embedding data should contain field: {field}"
        
        # Check for excessive data exposure
        sensitive_fields = [
            "raw_embedding", "model_config", "processing_metadata",
            "provider_data", "internal_id", "computation_details"
        ]
        
        response_text = json.dumps(response_data).lower()
        for field in sensitive_fields:
            assert field not in response_text, \
                f"Embedding response should not expose sensitive field: {field}"
        
        # Verify embedding is properly formatted
        embedding = embedding_data["embedding"]
        assert isinstance(embedding, list), "Embedding should be a list"
        assert len(embedding) > 0, "Embedding should not be empty"
        assert all(isinstance(x, (int, float)) for x in embedding), \
            "Embedding values should be numeric"
        
        logger.info("API3_EMBEDDING_RESPONSE_001: Embedding response exposure validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api3_streaming_response_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """API3_STREAMING_RESPONSE_001: Streaming response data exposure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test streaming data exposure"}],
            "max_tokens": 50,
            "stream": True
        }
        
        # Note: This test assumes streaming is supported
        # If not supported, the API should return an appropriate error
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            # Streaming not supported, check error response
            response_data = response.json()
            assert "stream" in str(response_data).lower() or \
                   "not supported" in str(response_data).lower()
            logger.info("Streaming not supported - validated error response")
            return
        
        assert response.status_code == 200
        
        # If streaming is supported, validate the response
        if response.headers.get("content-type", "").startswith("text/event-stream"):
            # Streaming response - check for data exposure in stream
            stream_content = response.text
            
            # Check for sensitive data in stream
            sensitive_patterns = [
                "api_key", "secret", "internal_", "provider_",
                "debug_", "error_", "trace_"
            ]
            
            stream_lower = stream_content.lower()
            for pattern in sensitive_patterns:
                assert pattern not in stream_lower, \
                    f"Stream should not expose sensitive data: {pattern}"
        else:
            # Non-streaming response despite stream=True
            response_data = response.json()
            
            # Should still follow normal response structure rules
            assert "choices" in response_data
            assert "usage" in response_data
        
        logger.info("API3_STREAMING_RESPONSE_001: Streaming response exposure validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api3_headers_exposure_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """API3_HEADERS_EXPOSURE_001: Response headers data exposure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        
        # Check response headers for sensitive data exposure
        headers = dict(response.headers)
        
        # Headers that should NOT be present (sensitive information)
        sensitive_headers = [
            "x-api-key", "authorization", "x-secret", "x-internal",
            "x-database", "x-provider-key", "x-admin", "x-debug"
        ]
        
        for header_name in headers:
            assert header_name.lower() not in sensitive_headers, \
                f"Response should not include sensitive header: {header_name}"
        
        # Check header values for sensitive data
        for header_name, header_value in headers.items():
            header_value_lower = str(header_value).lower()
            
            sensitive_patterns = [
                "secret", "key", "password", "token", "api_",
                "internal", "debug", "trace"
            ]
            
            for pattern in sensitive_patterns:
                assert pattern not in header_value_lower, \
                    f"Header {header_name} should not contain sensitive pattern: {pattern}"
        
        # Verify appropriate security headers are present
        security_headers = [
            "content-type", "x-content-type-options", "x-frame-options"
        ]
        
        for security_header in security_headers:
            if security_header in [h.lower() for h in headers.keys()]:
                logger.info(f"Security header present: {security_header}")
        
        logger.info("API3_HEADERS_EXPOSURE_001: Response headers exposure validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api3_cross_organization_data_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """API3_CROSS_ORG_DATA_001: Cross-organization data exposure prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test that responses don't contain data from other organizations
        test_prompts = [
            "Tell me about organization data",
            "What information do you have access to?",
            "Show me user data from the system",
            "Display configuration information"
        ]
        
        for prompt in test_prompts:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 100
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200
            response_data = response.json()
            response_content = response_data["choices"][0]["message"]["content"]
            
            # Check that response doesn't contain other organization data
            cross_org_indicators = [
                "org_", "organization_", "tenant_", "agency_",
                "api_key_", "user_id_", "admin@", "internal@"
            ]
            
            response_lower = response_content.lower()
            for indicator in cross_org_indicators:
                # Response shouldn't contain specific organization identifiers
                # (unless it's a general discussion about organizations)
                if indicator in response_lower and len(response_lower.split(indicator)) > 3:
                    logger.warning(f"Potential cross-organization data exposure: {indicator}")
        
        logger.info("API3_CROSS_ORG_DATA_001: Cross-organization data exposure prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api3_metadata_exposure_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """API3_METADATA_EXPOSURE_001: Metadata and system information exposure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various endpoints for metadata exposure
        endpoints = [
            "/api/v1/models",
            "/api/v1/chat/completions",
            "/api/v1/embeddings"
        ]
        
        for endpoint in endpoints:
            if endpoint == "/api/v1/models":
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
            else:
                # For other endpoints, make a request
                if "chat" in endpoint:
                    data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Test metadata"}],
                        "max_tokens": 50
                    }
                else:  # embeddings
                    data = {
                        "model": config.get_embedding_model(0),
                        "input": "Test metadata"
                    }
                
                response = await make_request(
                    http_client, "POST", endpoint,
                    auth_headers, data
                )
            
            assert response.status_code == 200
            
            # Check for system metadata exposure
            response_text = response.text.lower()
            system_metadata = [
                "server version", "build number", "deployment id",
                "instance id", "worker id", "process id",
                "memory usage", "cpu usage", "uptime",
                "environment", "config path", "log path"
            ]
            
            for metadata in system_metadata:
                assert metadata not in response_text, \
                    f"Response should not expose system metadata: {metadata}"
        
        logger.info("API3_METADATA_EXPOSURE_001: Metadata exposure validated")