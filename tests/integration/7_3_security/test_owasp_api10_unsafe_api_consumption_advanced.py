# Section 7.3 - Advanced OWASP API10:2023 Unsafe Consumption of APIs Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API10_2023 - Unsafe Consumption of APIs (Downstream LLMs).md
# Implements missing test cases for unsafe downstream API consumption

import pytest
import httpx
import os
import json
from typing import Dict, Any, List
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.security_fixtures import SecurityFixtures
from utils.security_validators import SecurityValidator


class TestOWASPAPI10UnsafeConsumptionAdvanced:
    """Advanced tests for OWASP API10:2023 - Unsafe Consumption of APIs"""
    
    @pytest.mark.security
    @pytest.mark.owasp_api10
    @pytest.mark.asyncio
    async def test_uca_provider_malformed_json_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 security_validator: SecurityValidator,
                                                 make_request):
        """UCA_PROVIDER_MALFORMED_JSON_001: Malformed JSON from downstream provider"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        malformed_json_responses = [
            '{"key": "value"',  # Missing closing brace
            '{"key": "value", }',  # Trailing comma
            '{"key": value}',  # Unquoted value
            '{"key": "val\nue"}',  # Invalid escape
            '{"key": "value", "key2":}',  # Missing value
            'not json at all',  # Not JSON
            '',  # Empty response
            '{"choices": [{"message": {"content": "test"}, }]}',  # Trailing comma in nested
        ]
        
        for malformed_json in malformed_json_responses:
            # Mock provider response to return malformed JSON
            with patch('httpx.AsyncClient.post') as mock_post:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = malformed_json
                mock_response.headers = {"content-type": "application/json"}
                
                # Mock json() to raise JSONDecodeError
                def mock_json():
                    return json.loads(malformed_json)
                
                mock_response.json = mock_json
                mock_post.return_value = mock_response
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                # Should handle malformed JSON gracefully
                assert response.status_code in [500, 502, 503], \
                    f"Malformed JSON should cause server error: {malformed_json[:50]}..."
                
                if response.status_code == 500:
                    error_data = response.json()
                    assert "detail" in error_data
                    assert "request_id" in error_data or "error" in str(error_data)
                    
                    # Should not expose raw malformed JSON
                    response_str = str(error_data)
                    assert malformed_json not in response_str, \
                        f"Should not expose malformed JSON in error response"
        
        logger.info("UCA_PROVIDER_MALFORMED_JSON_001: Malformed JSON handling tested")

    @pytest.mark.security
    @pytest.mark.owasp_api10
    @pytest.mark.asyncio
    async def test_uca_provider_schema_mismatch_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  security_validator: SecurityValidator,
                                                  make_request):
        """UCA_PROVIDER_SCHEMA_MISMATCH_001: Schema mismatch from downstream provider"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        schema_mismatched_responses = [
            {"choices": "not_an_array"},  # choices should be array
            {"choices": [{"message": 123}]},  # message should be object
            {"choices": [{"message": {"content": ["not_string"]}}]},  # content wrong type
            {"invalid_structure": "test"},  # Missing required fields
            {"choices": [{"message": {"role": "user"}}]},  # Missing content
            {"choices": [{"delta": {"content": "test"}}]},  # Wrong structure for non-streaming
            {"error": {"code": "test", "message": 123}},  # Error with wrong message type
        ]
        
        for invalid_response in schema_mismatched_responses:
            with patch('httpx.AsyncClient.post') as mock_post:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = invalid_response
                mock_response.headers = {"content-type": "application/json"}
                mock_post.return_value = mock_response
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                # Should handle schema mismatch gracefully
                assert response.status_code in [500, 502, 503], \
                    f"Schema mismatch should cause server error: {invalid_response}"
                
                if response.status_code == 500:
                    error_data = response.json()
                    
                    # Should not expose provider-specific schema details
                    validation_result = security_validator.validate_schema_error_exposure(
                        invalid_response, error_data
                    )
                    
                    assert validation_result["is_secure"], \
                        f"Should not expose provider schema details: {invalid_response}"
        
        logger.info("UCA_PROVIDER_SCHEMA_MISMATCH_001: Schema mismatch handling tested")

    @pytest.mark.security
    @pytest.mark.owasp_api10
    @pytest.mark.asyncio
    async def test_uca_provider_unexpected_error_code_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        security_validator: SecurityValidator,
                                                        make_request):
        """UCA_PROVIDER_UNEXPECTED_ERROR_CODE_001: Unexpected HTTP error codes"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        unusual_error_codes = [418, 507, 451, 422, 424, 511, 999, 598]
        
        for error_code in unusual_error_codes:
            with patch('httpx.AsyncClient.post') as mock_post:
                mock_response = MagicMock()
                mock_response.status_code = error_code
                mock_response.text = f"Provider returned {error_code}"
                mock_response.json.return_value = {"error": f"Unusual error {error_code}"}
                mock_post.return_value = mock_response
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                # Should handle unusual error codes gracefully
                assert response.status_code in [500, 502, 503], \
                    f"Unusual error code {error_code} should be normalized"
                
                error_data = response.json()
                
                # Should not expose the unusual status code directly
                error_str = str(error_data).lower()
                assert str(error_code) not in error_str, \
                    f"Should not expose unusual error code {error_code} to client"
                
                # Should provide generic error message
                assert "detail" in error_data or "error" in error_data, \
                    f"Should provide generic error for code {error_code}"
        
        logger.info("UCA_PROVIDER_UNEXPECTED_ERROR_CODE_001: Unusual error code handling tested")

    @pytest.mark.security
    @pytest.mark.owasp_api10
    @pytest.mark.asyncio
    async def test_uca_provider_timeout_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          security_validator: SecurityValidator,
                                          make_request):
        """UCA_PROVIDER_TIMEOUT_001: Provider timeout handling"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        import asyncio
        from httpx import TimeoutException, ConnectTimeout, ReadTimeout
        
        timeout_exceptions = [
            TimeoutException("Connection timeout"),
            ConnectTimeout("Connect timeout"),
            ReadTimeout("Read timeout"),
            asyncio.TimeoutError("Async timeout")
        ]
        
        for timeout_exception in timeout_exceptions:
            with patch('httpx.AsyncClient.post') as mock_post:
                mock_post.side_effect = timeout_exception
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                # Should handle timeout gracefully
                assert response.status_code in [500, 502, 503, 504], \
                    f"Timeout should be handled gracefully: {type(timeout_exception).__name__}"
                
                # Ideally should return 504 Gateway Timeout
                if response.status_code == 504:
                    error_data = response.json()
                    assert "timeout" in str(error_data).lower() or "gateway" in str(error_data).lower()
                
                # Validate timeout response security
                validation_result = security_validator.validate_timeout_response_security(
                    str(timeout_exception), response.json() if response.status_code != 204 else {}
                )
                
                assert validation_result["is_secure"], \
                    f"Timeout response should be secure: {type(timeout_exception).__name__}"
        
        logger.info("UCA_PROVIDER_TIMEOUT_001: Provider timeout handling tested")

    @pytest.mark.security
    @pytest.mark.owasp_api10
    @pytest.mark.asyncio
    async def test_uca_provider_harmful_content_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   security_validator: SecurityValidator,
                                                   make_request):
        """UCA_PROVIDER_HARMFUL_CONTENT_001: Harmful content from provider"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        harmful_content_responses = [
            "<script>alert('XSS')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';DROP TABLE users;--",
            "<iframe src='javascript:alert(1)'></iframe>",
            "data:text/html,<script>alert('xss')</script>",
            "<svg onload=alert('xss')>",
            "${7*7}#{7*7}<%=7*7%>{{7*7}}"  # Template injection
        ]
        
        for harmful_content in harmful_content_responses:
            with patch('httpx.AsyncClient.post') as mock_post:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "choices": [{
                        "message": {
                            "content": harmful_content,
                            "role": "assistant"
                        }
                    }]
                }
                mock_post.return_value = mock_response
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 100
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                assert response.status_code == 200
                response_data = response.json()
                
                # Validate JSON encoding of harmful content
                validation_result = security_validator.validate_harmful_content_encoding(
                    harmful_content, response_data
                )
                
                assert validation_result["is_properly_encoded"], \
                    f"Harmful content should be properly JSON encoded: {harmful_content[:50]}..."
                
                # Check that content is properly escaped in JSON
                response_str = json.dumps(response_data)
                
                # Verify dangerous characters are escaped
                assert "<script>" not in response_str, \
                    f"Script tags should be escaped in JSON response"
                assert "javascript:" not in response_str, \
                    f"Javascript protocol should be escaped in JSON response"
                
                # Content should be present but safely encoded
                if "choices" in response_data and response_data["choices"]:
                    content = response_data["choices"][0]["message"]["content"]
                    assert harmful_content in content, \
                        f"Content should be preserved (but safely encoded)"
        
        logger.info("UCA_PROVIDER_HARMFUL_CONTENT_001: Harmful content encoding tested")

    @pytest.mark.security
    @pytest.mark.owasp_api10
    @pytest.mark.asyncio
    async def test_uca_provider_data_leakage_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               security_validator: SecurityValidator,
                                               make_request):
        """UCA_PROVIDER_DATA_LEAKAGE_001: Provider data leakage prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Mock provider response with extra fields that shouldn't leak through
        provider_response_with_extras = {
            "choices": [{
                "message": {
                    "content": "Test response",
                    "role": "assistant"
                },
                "finish_reason": "stop"
            }],
            "model": "gpt-3.5-turbo",
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15
            },
            # Extra fields that shouldn't leak through
            "internal_provider_id": "secret-internal-id-12345",
            "billing_account": "acct_1234567890",
            "provider_metadata": {
                "server_id": "prod-server-42",
                "request_cost": 0.00001,
                "api_version": "2023-internal"
            },
            "debug_info": {
                "processing_time_ms": 123,
                "model_load_time": 45,
                "cache_hit": True
            },
            "_private_fields": {
                "user_id": "user_12345",
                "organization_id": "org_67890"
            }
        }
        
        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = provider_response_with_extras
            mock_post.return_value = mock_response
            
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 10
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            assert response.status_code == 200
            response_data = response.json()
            
            # Validate no data leakage
            validation_result = security_validator.validate_provider_data_leakage(
                provider_response_with_extras, response_data
            )
            
            assert validation_result["is_secure"], \
                "Provider-specific fields should not leak through to client"
            
            # Check that only expected fields are present
            expected_fields = {"choices", "model", "usage", "id", "object", "created"}
            response_fields = set(response_data.keys())
            
            # Should not contain provider-specific fields
            forbidden_fields = {
                "internal_provider_id", "billing_account", "provider_metadata",
                "debug_info", "_private_fields"
            }
            
            leaked_fields = forbidden_fields.intersection(response_fields)
            assert len(leaked_fields) == 0, \
                f"Provider-specific fields leaked to client: {leaked_fields}"
            
            # Check nested objects don't contain extra fields
            response_str = json.dumps(response_data)
            sensitive_values = [
                "secret-internal-id", "acct_1234567890", "prod-server-42",
                "user_12345", "org_67890", "processing_time_ms"
            ]
            
            for sensitive_value in sensitive_values:
                assert sensitive_value not in response_str, \
                    f"Sensitive provider value leaked: {sensitive_value}"
        
        logger.info("UCA_PROVIDER_DATA_LEAKAGE_001: Provider data leakage prevention tested")

    @pytest.mark.security
    @pytest.mark.owasp_api10
    @pytest.mark.asyncio
    async def test_uca_provider_authentication_failure_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          security_validator: SecurityValidator,
                                                          make_request):
        """UCA_PROVIDER_AUTH_FAILURE_001: Provider authentication failure handling"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        auth_failure_responses = [
            {"error": {"type": "authentication_error", "message": "Invalid API key"}},
            {"error": {"code": 401, "message": "Unauthorized"}},
            {"error": {"type": "permission_error", "message": "Insufficient permissions"}},
            {"detail": "Authentication failed"},
        ]
        
        auth_failure_status_codes = [401, 403]
        
        for status_code in auth_failure_status_codes:
            for error_response in auth_failure_responses:
                with patch('httpx.AsyncClient.post') as mock_post:
                    mock_response = MagicMock()
                    mock_response.status_code = status_code
                    mock_response.json.return_value = error_response
                    mock_post.return_value = mock_response
                    
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "test"}],
                        "max_tokens": 10
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    # Should handle provider auth failure gracefully
                    assert response.status_code in [500, 502, 503], \
                        f"Provider auth failure should be handled: {status_code}"
                    
                    error_data = response.json()
                    
                    # Should not expose provider auth details
                    validation_result = security_validator.validate_auth_error_exposure(
                        error_response, error_data
                    )
                    
                    assert validation_result["is_secure"], \
                        f"Should not expose provider auth details: {error_response}"
                    
                    # Should not reveal it's a provider auth issue
                    error_str = str(error_data).lower()
                    auth_indicators = ["api key", "unauthorized", "authentication", "permission"]
                    has_auth_leak = any(indicator in error_str for indicator in auth_indicators)
                    
                    # Some generic error message is okay, but not provider-specific details
                    if has_auth_leak:
                        logger.warning(f"Potential auth detail exposure: {error_data}")
        
        logger.info("UCA_PROVIDER_AUTH_FAILURE_001: Provider authentication failure handling tested")

    @pytest.mark.security
    @pytest.mark.owasp_api10
    @pytest.mark.asyncio
    async def test_uca_provider_connection_security_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       security_validator: SecurityValidator,
                                                       make_request):
        """UCA_PROVIDER_CONNECTION_001: Provider connection security validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        import ssl
        from httpx import ConnectError, TLSError
        
        connection_security_exceptions = [
            ConnectError("SSL: CERTIFICATE_VERIFY_FAILED"),
            TLSError("SSL handshake failed"),
            ConnectError("SSL: WRONG_VERSION_NUMBER"),
            TLSError("SSL certificate error"),
        ]
        
        for security_exception in connection_security_exceptions:
            with patch('httpx.AsyncClient.post') as mock_post:
                mock_post.side_effect = security_exception
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                # Should handle connection security failures
                assert response.status_code in [500, 502, 503], \
                    f"Connection security failure should be handled: {type(security_exception).__name__}"
                
                error_data = response.json()
                
                # Should not expose SSL/TLS details to client
                validation_result = security_validator.validate_connection_error_exposure(
                    str(security_exception), error_data
                )
                
                assert validation_result["is_secure"], \
                    f"Should not expose connection security details: {type(security_exception).__name__}"
                
                # Should not reveal SSL certificate details
                error_str = str(error_data).lower()
                ssl_indicators = ["ssl", "certificate", "tls", "handshake", "verify_failed"]
                has_ssl_leak = any(indicator in error_str for indicator in ssl_indicators)
                
                assert not has_ssl_leak, \
                    f"Should not expose SSL details: {security_exception}"
        
        logger.info("UCA_PROVIDER_CONNECTION_001: Provider connection security tested")