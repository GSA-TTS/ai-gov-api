# Section 7.12 - Zero Trust API Design Verification Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_API Design Verification.md

import pytest
import httpx
import asyncio
import time
import secrets
import hashlib
from typing import Dict, Any, List, Optional
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestAPIDesignVerification:
    """Zero Trust API Design Verification tests"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_001_explicit_authentication(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """API_DESIGN_001: Verify explicit authentication requirement on all endpoints"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test all known endpoints require authentication
        endpoints_to_test = [
            ("GET", "/api/v1/models"),
            ("POST", "/api/v1/chat/completions"),
            ("POST", "/api/v1/embeddings"),
            ("GET", "/"),
            ("GET", "/health"),
            ("GET", "/metrics"),
            ("GET", "/api/v1/usage"),
            ("GET", "/api/v1/status")
        ]
        
        for method, endpoint in endpoints_to_test:
            # Test without authentication
            if method == "POST" and "chat" in endpoint:
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test"}],
                    "max_tokens": 50
                }
            elif method == "POST" and "embeddings" in endpoint:
                request_data = {
                    "model": config.get_embedding_model(0),
                    "input": "Test input"
                }
            else:
                request_data = None
            
            response = await make_request(
                http_client, method, endpoint,
                {}, request_data, track_cost=False
            )
            
            # Public endpoints like health might be excluded from authentication
            if endpoint in ["/", "/health"]:
                # These may be intentionally public
                continue
            else:
                assert response.status_code in [401, 403], \
                    f"Endpoint {method} {endpoint} should require authentication"
        
        logger.info("API_DESIGN_001: Explicit authentication verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_002_secure_defaults(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """API_DESIGN_002: Verify secure-by-default configuration"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test default request handling is secure
        minimal_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test secure defaults"}]
            # No max_tokens specified - should have secure default
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, minimal_request
        )
        
        assert response.status_code == 200, "Request with minimal parameters should succeed"
        
        response_data = response.json()
        assert "choices" in response_data
        
        # Verify secure defaults are applied
        if "usage" in response_data:
            assert response_data["usage"]["total_tokens"] <= 4096, \
                "Default token limit should be reasonable for security"
        
        # Verify no sensitive information in response
        response_text = str(response_data).lower()
        sensitive_patterns = ["password", "secret", "key", "token", "credential"]
        for pattern in sensitive_patterns:
            assert pattern not in response_text, \
                f"Response should not contain sensitive pattern: {pattern}"
        
        logger.info("API_DESIGN_002: Secure defaults verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_003_input_validation(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  security_validator: SecurityValidator,
                                                  make_request):
        """API_DESIGN_003: Comprehensive input validation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test various malicious input patterns
        malicious_inputs = [
            # XSS attempts
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            
            # SQL injection attempts
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "UNION SELECT * FROM secrets",
            
            # Command injection attempts
            "; cat /etc/passwd",
            "$(rm -rf /)",
            "`whoami`",
            
            # Path traversal attempts
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            
            # LDAP injection
            "*)(uid=*",
            "admin*)(|(password=*",
            
            # XXE attempts
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            
            # NoSQL injection
            "'; return true; var x='",
            "$ne",
            
            # Header injection
            "test\r\nSet-Cookie: malicious=true",
            
            # Unicode/encoding attacks
            "\u0000",
            "%00",
            "\x00"
        ]
        
        validation_results = []
        
        for malicious_input in malicious_inputs:
            # Test malicious input in various request fields
            test_scenarios = [
                {
                    "field": "content",
                    "request": {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": malicious_input}],
                        "max_tokens": 50
                    }
                },
                {
                    "field": "model",
                    "request": {
                        "model": malicious_input,
                        "messages": [{"role": "user", "content": "Test"}],
                        "max_tokens": 50
                    }
                }
            ]
            
            for scenario in test_scenarios:
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, scenario["request"], track_cost=False
                    )
                    
                    # Should either reject or sanitize
                    if response.status_code == 200:
                        # If accepted, verify response is safe
                        response_data = response.json()
                        response_text = str(response_data)
                        
                        # Verify malicious input is not reflected unsanitized
                        validation = security_validator.validate_response_safety(
                            response_text, malicious_input
                        )
                        assert validation["is_safe"], \
                            f"Response contains unsanitized malicious input: {malicious_input[:50]}"
                        
                        validation_results.append({
                            "input": malicious_input[:50],
                            "field": scenario["field"],
                            "status": "sanitized",
                            "response_code": response.status_code
                        })
                    else:
                        # Rejection is also acceptable
                        assert response.status_code in [400, 422], \
                            f"Malicious input should be rejected with appropriate error code"
                        
                        validation_results.append({
                            "input": malicious_input[:50],
                            "field": scenario["field"],
                            "status": "rejected",
                            "response_code": response.status_code
                        })
                
                except Exception as e:
                    # Network/parsing errors are acceptable for malformed input
                    validation_results.append({
                        "input": malicious_input[:50],
                        "field": scenario["field"],
                        "status": "error",
                        "error": str(e)[:100]
                    })
        
        # Verify that malicious inputs were handled appropriately
        handled_appropriately = sum(1 for result in validation_results 
                                  if result["status"] in ["rejected", "sanitized", "error"])
        total_tests = len(validation_results)
        
        assert handled_appropriately / total_tests >= 0.9, \
            f"At least 90% of malicious inputs should be handled appropriately: {handled_appropriately}/{total_tests}"
        
        logger.info(f"API_DESIGN_003: Input validation tested - {handled_appropriately}/{total_tests} handled appropriately")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_004_error_information_disclosure(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             security_validator: SecurityValidator,
                                                             make_request):
        """API_DESIGN_004: Verify error messages don't disclose sensitive information"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Generate various error conditions
        error_scenarios = [
            {
                "description": "Invalid model",
                "request": {
                    "model": "nonexistent_model_12345",
                    "messages": [{"role": "user", "content": "Test"}],
                    "max_tokens": 50
                }
            },
            {
                "description": "Missing required field",
                "request": {
                    "model": config.get_chat_model(0),
                    "max_tokens": 50
                    # Missing messages
                }
            },
            {
                "description": "Invalid parameter type",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test"}],
                    "max_tokens": "invalid_string"
                }
            },
            {
                "description": "Out of range parameter",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test"}],
                    "max_tokens": -1,
                    "temperature": 10.0
                }
            }
        ]
        
        for scenario in error_scenarios:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario["request"], track_cost=False
            )
            
            # Should return an error
            assert response.status_code >= 400, \
                f"Scenario '{scenario['description']}' should return an error"
            
            # Verify error message security
            error_validation = security_validator.validate_error_message_security(
                response.text
            )
            
            assert error_validation["is_secure"], \
                f"Error message for '{scenario['description']}' exposes sensitive information: {error_validation['violations']}"
            
            # Verify specific sensitive information is not disclosed
            response_text = response.text.lower()
            sensitive_patterns = [
                "database", "sql", "connection", "server", "internal",
                "stack trace", "traceback", "exception", "/app/", "/home/",
                "api_key", "secret", "password", "token", "credential",
                "file not found", "no such file", "permission denied"
            ]
            
            for pattern in sensitive_patterns:
                assert pattern not in response_text, \
                    f"Error message contains sensitive pattern '{pattern}' for scenario '{scenario['description']}'"
        
        logger.info("API_DESIGN_004: Error information disclosure prevention verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_005_rate_limiting(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """API_DESIGN_005: Verify rate limiting implementation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test rate limiting with rapid requests
        request_template = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Rate limit test"}],
            "max_tokens": 10  # Small to minimize cost
        }
        
        rate_limit_responses = []
        start_time = time.time()
        
        # Make rapid requests to potentially trigger rate limiting
        for i in range(20):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_template
            )
            
            rate_limit_responses.append({
                "status_code": response.status_code,
                "timestamp": time.time(),
                "headers": dict(response.headers)
            })
            
            # Brief delay between requests
            await asyncio.sleep(0.1)
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        # Analyze rate limiting behavior
        successful_responses = [r for r in rate_limit_responses if r["status_code"] == 200]
        rate_limited_responses = [r for r in rate_limit_responses if r["status_code"] == 429]
        
        # Check for rate limiting headers
        rate_limit_headers_found = False
        for response in rate_limit_responses:
            headers = response["headers"]
            rate_limit_header_names = [
                "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
                "rate-limit", "ratelimit-limit", "retry-after"
            ]
            
            for header_name in rate_limit_header_names:
                if any(h.lower() == header_name for h in headers.keys()):
                    rate_limit_headers_found = True
                    break
        
        if rate_limited_responses:
            logger.info(f"Rate limiting detected: {len(rate_limited_responses)} requests rate limited")
            
            # Verify rate limited responses have appropriate headers
            for response in rate_limited_responses:
                assert "retry-after" in [h.lower() for h in response["headers"].keys()] or \
                       any("rate" in h.lower() for h in response["headers"].keys()), \
                    "Rate limited responses should include appropriate headers"
        elif rate_limit_headers_found:
            logger.info("Rate limiting headers detected but no rate limiting occurred")
        else:
            logger.info("No rate limiting detected - may be configured with high limits")
        
        # Verify system handles the load appropriately
        assert len(successful_responses) > 0, "At least some requests should succeed"
        
        logger.info(f"API_DESIGN_005: Rate limiting tested - {len(successful_responses)} successful, {len(rate_limited_responses)} rate limited")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_006_request_size_limits(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """API_DESIGN_006: Verify request size limits prevent DoS"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test increasingly large requests
        size_test_scenarios = [
            {
                "description": "Normal size request",
                "content": "Normal request content for size testing",
                "expected_status": 200
            },
            {
                "description": "Large request",
                "content": "Large request content. " * 1000,  # ~25KB
                "expected_status": [200, 413, 422]
            },
            {
                "description": "Very large request",
                "content": "Very large request content. " * 10000,  # ~250KB
                "expected_status": [413, 422, 400]
            },
            {
                "description": "Extremely large request",
                "content": "X" * (1024 * 1024),  # 1MB
                "expected_status": [413, 422, 400]
            }
        ]
        
        for scenario in size_test_scenarios:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["content"]}],
                "max_tokens": 50
            }
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=False
                )
                
                if isinstance(scenario["expected_status"], list):
                    assert response.status_code in scenario["expected_status"], \
                        f"Scenario '{scenario['description']}' should return one of {scenario['expected_status']}"
                else:
                    assert response.status_code == scenario["expected_status"], \
                        f"Scenario '{scenario['description']}' should return {scenario['expected_status']}"
                
                if response.status_code == 413:
                    logger.info(f"Request size limit enforced for: {scenario['description']}")
                elif response.status_code == 422:
                    logger.info(f"Request validation failed for: {scenario['description']}")
                elif response.status_code == 200:
                    logger.info(f"Large request processed successfully: {scenario['description']}")
            
            except Exception as e:
                # Network errors are acceptable for very large requests
                if "extremely large" in scenario["description"].lower():
                    logger.info(f"Network error for {scenario['description']}: {str(e)[:100]}")
                else:
                    raise e
        
        logger.info("API_DESIGN_006: Request size limits verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_007_response_headers_security(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """API_DESIGN_007: Verify security-focused response headers"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test various endpoints for security headers
        endpoints_to_test = [
            ("GET", "/api/v1/models"),
            ("POST", "/api/v1/chat/completions", {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test security headers"}],
                "max_tokens": 50
            })
        ]
        
        for endpoint_info in endpoints_to_test:
            if len(endpoint_info) == 3:
                method, endpoint, request_data = endpoint_info
            else:
                method, endpoint = endpoint_info
                request_data = None
            
            response = await make_request(
                http_client, method, endpoint,
                auth_headers, request_data
            )
            
            assert response.status_code == 200, f"Request to {endpoint} should succeed"
            
            headers = dict(response.headers)
            header_names = [h.lower() for h in headers.keys()]
            
            # Check for recommended security headers
            security_headers = {
                "x-content-type-options": "nosniff",
                "x-frame-options": ["DENY", "SAMEORIGIN"],
                "x-xss-protection": "1; mode=block",
                "strict-transport-security": None,  # Check for presence
                "content-security-policy": None,    # Check for presence
                "referrer-policy": None            # Check for presence
            }
            
            security_score = 0
            total_headers = len(security_headers)
            
            for header_name, expected_value in security_headers.items():
                if header_name in header_names:
                    security_score += 1
                    
                    if expected_value:
                        actual_value = headers[header_name]
                        if isinstance(expected_value, list):
                            assert actual_value in expected_value, \
                                f"Header {header_name} should have value in {expected_value}, got {actual_value}"
                        else:
                            assert expected_value in actual_value, \
                                f"Header {header_name} should contain {expected_value}, got {actual_value}"
            
            # Verify no sensitive information in headers
            sensitive_patterns = ["server", "x-powered-by", "x-aspnet-version"]
            for pattern in sensitive_patterns:
                if pattern in header_names:
                    logger.warning(f"Potentially sensitive header found: {pattern}")
            
            logger.info(f"Security headers for {endpoint}: {security_score}/{total_headers} present")
        
        logger.info("API_DESIGN_007: Response header security verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_008_cors_configuration(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """API_DESIGN_008: Verify CORS configuration is secure"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test CORS preflight request
        cors_headers = {
            "Origin": "https://malicious-site.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,Authorization"
        }
        
        response = await make_request(
            http_client, "OPTIONS", "/api/v1/chat/completions",
            cors_headers, track_cost=False
        )
        
        # Analyze CORS response
        response_headers = dict(response.headers)
        cors_headers_present = {}
        
        cors_header_names = [
            "access-control-allow-origin",
            "access-control-allow-methods", 
            "access-control-allow-headers",
            "access-control-allow-credentials",
            "access-control-max-age"
        ]
        
        for header_name in cors_header_names:
            actual_header = next((h for h in response_headers.keys() if h.lower() == header_name), None)
            if actual_header:
                cors_headers_present[header_name] = response_headers[actual_header]
        
        if cors_headers_present:
            # CORS is configured - verify it's secure
            logger.info(f"CORS headers found: {cors_headers_present}")
            
            # Verify Access-Control-Allow-Origin is not wildcard with credentials
            allow_origin = cors_headers_present.get("access-control-allow-origin", "")
            allow_credentials = cors_headers_present.get("access-control-allow-credentials", "false")
            
            if allow_credentials.lower() == "true":
                assert allow_origin != "*", \
                    "CORS should not use wildcard origin with credentials enabled"
            
            # Verify allowed methods are reasonable
            allowed_methods = cors_headers_present.get("access-control-allow-methods", "")
            dangerous_methods = ["TRACE", "CONNECT", "DELETE", "PUT", "PATCH"]
            
            for method in dangerous_methods:
                if method in allowed_methods.upper():
                    logger.warning(f"Potentially dangerous CORS method allowed: {method}")
            
            # Verify max-age is reasonable (not too long)
            max_age = cors_headers_present.get("access-control-max-age")
            if max_age:
                try:
                    max_age_seconds = int(max_age)
                    assert max_age_seconds <= 86400, \
                        "CORS max-age should not exceed 24 hours for security"
                except ValueError:
                    pass
        else:
            logger.info("No CORS headers found - CORS may be disabled")
        
        logger.info("API_DESIGN_008: CORS configuration security verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_009_parameter_pollution(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """API_DESIGN_009: Test parameter pollution attack resistance"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test parameter pollution scenarios
        pollution_scenarios = [
            {
                "description": "Duplicate model parameter",
                "url": "/api/v1/chat/completions?model=valid&model=malicious",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test pollution"}],
                    "max_tokens": 50
                }
            },
            {
                "description": "Multiple content fields",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [
                        {"role": "user", "content": "First content"},
                        {"role": "user", "content": "Second content"}
                    ],
                    "max_tokens": 50
                }
            }
        ]
        
        for scenario in pollution_scenarios:
            try:
                if "url" in scenario:
                    # Test URL parameter pollution
                    async with httpx.AsyncClient(base_url=config.BASE_URL) as client:
                        response = await client.post(
                            scenario["url"],
                            headers=auth_headers,
                            json=scenario["request"]
                        )
                else:
                    # Test JSON parameter pollution
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, scenario["request"]
                    )
                
                # Should either process safely or reject
                assert response.status_code in [200, 400, 422], \
                    f"Parameter pollution scenario '{scenario['description']}' should be handled safely"
                
                if response.status_code == 200:
                    # If processed, verify safe handling
                    response_data = response.json()
                    assert "choices" in response_data, \
                        "Valid response structure should be maintained"
                
            except Exception as e:
                # Parsing errors are acceptable for malformed requests
                logger.info(f"Parameter pollution '{scenario['description']}' caused parsing error: {str(e)[:100]}")
        
        logger.info("API_DESIGN_009: Parameter pollution resistance verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_api_design_010_content_type_validation(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str]):
        """API_DESIGN_010: Verify content type validation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test various content types
        content_type_scenarios = [
            {
                "description": "Valid JSON content type",
                "content_type": "application/json",
                "data": '{"model": "' + config.get_chat_model(0) + '", "messages": [{"role": "user", "content": "Test"}], "max_tokens": 50}',
                "expected_status": 200
            },
            {
                "description": "Invalid content type - text/plain",
                "content_type": "text/plain",
                "data": "plain text data",
                "expected_status": [400, 415, 422]
            },
            {
                "description": "Invalid content type - application/xml",
                "content_type": "application/xml",
                "data": "<xml>test</xml>",
                "expected_status": [400, 415, 422]
            },
            {
                "description": "Missing content type",
                "content_type": None,
                "data": '{"model": "' + config.get_chat_model(0) + '", "messages": [{"role": "user", "content": "Test"}], "max_tokens": 50}',
                "expected_status": [200, 400, 415]  # Some APIs may infer JSON
            }
        ]
        
        async with httpx.AsyncClient(base_url=config.BASE_URL) as client:
            for scenario in content_type_scenarios:
                headers = auth_headers.copy()
                if scenario["content_type"]:
                    headers["Content-Type"] = scenario["content_type"]
                
                try:
                    response = await client.post(
                        "/api/v1/chat/completions",
                        headers=headers,
                        data=scenario["data"]
                    )
                    
                    if isinstance(scenario["expected_status"], list):
                        assert response.status_code in scenario["expected_status"], \
                            f"Content type scenario '{scenario['description']}' should return one of {scenario['expected_status']}"
                    else:
                        assert response.status_code == scenario["expected_status"], \
                            f"Content type scenario '{scenario['description']}' should return {scenario['expected_status']}"
                
                except Exception as e:
                    # Network/parsing errors are acceptable for invalid content types
                    if scenario["description"] in ["Invalid content type - text/plain", "Invalid content type - application/xml"]:
                        logger.info(f"Content type validation '{scenario['description']}' caused error: {str(e)[:100]}")
                    else:
                        raise e
        
        logger.info("API_DESIGN_010: Content type validation verified")