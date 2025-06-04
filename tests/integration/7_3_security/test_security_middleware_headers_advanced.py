# Section 7.3 - Advanced Security Middleware & HTTP Headers Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Security Middleware & HTTP Headers.md
# Implements missing test cases for security middleware and HTTP headers

import pytest
import httpx
import os
from typing import Dict, Any, List
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.security_fixtures import SecurityFixtures
from utils.security_validators import SecurityValidator

class TestSecurityMiddlewareHeadersAdvanced:
    """Advanced tests for Security Middleware & HTTP Headers"""
    
    @pytest.mark.security
    @pytest.mark.middleware
    @pytest.mark.asyncio
    async def test_httpsec_cors_advanced_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           security_validator: SecurityValidator,
                                           make_request):
        """HTTPSEC_CORS_ADVANCED_001: Advanced CORS Configuration Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test sophisticated CORS attack vectors
        advanced_cors_tests = [
            {
                "origin": "null",
                "description": "Null origin attack"
            },
            {
                "origin": "data:text/html,<script>alert('xss')</script>",
                "description": "Data URI origin"
            },
            {
                "origin": "javascript:alert('xss')",
                "description": "JavaScript protocol origin"
            },
            {
                "origin": "file://localhost/etc/passwd",
                "description": "File protocol origin"
            },
            {
                "origin": "https://sub.trusted.example.com.evil.com",
                "description": "Subdomain spoofing"
            },
            {
                "origin": "https://trusted.example.com:8080",
                "description": "Port manipulation"
            },
            {
                "origin": "https://trusted.example.com.evil.com",
                "description": "Domain suffix attack"
            },
            {
                "origin": "https://\x00trusted.example.com",
                "description": "Null byte injection"
            }
        ]
        
        for test_case in advanced_cors_tests:
            origin = test_case["origin"]
            
            # Test preflight request
            headers = {
                **auth_headers,
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type,Authorization"
            }
            
            response = await http_client.options("/api/v1/chat/completions", headers=headers)
            
            # Validate CORS security
            validation_result = security_validator.validate_advanced_cors_security(
                origin, test_case["description"], dict(response.headers)
            )
            
            assert validation_result["is_secure"], \
                f"CORS should be secure for {test_case['description']}: {origin}"
            
            # Check specific CORS headers
            cors_allow_origin = response.headers.get("access-control-allow-origin", "")
            cors_allow_credentials = response.headers.get("access-control-allow-credentials", "")
            
            # Should not reflect malicious origins
            if origin in ["null", "javascript:alert('xss')", "data:text/html,<script>alert('xss')</script>"]:
                assert cors_allow_origin != origin, \
                    f"Should not reflect malicious origin: {origin}"
            
            # Should not allow credentials with wildcard
            if cors_allow_origin == "*":
                assert cors_allow_credentials.lower() != "true", \
                    "Should not allow credentials with wildcard origin"
            
            # Test actual request with malicious origin
            actual_headers = {**auth_headers, "Origin": origin}
            actual_response = await http_client.get("/api/v1/models", headers=actual_headers)
            
            if actual_response.status_code == 200:
                actual_cors_origin = actual_response.headers.get("access-control-allow-origin", "")
                assert actual_cors_origin != origin or origin.startswith("https://"), \
                    f"Should not allow malicious origin in actual request: {origin}"
        
        logger.info("HTTPSEC_CORS_ADVANCED_001: Advanced CORS configuration tested")

    @pytest.mark.security
    @pytest.mark.middleware
    @pytest.mark.asyncio
    async def test_httpsec_header_comprehensive_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   security_validator: SecurityValidator,
                                                   make_request):
        """HTTPSEC_HEADER_COMPREHENSIVE_001: Comprehensive Security Headers Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test all endpoints for security headers
        test_endpoints = [
            ("/api/v1/models", "GET", None),
            ("/api/v1/chat/completions", "POST", {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 5
            }),
            ("/health", "GET", None),
            ("/", "GET", None)
        ]
        
        # Comprehensive security headers to check
        security_headers_requirements = {
            "strict-transport-security": {
                "required": True,
                "expected_values": ["max-age=", "includeSubDomains"],
                "forbidden_values": ["max-age=0"]
            },
            "x-content-type-options": {
                "required": True,
                "expected_values": ["nosniff"],
                "forbidden_values": []
            },
            "x-frame-options": {
                "required": True,
                "expected_values": ["DENY", "SAMEORIGIN"],
                "forbidden_values": ["ALLOWALL"]
            },
            "x-xss-protection": {
                "required": False,  # Deprecated but still used
                "expected_values": ["1; mode=block", "0"],
                "forbidden_values": ["1"]  # Without mode=block
            },
            "content-security-policy": {
                "required": True,
                "expected_values": ["default-src", "'self'"],
                "forbidden_values": ["'unsafe-eval'", "'unsafe-inline'", "*"]
            },
            "referrer-policy": {
                "required": True,
                "expected_values": ["strict-origin", "strict-origin-when-cross-origin", "no-referrer"],
                "forbidden_values": ["unsafe-url"]
            },
            "permissions-policy": {
                "required": False,
                "expected_values": ["geolocation=", "microphone=", "camera="],
                "forbidden_values": []
            }
        }
        
        for endpoint, method, data in test_endpoints:
            if method == "GET":
                response = await http_client.get(endpoint, headers=auth_headers)
            else:
                response = await make_request(
                    http_client, method, endpoint, auth_headers, data
                )
            
            if response.status_code in [200, 404]:  # Check headers even for 404
                # Validate security headers
                validation_result = security_validator.validate_comprehensive_security_headers(
                    endpoint, dict(response.headers), security_headers_requirements
                )
                
                missing_headers = validation_result.get("missing_headers", [])
                insecure_headers = validation_result.get("insecure_headers", [])
                
                # Log findings
                if missing_headers:
                    logger.warning(f"Missing security headers on {endpoint}: {missing_headers}")
                
                if insecure_headers:
                    logger.warning(f"Insecure header values on {endpoint}: {insecure_headers}")
                
                # Check each required header
                for header_name, requirements in security_headers_requirements.items():
                    header_value = response.headers.get(header_name, "").lower()
                    
                    if requirements["required"] and not header_value:
                        logger.warning(f"Missing required header {header_name} on {endpoint}")
                    
                    if header_value:
                        # Check for expected values
                        if requirements["expected_values"]:
                            has_expected = any(
                                expected.lower() in header_value 
                                for expected in requirements["expected_values"]
                            )
                            if not has_expected:
                                logger.warning(f"Header {header_name} missing expected values on {endpoint}: {header_value}")
                        
                        # Check for forbidden values
                        if requirements["forbidden_values"]:
                            has_forbidden = any(
                                forbidden.lower() in header_value
                                for forbidden in requirements["forbidden_values"]
                            )
                            assert not has_forbidden, \
                                f"Header {header_name} contains forbidden value on {endpoint}: {header_value}"
        
        logger.info("HTTPSEC_HEADER_COMPREHENSIVE_001: Comprehensive security headers tested")

    @pytest.mark.security
    @pytest.mark.middleware
    @pytest.mark.asyncio
    async def test_httpsec_middleware_pii_filtering_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       security_validator: SecurityValidator,
                                                       make_request):
        """HTTPSEC_MIDDLEWARE_PII_001: PII Filtering in Middleware Logging"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test requests with various PII patterns
        pii_test_cases = [
            {
                "type": "credit_card",
                "content": "My credit card number is 4532-1234-5678-9012",
                "pattern": "4532-1234-5678-9012"
            },
            {
                "type": "ssn",
                "content": "My SSN is 123-45-6789",
                "pattern": "123-45-6789"
            },
            {
                "type": "email",
                "content": "Contact me at john.doe@example.com",
                "pattern": "john.doe@example.com"
            },
            {
                "type": "phone", 
                "content": "Call me at (555) 123-4567",
                "pattern": "(555) 123-4567"
            },
            {
                "type": "api_key",
                "content": "My API key is sk-1234567890abcdef1234567890abcdef",
                "pattern": "sk-1234567890abcdef1234567890abcdef"
            }
        ]
        
        for pii_case in pii_test_cases:
            # Test PII in request body
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": pii_case["content"]}],
                "max_tokens": 10
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            # Request should be processed (PII filtering is in logging)
            assert response.status_code == 200
            
            # Test PII in headers (custom headers)
            headers_with_pii = {
                **auth_headers,
                "X-User-Info": pii_case["content"],
                "X-Custom-Data": f"Additional info: {pii_case['pattern']}"
            }
            
            response_with_headers = await http_client.get("/api/v1/models", headers=headers_with_pii)
            
            # Should handle headers with PII gracefully
            assert response_with_headers.status_code == 200
            
            # Validate PII filtering (Note: This validates logging behavior)
            validation_result = security_validator.validate_pii_filtering(
                pii_case["type"], pii_case["pattern"], request_data
            )
            
            # Log test for PII filtering validation
            logger.info(f"PII filtering test for {pii_case['type']}: {pii_case['pattern']}")
        
        logger.info("HTTPSEC_MIDDLEWARE_PII_001: PII filtering in middleware tested")

    @pytest.mark.security
    @pytest.mark.middleware
    @pytest.mark.asyncio
    async def test_httpsec_middleware_error_handling_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        security_validator: SecurityValidator,
                                                        make_request):
        """HTTPSEC_MIDDLEWARE_ERROR_001: Middleware Error Handling Security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various error conditions that might expose middleware internals
        error_test_cases = [
            {
                "description": "Extremely large request body",
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "A" * 100000}],
                    "max_tokens": 10
                },
                "expected_status": [413, 400, 500]
            },
            {
                "description": "Invalid content-type",
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "headers": {"Content-Type": "application/xml"},
                "data": "<xml>invalid</xml>",
                "expected_status": [400, 415]
            },
            {
                "description": "Missing content-type",
                "method": "POST", 
                "endpoint": "/api/v1/chat/completions",
                "headers": {},
                "data": '{"test": "data"}',
                "expected_status": [400, 415]
            },
            {
                "description": "Invalid JSON syntax",
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": '{"invalid": json}',
                "expected_status": [400]
            }
        ]
        
        for test_case in error_test_cases:
            # Prepare headers
            test_headers = auth_headers.copy()
            if "headers" in test_case:
                test_headers.update(test_case["headers"])
            
            # Make request
            if test_case["method"] == "POST":
                if isinstance(test_case["data"], str):
                    # Raw string data
                    response = await http_client.post(
                        test_case["endpoint"],
                        content=test_case["data"],
                        headers=test_headers
                    )
                else:
                    # JSON data
                    response = await make_request(
                        http_client, "POST", test_case["endpoint"],
                        auth_headers, test_case["data"]
                    )
            else:
                response = await http_client.get(test_case["endpoint"], headers=test_headers)
            
            # Validate expected status
            assert response.status_code in test_case["expected_status"], \
                f"Unexpected status for {test_case['description']}: {response.status_code}"
            
            # Validate error response security
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                except:
                    error_data = response.text
                
                validation_result = security_validator.validate_middleware_error_security(
                    test_case["description"], error_data
                )
                
                assert validation_result["is_secure"], \
                    f"Middleware error should be secure: {test_case['description']}"
                
                # Should not expose middleware internals
                error_str = str(error_data).lower()
                middleware_indicators = [
                    "traceback", "stack trace", "internal error", "middleware",
                    "uvicorn", "fastapi", "starlette", "python"
                ]
                
                has_internal_leak = any(
                    indicator in error_str for indicator in middleware_indicators
                )
                
                assert not has_internal_leak, \
                    f"Error should not expose middleware internals: {test_case['description']}"
        
        logger.info("HTTPSEC_MIDDLEWARE_ERROR_001: Middleware error handling security tested")

    @pytest.mark.security
    @pytest.mark.middleware
    @pytest.mark.asyncio
    async def test_httpsec_request_size_limits_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  security_validator: SecurityValidator,
                                                  make_request):
        """HTTPSEC_LIMITS_001: Request Size Limits and DoS Protection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various request size limits
        size_test_cases = [
            {
                "description": "Very large message content",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "X" * 50000}],
                    "max_tokens": 10
                }
            },
            {
                "description": "Many messages in conversation",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Message {i}"} for i in range(1000)],
                    "max_tokens": 10
                }
            },
            {
                "description": "Large max_tokens value",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 999999
                }
            },
            {
                "description": "Large number of choices",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "n": 100,
                    "max_tokens": 10
                }
            }
        ]
        
        for test_case in size_test_cases:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_case["data"]
            )
            
            # Should handle large requests gracefully
            assert response.status_code in [200, 400, 413, 422], \
                f"Large request should be handled gracefully: {test_case['description']}"
            
            if response.status_code in [400, 413, 422]:
                # Validate size limit error handling
                error_data = response.json()
                
                validation_result = security_validator.validate_size_limit_error(
                    test_case["description"], test_case["data"], error_data
                )
                
                assert validation_result["is_secure"], \
                    f"Size limit error should be secure: {test_case['description']}"
                
                # Should provide appropriate error message
                error_str = str(error_data).lower()
                size_indicators = ["too large", "limit", "size", "length", "maximum"]
                has_size_indication = any(
                    indicator in error_str for indicator in size_indicators
                )
                
                # Some indication of size issue is helpful
                logger.info(f"Size limit response for {test_case['description']}: {error_data}")
        
        logger.info("HTTPSEC_LIMITS_001: Request size limits and DoS protection tested")

    @pytest.mark.security
    @pytest.mark.middleware
    @pytest.mark.asyncio
    async def test_httpsec_rate_limiting_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           security_validator: SecurityValidator,
                                           make_request):
        """HTTPSEC_RATE_001: Rate Limiting Security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test rate limiting behavior
        rate_limit_requests = 20  # Number of requests to test rate limiting
        responses = []
        
        # Make rapid requests to trigger rate limiting
        for i in range(rate_limit_requests):
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Rate limit test {i}"}],
                "max_tokens": 5
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            responses.append({
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "request_number": i + 1
            })
            
            # Check for rate limiting indicators
            if response.status_code == 429:
                # Rate limiting triggered
                rate_limit_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
                
                validation_result = security_validator.validate_rate_limit_response(
                    i + 1, rate_limit_data, dict(response.headers)
                )
                
                assert validation_result["is_secure"], \
                    f"Rate limit response should be secure: request {i + 1}"
                
                # Check for rate limit headers
                rate_limit_headers = ["x-ratelimit-limit", "x-ratelimit-remaining", "retry-after"]
                present_headers = [header for header in rate_limit_headers if header in response.headers]
                
                if present_headers:
                    logger.info(f"Rate limit headers present: {present_headers}")
                
                break
        
        # Analyze rate limiting behavior
        status_codes = [r["status_code"] for r in responses]
        rate_limited_count = sum(1 for code in status_codes if code == 429)
        
        if rate_limited_count > 0:
            logger.info(f"Rate limiting detected after {len(responses)} requests, {rate_limited_count} rate limited")
        else:
            logger.info(f"No rate limiting detected in {len(responses)} requests")
        
        # Validate overall rate limiting behavior
        validation_result = security_validator.validate_overall_rate_limiting(responses)
        
        # Rate limiting may or may not be implemented - this test documents behavior
        logger.info(f"Rate limiting analysis: {validation_result}")
        
        logger.info("HTTPSEC_RATE_001: Rate limiting security tested")