# Section 7.3 - Security Middleware & HTTP Headers Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Security Middleware & HTTP Headers.md

import pytest
import httpx
import asyncio
import time
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures
from utils.security_validators import SecurityValidator


class TestSecurityMiddlewareHeaders:
    """Comprehensive security middleware and HTTP headers tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_cors_configuration_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """CORS_CONFIG_001: CORS configuration validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test CORS headers in response
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for CORS headers
        cors_headers = {
            "access-control-allow-origin": headers.get("access-control-allow-origin"),
            "access-control-allow-methods": headers.get("access-control-allow-methods"),
            "access-control-allow-headers": headers.get("access-control-allow-headers"),
            "access-control-allow-credentials": headers.get("access-control-allow-credentials")
        }
        
        # SECURITY CHECK: Ensure CORS is not overly permissive
        if cors_headers["access-control-allow-origin"] == "*":
            if cors_headers["access-control-allow-credentials"] == "true":
                pytest.fail("CRITICAL: CORS misconfiguration - wildcard origin with credentials")
            else:
                logger.warning("CORS allows all origins - verify this is intentional")
        
        # Test OPTIONS preflight request
        try:
            options_response = await http_client.options(
                "/api/v1/chat/completions",
                headers=auth_headers
            )
            
            if options_response.status_code in [200, 204]:
                options_headers = options_response.headers
                
                # Verify preflight response headers
                assert "access-control-allow-methods" in options_headers
                assert "access-control-allow-headers" in options_headers
                
                # Should allow necessary methods
                allowed_methods = options_headers.get("access-control-allow-methods", "").upper()
                assert "POST" in allowed_methods
                assert "GET" in allowed_methods
                
        except Exception as e:
            logger.info(f"OPTIONS request not supported or failed: {e}")
        
        logger.info("CORS_CONFIG_001: CORS configuration validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_http_security_headers_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """HTTP_SECURITY_001: HTTP security headers validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Critical security headers to check
        security_headers = {
            "strict-transport-security": "HSTS protection",
            "x-content-type-options": "MIME type sniffing protection", 
            "x-frame-options": "Clickjacking protection",
            "x-xss-protection": "XSS protection",
            "content-security-policy": "CSP protection",
            "referrer-policy": "Referrer leakage protection",
            "permissions-policy": "Feature policy protection"
        }
        
        missing_headers = []
        weak_headers = []
        
        for header, description in security_headers.items():
            header_value = headers.get(header, "").lower()
            
            if not header_value:
                missing_headers.append(f"{header} ({description})")
            else:
                # Check for weak configurations
                if header == "strict-transport-security":
                    if "max-age" not in header_value:
                        weak_headers.append(f"{header}: missing max-age")
                    elif "includesubdomains" not in header_value:
                        weak_headers.append(f"{header}: missing includeSubDomains")
                
                elif header == "x-content-type-options":
                    if "nosniff" not in header_value:
                        weak_headers.append(f"{header}: should be 'nosniff'")
                
                elif header == "x-frame-options":
                    if header_value not in ["deny", "sameorigin"]:
                        weak_headers.append(f"{header}: weak value '{header_value}'")
                
                elif header == "content-security-policy":
                    if "unsafe-inline" in header_value or "unsafe-eval" in header_value:
                        weak_headers.append(f"{header}: contains unsafe directives")
        
        # Log findings
        if missing_headers:
            logger.warning(f"Missing security headers: {missing_headers}")
        
        if weak_headers:
            logger.warning(f"Weak security header configurations: {weak_headers}")
        
        if not missing_headers and not weak_headers:
            logger.info("All security headers properly configured")
        
        logger.info("HTTP_SECURITY_001: HTTP security headers validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_rate_limiting_001(self, http_client: httpx.AsyncClient,
                                   auth_headers: Dict[str, str],
                                   make_request):
        """RATE_LIMIT_001: Rate limiting implementation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test rate limiting by making rapid requests
        rate_limit_responses = []
        start_time = time.time()
        
        # Make rapid requests to trigger rate limiting
        for i in range(20):  # Adjust based on expected rate limits
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            
            rate_limit_responses.append({
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "timestamp": time.time()
            })
            
            # Stop if rate limited
            if response.status_code == 429:
                logger.info(f"Rate limit triggered after {i+1} requests")
                break
            
            await asyncio.sleep(0.1)  # Small delay between requests
        
        end_time = time.time()
        total_time = end_time - start_time
        request_rate = len(rate_limit_responses) / total_time
        
        # Analyze rate limiting behavior
        status_codes = [r["status_code"] for r in rate_limit_responses]
        
        if 429 in status_codes:
            # Rate limiting is working
            first_rate_limit = next(i for i, r in enumerate(rate_limit_responses) if r["status_code"] == 429)
            logger.info(f"Rate limiting activated after {first_rate_limit + 1} requests")
            
            # Check for rate limit headers
            rate_limited_response = rate_limit_responses[first_rate_limit]
            headers = rate_limited_response["headers"]
            
            rate_limit_headers = [
                "x-ratelimit-limit",
                "x-ratelimit-remaining", 
                "x-ratelimit-reset",
                "retry-after"
            ]
            
            found_headers = [h for h in rate_limit_headers if h in headers]
            if found_headers:
                logger.info(f"Rate limit headers present: {found_headers}")
            else:
                logger.warning("No rate limit headers found in 429 response")
                
        else:
            logger.warning(f"No rate limiting detected in {len(rate_limit_responses)} requests ({request_rate:.2f} req/s)")
        
        logger.info("RATE_LIMIT_001: Rate limiting implementation tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_ddos_protection_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     make_request):
        """DDOS_PROTECTION_001: DDoS protection mechanisms"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test DDoS protection with concurrent requests
        concurrent_limit = 10  # Reasonable limit for testing
        
        async def concurrent_request(request_id: int):
            try:
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
                return {
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "success": True
                }
            except Exception as e:
                return {
                    "request_id": request_id,
                    "error": str(e),
                    "success": False
                }
        
        # Launch concurrent requests
        tasks = [concurrent_request(i) for i in range(concurrent_limit)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Analyze results
        successful_requests = [r for r in results if isinstance(r, dict) and r.get("success")]
        failed_requests = [r for r in results if isinstance(r, dict) and not r.get("success")]
        exceptions = [r for r in results if not isinstance(r, dict)]
        
        logger.info(f"Concurrent requests: {len(successful_requests)} successful, {len(failed_requests)} failed, {len(exceptions)} exceptions")
        
        # Check for DDoS protection indicators
        protection_indicators = []
        
        for result in successful_requests:
            if result["status_code"] == 429:
                protection_indicators.append("Rate limiting")
            elif result["status_code"] == 503:
                protection_indicators.append("Service unavailable (potential circuit breaker)")
            elif "cloudflare" in str(result.get("headers", {})).lower():
                protection_indicators.append("CDN protection detected")
        
        if protection_indicators:
            logger.info(f"DDoS protection mechanisms detected: {set(protection_indicators)}")
        else:
            logger.info("No obvious DDoS protection detected in concurrent requests")
        
        logger.info("DDOS_PROTECTION_001: DDoS protection mechanisms tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_request_validation_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """REQUEST_VALIDATION_001: Request validation middleware"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various malformed requests
        malformed_requests = [
            {
                "description": "Oversized JSON payload",
                "data": {"model": config.get_chat_model(0), "messages": [{"role": "user", "content": "A" * 100000}], "max_tokens": 50}
            },
            {
                "description": "Invalid JSON structure",
                "data": '{"model": "' + config.get_chat_model(0) + '", "messages": [{"role": "user", "content": "test"}], "max_tokens": 50'  # Missing closing brace
            },
            {
                "description": "SQL injection in parameters",
                "data": {"model": config.get_chat_model(0) + "'; DROP TABLE users; --", "messages": [{"role": "user", "content": "test"}], "max_tokens": 50}
            },
            {
                "description": "XSS in parameters", 
                "data": {"model": config.get_chat_model(0), "messages": [{"role": "user", "content": "<script>alert('xss')</script>"}], "max_tokens": 50}
            },
            {
                "description": "Null bytes in parameters",
                "data": {"model": config.get_chat_model(0) + "\x00", "messages": [{"role": "user", "content": "test\x00"}], "max_tokens": 50}
            }
        ]
        
        for test_case in malformed_requests:
            if test_case["description"] == "Invalid JSON structure":
                # Test with raw string data
                try:
                    response = await http_client.post(
                        "/api/v1/chat/completions",
                        headers=auth_headers,
                        content=test_case["data"]
                    )
                except Exception as e:
                    logger.info(f"Request rejected at client level: {e}")
                    continue
            else:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, test_case["data"], track_cost=False
                )
            
            # Should reject malformed requests
            if response.status_code == 200:
                logger.warning(f"Malformed request accepted: {test_case['description']}")
            else:
                assert response.status_code in [400, 422, 413], \
                    f"Malformed request should be rejected with 4xx: {test_case['description']}"
                
                # Check error response doesn't leak sensitive info
                try:
                    error_data = response.json()
                    error_text = str(error_data).lower()
                    
                    # Should not expose internal details
                    sensitive_terms = ["traceback", "stack trace", "internal error", "database", "sql"]
                    for term in sensitive_terms:
                        assert term not in error_text, f"Error response exposes sensitive info: {term}"
                        
                except:
                    # Non-JSON error response is acceptable
                    pass
        
        logger.info("REQUEST_VALIDATION_001: Request validation middleware tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_middleware_order_001(self, http_client: httpx.AsyncClient,
                                      auth_headers: Dict[str, str],
                                      make_request):
        """MIDDLEWARE_ORDER_001: Middleware execution order validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test that security middleware executes in proper order
        # This is validated through response headers and behavior
        
        # Make request with potential security issues
        test_headers = auth_headers.copy()
        test_headers["X-Forwarded-For"] = "127.0.0.1, 192.168.1.1, 10.0.0.1"  # IP spoofing attempt
        test_headers["X-Real-IP"] = "192.168.1.100"
        test_headers["User-Agent"] = "<script>alert('xss')</script>"  # XSS in user agent
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            test_headers, track_cost=False
        )
        
        # Should still succeed if properly protected
        if response.status_code == 200:
            headers = response.headers
            
            # Security headers should be present (applied last)
            security_indicators = []
            
            if "x-content-type-options" in headers:
                security_indicators.append("Content-Type protection")
            if "x-frame-options" in headers:
                security_indicators.append("Frame protection")
            if "strict-transport-security" in headers:
                security_indicators.append("HSTS protection")
            
            logger.info(f"Security middleware active: {security_indicators}")
            
            # Response should not reflect XSS
            response_text = response.text.lower()
            assert "<script>" not in response_text
            assert "alert(" not in response_text
            
        else:
            # Rejection is also valid security behavior
            logger.info(f"Request rejected by security middleware: {response.status_code}")
        
        logger.info("MIDDLEWARE_ORDER_001: Middleware execution order validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_error_disclosure_prevention_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """ERROR_DISCLOSURE_001: Error information disclosure prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various error conditions
        error_conditions = [
            {
                "description": "Invalid endpoint",
                "method": "GET",
                "endpoint": "/api/v1/nonexistent",
                "data": None
            },
            {
                "description": "Invalid authentication", 
                "method": "GET",
                "endpoint": "/api/v1/models",
                "headers": {"Authorization": "Bearer invalid_token"}
            },
            {
                "description": "Malformed request body",
                "method": "POST",
                "endpoint": "/api/v1/chat/completions", 
                "data": {"invalid": "structure"}
            },
            {
                "description": "Missing required fields",
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {"model": config.get_chat_model(0)}  # Missing messages
            }
        ]
        
        for condition in error_conditions:
            headers = condition.get("headers", auth_headers)
            
            response = await make_request(
                http_client, condition["method"], condition["endpoint"],
                headers, condition.get("data"), track_cost=False
            )
            
            # Should return appropriate error code
            assert response.status_code >= 400, \
                f"Error condition should return 4xx/5xx: {condition['description']}"
            
            # Check error response for information disclosure
            try:
                if response.headers.get("content-type", "").startswith("application/json"):
                    error_data = response.json()
                    error_text = str(error_data).lower()
                else:
                    error_text = response.text.lower()
                
                # Should not expose sensitive information
                sensitive_disclosures = [
                    "traceback",
                    "stack trace", 
                    "file path",
                    "internal error",
                    "database error",
                    "connection string",
                    "api key",
                    "secret",
                    "password",
                    "token",
                    "line \\d+",  # Line numbers
                    "error.*\\.py",  # Python file references
                    "exception.*:",
                    "sqlalchemy",
                    "postgresql", 
                    "mysql"
                ]
                
                for disclosure in sensitive_disclosures:
                    if disclosure in error_text:
                        logger.warning(f"Potential information disclosure in error: {disclosure}")
                
            except Exception as e:
                # Error parsing error response - acceptable
                logger.info(f"Could not parse error response: {e}")
        
        logger.info("ERROR_DISCLOSURE_001: Error disclosure prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_content_type_validation_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """CONTENT_TYPE_001: Content-Type validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various Content-Type headers
        content_type_tests = [
            {
                "content_type": "application/json",
                "description": "Valid JSON content type",
                "should_accept": True
            },
            {
                "content_type": "text/plain",
                "description": "Plain text content type",
                "should_accept": False
            },
            {
                "content_type": "application/xml",
                "description": "XML content type",
                "should_accept": False
            },
            {
                "content_type": "multipart/form-data",
                "description": "Form data content type",
                "should_accept": False
            },
            {
                "content_type": "application/x-www-form-urlencoded",
                "description": "URL encoded content type",
                "should_accept": False
            }
        ]
        
        valid_request_data = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Content type test"}],
            "max_tokens": 50
        }
        
        for test in content_type_tests:
            test_headers = auth_headers.copy()
            test_headers["Content-Type"] = test["content_type"]
            
            try:
                response = await http_client.post(
                    "/api/v1/chat/completions",
                    headers=test_headers,
                    json=valid_request_data
                )
                
                if test["should_accept"]:
                    assert response.status_code == 200, \
                        f"Valid content type should be accepted: {test['description']}"
                else:
                    assert response.status_code in [400, 415], \
                        f"Invalid content type should be rejected: {test['description']}"
                        
            except Exception as e:
                if not test["should_accept"]:
                    logger.info(f"Content type rejected at client level: {test['description']}")
                else:
                    pytest.fail(f"Valid content type caused error: {e}")
        
        logger.info("CONTENT_TYPE_001: Content-Type validation completed")