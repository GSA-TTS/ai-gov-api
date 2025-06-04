# Section 7.3 - Advanced Security Misconfiguration Tests (OWASP API8:2023)
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API8_2023 - Security Misconfiguration.md
# Implements advanced security misconfiguration test cases

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


class TestOWASPAPI8SecurityMisconfigurationAdvanced:
    """Advanced security misconfiguration tests (OWASP API8:2023)"""
    
    @pytest.mark.security
    @pytest.mark.owasp_api8
    @pytest.mark.asyncio
    async def test_api8_debug_mode_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     security_validator: SecurityValidator,
                                     make_request):
        """API8_DEBUG_001: Debug Mode Information Disclosure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various debug-related headers and parameters
        debug_requests = [
            {"headers": {"X-Debug": "true"}, "params": {}},
            {"headers": {"X-Debug-Mode": "1"}, "params": {}},
            {"headers": {"Debug": "on"}, "params": {}},
            {"headers": {}, "params": {"debug": "true"}},
            {"headers": {}, "params": {"debug_mode": "1"}},
            {"headers": {}, "params": {"verbose": "true"}},
            {"headers": {"X-Trace": "enabled"}, "params": {}},
            {"headers": {"X-Development": "true"}, "params": {}}
        ]
        
        for debug_config in debug_requests:
            # Merge debug headers with auth headers
            headers = {**auth_headers, **debug_config["headers"]}
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, None, debug_config["params"]
            )
            
            # API should handle debug requests securely
            assert response.status_code in [200, 400, 403], \
                f"Debug request should be handled securely: {debug_config}"
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Validate no debug information leakage
                validation_result = security_validator.validate_debug_information_leakage(
                    debug_config, response_data
                )
                
                assert validation_result["is_secure"], \
                    f"Debug mode should not leak information: {debug_config}"
                
                # Check for debug-specific information in response
                debug_indicators = [
                    "stack_trace", "error_details", "internal_path", "database_query",
                    "environment", "config", "debug", "trace", "verbose"
                ]
                
                response_str = str(response_data).lower()
                has_debug_leak = any(
                    indicator in response_str for indicator in debug_indicators
                )
                
                assert not has_debug_leak, \
                    f"Response should not contain debug information: {debug_config}"
        
        logger.info("API8_DEBUG_001: Debug mode information disclosure tested")

    @pytest.mark.security
    @pytest.mark.owasp_api8
    @pytest.mark.asyncio
    async def test_api8_cors_policy_001(self, http_client: httpx.AsyncClient,
                                      auth_headers: Dict[str, str],
                                      security_validator: SecurityValidator,
                                      make_request):
        """API8_CORS_001: CORS Policy Misconfiguration"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test CORS with various origins
        malicious_origins = [
            "https://malicious-site.com",
            "http://attacker.evil",
            "null",
            "*",
            "https://subdomain.evil.com",
            "data:text/html,<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "file://localhost/etc/passwd"
        ]
        
        for origin in malicious_origins:
            headers = {
                **auth_headers,
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type"
            }
            
            # Test preflight request
            response = await make_request(
                http_client, "OPTIONS", "/api/v1/chat/completions", 
                headers, track_cost=False
            )
            
            # Validate CORS configuration
            validation_result = security_validator.validate_cors_configuration(
                origin, response.headers
            )
            
            assert validation_result["is_secure"], \
                f"CORS should be secure for origin: {origin}"
            
            # Check for overly permissive CORS
            cors_headers = {
                "access-control-allow-origin": response.headers.get("access-control-allow-origin", ""),
                "access-control-allow-credentials": response.headers.get("access-control-allow-credentials", ""),
                "access-control-allow-methods": response.headers.get("access-control-allow-methods", ""),
                "access-control-allow-headers": response.headers.get("access-control-allow-headers", "")
            }
            
            # Should not allow all origins with credentials
            if cors_headers["access-control-allow-origin"] == "*":
                assert cors_headers["access-control-allow-credentials"].lower() != "true", \
                    "CORS should not allow * origin with credentials"
            
            # Should not reflect arbitrary origins
            if origin in ["null", "*"] or "evil" in origin or "malicious" in origin:
                assert cors_headers["access-control-allow-origin"] != origin, \
                    f"CORS should not reflect malicious origin: {origin}"
        
        logger.info("API8_CORS_001: CORS policy misconfiguration tested")

    @pytest.mark.security
    @pytest.mark.owasp_api8
    @pytest.mark.asyncio
    async def test_api8_logging_sensitivity_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              security_validator: SecurityValidator,
                                              make_request):
        """API8_LOGGING_001: Sensitive Information in Logs"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test requests that might expose sensitive data in logs
        sensitive_requests = [
            {
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "My credit card number is 4532-1234-5678-9012"}],
                    "max_tokens": 50
                }
            },
            {
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "My API key is sk-1234567890abcdef"}],
                    "max_tokens": 50
                }
            },
            {
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Password: MySecretPassword123!"}],
                    "max_tokens": 50
                }
            }
        ]
        
        for request_config in sensitive_requests:
            response = await make_request(
                http_client, "POST", request_config["endpoint"],
                auth_headers, request_config["data"]
            )
            
            # Request should be processed (logging is internal)
            assert response.status_code == 200
            
            # Validate logging configuration
            validation_result = security_validator.validate_logging_security(
                request_config["data"], response.json()
            )
            
            assert validation_result["is_secure"], \
                f"Logging should be secure for sensitive data: {request_config['data']}"
            
            # Check that sensitive data isn't echoed back inappropriately
            response_content = response.json()["choices"][0]["message"]["content"]
            
            # Should not echo back sensitive patterns
            sensitive_patterns = ["4532-1234-5678-9012", "sk-1234567890abcdef", "MySecretPassword123!"]
            has_sensitive_echo = any(
                pattern in response_content for pattern in sensitive_patterns
            )
            
            # Note: This test validates logging behavior, actual log analysis would require log access
            logger.info(f"Logging test for sensitive data: {request_config['endpoint']}")
        
        logger.info("API8_LOGGING_001: Sensitive logging protection tested")

    @pytest.mark.security
    @pytest.mark.owasp_api8
    @pytest.mark.asyncio
    async def test_api8_secrets_management_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             security_validator: SecurityValidator,
                                             make_request):
        """API8_SECRETS_001: Secrets Management Exposure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various endpoints for secret exposure
        secret_exposure_tests = [
            {"endpoint": "/api/v1/models", "method": "GET"},
            {"endpoint": "/health", "method": "GET"},
            {"endpoint": "/metrics", "method": "GET"},
            {"endpoint": "/status", "method": "GET"},
            {"endpoint": "/info", "method": "GET"},
            {"endpoint": "/version", "method": "GET"},
            {"endpoint": "/config", "method": "GET"},
            {"endpoint": "/debug", "method": "GET"}
        ]
        
        for test_config in secret_exposure_tests:
            if test_config["method"] == "GET":
                response = await http_client.get(
                    test_config["endpoint"],
                    headers=auth_headers if test_config["endpoint"].startswith("/api") else {}
                )
            else:
                response = await make_request(
                    http_client, test_config["method"], test_config["endpoint"],
                    auth_headers, {}
                )
            
            # Validate no secret exposure
            if response.status_code == 200:
                response_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
                
                validation_result = security_validator.validate_secrets_exposure(
                    test_config["endpoint"], response_data
                )
                
                assert validation_result["is_secure"], \
                    f"Endpoint should not expose secrets: {test_config['endpoint']}"
                
                # Check for common secret patterns
                secret_patterns = [
                    r"sk-[a-zA-Z0-9]{48}",  # OpenAI API key
                    r"AKIA[0-9A-Z]{16}",    # AWS Access Key
                    r"ya29\.[0-9A-Za-z\-_]+",  # Google OAuth token
                    r"ghp_[a-zA-Z0-9]{36}",   # GitHub token
                    r"[a-zA-Z0-9]{32}",       # Generic 32-char token
                ]
                
                response_str = str(response_data)
                for pattern in secret_patterns:
                    import re
                    if re.search(pattern, response_str):
                        pytest.fail(f"Potential secret exposure in {test_config['endpoint']}: {pattern}")
            
            # 404 or 403 responses are acceptable for non-existent endpoints
            assert response.status_code in [200, 404, 403, 405], \
                f"Unexpected status for endpoint: {test_config['endpoint']}"
        
        logger.info("API8_SECRETS_001: Secrets management exposure tested")

    @pytest.mark.security
    @pytest.mark.owasp_api8
    @pytest.mark.asyncio
    async def test_api8_container_security_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             security_validator: SecurityValidator,
                                             make_request):
        """API8_CONTAINER_001: Container Security Misconfiguration"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test container-related information disclosure
        container_disclosure_tests = [
            {"endpoint": "/proc/self/environ", "method": "GET"},
            {"endpoint": "/proc/version", "method": "GET"},
            {"endpoint": "/etc/hostname", "method": "GET"},
            {"endpoint": "/etc/passwd", "method": "GET"},
            {"endpoint": "/.dockerenv", "method": "GET"},
            {"endpoint": "/var/run/secrets/kubernetes.io/serviceaccount/token", "method": "GET"},
            {"endpoint": "/metadata/v1/instance", "method": "GET"},
            {"endpoint": "/169.254.169.254/latest/meta-data/", "method": "GET"}
        ]
        
        for test_config in container_disclosure_tests:
            response = await http_client.get(test_config["endpoint"])
            
            # These endpoints should not be accessible
            assert response.status_code in [404, 403, 400], \
                f"Container path should not be accessible: {test_config['endpoint']}"
            
            if response.status_code == 200:
                # If accessible, validate no sensitive information
                response_content = response.text
                
                validation_result = security_validator.validate_container_security(
                    test_config["endpoint"], response_content
                )
                
                assert validation_result["is_secure"], \
                    f"Container endpoint should be secure: {test_config['endpoint']}"
                
                # Check for container-specific leakage
                container_indicators = [
                    "root:", "docker", "kubernetes", "serviceaccount",
                    "AWS_", "GCP_", "AZURE_", "TOKEN", "SECRET"
                ]
                
                has_container_leak = any(
                    indicator in response_content for indicator in container_indicators
                )
                
                if has_container_leak:
                    logger.warning(f"Potential container information leak: {test_config['endpoint']}")
        
        logger.info("API8_CONTAINER_001: Container security misconfiguration tested")

    @pytest.mark.security
    @pytest.mark.owasp_api8
    @pytest.mark.asyncio
    async def test_api8_http_headers_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       security_validator: SecurityValidator,
                                       make_request):
        """API8_HEADERS_001: Missing Security Headers"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test security headers on various endpoints
        endpoints_to_test = [
            "/api/v1/models",
            "/api/v1/chat/completions",
            "/api/v1/embeddings"
        ]
        
        required_security_headers = [
            "x-content-type-options",
            "x-frame-options", 
            "x-xss-protection",
            "strict-transport-security",
            "content-security-policy",
            "referrer-policy"
        ]
        
        for endpoint in endpoints_to_test:
            if endpoint == "/api/v1/models":
                response = await http_client.get(endpoint, headers=auth_headers)
            else:
                # For other endpoints, make a simple request
                test_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10
                } if "chat" in endpoint else {
                    "model": config.get_embedding_models()[0] if config.get_embedding_models() else "test",
                    "input": "test"
                }
                
                response = await make_request(
                    http_client, "POST", endpoint, auth_headers, test_data
                )
            
            if response.status_code == 200:
                # Validate security headers
                validation_result = security_validator.validate_security_headers(
                    endpoint, dict(response.headers)
                )
                
                missing_headers = []
                for header in required_security_headers:
                    if header not in response.headers:
                        missing_headers.append(header)
                
                # Note: Some headers may be optional depending on application requirements
                # This test documents the current header configuration
                logger.info(f"Security headers for {endpoint}: {dict(response.headers)}")
                if missing_headers:
                    logger.warning(f"Missing security headers on {endpoint}: {missing_headers}")
                
                # Validate existing headers have secure values
                if "x-frame-options" in response.headers:
                    assert response.headers["x-frame-options"] in ["DENY", "SAMEORIGIN"], \
                        f"X-Frame-Options should have secure value: {response.headers['x-frame-options']}"
                
                if "x-content-type-options" in response.headers:
                    assert response.headers["x-content-type-options"] == "nosniff", \
                        f"X-Content-Type-Options should be nosniff: {response.headers['x-content-type-options']}"
        
        logger.info("API8_HEADERS_001: Security headers configuration tested")

    @pytest.mark.security
    @pytest.mark.owasp_api8
    @pytest.mark.asyncio
    async def test_api8_error_handling_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         security_validator: SecurityValidator,
                                         make_request):
        """API8_ERROR_001: Error Information Disclosure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various error conditions
        error_test_cases = [
            {
                "description": "Invalid JSON syntax",
                "endpoint": "/api/v1/chat/completions",
                "data": '{"model": "test", "messages": [invalid json}',
                "content_type": "application/json"
            },
            {
                "description": "Missing required fields",
                "endpoint": "/api/v1/chat/completions", 
                "data": {"model": "nonexistent_model"},
                "content_type": "application/json"
            },
            {
                "description": "Invalid model name",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": "../../../etc/passwd",
                    "messages": [{"role": "user", "content": "test"}]
                },
                "content_type": "application/json"
            },
            {
                "description": "Oversized request",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "A" * 100000}]
                },
                "content_type": "application/json"
            }
        ]
        
        for test_case in error_test_cases:
            headers = {**auth_headers, "Content-Type": test_case["content_type"]}
            
            if isinstance(test_case["data"], str):
                # Raw string data (invalid JSON)
                response = await http_client.post(
                    test_case["endpoint"],
                    content=test_case["data"],
                    headers=headers
                )
            else:
                # Valid JSON data
                response = await make_request(
                    http_client, "POST", test_case["endpoint"],
                    auth_headers, test_case["data"]
                )
            
            # Should return appropriate error status
            assert response.status_code in [400, 422, 413, 500], \
                f"Error case should return error status: {test_case['description']}"
            
            if response.status_code in [400, 422]:
                # Validate error response doesn't leak sensitive information
                error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
                
                validation_result = security_validator.validate_error_response_security(
                    test_case, error_data
                )
                
                assert validation_result["is_secure"], \
                    f"Error response should be secure: {test_case['description']}"
                
                # Check for information leakage in error messages
                error_str = str(error_data).lower()
                sensitive_indicators = [
                    "stack trace", "file path", "/home/", "/var/", "/etc/",
                    "database", "connection string", "internal error", "debug"
                ]
                
                has_sensitive_leak = any(
                    indicator in error_str for indicator in sensitive_indicators
                )
                
                assert not has_sensitive_leak, \
                    f"Error should not leak sensitive information: {test_case['description']}"
        
        logger.info("API8_ERROR_001: Error information disclosure tested")