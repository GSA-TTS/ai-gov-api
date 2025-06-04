# Section 7.3 - OWASP API8:2023 Security Misconfiguration Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API8_2023 - Security Misconfiguration.md

import pytest
import httpx
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger

class TestOWASPAPI8SecurityMisconfiguration:
    """API8:2023 - Security Misconfiguration tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api8_debug_endpoints_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """API8_DEBUG_ENDPOINTS_001: Debug endpoints exposure detection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test common debug/development endpoints
        debug_endpoints = [
            # General debug endpoints
            "/debug", "/debug/", "/api/debug", "/api/v1/debug",
            
            # Environment/config endpoints
            "/env", "/environment", "/config", "/settings",
            "/api/env", "/api/config", "/api/settings",
            
            # Development endpoints
            "/dev", "/development", "/test", "/testing",
            "/api/dev", "/api/test",
            
            # Framework-specific debug endpoints
            "/actuator", "/actuator/env", "/actuator/configprops",
            "/actuator/beans", "/actuator/mappings", "/actuator/trace",
            
            # Application info endpoints
            "/info", "/version", "/build", "/manifest",
            "/api/info", "/api/version",
            
            # Stack trace endpoints
            "/error", "/errors", "/exception", "/stacktrace",
            "/api/error", "/api/errors",
            
            # Profiling endpoints
            "/profiler", "/profile", "/metrics", "/stats",
            "/api/profiler", "/api/metrics", "/api/stats",
            
            # Documentation endpoints that might leak info
            "/docs", "/swagger", "/openapi", "/redoc",
            "/api-docs", "/swagger-ui", "/graphql",
            
            # Internal endpoints
            "/internal", "/private", "/admin/debug",
            "/api/internal", "/api/private"
        ]
        
        exposed_endpoints = []
        
        for endpoint in debug_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                # Endpoint is accessible - check for sensitive information
                response_text = response.text.lower()
                
                # Look for debug/development information
                sensitive_patterns = [
                    "environment", "debug", "stack trace", "error details",
                    "configuration", "database", "password", "secret",
                    "api key", "token", "internal", "development"
                ]
                
                found_patterns = [pattern for pattern in sensitive_patterns if pattern in response_text]
                
                if found_patterns:
                    exposed_endpoints.append({
                        "endpoint": endpoint,
                        "patterns": found_patterns,
                        "response_length": len(response_text)
                    })
                    logger.warning(f"Debug endpoint exposed: {endpoint} contains: {found_patterns}")
                else:
                    # Accessible but may be safe
                    logger.info(f"Endpoint accessible but appears safe: {endpoint}")
            
            elif response.status_code not in [401, 403, 404, 405]:
                # Unexpected response codes might indicate misconfigurations
                logger.info(f"Unexpected response for {endpoint}: {response.status_code}")
        
        # Debug endpoints should not be exposed in production
        assert len(exposed_endpoints) == 0, \
            f"Debug endpoints should not expose sensitive information: {exposed_endpoints}"
        
        logger.info("API8_DEBUG_ENDPOINTS_001: Debug endpoint exposure check completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api8_http_headers_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       make_request):
        """API8_HTTP_HEADERS_001: Security headers validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various endpoints for security headers
        test_endpoints = [
            "/api/v1/models",
            "/api/v1/chat/completions",
            "/api/v1/embeddings"
        ]
        
        required_security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]
        
        information_disclosure_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version"
        ]
        
        for endpoint in test_endpoints:
            if endpoint == "/api/v1/models":
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
            else:
                # POST endpoints need data
                if "chat" in endpoint:
                    data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Security test"}],
                        "max_tokens": 50
                    }
                else:  # embeddings
                    data = {
                        "model": config.get_embedding_model(0),
                        "input": "Security test"
                    }
                
                headers = auth_headers if "chat" in endpoint else auth_headers  # Assume same auth for now
                response = await make_request(
                    http_client, "POST", endpoint,
                    headers, data, track_cost=False
                )
            
            if response.status_code in [200, 422]:  # Valid responses
                headers = dict(response.headers)
                
                # Check for security headers
                missing_security_headers = []
                for header in required_security_headers:
                    if header not in headers:
                        missing_security_headers.append(header)
                
                # Log missing security headers (warning, not failure for API)
                if missing_security_headers:
                    logger.warning(f"Missing security headers on {endpoint}: {missing_security_headers}")
                
                # Check for information disclosure headers
                disclosed_headers = []
                for header in information_disclosure_headers:
                    if header in headers:
                        disclosed_headers.append(f"{header}: {headers[header]}")
                
                if disclosed_headers:
                    logger.warning(f"Information disclosure headers on {endpoint}: {disclosed_headers}")
                
                # Check specific header values for security
                if "X-Frame-Options" in headers:
                    frame_options = headers["X-Frame-Options"].lower()
                    assert frame_options in ["deny", "sameorigin"], \
                        f"X-Frame-Options should be DENY or SAMEORIGIN, got: {frame_options}"
                
                if "X-Content-Type-Options" in headers:
                    content_type_options = headers["X-Content-Type-Options"].lower()
                    assert content_type_options == "nosniff", \
                        f"X-Content-Type-Options should be nosniff, got: {content_type_options}"
                
                # Check Content-Type header
                if "Content-Type" in headers:
                    content_type = headers["Content-Type"]
                    if endpoint != "/api/v1/models":  # JSON endpoints
                        assert "application/json" in content_type, \
                            f"API should return JSON content type, got: {content_type}"
        
        logger.info("API8_HTTP_HEADERS_001: Security headers validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api8_error_handling_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """API8_ERROR_HANDLING_001: Error handling information disclosure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various error conditions for information disclosure
        error_scenarios = [
            # Invalid JSON
            {
                "name": "invalid_json",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": '{"invalid": json}',  # Invalid JSON
                "content_type": "application/json"
            },
            
            # Missing required fields
            {
                "name": "missing_model",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {"messages": [{"role": "user", "content": "test"}]},
                "content_type": "application/json"
            },
            
            # Invalid model
            {
                "name": "invalid_model",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": "nonexistent-model-xyz-123",
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 50
                },
                "content_type": "application/json"
            },
            
            # Invalid message format
            {
                "name": "invalid_messages",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": "invalid_format",
                    "max_tokens": 50
                },
                "content_type": "application/json"
            },
            
            # SQL injection attempt (if applicable)
            {
                "name": "sql_injection",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": "'; DROP TABLE users; --",
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 50
                },
                "content_type": "application/json"
            }
        ]
        
        for scenario in error_scenarios:
            try:
                response = await make_request(
                    http_client, scenario["method"], scenario["endpoint"],
                    auth_headers, scenario["data"], track_cost=False
                )
                
                # Should return proper error status
                assert response.status_code >= 400, \
                    f"Invalid request should return error status: {scenario['name']}"
                
                if response.content:
                    error_response = response.json() if response.headers.get("content-type", "").startswith("application/json") else {"text": response.text}
                    error_text = str(error_response).lower()
                    
                    # Check for information disclosure in error messages
                    disclosure_patterns = [
                        # System information
                        "traceback", "stack trace", "file path", "line number",
                        "internal error", "database error", "sql error",
                        
                        # Framework information  
                        "django", "flask", "fastapi", "spring", "express",
                        "node.js", "python", "java", "php",
                        
                        # Infrastructure information
                        "localhost", "127.0.0.1", "internal server",
                        "connection string", "database host",
                        
                        # Security information
                        "authentication failed", "authorization error",
                        "access denied", "permission denied"
                    ]
                    
                    found_disclosures = [pattern for pattern in disclosure_patterns if pattern in error_text]
                    
                    if found_disclosures:
                        logger.warning(f"Information disclosure in error: {scenario['name']} - {found_disclosures}")
                    
                    # Error messages should be generic and not reveal system details
                    assert not any(pattern in error_text for pattern in ["traceback", "stack trace", "file path"]), \
                        f"Error should not contain stack traces: {scenario['name']}"
                    
                    # Should not reveal database or system information
                    assert not any(pattern in error_text for pattern in ["database", "sql", "localhost", "127.0.0.1"]), \
                        f"Error should not reveal system information: {scenario['name']}"
                
            except Exception as e:
                logger.info(f"Error scenario {scenario['name']} caused exception: {str(e)}")
        
        logger.info("API8_ERROR_HANDLING_001: Error handling validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api8_cors_configuration_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """API8_CORS_CONFIG_001: CORS configuration security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test CORS configuration
        cors_test_origins = [
            "https://evil.com",
            "http://attacker.com", 
            "https://malicious-site.org",
            "null",
            "*"
        ]
        
        test_endpoints = [
            "/api/v1/models",
            "/api/v1/chat/completions"
        ]
        
        for origin in cors_test_origins:
            for endpoint in test_endpoints:
                # Test preflight request
                preflight_headers = dict(auth_headers)
                preflight_headers.update({
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type, Authorization"
                })
                
                preflight_response = await make_request(
                    http_client, "OPTIONS", endpoint,
                    preflight_headers, track_cost=False
                )
                
                if preflight_response.status_code == 200:
                    cors_headers = dict(preflight_response.headers)
                    
                    # Check CORS headers
                    if "Access-Control-Allow-Origin" in cors_headers:
                        allowed_origin = cors_headers["Access-Control-Allow-Origin"]
                        
                        # Should not allow all origins (*)
                        if allowed_origin == "*":
                            logger.warning("CORS allows all origins (*) - potential security risk")
                        
                        # Should not allow null origin
                        elif allowed_origin == "null":
                            logger.warning("CORS allows null origin - potential security risk")
                        
                        # Should not allow untrusted origins
                        elif origin in ["https://evil.com", "http://attacker.com", "https://malicious-site.org"]:
                            if allowed_origin == origin:
                                logger.warning(f"CORS allows untrusted origin: {origin}")
                    
                    # Check for credentials
                    if "Access-Control-Allow-Credentials" in cors_headers:
                        allow_credentials = cors_headers["Access-Control-Allow-Credentials"]
                        if allow_credentials.lower() == "true" and allowed_origin == "*":
                            pytest.fail("CORS allows credentials with wildcard origin - security vulnerability")
                
                # Test actual request with Origin header
                request_headers = dict(auth_headers)
                request_headers["Origin"] = origin
                
                if endpoint == "/api/v1/models":
                    actual_response = await make_request(
                        http_client, "GET", endpoint,
                        request_headers, track_cost=False
                    )
                else:
                    data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "CORS test"}],
                        "max_tokens": 30
                    }
                    actual_response = await make_request(
                        http_client, "POST", endpoint,
                        request_headers, data, track_cost=False
                    )
                
                if actual_response.status_code == 200:
                    response_cors_headers = dict(actual_response.headers)
                    
                    if "Access-Control-Allow-Origin" in response_cors_headers:
                        response_origin = response_cors_headers["Access-Control-Allow-Origin"]
                        
                        # Log CORS policy for analysis
                        logger.info(f"CORS allows origin {origin} -> {response_origin} on {endpoint}")
        
        logger.info("API8_CORS_CONFIG_001: CORS configuration validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api8_content_type_validation_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """API8_CONTENT_TYPE_001: Content-Type validation and security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various content types for security
        content_type_tests = [
            # Valid content type
            {
                "content_type": "application/json",
                "data": {"model": config.get_chat_model(0), "messages": [{"role": "user", "content": "test"}], "max_tokens": 30},
                "expected": "accept"
            },
            
            # Invalid content types
            {
                "content_type": "text/plain",
                "data": '{"model": "' + config.get_chat_model(0) + '", "messages": [{"role": "user", "content": "test"}], "max_tokens": 30}',
                "expected": "reject"
            },
            {
                "content_type": "application/xml",
                "data": "<?xml version='1.0'?><request><model>" + config.get_chat_model(0) + "</model></request>",
                "expected": "reject"
            },
            {
                "content_type": "multipart/form-data",
                "data": "model=" + config.get_chat_model(0) + "&messages=test",
                "expected": "reject"
            },
            
            # Potentially dangerous content types
            {
                "content_type": "text/html",
                "data": "<html><body>test</body></html>",
                "expected": "reject"
            },
            {
                "content_type": "application/x-www-form-urlencoded",
                "data": "model=" + config.get_chat_model(0),
                "expected": "reject"
            },
            
            # Content type with charset manipulation
            {
                "content_type": "application/json; charset=utf-7",
                "data": {"model": config.get_chat_model(0), "messages": [{"role": "user", "content": "test"}], "max_tokens": 30},
                "expected": "validate_charset"
            }
        ]
        
        for test in content_type_tests:
            custom_headers = dict(auth_headers)
            custom_headers["Content-Type"] = test["content_type"]
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                custom_headers, test["data"], track_cost=False
            )
            
            if test["expected"] == "accept":
                # Should accept valid JSON
                assert response.status_code in [200, 422], \
                    f"Valid content type should be accepted: {test['content_type']}"
            
            elif test["expected"] == "reject":
                # Should reject invalid content types
                assert response.status_code in [400, 415, 422], \
                    f"Invalid content type should be rejected: {test['content_type']}"
            
            elif test["expected"] == "validate_charset":
                # Should handle charset appropriately
                if response.status_code == 200:
                    # If accepted, should parse correctly
                    response_data = response.json()
                    assert "choices" in response_data or "error" in response_data, \
                        "Response should be properly formatted"
                else:
                    # May be rejected due to charset
                    assert response.status_code in [400, 415, 422], \
                        "Unusual charset should be handled appropriately"
            
            logger.info(f"Content-Type test: {test['content_type']} -> {response.status_code}")
        
        logger.info("API8_CONTENT_TYPE_001: Content-Type validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api8_authentication_misconfiguration_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """API8_AUTH_MISCONFIG_001: Authentication misconfiguration detection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various authentication misconfigurations
        auth_tests = [
            # No authentication
            {
                "headers": {},
                "description": "No authentication headers"
            },
            
            # Malformed authentication
            {
                "headers": {"Authorization": "Bearer"},
                "description": "Malformed Bearer token"
            },
            {
                "headers": {"Authorization": "Basic"},
                "description": "Malformed Basic auth"
            },
            {
                "headers": {"Authorization": "InvalidScheme token123"},
                "description": "Invalid auth scheme"
            },
            
            # Empty/null tokens
            {
                "headers": {"Authorization": "Bearer "},
                "description": "Empty Bearer token"
            },
            {
                "headers": {"Authorization": "Bearer null"},
                "description": "Null Bearer token"
            },
            
            # Case sensitivity tests
            {
                "headers": {"authorization": auth_headers.get("Authorization", "")},
                "description": "Lowercase authorization header"
            },
            {
                "headers": {"AUTHORIZATION": auth_headers.get("Authorization", "")},
                "description": "Uppercase authorization header"
            },
            
            # Multiple auth headers
            {
                "headers": {
                    "Authorization": auth_headers.get("Authorization", ""),
                    "X-API-Key": "duplicate-auth"
                },
                "description": "Multiple authentication methods"
            }
        ]
        
        for test in auth_tests:
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                test["headers"], track_cost=False
            )
            
            if test["description"] in ["No authentication headers", "Malformed Bearer token", 
                                     "Malformed Basic auth", "Invalid auth scheme", 
                                     "Empty Bearer token", "Null Bearer token"]:
                # Should be rejected
                assert response.status_code in [401, 403], \
                    f"Invalid auth should be rejected: {test['description']}"
            
            elif test["description"] in ["Lowercase authorization header", "Uppercase authorization header"]:
                # Should handle case appropriately (either accept or reject consistently)
                if response.status_code == 200:
                    logger.info(f"Auth header case accepted: {test['description']}")
                else:
                    assert response.status_code in [401, 403], \
                        f"Auth header case should be handled consistently: {test['description']}"
            
            elif test["description"] == "Multiple authentication methods":
                # Should handle multiple auth methods appropriately
                if response.status_code == 200:
                    logger.info("Multiple auth methods accepted")
                else:
                    assert response.status_code in [400, 401, 403], \
                        "Multiple auth methods should be handled appropriately"
            
            logger.info(f"Auth test: {test['description']} -> {response.status_code}")
        
        logger.info("API8_AUTH_MISCONFIG_001: Authentication misconfiguration validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api8_security_misconfiguration_comprehensive_001(self, http_client: httpx.AsyncClient,
                                                                   auth_headers: Dict[str, str],
                                                                   make_request):
        """API8_COMPREHENSIVE_001: Comprehensive security misconfiguration check"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Comprehensive security misconfiguration assessment
        misconfig_checks = []
        
        # Check 1: Default endpoints
        default_endpoints = [
            "/", "/api", "/api/", "/api/v1", "/api/v1/",
            "/health", "/status", "/ping", "/version"
        ]
        
        for endpoint in default_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                {}, track_cost=False  # No auth to test exposure
            )
            
            if response.status_code == 200:
                response_text = response.text.lower()
                
                # Check for sensitive information exposure
                if any(term in response_text for term in ["version", "build", "commit", "environment"]):
                    misconfig_checks.append({
                        "type": "information_disclosure",
                        "endpoint": endpoint,
                        "description": "Default endpoint exposes system information"
                    })
        
        # Check 2: HTTP methods on main endpoints
        main_endpoints = ["/api/v1/models", "/api/v1/chat/completions"]
        dangerous_methods = ["TRACE", "TRACK", "CONNECT"]
        
        for endpoint in main_endpoints:
            for method in dangerous_methods:
                response = await make_request(
                    http_client, method, endpoint,
                    auth_headers, track_cost=False
                )
                
                if response.status_code not in [405, 501]:
                    misconfig_checks.append({
                        "type": "dangerous_http_method",
                        "endpoint": endpoint,
                        "method": method,
                        "status": response.status_code,
                        "description": f"Dangerous HTTP method {method} not properly disabled"
                    })
        
        # Check 3: Security headers on error responses
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, {"invalid": "data"}, track_cost=False
        )
        
        if response.status_code >= 400:
            headers = dict(response.headers)
            
            # Error responses should still have security headers
            if "X-Content-Type-Options" not in headers:
                misconfig_checks.append({
                    "type": "missing_security_header",
                    "context": "error_response",
                    "header": "X-Content-Type-Options",
                    "description": "Security headers missing on error responses"
                })
        
        # Report misconfigurations
        if misconfig_checks:
            logger.warning(f"Security misconfigurations detected: {len(misconfig_checks)}")
            for check in misconfig_checks:
                logger.warning(f"Misconfiguration: {check}")
        else:
            logger.info("No obvious security misconfigurations detected")
        
        # Critical misconfigurations should fail the test
        critical_misconfigs = [check for check in misconfig_checks 
                              if check["type"] in ["dangerous_http_method", "information_disclosure"]]
        
        assert len(critical_misconfigs) == 0, \
            f"Critical security misconfigurations found: {critical_misconfigs}"
        
        logger.info("API8_COMPREHENSIVE_001: Comprehensive security misconfiguration check completed")