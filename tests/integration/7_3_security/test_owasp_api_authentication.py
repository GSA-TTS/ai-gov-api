# Section 7.3 - OWASP API2:2023 Broken Authentication Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API2_2023 - Broken Authentication.md

import pytest
import httpx
import time
from typing import Dict, Any, List

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures
from utils.security_validators import SecurityValidator


class TestOWASPAPI2Authentication:
    """Test cases for API2:2023 - Broken Authentication"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_missing_auth_001(self, http_client: httpx.AsyncClient,
                                       make_request):
        """API2_MISSING_AUTH_001: Test access without authentication"""
        # Test all major endpoints without authentication
        endpoints = [
            ("/api/v1/models", "GET", None),
            ("/api/v1/chat/completions", "POST", {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            }),
            ("/api/v1/embeddings", "POST", {
                "model": config.get_embedding_model(0),
                "input": "Test input"
            })
        ]
        
        for endpoint, method, data in endpoints:
            response = await make_request(
                http_client, method, endpoint,
                {}, data, track_cost=False  # No auth headers
            )
            
            assert response.status_code in [401, 403], \
                f"Endpoint {endpoint} should reject requests without authentication"
            
            response_data = response.json()
            assert "detail" in response_data
            assert "authenticated" in response_data["detail"].lower() or \
                   "authorized" in response_data["detail"].lower()
        
        logger.info("API2_MISSING_AUTH_001: Missing authentication properly rejected")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_invalid_key_001(self, http_client: httpx.AsyncClient,
                                      auth_fixtures: AuthFixtures, make_request):
        """API2_INVALID_KEY_001: Test with invalid API keys"""
        invalid_headers = [
            auth_fixtures.get_invalid_key_headers(0),
            auth_fixtures.get_invalid_key_headers(1),
            auth_fixtures.get_invalid_key_headers(2)
        ]
        
        for headers in invalid_headers:
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, track_cost=False
            )
            
            assert response.status_code == 401, \
                "Invalid API key should be rejected with 401"
            
            response_data = response.json()
            assert "detail" in response_data
            assert "invalid" in response_data["detail"].lower() or \
                   "missing" in response_data["detail"].lower()
        
        logger.info("API2_INVALID_KEY_001: Invalid API keys properly rejected")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_malformed_header_001(self, http_client: httpx.AsyncClient,
                                           auth_fixtures: AuthFixtures, make_request):
        """API2_MALFORMED_HEADER_001: Test with malformed authorization headers"""
        malformed_headers = [
            auth_fixtures.get_malformed_header(0),
            auth_fixtures.get_malformed_header(1),
            auth_fixtures.get_malformed_header(2),
            auth_fixtures.get_malformed_header(3)
        ]
        
        for headers in malformed_headers:
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, track_cost=False
            )
            
            assert response.status_code in [401, 422], \
                "Malformed authorization header should be rejected"
            
            response_data = response.json()
            assert "detail" in response_data
        
        logger.info("API2_MALFORMED_HEADER_001: Malformed headers properly rejected")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_expired_key_simulation_001(self, http_client: httpx.AsyncClient,
                                                  auth_fixtures: AuthFixtures, 
                                                  make_request):
        """API2_EXPIRED_KEY_001: Test with expired API key simulation"""
        expired_headers = auth_fixtures.get_expired_key_simulation()
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            expired_headers, track_cost=False
        )
        
        # Should be rejected (assuming the simulation key is not in the system)
        assert response.status_code == 401
        response_data = response.json()
        assert "detail" in response_data
        
        logger.info("API2_EXPIRED_KEY_001: Expired key simulation rejected")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_brute_force_protection_001(self, http_client: httpx.AsyncClient,
                                                  auth_fixtures: AuthFixtures,
                                                  security_validator: SecurityValidator,
                                                  make_request):
        """API2_BRUTE_FORCE_001: Test brute force attack protection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Generate multiple invalid keys for brute force simulation
        brute_force_keys = auth_fixtures.get_brute_force_test_keys(20)
        
        failed_attempts = 0
        response_times = []
        
        for i, key in enumerate(brute_force_keys[:10]):  # Test first 10 to avoid overwhelming
            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json"
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, track_cost=False
            )
            end_time = time.time()
            
            response_times.append(end_time - start_time)
            
            # Should be rejected
            assert response.status_code == 401
            failed_attempts += 1
            
            # Short delay between attempts
            await asyncio.sleep(0.1)
        
        # Analyze response times for rate limiting indicators
        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)
        
        # Log brute force attempt results
        logger.info(f"API2_BRUTE_FORCE_001: {failed_attempts} failed attempts")
        logger.info(f"Average response time: {avg_response_time:.3f}s")
        logger.info(f"Max response time: {max_response_time:.3f}s")
        
        # Check if there's evidence of rate limiting (increasing response times)
        if max_response_time > avg_response_time * 2:
            logger.info("Rate limiting appears to be active")
        
        assert failed_attempts == len(brute_force_keys[:10])
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_timing_attack_001(self, http_client: httpx.AsyncClient,
                                        auth_fixtures: AuthFixtures,
                                        security_validator: SecurityValidator,
                                        make_request):
        """API2_TIMING_ATTACK_001: Test timing attack resistance"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        timing_keys = auth_fixtures.get_timing_attack_keys()
        
        async def test_key_timing(key: str):
            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json"
            }
            
            start_time = time.perf_counter()
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, track_cost=False
            )
            end_time = time.perf_counter()
            
            return {
                "key": key[:10] + "...",  # Truncated for security
                "response_time": end_time - start_time,
                "status_code": response.status_code
            }
        
        # Test timing for different key patterns
        timing_results = []
        for key in timing_keys:
            result = await test_key_timing(key)
            timing_results.append(result)
            await asyncio.sleep(0.1)  # Small delay between tests
        
        # Analyze timing patterns
        response_times = [r["response_time"] for r in timing_results]
        avg_time = sum(response_times) / len(response_times)
        max_deviation = max(abs(t - avg_time) for t in response_times)
        
        logger.info(f"API2_TIMING_ATTACK_001: Average response time: {avg_time:.4f}s")
        logger.info(f"Max deviation: {max_deviation:.4f}s")
        
        # Large timing differences could indicate vulnerability
        if max_deviation > 0.1:  # 100ms threshold
            logger.warning("Potential timing attack vulnerability detected")
        else:
            logger.info("Timing appears consistent - good timing attack resistance")
        
        # All requests should be rejected
        for result in timing_results:
            assert result["status_code"] == 401
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_session_management_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str], make_request):
        """API2_SESSION_MGMT_001: Test session management security"""
        # Test that API keys work consistently (stateless authentication)
        
        # Make multiple requests with the same key
        for i in range(5):
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            
            assert response.status_code == 200, f"Request {i+1} should succeed"
            response_data = response.json()
            assert "data" in response_data
        
        logger.info("API2_SESSION_MGMT_001: Consistent stateless authentication verified")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_token_leakage_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        security_validator: SecurityValidator,
                                        make_request):
        """API2_TOKEN_LEAKAGE_001: Test for token leakage in responses"""
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        
        # Check response body for token leakage
        response_text = response.text
        security_validation = security_validator.validate_response_security(
            response_text, dict(response.headers)
        )
        
        # Check for potential API key exposure
        sensitive_data = security_validator.detect_sensitive_data(response_text)
        api_key_exposure = [
            item for item in sensitive_data 
            if "api" in item.get("pattern", "").lower() and "key" in item.get("pattern", "").lower()
        ]
        
        assert len(api_key_exposure) == 0, "API key should not be exposed in response"
        
        # Check response headers for token leakage
        sensitive_headers = ["authorization", "x-api-key", "api-key"]
        for header_name, header_value in response.headers.items():
            assert header_name.lower() not in sensitive_headers, \
                f"Sensitive header {header_name} should not be echoed back"
        
        logger.info("API2_TOKEN_LEAKAGE_001: No token leakage detected")


class TestAdvancedAuthentication:
    """Advanced authentication security tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_concurrent_auth_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str], make_request):
        """API2_CONCURRENT_AUTH_001: Test concurrent authentication handling"""
        import asyncio
        
        # Create multiple concurrent requests with the same API key
        async def make_concurrent_request():
            return await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
        
        # Execute 5 concurrent requests
        tasks = [make_concurrent_request() for _ in range(5)]
        responses = await asyncio.gather(*tasks)
        
        # All should succeed
        for i, response in enumerate(responses):
            assert response.status_code == 200, f"Concurrent request {i+1} should succeed"
        
        logger.info("API2_CONCURRENT_AUTH_001: Concurrent authentication handled correctly")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_auth_bypass_attempts_001(self, http_client: httpx.AsyncClient,
                                                make_request):
        """API2_AUTH_BYPASS_001: Test authentication bypass attempts"""
        bypass_attempts = [
            # No authorization header
            {},
            # Empty authorization header
            {"Authorization": ""},
            # SQL injection in authorization
            {"Authorization": "Bearer '; DROP TABLE api_keys; --"},
            # Command injection
            {"Authorization": "Bearer `whoami`"},
            # Path traversal
            {"Authorization": "Bearer ../../../etc/passwd"},
            # JSON injection
            {"Authorization": 'Bearer {"admin": true}'},
            # Unicode bypass attempts
            {"Authorization": "Bearer \u0000\u0001\u0002"},
            # Buffer overflow simulation
            {"Authorization": f"Bearer {'A' * 10000}"}
        ]
        
        for headers in bypass_attempts:
            headers.update({"Content-Type": "application/json"})
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, track_cost=False
            )
            
            # All bypass attempts should be rejected
            assert response.status_code in [401, 422, 400], \
                "Authentication bypass attempts should be rejected"
        
        logger.info("API2_AUTH_BYPASS_001: All bypass attempts properly rejected")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api2_error_message_security_001(self, http_client: httpx.AsyncClient,
                                                  security_validator: SecurityValidator,
                                                  make_request):
        """API2_ERROR_MSG_001: Test error message security"""
        # Test various invalid authentication scenarios
        error_scenarios = [
            {"Authorization": "Bearer invalid_key_123"},
            {"Authorization": "Token invalid_key_123"},
            {"Authorization": "Basic invalid_key_123"},
            {"X-API-Key": "invalid_key_123"}
        ]
        
        for headers in error_scenarios:
            headers.update({"Content-Type": "application/json"})
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, track_cost=False
            )
            
            assert response.status_code in [401, 422]
            
            # Validate error message security
            error_validation = security_validator.validate_error_message_security(
                response.text
            )
            
            # Error messages should not expose sensitive information
            assert error_validation["is_secure"], \
                f"Error message should not expose sensitive information: {error_validation}"
        
        logger.info("API2_ERROR_MSG_001: Error messages are secure")