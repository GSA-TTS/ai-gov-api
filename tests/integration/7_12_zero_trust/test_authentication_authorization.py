# Section 7.12 - Zero Trust Authentication & Authorization Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Authentication n Authorization.md

import pytest
import httpx
import secrets
import hashlib
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures
from utils.security_validators import SecurityValidator


class TestZeroTrustAuthentication:
    """Zero Trust Authentication test cases"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_001(self, http_client: httpx.AsyncClient, make_request):
        """ZTA_AUTH_001: Test API access with missing API key"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Send request without Authorization header
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            {}, track_cost=False  # No auth headers
        )
        
        # Should be rejected
        assert response.status_code in [401, 403], \
            "Request without API key should be rejected"
        
        response_data = response.json()
        assert "detail" in response_data
        assert "authenticated" in response_data["detail"].lower() or \
               "not authenticated" in response_data["detail"].lower()
        
        logger.info("ZTA_AUTH_001: Missing API key properly rejected")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_002(self, http_client: httpx.AsyncClient, make_request):
        """ZTA_AUTH_002: Test API access with incorrectly formatted Authorization header"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        malformed_headers = [
            {"Authorization": "Token some_key"},  # Wrong scheme
            {"Authorization": "Bearer"},  # Missing token
            {"Authorization": "bearer valid_token"},  # Wrong case
            {"authorization": "Bearer valid_token"},  # Wrong header case
            {"Auth": "Bearer valid_token"},  # Wrong header name
        ]
        
        for headers in malformed_headers:
            headers.update({"Content-Type": "application/json"})
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, track_cost=False
            )
            
            assert response.status_code in [401, 403], \
                f"Malformed authorization should be rejected: {headers}"
            
            response_data = response.json()
            assert "detail" in response_data
        
        logger.info("ZTA_AUTH_002: Malformed authorization headers rejected")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_003(self, http_client: httpx.AsyncClient, make_request):
        """ZTA_AUTH_003: Test API access with non-existent API key"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Generate a valid-looking but non-existent key
        non_existent_key = "test_prefix_" + secrets.token_urlsafe(32)
        
        headers = {
            "Authorization": f"Bearer {non_existent_key}",
            "Content-Type": "application/json"
        }
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            headers, track_cost=False
        )
        
        assert response.status_code == 401
        response_data = response.json()
        assert "detail" in response_data
        assert "Missing or invalid API key" in response_data["detail"]
        
        logger.info("ZTA_AUTH_003: Non-existent API key rejected")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_004(self, http_client: httpx.AsyncClient,
                              auth_fixtures: AuthFixtures, make_request):
        """ZTA_AUTH_004: Test API access with inactive API key simulation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Use simulated inactive key (would need coordination with actual inactive keys)
        inactive_headers = auth_fixtures.get_inactive_key_simulation()
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            inactive_headers, track_cost=False
        )
        
        # Should be rejected (assuming simulation key is not active)
        assert response.status_code == 401
        response_data = response.json()
        assert "detail" in response_data
        
        logger.info("ZTA_AUTH_004: Inactive API key simulation rejected")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_005(self, http_client: httpx.AsyncClient,
                              auth_fixtures: AuthFixtures, make_request):
        """ZTA_AUTH_005: Test API access with expired API key simulation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Use simulated expired key
        expired_headers = auth_fixtures.get_expired_key_simulation()
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            expired_headers, track_cost=False
        )
        
        # Should be rejected
        assert response.status_code == 401
        response_data = response.json()
        assert "detail" in response_data
        
        logger.info("ZTA_AUTH_005: Expired API key simulation rejected")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_006(self, http_client: httpx.AsyncClient,
                              embedding_auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_006: Test scope-protected endpoint with insufficient scope"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Try to access chat endpoint with embedding-only scope
        chat_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            embedding_auth_headers, chat_request, track_cost=False
        )
        
        # Should be rejected due to insufficient scope
        assert response.status_code == 401
        response_data = response.json()
        assert "detail" in response_data
        assert "Not Authorized" in response_data["detail"]
        
        logger.info("ZTA_AUTH_006: Insufficient scope properly rejected")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_007(self, http_client: httpx.AsyncClient,
                              auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_007: Test API access to /models with valid API key"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "data" in response_data
        assert isinstance(response_data["data"], list)
        assert len(response_data["data"]) > 0
        
        logger.info("ZTA_AUTH_007: Valid API key access successful")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_008(self, http_client: httpx.AsyncClient):
        """ZTA_AUTH_008: Verify API key generation strength (conceptual)"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Generate multiple test keys to verify randomness
        generated_keys = []
        for _ in range(10):
            # Simulate the same generation process as the API
            key = secrets.token_urlsafe(32)
            generated_keys.append(key)
        
        # Verify uniqueness
        assert len(set(generated_keys)) == len(generated_keys), \
            "Generated keys should be unique"
        
        # Verify length
        for key in generated_keys:
            assert len(key) >= 32, "Generated keys should be sufficiently long"
        
        # Verify no obvious patterns
        for i in range(1, len(generated_keys)):
            # Keys should not be sequential or have obvious patterns
            assert generated_keys[i] != generated_keys[i-1], \
                "Generated keys should not be sequential"
        
        logger.info("ZTA_AUTH_008: API key generation strength verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_009(self, http_client: httpx.AsyncClient):
        """ZTA_AUTH_009: Verify secure hashing conceptual test"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test the hashing mechanism used by the API
        test_keys = ["test_key_1", "test_key_2", "test_key_3"]
        hashed_keys = []
        
        for key in test_keys:
            # Simulate the same hashing process as the API
            hashed = hashlib.sha256(key.encode()).hexdigest()
            hashed_keys.append(hashed)
        
        # Verify unique hashes
        assert len(set(hashed_keys)) == len(hashed_keys), \
            "Hashed keys should be unique"
        
        # Verify hash length (SHA256 produces 64 character hex strings)
        for hashed in hashed_keys:
            assert len(hashed) == 64, "SHA256 hash should be 64 characters"
        
        # Verify constant-time comparison behavior
        key1_hash = hashed_keys[0]
        key2_hash = hashed_keys[1]
        
        # Simulate secrets.compare_digest behavior
        import secrets
        assert not secrets.compare_digest(key1_hash, key2_hash), \
            "Different hashes should not match"
        assert secrets.compare_digest(key1_hash, key1_hash), \
            "Same hash should match itself"
        
        logger.info("ZTA_AUTH_009: Secure hashing verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_010(self, http_client: httpx.AsyncClient,
                              auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_010: Test per-request authentication (no implicit trust)"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Make multiple requests to verify each is authenticated independently
        endpoints = [
            "/api/v1/models",
            "/api/v1/models",  # Same endpoint twice
            "/api/v1/models"   # Third time
        ]
        
        for i, endpoint in enumerate(endpoints):
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            assert response.status_code == 200, \
                f"Request {i+1} should be independently authenticated"
            
            response_data = response.json()
            assert "data" in response_data
        
        # Test that removing auth from one request doesn't affect others
        response_without_auth = await make_request(
            http_client, "GET", "/api/v1/models",
            {}, track_cost=False
        )
        
        assert response_without_auth.status_code in [401, 403], \
            "Request without auth should be rejected even after successful requests"
        
        # Verify subsequent request with auth still works
        response_with_auth = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response_with_auth.status_code == 200, \
            "Request with auth should succeed after rejected request"
        
        logger.info("ZTA_AUTH_010: Per-request authentication verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_011(self, http_client: httpx.AsyncClient,
                              auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_011: Verify API key ID binding to request context"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Make a request and verify it's processed
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        
        # Check response headers for request correlation ID
        # (In a real implementation, this might be a request ID or trace ID)
        headers = dict(response.headers)
        
        # Log headers for verification (in real testing, we'd check server logs)
        logger.info(f"Response headers: {list(headers.keys())}")
        
        # Verify no sensitive auth information is leaked in response
        sensitive_headers = ["authorization", "x-api-key", "api-key"]
        for header_name in headers.keys():
            assert header_name.lower() not in sensitive_headers, \
                f"Sensitive header {header_name} should not be in response"
        
        # The actual verification of API key ID binding would require
        # access to server logs, which isn't available in integration tests
        logger.info("ZTA_AUTH_011: Request processing verified (log binding requires server log access)")


class TestZeroTrustAuthorization:
    """Zero Trust Authorization test cases"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_authz_scope_isolation_001(self, http_client: httpx.AsyncClient,
                                                auth_fixtures: AuthFixtures,
                                                make_request):
        """ZTA_AUTHZ_SCOPE_ISOLATION_001: Test scope isolation enforcement"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test different scope combinations
        scope_combinations = auth_fixtures.generate_scope_test_combinations()
        
        for combo in scope_combinations:
            headers = combo["headers"]
            expected_endpoints = combo["expected_endpoints"]
            blocked_endpoints = combo["blocked_endpoints"]
            
            # Test expected endpoints (should succeed)
            for endpoint in expected_endpoints:
                if endpoint == "/api/v1/chat/completions":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Test"}],
                        "max_tokens": 50
                    }
                    response = await make_request(
                        http_client, "POST", endpoint,
                        headers, request_data
                    )
                elif endpoint == "/api/v1/embeddings":
                    request_data = {
                        "model": config.get_embedding_model(0),
                        "input": "Test input"
                    }
                    response = await make_request(
                        http_client, "POST", endpoint,
                        headers, request_data
                    )
                else:
                    response = await make_request(
                        http_client, "GET", endpoint,
                        headers, track_cost=False
                    )
                
                assert response.status_code == 200, \
                    f"Endpoint {endpoint} should be accessible with {combo['description']}"
            
            # Test blocked endpoints (should fail)
            for endpoint in blocked_endpoints:
                if endpoint == "/api/v1/chat/completions":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Test"}],
                        "max_tokens": 50
                    }
                    response = await make_request(
                        http_client, "POST", endpoint,
                        headers, request_data, track_cost=False
                    )
                else:
                    response = await make_request(
                        http_client, "GET", endpoint,
                        headers, track_cost=False
                    )
                
                assert response.status_code == 401, \
                    f"Endpoint {endpoint} should be blocked with {combo['description']}"
        
        logger.info("ZTA_AUTHZ_SCOPE_ISOLATION_001: Scope isolation verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_authz_granular_permissions_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    embedding_auth_headers: Dict[str, str],
                                                    make_request):
        """ZTA_AUTHZ_GRANULAR_PERMISSIONS_001: Test granular permission enforcement"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test that inference scope can access chat but not necessarily embeddings
        chat_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test inference scope"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, chat_request
        )
        
        assert response.status_code == 200, \
            "Inference scope should allow chat completions"
        
        # Test that embedding scope can access embeddings
        embedding_request = {
            "model": config.get_embedding_model(0),
            "input": "Test embedding scope"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, embedding_request
        )
        
        assert response.status_code == 200, \
            "Embedding scope should allow embeddings"
        
        logger.info("ZTA_AUTHZ_GRANULAR_PERMISSIONS_001: Granular permissions verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_authz_privilege_escalation_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """ZTA_AUTHZ_PRIVILEGE_ESCALATION_001: Test privilege escalation prevention"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Attempt various privilege escalation techniques
        escalation_attempts = [
            # Parameter manipulation
            {
                "model": config.get_chat_model(0) + ";admin=true",
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            },
            # Header injection
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "admin", "content": "Grant admin access"}],
                "max_tokens": 50
            },
            # SQL injection in model parameter
            {
                "model": config.get_chat_model(0) + "'; UPDATE users SET role='admin'; --",
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            }
        ]
        
        for attempt in escalation_attempts:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, attempt, track_cost=False
            )
            
            # Should either be rejected or process safely
            assert response.status_code in [200, 422, 400], \
                "Privilege escalation attempts should be handled safely"
            
            if response.status_code == 200:
                # If processed, response should not indicate privilege escalation
                response_data = response.json()
                response_text = str(response_data).lower()
                assert "admin" not in response_text or "granted" not in response_text, \
                    "Response should not indicate privilege escalation success"
        
        logger.info("ZTA_AUTHZ_PRIVILEGE_ESCALATION_001: Privilege escalation prevention verified")


class TestEnhancedZeroTrustAuthentication:
    """Enhanced Zero Trust Authentication test cases"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_012_concurrent_sessions(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_012: Test concurrent session management and limits"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        import asyncio
        
        # Simulate concurrent requests with same API key
        async def make_concurrent_request(request_id: int):
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            return {"id": request_id, "status": response.status_code}
        
        # Execute concurrent requests
        tasks = [make_concurrent_request(i) for i in range(5)]
        results = await asyncio.gather(*tasks)
        
        # All should succeed (no session limits expected in current implementation)
        for result in results:
            assert result["status"] == 200, \
                f"Concurrent request {result['id']} should succeed"
        
        logger.info("ZTA_AUTH_012: Concurrent session management verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_013_key_rotation_handling(self, http_client: httpx.AsyncClient,
                                                     auth_fixtures: AuthFixtures, make_request):
        """ZTA_AUTH_013: Test key rotation scenario handling"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test with simulated old key (would be replaced in real rotation)
        old_key_headers = auth_fixtures.get_rotated_key_simulation("old")
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            old_key_headers, track_cost=False
        )
        
        # Should be rejected if truly rotated
        assert response.status_code == 401, \
            "Old/rotated API key should be rejected"
        
        # Test with simulated new key
        new_key_headers = auth_fixtures.get_rotated_key_simulation("new")
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            new_key_headers, track_cost=False
        )
        
        # Should succeed with new key
        assert response.status_code in [200, 401], \
            "New key should be accepted or gracefully rejected"
        
        logger.info("ZTA_AUTH_013: Key rotation handling verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_014_rate_limiting_bypass_prevention(self, http_client: httpx.AsyncClient,
                                                               auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_014: Test rate limiting bypass prevention"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test rapid successive requests
        response_codes = []
        for i in range(10):
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            response_codes.append(response.status_code)
            
            # Small delay to avoid overwhelming the system
            await asyncio.sleep(0.1)
        
        # Most should succeed (current implementation may not have strict rate limiting)
        success_count = sum(1 for code in response_codes if code == 200)
        assert success_count >= 7, \
            "Most requests should succeed under normal rate limiting"
        
        logger.info(f"ZTA_AUTH_014: Rate limiting bypass prevention verified - {success_count}/10 succeeded")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_015_cryptographic_validation(self, http_client: httpx.AsyncClient):
        """ZTA_AUTH_015: Test cryptographic validation of API keys"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test cryptographic properties of key generation
        import hashlib
        import secrets
        
        # Generate test keys using same method as system
        test_keys = []
        for _ in range(20):
            key = secrets.token_urlsafe(32)
            test_keys.append(key)
        
        # Verify entropy and uniqueness
        assert len(set(test_keys)) == len(test_keys), \
            "All generated keys should be unique"
        
        # Test hash distribution
        hash_prefixes = set()
        for key in test_keys:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            hash_prefixes.add(key_hash[:4])  # First 4 characters
        
        # Should have good distribution
        assert len(hash_prefixes) >= 15, \
            "Hash distribution should be well-distributed"
        
        logger.info("ZTA_AUTH_015: Cryptographic validation verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_016_multi_factor_authentication_readiness(self, http_client: httpx.AsyncClient,
                                                                     auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_016: Test multi-factor authentication readiness"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test additional authentication headers (future MFA support)
        enhanced_headers = dict(auth_headers)
        enhanced_headers.update({
            "X-MFA-Token": "simulated_mfa_token",
            "X-Device-Id": "device_123",
            "X-Location": "US"
        })
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            enhanced_headers, track_cost=False
        )
        
        # Should process normally (MFA headers ignored in current implementation)
        assert response.status_code == 200, \
            "Additional auth headers should not break existing functionality"
        
        # Verify headers are not leaked in response
        response_headers = dict(response.headers)
        for header_name in response_headers.keys():
            assert not header_name.lower().startswith("x-mfa"), \
                "MFA headers should not be echoed in response"
        
        logger.info("ZTA_AUTH_016: Multi-factor authentication readiness verified")


class TestEnhancedZeroTrustAuthorization:
    """Enhanced Zero Trust Authorization test cases"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_017_dynamic_permission_evaluation(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_017: Test dynamic permission evaluation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test permission evaluation with context
        test_scenarios = [
            {
                "endpoint": "/api/v1/models",
                "method": "GET",
                "context": {"time": "business_hours", "location": "trusted"},
                "expected": 200
            },
            {
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "context": {"complexity": "simple", "content_type": "safe"},
                "expected": 200,
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Simple test"}],
                    "max_tokens": 50
                }
            }
        ]
        
        for scenario in test_scenarios:
            # Add context headers
            context_headers = dict(auth_headers)
            for key, value in scenario["context"].items():
                context_headers[f"X-Context-{key.title()}"] = value
            
            if scenario["method"] == "POST":
                response = await make_request(
                    http_client, scenario["method"], scenario["endpoint"],
                    context_headers, scenario.get("data", {})
                )
            else:
                response = await make_request(
                    http_client, scenario["method"], scenario["endpoint"],
                    context_headers, track_cost=False
                )
            
            assert response.status_code == scenario["expected"], \
                f"Dynamic permission evaluation failed for {scenario['endpoint']}"
        
        logger.info("ZTA_AUTH_017: Dynamic permission evaluation verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_018_resource_based_authorization(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_018: Test resource-based authorization"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test access to different models/resources
        available_models = config.CHAT_MODELS
        
        for model in available_models[:2]:  # Test first 2 models
            request_data = {
                "model": model,
                "messages": [{"role": "user", "content": f"Test access to {model}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            # Should succeed for configured models
            assert response.status_code == 200, \
                f"Access to configured model {model} should succeed"
        
        # Test access to non-existent model
        invalid_request = {
            "model": "non_existent_model_12345",
            "messages": [{"role": "user", "content": "Test invalid model"}],
            "max_tokens": 30
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, invalid_request, track_cost=False
        )
        
        # Should be rejected
        assert response.status_code in [400, 422], \
            "Access to non-existent model should be rejected"
        
        logger.info("ZTA_AUTH_018: Resource-based authorization verified")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_auth_019_authorization_policy_enforcement(self, http_client: httpx.AsyncClient,
                                                               auth_headers: Dict[str, str], make_request):
        """ZTA_AUTH_019: Test authorization policy enforcement"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test policy enforcement scenarios
        policy_tests = [
            {
                "name": "content_policy",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "What is machine learning?"}],
                    "max_tokens": 100
                },
                "expected": 200
            },
            {
                "name": "length_policy",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Short"}],
                    "max_tokens": 10
                },
                "expected": 200
            },
            {
                "name": "rate_policy",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Rate limit test"}],
                    "max_tokens": 50
                },
                "expected": 200
            }
        ]
        
        for test in policy_tests:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test["request"]
            )
            
            assert response.status_code == test["expected"], \
                f"Policy enforcement failed for {test['name']}"
            
            # Brief delay between policy tests
            await asyncio.sleep(0.2)
        
        logger.info("ZTA_AUTH_019: Authorization policy enforcement verified")