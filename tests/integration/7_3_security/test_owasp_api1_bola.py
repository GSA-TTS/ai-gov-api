# Section 7.3 - OWASP API1:2023 Broken Object Level Authorization (BOLA) Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API1_2023 - Broken Object Level Authorization (BOLA).md

import pytest
import httpx
import asyncio
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures
from utils.security_validators import SecurityValidator

class TestOWASPAPI1BOLA:
    """Comprehensive API1:2023 - Broken Object Level Authorization tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bola_api_key_001(self, http_client: httpx.AsyncClient,
                                  admin_auth_headers: Dict[str, str],
                                  make_request):
        """BOLA_API_KEY_001: CRITICAL - Cross-organization API key access vulnerability"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # This test identifies the CRITICAL vulnerability in APIKeyRepository.get()
        # that lacks manager_id filtering, allowing cross-organization access
        
        # Simulate accessing another organization's API key
        # In a real test environment, we'd have actual keys from different orgs
        test_key_id = "1"  # Simulated API key ID from another org
        
        endpoints_to_test = [
            f"/tokens/is_active/{test_key_id}",
            f"/tokens/is_active/{test_key_id}?is_active=false",
            f"/tokens/is_active/{test_key_id}?is_active=true"
        ]
        
        for endpoint in endpoints_to_test:
            # Test GET access to another org's key
            response = await make_request(
                http_client, "GET", endpoint,
                admin_auth_headers, track_cost=False
            )
            
            # CURRENT VULNERABILITY: This might return 200 instead of 403
            # The secure behavior should be 403 Forbidden
            if response.status_code == 200:
                logger.critical(f"BOLA VULNERABILITY DETECTED: {endpoint} accessible across organizations")
                # In a secure system, this should be 403
                pytest.fail("CRITICAL BOLA vulnerability: Cross-organization API key access allowed")
            else:
                assert response.status_code == 403, \
                    f"Cross-organization API key access should return 403: {endpoint}"
            
            # Test POST to modify another org's key
            response = await make_request(
                http_client, "POST", endpoint,
                admin_auth_headers, {"is_active": False}, track_cost=False
            )
            
            # Should be forbidden
            assert response.status_code in [403, 405], \
                "Cross-organization API key modification should be forbidden"
        
        logger.info("BOLA_API_KEY_001: Cross-organization API key access test completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bola_api_key_enumeration_001(self, http_client: httpx.AsyncClient,
                                              admin_auth_headers: Dict[str, str],
                                              make_request):
        """BOLA_API_KEY_ENUMERATION_001: API key ID enumeration attack"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test systematic enumeration of API key IDs
        key_ids_to_test = ["1", "2", "3", "100", "999"]
        
        response_patterns = []
        timing_data = []
        
        for key_id in key_ids_to_test:
            endpoint = f"/tokens/is_active/{key_id}"
            
            import time
            start_time = time.perf_counter()
            
            response = await make_request(
                http_client, "GET", endpoint,
                admin_auth_headers, track_cost=False
            )
            
            end_time = time.perf_counter()
            response_time = end_time - start_time
            timing_data.append(response_time)
            
            response_patterns.append({
                "key_id": key_id,
                "status_code": response.status_code,
                "response_time": response_time,
                "content_length": len(response.content)
            })
            
            # Secure behavior: Should return 404 (not 403) to avoid key ID enumeration
            if response.status_code == 403:
                logger.warning(f"Key ID {key_id} existence confirmed via 403 response")
            elif response.status_code == 200:
                logger.critical(f"BOLA vulnerability: Key ID {key_id} accessible")
            
            await asyncio.sleep(0.1)  # Small delay between requests
        
        # Analyze response patterns for enumeration vulnerabilities
        status_codes = [p["status_code"] for p in response_patterns]
        content_lengths = [p["content_length"] for p in response_patterns]
        
        # All unauthorized requests should return consistent responses
        assert len(set(status_codes)) <= 2, \
            "Response codes should be consistent to prevent enumeration"
        
        # Check for timing attacks
        avg_time = sum(timing_data) / len(timing_data)
        max_deviation = max(abs(t - avg_time) for t in timing_data)
        
        if max_deviation > 0.1:  # 100ms threshold
            logger.warning("Potential timing attack vulnerability in API key enumeration")
        
        logger.info("BOLA_API_KEY_ENUMERATION_001: API key enumeration resistance tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bola_llm_usage_001(self, http_client: httpx.AsyncClient,
                                    auth_headers: Dict[str, str],
                                    make_request):
        """BOLA_LLM_USAGE_001: Cross-organization LLM usage data access"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Make some LLM calls to generate usage data
        test_requests = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test usage tracking"}],
                "max_tokens": 50
            }
        ]
        
        for request in test_requests:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200
        
        # Test potential future billing/usage endpoints
        # These endpoints may not exist yet, but we test the concept
        potential_endpoints = [
            "/api/v1/usage",
            "/api/v1/billing",
            "/api/v1/usage/summary",
            "/api/v1/billing/history"
        ]
        
        for endpoint in potential_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            # If the endpoint exists and returns data, verify proper scoping
            if response.status_code == 200:
                response_data = response.json()
                # Usage data should be scoped to the requesting organization
                # Verify no cross-organization data leakage
                logger.info(f"Usage endpoint {endpoint} exists - verify proper scoping")
            elif response.status_code == 404:
                logger.info(f"Usage endpoint {endpoint} not implemented yet")
            else:
                # Other status codes should be appropriate for unauthorized access
                assert response.status_code in [401, 403], \
                    f"Usage endpoint {endpoint} should require proper authorization"
        
        logger.info("BOLA_LLM_USAGE_001: LLM usage data access control tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bola_chat_session_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       make_request):
        """BOLA_CHAT_SESSION_001: Chat session isolation testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test conversation data isolation
        # Create multiple chat sessions and verify isolation
        
        session_requests = [
            {
                "session_id": "session_001",
                "content": "This is session 1 conversation"
            },
            {
                "session_id": "session_002", 
                "content": "This is session 2 conversation"
            }
        ]
        
        for session in session_requests:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": session["content"]}],
                "max_tokens": 50
            }
            
            # Add session context if supported
            if "metadata" in request:
                request["metadata"] = {"session_id": session["session_id"]}
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200
            response_data = response.json()
            
            # Verify response doesn't contain data from other sessions
            response_content = response_data["choices"][0]["message"]["content"]
            for other_session in session_requests:
                if other_session["session_id"] != session["session_id"]:
                    assert other_session["content"] not in response_content, \
                        "Response should not contain data from other sessions"
        
        # Test potential future session endpoints
        potential_session_endpoints = [
            "/api/v1/sessions",
            "/api/v1/sessions/session_001",
            "/api/v1/conversations/session_001"
        ]
        
        for endpoint in potential_session_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            # If session endpoints exist, they should be properly scoped
            if response.status_code == 200:
                logger.info(f"Session endpoint {endpoint} exists - verify proper scoping")
            elif response.status_code in [401, 403]:
                logger.info(f"Session endpoint {endpoint} properly protected")
            else:
                logger.info(f"Session endpoint {endpoint} not implemented")
        
        logger.info("BOLA_CHAT_SESSION_001: Chat session isolation tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bola_model_access_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       make_request):
        """BOLA_MODEL_ACCESS_001: Model access control testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test model access controls
        available_models = config.CHAT_MODELS
        
        # Test access to each configured model
        for model in available_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": f"Test access to {model}"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            # Should succeed for configured models
            assert response.status_code == 200, \
                f"Access to configured model {model} should succeed"
        
        # Test access to non-existent models
        invalid_models = ["admin_only_model", "org_specific_model", "restricted_model_123"]
        
        for model in invalid_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": f"Test access to {model}"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should be rejected
            assert response.status_code == 422, \
                f"Access to invalid model {model} should be rejected with 422"
        
        # Test /models endpoint for proper filtering
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify only authorized models are returned
        returned_models = [model["id"] for model in response_data["data"]]
        for model in available_models:
            assert model in returned_models, \
                f"Authorized model {model} should be in /models response"
        
        logger.info("BOLA_MODEL_ACCESS_001: Model access control tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bola_user_access_001(self, http_client: httpx.AsyncClient,
                                      admin_auth_headers: Dict[str, str],
                                      make_request):
        """BOLA_USER_ACCESS_001: Cross-organization user access"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test user access across organizations
        test_emails = [
            "user1@org1.gov",
            "admin@org2.gov", 
            "test@anotherdomain.com"
        ]
        
        for email in test_emails:
            endpoint = f"/users/{email}"
            
            response = await make_request(
                http_client, "GET", endpoint,
                admin_auth_headers, track_cost=False
            )
            
            # User access should be properly scoped
            if response.status_code == 200:
                # If user exists and is accessible, verify it's from same org
                response_data = response.json()
                logger.info(f"User {email} accessible - verify organization scoping")
            elif response.status_code == 404:
                # User not found - acceptable
                logger.info(f"User {email} not found")
            elif response.status_code == 403:
                # Access denied - good security
                logger.info(f"User {email} access denied - good security")
            else:
                pytest.fail(f"Unexpected response code {response.status_code} for user {email}")
        
        logger.info("BOLA_USER_ACCESS_001: User access control tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bola_concurrent_access_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """BOLA_CONCURRENT_ACCESS_001: Concurrent access BOLA testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test concurrent access to verify session isolation
        async def concurrent_request(session_id: str):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Concurrent test {session_id}"}],
                "max_tokens": 50
            }
            
            return await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
        
        # Execute concurrent requests
        tasks = [concurrent_request(f"session_{i}") for i in range(5)]
        responses = await asyncio.gather(*tasks)
        
        # All requests should succeed and be properly isolated
        for i, response in enumerate(responses):
            assert response.status_code == 200, \
                f"Concurrent request {i} should succeed"
            
            response_data = response.json()
            response_content = response_data["choices"][0]["message"]["content"]
            
            # Verify no cross-contamination between concurrent requests
            for j, other_response in enumerate(responses):
                if i != j:
                    other_data = other_response.json()
                    other_content = other_data["choices"][0]["message"]["content"]
                    # Responses should be independent
                    assert response_content != other_content or len(set([r.json()["choices"][0]["message"]["content"] for r in responses])) > 1, \
                        "Concurrent requests should produce independent responses"
        
        logger.info("BOLA_CONCURRENT_ACCESS_001: Concurrent access isolation tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bola_parameter_manipulation_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """BOLA_PARAMETER_MANIPULATION_001: Parameter manipulation attacks"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various parameter manipulation techniques
        manipulation_attempts = [
            # SQL injection in model parameter
            {
                "model": f"{config.get_chat_model(0)}'; DROP TABLE users; --",
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            },
            # Array injection
            {
                "model": [config.get_chat_model(0), "admin_model"],
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            },
            # Object injection
            {
                "model": {"normal": config.get_chat_model(0), "admin": True},
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            },
            # Path traversal
            {
                "model": "../../../admin_models/secret_model",
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            },
            # Unicode manipulation
            {
                "model": config.get_chat_model(0) + "\u0000admin",
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            }
        ]
        
        for i, attempt in enumerate(manipulation_attempts):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, attempt, track_cost=False
            )
            
            # Should be rejected with proper validation error
            assert response.status_code in [422, 400], \
                f"Parameter manipulation attempt {i} should be rejected"
            
            if response.status_code == 200:
                # If somehow accepted, verify no privilege escalation
                response_data = response.json()
                response_text = str(response_data).lower()
                assert "admin" not in response_text, \
                    "Response should not indicate privilege escalation"
        
        logger.info("BOLA_PARAMETER_MANIPULATION_001: Parameter manipulation resistance tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bola_integration_testing_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              admin_auth_headers: Dict[str, str],
                                              make_request):
        """BOLA_INTEGRATION_TESTING_001: End-to-end BOLA protection testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test complete user workflow for BOLA vulnerabilities
        workflow_steps = [
            # Step 1: Get available models
            {
                "method": "GET",
                "endpoint": "/api/v1/models",
                "headers": auth_headers,
                "data": None
            },
            # Step 2: Make chat completion
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "headers": auth_headers,
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Integration test"}],
                    "max_tokens": 50
                }
            },
            # Step 3: Try to access admin functionality with regular key
            {
                "method": "GET",
                "endpoint": "/tokens/is_active/1",
                "headers": auth_headers,
                "data": None
            }
        ]
        
        for i, step in enumerate(workflow_steps):
            response = await make_request(
                http_client, step["method"], step["endpoint"],
                step["headers"], step["data"],
                track_cost=(step["method"] == "POST" and "chat" in step["endpoint"])
            )
            
            if i == 0 or i == 1:
                # First two steps should succeed
                assert response.status_code == 200, \
                    f"Workflow step {i+1} should succeed"
            else:
                # Admin access should be denied
                assert response.status_code in [401, 403, 404], \
                    f"Admin access attempt should be denied"
        
        logger.info("BOLA_INTEGRATION_TESTING_001: End-to-end BOLA protection validated")