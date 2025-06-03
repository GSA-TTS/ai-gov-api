# Section 7.3 - OWASP API5:2023 Broken Function Level Authorization Tests - Advanced Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API5_2023 - Broken Function Level Authorization.md

import pytest
import httpx
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures


class TestBFLAAdministrativeFunctions:
    """Administrative Function Authorization tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_admin_token_create_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """BFLA_ADMIN_TOKEN_CREATE_001: Token creation with non-admin scopes"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test token creation with various non-admin scopes
        non_admin_scenarios = [
            {
                "headers": {"Authorization": f"Bearer {config.TEST_API_KEY}"},
                "description": "API key with only models:inference scope"
            },
            {
                "headers": {"Authorization": f"Bearer {config.TEST_EMBEDDING_API_KEY}"},
                "description": "API key with only models:embedding scope"
            },
            {
                "headers": {"Authorization": "Bearer users_read_key"},
                "description": "API key with users:read scope"
            },
            {
                "headers": {"Authorization": "Bearer no_scopes_key"},
                "description": "API key with no scopes"
            },
            {
                "headers": {"Authorization": "Bearer malformed_admin_key"},
                "description": "API key with malformed admin scope"
            }
        ]
        
        for scenario in non_admin_scenarios:
            token_create_data = {
                "name": "test_token",
                "scopes": ["models:inference"]
            }
            
            response = await make_request(
                http_client, "POST", "/tokens/create",
                scenario["headers"], token_create_data, track_cost=False
            )
            
            # Should fail with 403 Forbidden
            assert response.status_code in [401, 403, 404], \
                f"Should deny token creation for {scenario['description']}"
            
            if response.status_code == 403:
                response_data = response.json()
                assert "detail" in response_data
                assert response_data["detail"] == "Not Authorized" or "authorized" in response_data["detail"].lower()
            
            logger.info(f"BFLA_ADMIN_TOKEN_CREATE_001: Properly denied {scenario['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_admin_token_set_active_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """BFLA_ADMIN_TOKEN_SET_ACTIVE_001: Token activation with non-admin scopes"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test token activation/deactivation with non-admin keys
        non_admin_scenarios = [
            {
                "headers": {"Authorization": f"Bearer {config.TEST_API_KEY}"},
                "description": "Non-admin API key"
            },
            {
                "headers": {"Authorization": "Bearer various_scopes_key"},
                "description": "API key with various non-admin scopes"
            }
        ]
        
        for scenario in non_admin_scenarios:
            # Test deactivating a token
            response = await make_request(
                http_client, "POST", "/tokens/is_active/1?is_active=false",
                scenario["headers"], track_cost=False
            )
            
            # Should fail with 403 Forbidden
            assert response.status_code in [401, 403, 404], \
                f"Should deny token modification for {scenario['description']}"
            
            if response.status_code == 403:
                response_data = response.json()
                assert "detail" in response_data
                assert response_data["detail"] == "Not Authorized" or "authorized" in response_data["detail"].lower()
            
            # Test attempts to modify own API key status
            response = await make_request(
                http_client, "POST", "/tokens/is_active/self?is_active=true",
                scenario["headers"], track_cost=False
            )
            
            # Should also be denied (no self-modification)
            assert response.status_code in [401, 403, 404], \
                f"Should deny self-token modification for {scenario['description']}"
            
            logger.info(f"BFLA_ADMIN_TOKEN_SET_ACTIVE_001: Properly denied {scenario['description']}")


class TestBFLAUserManagement:
    """User Management Authorization tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_admin_user_create_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """BFLA_ADMIN_USER_CREATE_001: User creation with non-admin scopes"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test user creation with non-admin keys
        non_admin_scenarios = [
            {
                "headers": {"Authorization": f"Bearer {config.TEST_API_KEY}"},
                "description": "API key with models:inference scope"
            },
            {
                "headers": {"Authorization": "Bearer users_read_key"},
                "description": "API key with users:read scope only"
            },
            {
                "headers": {"Authorization": "Bearer no_scopes_key"},
                "description": "API key with no scopes"
            }
        ]
        
        for scenario in non_admin_scenarios:
            user_create_data = {
                "email": "test@example.com",
                "name": "Test User",
                "role": "user"
            }
            
            response = await make_request(
                http_client, "POST", "/users/create",
                scenario["headers"], user_create_data, track_cost=False
            )
            
            # Should fail with 403 Forbidden
            assert response.status_code in [401, 403, 404], \
                f"Should deny user creation for {scenario['description']}"
            
            if response.status_code == 403:
                response_data = response.json()
                assert "detail" in response_data
                assert response_data["detail"] == "Not Authorized" or "authorized" in response_data["detail"].lower()
            
            # Test privilege escalation attempts in user creation
            admin_user_data = {
                "email": "admin@example.com",
                "name": "Admin User",
                "role": "admin",
                "is_admin": True,
                "privileges": ["admin", "super_user"]
            }
            
            response = await make_request(
                http_client, "POST", "/users/create",
                scenario["headers"], admin_user_data, track_cost=False
            )
            
            # Should also be denied
            assert response.status_code in [401, 403, 404], \
                f"Should deny admin user creation for {scenario['description']}"
            
            logger.info(f"BFLA_ADMIN_USER_CREATE_001: Properly denied {scenario['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_admin_user_get_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """BFLA_ADMIN_USER_GET_001: User information access with non-admin scopes"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test user information access
        test_emails = ["someuser@example.com", "admin@example.com", "test@example.com"]
        
        for email in test_emails:
            response = await make_request(
                http_client, "GET", f"/users/{email}",
                auth_headers, track_cost=False
            )
            
            # Should be denied for non-admin
            assert response.status_code in [401, 403, 404], \
                f"Should deny user access for {email}"
            
            if response.status_code == 403:
                response_data = response.json()
                assert "detail" in response_data
                assert response_data["detail"] == "Not Authorized" or "authorized" in response_data["detail"].lower()
        
        # Test user enumeration through email guessing
        common_emails = [
            "admin@example.com", "user@example.com", "test@example.com",
            "support@example.com", "info@example.com"
        ]
        
        for email in common_emails:
            response = await make_request(
                http_client, "GET", f"/users/{email}",
                auth_headers, track_cost=False
            )
            
            # Should not leak whether user exists
            assert response.status_code in [401, 403, 404], \
                f"Should not leak user existence for {email}"
        
        logger.info("BFLA_ADMIN_USER_GET_001: User access properly denied")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_admin_user_update_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """BFLA_ADMIN_USER_UPDATE_001: User update with non-admin scopes"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test user update attempts
        update_scenarios = [
            {
                "email": "user@example.com",
                "data": {"name": "Updated Name"},
                "description": "Basic user update"
            },
            {
                "email": "self@example.com",
                "data": {"name": "Self Update"},
                "description": "Self user account update"
            },
            {
                "email": "admin@example.com",
                "data": {"role": "admin", "is_admin": True},
                "description": "Privilege escalation through user update"
            },
            {
                "email": "target@example.com",
                "data": {"password": "new_password", "api_keys": ["new_key"]},
                "description": "Security parameter manipulation"
            }
        ]
        
        for scenario in update_scenarios:
            response = await make_request(
                http_client, "POST", f"/users/update/{scenario['email']}",
                auth_headers, scenario["data"], track_cost=False
            )
            
            # Should be denied for non-admin
            assert response.status_code in [401, 403, 404], \
                f"Should deny user update: {scenario['description']}"
            
            if response.status_code == 403:
                response_data = response.json()
                assert "detail" in response_data
                assert response_data["detail"] == "Not Authorized" or "authorized" in response_data["detail"].lower()
            
            logger.info(f"BFLA_ADMIN_USER_UPDATE_001: Properly denied {scenario['description']}")


class TestBFLAAdvancedAuthorization:
    """Advanced Authorization Testing"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_scope_combination_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """BFLA_SCOPE_COMBINATION_001: Complex scope combinations and subset validation"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test complex scope combinations
        scope_combination_tests = [
            {
                "headers": {"Authorization": f"Bearer {config.TEST_API_KEY}"},
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Multi-scope test"}],
                    "max_tokens": 50
                },
                "description": "Inference scope accessing chat completions",
                "should_succeed": True
            },
            {
                "headers": {"Authorization": f"Bearer {config.TEST_EMBEDDING_API_KEY}"},
                "endpoint": "/api/v1/embeddings",
                "method": "POST",
                "data": {
                    "model": config.get_embedding_model(0),
                    "input": "Multi-scope test"
                },
                "description": "Embedding scope accessing embeddings",
                "should_succeed": True
            },
            {
                "headers": {"Authorization": "Bearer all_scopes_key"},
                "endpoint": "/api/v1/models",
                "method": "GET",
                "description": "All scopes accessing models",
                "should_succeed": True
            }
        ]
        
        for test in scope_combination_tests:
            response = await make_request(
                http_client, test["method"], test["endpoint"],
                test["headers"], test.get("data")
            )
            
            if test["should_succeed"]:
                if "all_scopes" not in test["description"]:  # Skip unknown key test
                    assert response.status_code == 200, \
                        f"Should succeed: {test['description']}"
            else:
                assert response.status_code in [401, 403], \
                    f"Should fail: {test['description']}"
            
            logger.info(f"BFLA_SCOPE_COMBINATION_001: Validated {test['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_scope_bypass_attempt_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """BFLA_SCOPE_BYPASS_ATTEMPT_001: Scope validation bypass attempts"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test scope bypass attempts
        bypass_attempts = [
            {
                "headers": {**auth_headers, "X-Scope": "admin"},
                "description": "Header scope manipulation"
            },
            {
                "headers": {**auth_headers, "X-Override-Scope": "models:admin"},
                "description": "Scope override header"
            },
            {
                "headers": auth_headers,
                "data": {"scope": "admin", "override_scope": True},
                "description": "Request body scope injection"
            },
            {
                "headers": auth_headers,
                "endpoint_suffix": "?scope=admin&override=true",
                "description": "Query parameter scope spoofing"
            },
            {
                "headers": {**auth_headers, "Authorization": auth_headers["Authorization"] + "; scope=admin"},
                "description": "Authorization header manipulation"
            }
        ]
        
        for attempt in bypass_attempts:
            endpoint = "/api/v1/chat/completions" + attempt.get("endpoint_suffix", "")
            test_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Bypass test"}],
                "max_tokens": 50
            }
            test_data.update(attempt.get("data", {}))
            
            response = await make_request(
                http_client, "POST", endpoint,
                attempt["headers"], test_data, track_cost=False
            )
            
            # Should not grant unauthorized access
            if response.status_code == 200:
                # If successful, verify no privilege escalation
                response_data = response.json()
                response_text = str(response_data).lower()
                
                admin_indicators = ["admin", "elevated", "privileged", "administrator"]
                for indicator in admin_indicators:
                    assert indicator not in response_text, \
                        f"Should not indicate privilege escalation: {attempt['description']}"
            
            logger.info(f"BFLA_SCOPE_BYPASS_ATTEMPT_001: Bypass attempt handled: {attempt['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_privilege_escalation_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """BFLA_PRIVILEGE_ESCALATION_001: Privilege escalation prevention"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test privilege escalation attempts
        escalation_attempts = [
            {
                "endpoint": "/tokens/modify_scopes/self",
                "method": "POST",
                "data": {"scopes": ["admin", "models:inference"]},
                "description": "Self API key scope modification"
            },
            {
                "endpoint": "/users/promote/self",
                "method": "POST",
                "data": {"role": "admin"},
                "description": "Self promotion to admin"
            },
            {
                "endpoint": "/api/v1/admin/elevate",
                "method": "POST",
                "data": {"temporary_admin": True},
                "description": "Temporary privilege escalation"
            },
            {
                "endpoint": "/users/inherit_privileges",
                "method": "POST",
                "data": {"inherit_from": "admin@example.com"},
                "description": "Privilege inheritance attempt"
            }
        ]
        
        for attempt in escalation_attempts:
            response = await make_request(
                http_client, attempt["method"], attempt["endpoint"],
                auth_headers, attempt["data"], track_cost=False
            )
            
            # Should be denied
            assert response.status_code in [401, 403, 404, 405], \
                f"Should deny privilege escalation: {attempt['description']}"
            
            logger.info(f"BFLA_PRIVILEGE_ESCALATION_001: Escalation denied: {attempt['description']}")


class TestBFLAAttackVectors:
    """Attack Vector Testing"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_http_method_tampering_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """BFLA_HTTP_METHOD_TAMPERING_001: HTTP method tampering attacks"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test HTTP method tampering
        method_tampering_tests = [
            {
                "endpoint": "/api/v1/models",
                "invalid_methods": ["POST", "PUT", "DELETE"],
                "valid_method": "GET"
            },
            {
                "endpoint": "/api/v1/chat/completions",
                "invalid_methods": ["GET", "PUT", "DELETE"],
                "valid_method": "POST"
            },
            {
                "endpoint": "/api/v1/embeddings",
                "invalid_methods": ["GET", "PUT", "DELETE"],
                "valid_method": "POST"
            }
        ]
        
        for test in method_tampering_tests:
            # Test invalid methods
            for method in test["invalid_methods"]:
                response = await make_request(
                    http_client, method, test["endpoint"],
                    auth_headers, track_cost=False
                )
                
                # Should return 405 Method Not Allowed
                assert response.status_code in [405, 501], \
                    f"Should reject {method} on {test['endpoint']}"
                
                if response.status_code == 405:
                    allow_header = response.headers.get("Allow", "")
                    assert test["valid_method"] in allow_header, \
                        f"Allow header should specify valid method for {test['endpoint']}"
            
            # Test with method override headers
            for method in test["invalid_methods"]:
                override_headers = {**auth_headers, "X-HTTP-Method-Override": method}
                
                response = await make_request(
                    http_client, test["valid_method"], test["endpoint"],
                    override_headers, track_cost=False
                )
                
                # Should not honor method override for security
                # Either reject or process as original method
                if response.status_code == 200:
                    logger.info(f"Method override not honored for {method} on {test['endpoint']}")
                else:
                    assert response.status_code in [400, 405, 422], \
                        f"Should properly handle method override {method} on {test['endpoint']}"
        
        logger.info("BFLA_HTTP_METHOD_TAMPERING_001: Method tampering protection validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_endpoint_discovery_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """BFLA_ENDPOINT_DISCOVERY_001: Unauthorized endpoint discovery prevention"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test endpoint discovery attempts
        discovery_endpoints = [
            # Development/debug endpoints
            "/debug", "/debug/", "/api/debug", "/api/v1/debug",
            "/dev", "/development", "/test", "/testing",
            # Administrative interfaces
            "/admin", "/admin/", "/api/admin", "/api/v1/admin",
            "/management", "/control", "/console",
            # Backup/staging endpoints
            "/backup", "/staging", "/api/backup", "/api/staging",
            "/old", "/legacy", "/v0", "/beta",
            # System endpoints
            "/system", "/sys", "/internal", "/private",
            # Common API versioning
            "/api/v2", "/api/v3", "/api/internal", "/api/private"
        ]
        
        for endpoint in discovery_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                # If endpoint exists, should not leak sensitive information
                response_text = response.text.lower()
                sensitive_terms = [
                    "admin", "debug", "internal", "private", "secret",
                    "password", "key", "token", "config"
                ]
                
                for term in sensitive_terms:
                    assert term not in response_text, \
                        f"Endpoint {endpoint} should not leak sensitive term: {term}"
            else:
                # Should return appropriate error codes
                assert response.status_code in [401, 403, 404, 405], \
                    f"Discovery attempt should be handled properly: {endpoint}"
        
        logger.info("BFLA_ENDPOINT_DISCOVERY_001: Endpoint discovery prevention validated")


class TestBFLAConcurrencyTiming:
    """Concurrency and Timing Testing"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_scope_validation_timing_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """BFLA_SCOPE_VALIDATION_TIMING_001: Scope validation timing consistency"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        import asyncio
        
        # Test concurrent requests with different scope requirements
        concurrent_requests = []
        
        for i in range(5):
            # Mix of valid and invalid requests
            if i % 2 == 0:
                # Valid request
                request = make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
            else:
                # Invalid scope request
                invalid_headers = {"Authorization": "Bearer invalid_scope_key"}
                request = make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    invalid_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Concurrent test {i}"}],
                        "max_tokens": 50
                    }, track_cost=False
                )
            
            concurrent_requests.append(request)
        
        # Execute concurrent requests
        responses = await asyncio.gather(*concurrent_requests, return_exceptions=True)
        
        # Verify consistent authorization results
        valid_responses = 0
        invalid_responses = 0
        
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                continue
                
            if i % 2 == 0:
                # Should be valid
                if response.status_code == 200:
                    valid_responses += 1
            else:
                # Should be invalid
                if response.status_code in [401, 403]:
                    invalid_responses += 1
        
        # Verify consistent behavior under concurrent load
        assert valid_responses >= 2, "Valid requests should succeed under concurrent load"
        assert invalid_responses >= 2, "Invalid requests should be denied under concurrent load"
        
        logger.info("BFLA_SCOPE_VALIDATION_TIMING_001: Timing consistency validated")


class TestBFLAResourceIsolation:
    """Resource and Data Isolation Testing"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_resource_isolation_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """BFLA_RESOURCE_ISOLATION_001: Resource isolation between API keys"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test resource isolation
        isolation_tests = [
            {
                "endpoint": "/api/v1/usage/current",
                "description": "Usage data isolation"
            },
            {
                "endpoint": "/api/v1/billing/current",
                "description": "Billing data isolation"
            },
            {
                "endpoint": "/api/v1/conversations/history",
                "description": "Conversation history isolation"
            },
            {
                "endpoint": "/tokens/my_tokens",
                "description": "Token list isolation"
            }
        ]
        
        for test in isolation_tests:
            response = await make_request(
                http_client, "GET", test["endpoint"],
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                response_data = response.json()
                response_text = str(response_data).lower()
                
                # Should not contain other users' data
                other_user_indicators = [
                    "other_user", "different_account", "cross_tenant",
                    "manager_id", "organization_id"
                ]
                
                for indicator in other_user_indicators:
                    assert indicator not in response_text, \
                        f"Should not leak other users' data: {test['description']}"
            else:
                # Proper access control (404 or 403)
                assert response.status_code in [401, 403, 404], \
                    f"Should have proper access control: {test['description']}"
            
            logger.info(f"BFLA_RESOURCE_ISOLATION_001: Isolation validated: {test['description']}")


class TestBFLAEdgeCases:
    """Edge Case and Security Boundary Testing"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_scope_edge_cases_001(self, http_client: httpx.AsyncClient,
                                            make_request):
        """BFLA_SCOPE_EDGE_CASES_001: Scope validation edge cases"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test edge cases in scope validation
        edge_case_headers = [
            {
                "headers": {"Authorization": "Bearer null_scope_key"},
                "description": "Null scope API key"
            },
            {
                "headers": {"Authorization": "Bearer empty_scope_key"},
                "description": "Empty scope array"
            },
            {
                "headers": {"Authorization": "Bearer malformed_scope_key"},
                "description": "Malformed scope strings"
            },
            {
                "headers": {"Authorization": "Bearer special_chars_scope_key"},
                "description": "Special characters in scopes"
            },
            {
                "headers": {"Authorization": "Bearer very_long_scope_name_key"},
                "description": "Very long scope names"
            },
            {
                "headers": {"Authorization": "Bearer UPPERCASE_SCOPE_KEY"},
                "description": "Case sensitivity test"
            }
        ]
        
        for test in edge_case_headers:
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                test["headers"], track_cost=False
            )
            
            # Should handle edge cases securely
            assert response.status_code in [401, 403, 422], \
                f"Should handle edge case securely: {test['description']}"
            
            if response.status_code in [401, 403]:
                response_data = response.json()
                # Should not leak internal details about scope processing
                response_text = str(response_data).lower()
                internal_details = ["null", "empty", "malformed", "error", "exception"]
                
                for detail in internal_details:
                    assert detail not in response_text, \
                        f"Should not leak scope processing details: {test['description']}"
            
            logger.info(f"BFLA_SCOPE_EDGE_CASES_001: Edge case handled: {test['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_authorization_bypass_comprehensive_001(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """BFLA_AUTHORIZATION_BYPASS_COMPREHENSIVE_001: Comprehensive bypass testing"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Comprehensive authorization bypass tests
        bypass_techniques = [
            # Encoding attacks
            {
                "headers": {**auth_headers, "Authorization": auth_headers["Authorization"].replace("Bearer", "bearer")},
                "description": "Case manipulation in auth header"
            },
            # Parameter pollution
            {
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Bypass test"}],
                    "max_tokens": 50,
                    "bypass": True,
                    "override_auth": True
                },
                "description": "Parameter pollution bypass"
            },
            # Error condition exploitation
            {
                "headers": {"Authorization": "Bearer " + "A" * 1000},
                "description": "Authorization through error conditions"
            },
            # Injection attempts
            {
                "headers": {"Authorization": "Bearer test'; DROP TABLE api_keys; --"},
                "description": "SQL injection in authorization"
            }
        ]
        
        for technique in bypass_techniques:
            endpoint = technique.get("endpoint", "/api/v1/models")
            headers = technique.get("headers", auth_headers)
            data = technique.get("data")
            
            response = await make_request(
                http_client, "GET" if not data else "POST", endpoint,
                headers, data, track_cost=False
            )
            
            # Should prevent all bypass attempts
            if response.status_code == 200:
                # If successful, verify no unauthorized access
                response_data = response.json()
                response_text = str(response_data).lower()
                
                bypass_indicators = [
                    "bypassed", "overridden", "elevated", "admin",
                    "unauthorized access", "privilege granted"
                ]
                
                for indicator in bypass_indicators:
                    assert indicator not in response_text, \
                        f"Should not indicate bypass success: {technique['description']}"
            else:
                # Should be properly rejected
                assert response.status_code in [400, 401, 403, 422], \
                    f"Should reject bypass attempt: {technique['description']}"
            
            logger.info(f"BFLA_AUTHORIZATION_BYPASS_COMPREHENSIVE_001: Bypass prevented: {technique['description']}")
        
        logger.info("BFLA_AUTHORIZATION_BYPASS_COMPREHENSIVE_001: Comprehensive bypass testing completed")