# Section 7.3 - OWASP API5:2023 Broken Function Level Authorization Tests - Basic Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API5_2023 - Broken Function Level Authorization.md

import pytest
import httpx
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures


class TestOWASPAPI5FunctionAuthorization:
    """API5:2023 - Broken Function Level Authorization tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api5_admin_function_access_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 admin_auth_headers: Dict[str, str],
                                                 make_request):
        """API5_ADMIN_FUNCTION_001: CRITICAL - Admin function access with regular scope"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test admin-only functions with regular scope
        admin_functions = [
            # Administrative endpoints
            {
                "method": "GET",
                "endpoint": "/api/v1/admin/users",
                "description": "Admin user management"
            },
            {
                "method": "DELETE", 
                "endpoint": "/api/v1/admin/cache",
                "description": "Admin cache management"
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/admin/models/reload",
                "description": "Admin model reload"
            },
            # User management functions
            {
                "method": "GET",
                "endpoint": "/users/all",
                "description": "List all users"
            },
            {
                "method": "PUT",
                "endpoint": "/users/admin@example.com/role",
                "description": "Modify user roles",
                "data": {"role": "admin"}
            },
            {
                "method": "DELETE",
                "endpoint": "/users/test@example.com",
                "description": "Delete users"
            },
            # Token management functions
            {
                "method": "GET",
                "endpoint": "/tokens/all",
                "description": "List all tokens"
            },
            {
                "method": "DELETE",
                "endpoint": "/tokens/revoke_all",
                "description": "Revoke all tokens"
            },
            # System configuration functions
            {
                "method": "GET",
                "endpoint": "/api/v1/config/internal",
                "description": "System configuration access"
            },
            {
                "method": "PUT",
                "endpoint": "/api/v1/config/rate_limits",
                "description": "Rate limit configuration",
                "data": {"requests_per_minute": 1000}
            }
        ]
        
        for func in admin_functions:
            # Test with regular scope (should be denied)
            response = await make_request(
                http_client, func["method"], func["endpoint"],
                auth_headers, func.get("data"), track_cost=False
            )
            
            # Should be denied for regular scope
            assert response.status_code in [401, 403, 404, 405], \
                f"Regular scope should not access admin function: {func['description']}"
            
            logger.info(f"Admin function properly denied for regular scope: {func['description']}")
            
            # Test with admin scope (verify proper access control exists)
            if admin_auth_headers:
                admin_response = await make_request(
                    http_client, func["method"], func["endpoint"],
                    admin_auth_headers, func.get("data"), track_cost=False
                )
                
                # Should either work or return appropriate error for non-existent endpoints
                if admin_response.status_code not in [200, 201, 204]:
                    assert admin_response.status_code in [404, 405, 501], \
                        f"Admin scope should have appropriate response: {func['description']}"
        
        logger.info("API5_ADMIN_FUNCTION_001: Admin function authorization validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api5_method_tampering_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """API5_METHOD_TAMPERING_001: HTTP method tampering attacks"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test method tampering on sensitive endpoints
        method_tests = [
            # Chat completions endpoint
            {
                "endpoint": "/api/v1/chat/completions",
                "allowed_methods": ["POST"],
                "forbidden_methods": ["GET", "PUT", "DELETE", "PATCH"],
                "test_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Method test"}],
                    "max_tokens": 50
                }
            },
            # Models endpoint  
            {
                "endpoint": "/api/v1/models",
                "allowed_methods": ["GET"],
                "forbidden_methods": ["POST", "PUT", "DELETE", "PATCH"],
                "test_data": None
            },
            # Embeddings endpoint
            {
                "endpoint": "/api/v1/embeddings", 
                "allowed_methods": ["POST"],
                "forbidden_methods": ["GET", "PUT", "DELETE", "PATCH"],
                "test_data": {
                    "model": config.get_embedding_model(0),
                    "input": "Method test"
                }
            }
        ]
        
        for test in method_tests:
            # Test allowed methods
            for method in test["allowed_methods"]:
                response = await make_request(
                    http_client, method, test["endpoint"],
                    auth_headers, test["test_data"], track_cost=False
                )
                
                # Should be accepted (200) or have proper validation error (422)
                assert response.status_code in [200, 422], \
                    f"Allowed method {method} should be accepted on {test['endpoint']}"
            
            # Test forbidden methods
            for method in test["forbidden_methods"]:
                response = await make_request(
                    http_client, method, test["endpoint"],
                    auth_headers, test["test_data"], track_cost=False
                )
                
                # Should be rejected with method not allowed
                assert response.status_code in [405, 501], \
                    f"Forbidden method {method} should be rejected on {test['endpoint']}"
                
                # Verify proper Allow header is present
                if response.status_code == 405:
                    allow_header = response.headers.get("Allow", "")
                    for allowed_method in test["allowed_methods"]:
                        assert allowed_method in allow_header, \
                            f"Allow header should specify allowed methods for {test['endpoint']}"
        
        logger.info("API5_METHOD_TAMPERING_001: HTTP method tampering protection validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api5_function_discovery_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """API5_FUNCTION_DISCOVERY_001: Unauthorized function discovery prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test discovery of hidden/admin functions
        discovery_attempts = [
            # Common admin paths
            "/admin", "/admin/", "/api/admin", "/api/v1/admin",
            # Debug/development endpoints
            "/debug", "/dev", "/test", "/api/debug", 
            "/api/v1/debug", "/api/internal",
            # Configuration endpoints
            "/config", "/settings", "/api/config", "/api/settings",
            # Monitoring endpoints  
            "/status", "/health/detailed", "/metrics", "/stats",
            "/api/status", "/api/metrics", "/api/stats",
            # User management
            "/users", "/accounts", "/api/users", "/api/accounts",
            # Token management
            "/tokens", "/keys", "/api/tokens", "/api/keys",
            # System functions
            "/system", "/sys", "/api/system", "/restart", "/reload",
            # Database functions
            "/db", "/database", "/api/db", "/schema",
            # File system functions
            "/files", "/uploads", "/downloads", "/api/files",
            # Common backup/export functions
            "/backup", "/export", "/dump", "/api/backup"
        ]
        
        for path in discovery_attempts:
            # Test GET request
            response = await make_request(
                http_client, "GET", path,
                auth_headers, track_cost=False
            )
            
            # Should not expose unauthorized functions
            if response.status_code == 200:
                # If endpoint exists, should not leak sensitive information
                response_text = response.text.lower()
                sensitive_terms = [
                    "admin", "password", "secret", "key", "token",
                    "database", "config", "internal", "debug"
                ]
                
                for term in sensitive_terms:
                    assert term not in response_text, \
                        f"Endpoint {path} should not leak sensitive information: {term}"
            else:
                # Should return appropriate error codes
                assert response.status_code in [401, 403, 404, 405], \
                    f"Discovery attempt should be properly handled: {path}"
        
        logger.info("API5_FUNCTION_DISCOVERY_001: Function discovery prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api5_vertical_privilege_escalation_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """API5_VERTICAL_ESCALATION_001: Vertical privilege escalation prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test vertical privilege escalation attempts
        escalation_attempts = [
            # Parameter pollution for privilege escalation
            {
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test"}],
                    "max_tokens": 50,
                    "admin": True,
                    "privilege": "admin",
                    "role": "administrator",
                    "is_admin": True,
                    "user_type": "admin"
                },
                "description": "Parameter pollution privilege escalation"
            },
            # Header manipulation
            {
                "endpoint": "/api/v1/models",
                "method": "GET", 
                "headers": {
                    "X-Admin": "true",
                    "X-Role": "admin",
                    "X-Privilege": "elevated",
                    "X-User-Type": "administrator"
                },
                "description": "Header-based privilege escalation"
            },
            # Function name manipulation
            {
                "endpoint": "/api/v1/chat/completions/admin",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Admin function test"}],
                    "max_tokens": 50
                },
                "description": "Function name privilege escalation"
            },
            # Query parameter escalation
            {
                "endpoint": "/api/v1/models?admin=true&role=admin",
                "method": "GET",
                "description": "Query parameter privilege escalation" 
            }
        ]
        
        for attempt in escalation_attempts:
            # Merge custom headers with auth headers
            test_headers = dict(auth_headers)
            if "headers" in attempt:
                test_headers.update(attempt["headers"])
            
            response = await make_request(
                http_client, attempt["method"], attempt["endpoint"],
                test_headers, attempt.get("data"), track_cost=False
            )
            
            # Should not grant elevated privileges
            if response.status_code == 200:
                # If request succeeds, verify no privilege escalation occurred
                response_data = response.json() if response.content else {}
                response_text = str(response_data).lower()
                
                # Should not contain indicators of elevated access
                escalation_indicators = [
                    "admin granted", "privilege elevated", "administrator access",
                    "elevated permissions", "admin mode", "super user"
                ]
                
                for indicator in escalation_indicators:
                    assert indicator not in response_text, \
                        f"Response should not indicate privilege escalation: {attempt['description']}"
            else:
                # Should be properly rejected
                assert response.status_code in [400, 401, 403, 404, 422], \
                    f"Privilege escalation attempt should be rejected: {attempt['description']}"
            
            logger.info(f"Vertical escalation attempt properly handled: {attempt['description']}")
        
        logger.info("API5_VERTICAL_ESCALATION_001: Vertical privilege escalation prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api5_horizontal_privilege_escalation_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """API5_HORIZONTAL_ESCALATION_001: Horizontal privilege escalation prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test horizontal privilege escalation (accessing other users' resources)
        horizontal_tests = [
            # Other user data access attempts
            {
                "endpoint": "/users/other_user@example.com",
                "method": "GET",
                "description": "Other user profile access"
            },
            {
                "endpoint": "/api/v1/usage/other_user@example.com",
                "method": "GET", 
                "description": "Other user usage data"
            },
            {
                "endpoint": "/tokens/user/other_user@example.com",
                "method": "GET",
                "description": "Other user tokens"
            },
            # Resource ID manipulation
            {
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test"}],
                    "max_tokens": 50,
                    "user_id": "other_user@example.com",
                    "organization_id": "other_org",
                    "account_id": "12345"
                },
                "description": "Resource ID manipulation"
            }
        ]
        
        for test in horizontal_tests:
            response = await make_request(
                http_client, test["method"], test["endpoint"],
                auth_headers, test.get("data"), track_cost=False
            )
            
            # Should not allow access to other users' resources
            if response.status_code == 200:
                # If successful, verify data isolation
                response_data = response.json() if response.content else {}
                
                # Should not contain other users' data
                response_text = str(response_data).lower()
                other_user_indicators = [
                    "other_user", "other_org", "different_user",
                    "account_id", "organization_id"
                ]
                
                # Verify proper data isolation
                if any(indicator in response_text for indicator in other_user_indicators):
                    logger.warning(f"Potential data leakage detected: {test['description']}")
            else:
                # Should be properly denied
                assert response.status_code in [401, 403, 404], \
                    f"Horizontal escalation should be denied: {test['description']}"
            
            logger.info(f"Horizontal escalation test passed: {test['description']}")
        
        logger.info("API5_HORIZONTAL_ESCALATION_001: Horizontal privilege escalation prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api5_function_bypass_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """API5_FUNCTION_BYPASS_001: Function-level authorization bypass attempts"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various bypass techniques
        bypass_attempts = [
            # Path traversal bypass
            {
                "endpoint": "/api/v1/../admin/config",
                "method": "GET",
                "description": "Path traversal bypass"
            },
            {
                "endpoint": "/api/v1/chat/../admin/users",
                "method": "GET", 
                "description": "Relative path bypass"
            },
            # URL encoding bypass
            {
                "endpoint": "/api/v1/%61%64%6d%69%6e/config",  # "admin" URL encoded
                "method": "GET",
                "description": "URL encoding bypass"
            },
            # Double URL encoding
            {
                "endpoint": "/api/v1/%2561%2564%256d%2569%256e/config",
                "method": "GET",
                "description": "Double URL encoding bypass"
            },
            # Case manipulation
            {
                "endpoint": "/API/V1/ADMIN/CONFIG",
                "method": "GET",
                "description": "Case manipulation bypass"
            },
            {
                "endpoint": "/api/v1/Admin/Config",
                "method": "GET",
                "description": "Mixed case bypass"
            },
            # Trailing slash bypass
            {
                "endpoint": "/api/v1/admin/",
                "method": "GET",
                "description": "Trailing slash bypass"
            },
            # HTTP verb override
            {
                "endpoint": "/api/v1/models",
                "method": "POST",
                "headers": {"X-HTTP-Method-Override": "DELETE"},
                "description": "HTTP method override bypass"
            }
        ]
        
        for attempt in bypass_attempts:
            # Merge custom headers if provided
            test_headers = dict(auth_headers)
            if "headers" in attempt:
                test_headers.update(attempt["headers"])
            
            response = await make_request(
                http_client, attempt["method"], attempt["endpoint"],
                test_headers, track_cost=False
            )
            
            # Bypass attempts should be denied or handled safely
            if response.status_code == 200:
                # If successful, should not provide unauthorized access
                response_data = response.json() if response.content else {}
                response_text = str(response_data).lower()
                
                # Should not leak administrative or sensitive information
                sensitive_data = [
                    "admin", "configuration", "password", "secret",
                    "internal", "debug", "system"
                ]
                
                for term in sensitive_data:
                    if term in response_text:
                        logger.warning(f"Potential information disclosure: {attempt['description']}")
            else:
                # Should be properly rejected
                assert response.status_code in [400, 401, 403, 404, 405], \
                    f"Bypass attempt should be rejected: {attempt['description']}"
            
            logger.info(f"Function bypass attempt handled: {attempt['description']}")
        
        logger.info("API5_FUNCTION_BYPASS_001: Function authorization bypass prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api5_scope_verification_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             embedding_auth_headers: Dict[str, str],
                                             make_request):
        """API5_SCOPE_VERIFICATION_001: Comprehensive scope-based function authorization"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test scope-based function access control
        scope_tests = [
            # Chat scope tests
            {
                "scope": "chat",
                "headers": auth_headers,
                "allowed_functions": [
                    {"endpoint": "/api/v1/chat/completions", "method": "POST"},
                    {"endpoint": "/api/v1/models", "method": "GET"}
                ],
                "denied_functions": [
                    {"endpoint": "/api/v1/embeddings", "method": "POST"},
                    {"endpoint": "/admin/chat/settings", "method": "GET"},
                    {"endpoint": "/api/v1/chat/admin", "method": "GET"}
                ]
            },
            # Embedding scope tests
            {
                "scope": "embedding", 
                "headers": embedding_auth_headers,
                "allowed_functions": [
                    {"endpoint": "/api/v1/embeddings", "method": "POST"},
                    {"endpoint": "/api/v1/models", "method": "GET"}
                ],
                "denied_functions": [
                    {"endpoint": "/api/v1/chat/completions", "method": "POST"},
                    {"endpoint": "/admin/embedding/settings", "method": "GET"},
                    {"endpoint": "/api/v1/embeddings/admin", "method": "GET"}
                ]
            }
        ]
        
        for test in scope_tests:
            # Test allowed functions
            for func in test["allowed_functions"]:
                test_data = None
                if "chat/completions" in func["endpoint"]:
                    test_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Scope test"}],
                        "max_tokens": 50
                    }
                elif "embeddings" in func["endpoint"]:
                    test_data = {
                        "model": config.get_embedding_model(0),
                        "input": "Scope test"
                    }
                
                response = await make_request(
                    http_client, func["method"], func["endpoint"],
                    test["headers"], test_data
                )
                
                # Should be allowed for this scope
                if test["scope"] == "chat" and "chat/completions" in func["endpoint"]:
                    assert response.status_code == 200, \
                        f"Chat scope should allow chat completions"
                elif test["scope"] == "embedding" and "embeddings" in func["endpoint"]:
                    assert response.status_code == 200, \
                        f"Embedding scope should allow embeddings"
                elif "models" in func["endpoint"]:
                    assert response.status_code == 200, \
                        f"Models endpoint should be accessible to all scopes"
            
            # Test denied functions
            for func in test["denied_functions"]:
                test_data = None
                if "chat/completions" in func["endpoint"]:
                    test_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Scope test"}],
                        "max_tokens": 50
                    }
                elif "embeddings" in func["endpoint"]:
                    test_data = {
                        "model": config.get_embedding_model(0),
                        "input": "Scope test"
                    }
                
                response = await make_request(
                    http_client, func["method"], func["endpoint"],
                    test["headers"], test_data, track_cost=False
                )
                
                # Should be denied for this scope
                assert response.status_code in [401, 403, 404], \
                    f"{test['scope']} scope should not access {func['endpoint']}"
        
        logger.info("API5_SCOPE_VERIFICATION_001: Scope-based function authorization validated")


class TestBFLALLMFunctionAuthorization:
    """LLM Function Authorization tests per design document"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_llm_inference_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """BFLA_LLM_INFERENCE_001: Chat completions with insufficient scopes"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test chat completions with various insufficient scopes
        insufficient_scope_scenarios = [
            {
                "headers": {"Authorization": f"Bearer {config.EMBEDDING_API_KEY}"},
                "description": "API key with only models:embedding scope"
            },
            {
                "headers": {"Authorization": f"Bearer {config.ADMIN_API_KEY}"},
                "description": "API key with only admin scope"
            },
            {
                "headers": {"Authorization": "Bearer invalid_key_no_scopes"},
                "description": "API key with no relevant scopes"
            },
            {
                "headers": {"Authorization": "Bearer custom_invalid_scope_key"},
                "description": "API key with custom/invalid scopes"
            }
        ]
        
        for scenario in insufficient_scope_scenarios:
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test insufficient scope"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                scenario["headers"], request_data, track_cost=False
            )
            
            # Should fail with 403 Forbidden or 401 Unauthorized
            assert response.status_code in [401, 403], \
                f"Should deny access for {scenario['description']}"
            
            if response.status_code == 403:
                response_data = response.json()
                assert "detail" in response_data
                assert response_data["detail"] == "Not Authorized" or "authorized" in response_data["detail"].lower()
            
            logger.info(f"BFLA_LLM_INFERENCE_001: Properly denied {scenario['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_llm_embedding_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """BFLA_LLM_EMBEDDING_001: Embeddings with insufficient scopes"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test embeddings with various insufficient scopes
        insufficient_scope_scenarios = [
            {
                "headers": {"Authorization": f"Bearer {config.API_KEY}"},
                "description": "API key with only models:inference scope"
            },
            {
                "headers": {"Authorization": f"Bearer {config.ADMIN_API_KEY}"},
                "description": "API key with only admin scope"
            },
            {
                "headers": {"Authorization": "Bearer no_model_scopes_key"},
                "description": "API key with no model-related scopes"
            },
            {
                "headers": {"Authorization": "Bearer malformed_scope_key"},
                "description": "API key with malformed scope values"
            }
        ]
        
        for scenario in insufficient_scope_scenarios:
            request_data = {
                "model": config.get_embedding_model(0),
                "input": "Test insufficient embedding scope"
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                scenario["headers"], request_data, track_cost=False
            )
            
            # Should fail with 403 Forbidden or 401 Unauthorized
            assert response.status_code in [401, 403], \
                f"Should deny embedding access for {scenario['description']}"
            
            if response.status_code == 403:
                response_data = response.json()
                assert "detail" in response_data
                assert response_data["detail"] == "Not Authorized" or "authorized" in response_data["detail"].lower()
            
            logger.info(f"BFLA_LLM_EMBEDDING_001: Properly denied {scenario['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_bfla_models_list_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       make_request):
        """BFLA_MODELS_LIST_001: Models endpoint accessibility and filtering"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test models endpoint with various scopes
        scope_scenarios = [
            {
                "headers": {"Authorization": f"Bearer {config.API_KEY}"},
                "description": "API key with models:inference scope"
            },
            {
                "headers": {"Authorization": f"Bearer {config.EMBEDDING_API_KEY}"},
                "description": "API key with models:embedding scope"
            },
            {
                "headers": {"Authorization": f"Bearer {config.ADMIN_API_KEY}"},
                "description": "API key with admin scope"
            },
            {
                "headers": {"Authorization": "Bearer users_read_only_key"},
                "description": "API key with no model-related scopes"
            }
        ]
        
        for scenario in scope_scenarios:
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                scenario["headers"], track_cost=False
            )
            
            if "users_read_only" in scenario["description"]:
                # Should be denied for keys without model scopes
                assert response.status_code in [401, 403], \
                    f"Should deny models access for {scenario['description']}"
            else:
                # Should succeed for valid API keys
                assert response.status_code == 200, \
                    f"Should allow models access for {scenario['description']}"
                
                response_data = response.json()
                assert "data" in response_data
                assert isinstance(response_data["data"], list)
                
                # Verify model list doesn't expose unauthorized information
                response_text = str(response_data).lower()
                unauthorized_info = ["password", "secret", "internal", "debug", "admin"]
                for info in unauthorized_info:
                    assert info not in response_text, \
                        f"Models list should not expose {info} for {scenario['description']}"
            
            logger.info(f"BFLA_MODELS_LIST_001: Models access validated for {scenario['description']}")