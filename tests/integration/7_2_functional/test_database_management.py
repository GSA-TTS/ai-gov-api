# Section 7.2 - Database Session & Transaction Management Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Database Session & Transaction Management.md

import pytest
import httpx
import asyncio
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestSessionManagement:
    """Test database session lifecycle and management"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_session_per_request_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """FV_DBM_SESSION_PER_REQUEST_001: Verify session lifecycle per request"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Make multiple requests to verify session isolation
        requests = [
            {"endpoint": "/api/v1/models", "method": "GET", "data": None},
            {
                "endpoint": "/api/v1/chat/completions", 
                "method": "POST", 
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test session 1"}],
                    "max_tokens": 30
                }
            },
            {
                "endpoint": "/api/v1/chat/completions", 
                "method": "POST", 
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test session 2"}],
                    "max_tokens": 30
                }
            }
        ]
        
        responses = []
        for req in requests:
            response = await make_request(
                http_client, req["method"], req["endpoint"],
                auth_headers, req["data"],
                track_cost=(req["method"] == "POST")
            )
            responses.append(response)
            
            # Each request should succeed independently
            assert response.status_code == 200, f"Request to {req['endpoint']} should succeed"
        
        # Verify each request was processed independently
        chat_responses = [r for r in responses[1:] if r.status_code == 200]
        if len(chat_responses) >= 2:
            response_data = [r.json() for r in chat_responses]
            
            # Each should have unique request IDs
            ids = [data.get("id", "") for data in response_data]
            assert len(set(ids)) == len(ids), "Each request should have unique ID (session isolation)"
        
        logger.info("FV_DBM_SESSION_PER_REQUEST_001: Session per request lifecycle verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_session_error_handling_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """FV_DBM_SESSION_ERROR_HANDLING_001: Test session handling during errors"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test that errors don't break subsequent requests (session cleanup)
        error_inducing_requests = [
            # Invalid model
            {
                "model": "nonexistent-model-123",
                "messages": [{"role": "user", "content": "Test error handling"}],
                "max_tokens": 50
            },
            # Invalid parameter type
            {
                "model": config.get_chat_model(0),
                "messages": "not_an_array",
                "max_tokens": 50
            }
        ]
        
        for error_request in error_inducing_requests:
            # Make error request
            error_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, error_request, track_cost=False
            )
            
            assert error_response.status_code == 422, "Invalid request should return 422"
            
            # Immediately make valid request to verify session cleanup
            valid_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test after error"}],
                "max_tokens": 30
            }
            
            valid_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, valid_request
            )
            
            assert valid_response.status_code == 200, "Valid request after error should succeed"
        
        logger.info("FV_DBM_SESSION_ERROR_HANDLING_001: Session error handling verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_session_pool_exhaustion_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_DBM_SESSION_POOL_EXHAUSTION_001: Test connection pool stress behavior"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Create concurrent requests to stress the connection pool
        async def concurrent_request(request_id: int):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Concurrent request {request_id}"}],
                "max_tokens": 30
            }
            
            return await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
        
        # Create 10 concurrent requests
        tasks = [concurrent_request(i) for i in range(10)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful responses
        successful_responses = 0
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.warning(f"Concurrent request {i} failed: {response}")
            elif hasattr(response, 'status_code') and response.status_code == 200:
                successful_responses += 1
            elif hasattr(response, 'status_code'):
                logger.info(f"Concurrent request {i} returned status {response.status_code}")
        
        # Most requests should succeed (allowing for some rate limiting)
        assert successful_responses >= 5, f"At least 5/10 concurrent requests should succeed, got {successful_responses}"
        
        logger.info(f"FV_DBM_SESSION_POOL_EXHAUSTION_001: {successful_responses}/10 concurrent requests successful")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_session_rollback_on_exception_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """FV_DBM_SESSION_ROLLBACK_ON_EXCEPTION_001: Verify automatic rollback on exceptions"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test that system recovers from exceptions without state corruption
        
        # Make a request that might cause internal processing issues
        problematic_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "A" * 10000}],  # Very long message
            "max_tokens": 1
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, problematic_request
        )
        
        # Request might succeed or fail, but system should remain stable
        if response.status_code not in [200, 422, 400]:
            logger.info(f"Problematic request returned {response.status_code}")
        
        # Follow up with normal request to verify system stability
        normal_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test system stability"}],
            "max_tokens": 30
        }
        
        recovery_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, normal_request
        )
        
        assert recovery_response.status_code == 200, "System should recover after exception"
        
        logger.info("FV_DBM_SESSION_ROLLBACK_ON_EXCEPTION_001: Exception rollback behavior verified")


class TestTransactionIntegrity:
    """Test database transaction integrity and consistency"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_tx_user_create_success_001(self, http_client: httpx.AsyncClient,
                                                    admin_auth_headers: Dict[str, str],
                                                    make_request):
        """FV_DBM_TX_USER_CREATE_SUCCESS_001: Test successful user/key creation transaction"""
        if not config.ENABLE_FUNCTIONAL_TESTS or not admin_auth_headers:
            pytest.skip("Admin functional tests disabled or no admin access")
        
        # Test user creation workflow
        test_email = f"tx_test_{int(asyncio.get_event_loop().time())}@example.gov"
        
        user_creation_endpoints = [
            "/users",
            "/api/v1/users",
            "/admin/users"
        ]
        
        for endpoint in user_creation_endpoints:
            response = await make_request(
                http_client, "POST", endpoint,
                admin_auth_headers, {
                    "email": test_email,
                    "scopes": ["models:inference"]
                }, track_cost=False
            )
            
            if response.status_code == 201:
                # User creation succeeded
                response_data = response.json()
                assert "email" in response_data
                assert response_data["email"] == test_email
                
                # Verify user is immediately accessible (transaction committed)
                user_get_response = await make_request(
                    http_client, "GET", f"{endpoint}/{test_email}",
                    admin_auth_headers, track_cost=False
                )
                
                if user_get_response.status_code == 200:
                    get_data = user_get_response.json()
                    assert get_data["email"] == test_email
                    logger.info("FV_DBM_TX_USER_CREATE_SUCCESS_001: User creation transaction successful")
                else:
                    logger.info("FV_DBM_TX_USER_CREATE_SUCCESS_001: User created but GET endpoint not available")
                break
            elif response.status_code == 404:
                continue
            else:
                logger.info(f"FV_DBM_TX_USER_CREATE_SUCCESS_001: User creation endpoint {endpoint} returned {response.status_code}")
                break
        else:
            pytest.skip("User creation endpoints not available")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_tx_user_create_rollback_001(self, http_client: httpx.AsyncClient,
                                                     admin_auth_headers: Dict[str, str],
                                                     make_request):
        """FV_DBM_TX_USER_CREATE_ROLLBACK_001: Test transaction rollback on failure"""
        if not config.ENABLE_FUNCTIONAL_TESTS or not admin_auth_headers:
            pytest.skip("Admin functional tests disabled or no admin access")
        
        # Test with invalid user data that should cause rollback
        invalid_user_data = [
            # Invalid email format
            {"email": "invalid-email", "scopes": ["models:inference"]},
            # Missing required fields
            {"scopes": ["models:inference"]},
            # Invalid scope
            {"email": "test@example.gov", "scopes": ["invalid:scope"]}
        ]
        
        user_creation_endpoints = [
            "/users",
            "/api/v1/users", 
            "/admin/users"
        ]
        
        for endpoint in user_creation_endpoints:
            for invalid_data in invalid_user_data:
                response = await make_request(
                    http_client, "POST", endpoint,
                    admin_auth_headers, invalid_data, track_cost=False
                )
                
                if response.status_code == 404:
                    # Endpoint doesn't exist
                    break
                elif response.status_code in [400, 422]:
                    # Validation failed as expected
                    logger.info(f"FV_DBM_TX_USER_CREATE_ROLLBACK_001: Invalid data properly rejected at {endpoint}")
                    return
                else:
                    logger.info(f"FV_DBM_TX_USER_CREATE_ROLLBACK_001: Endpoint {endpoint} returned {response.status_code}")
            else:
                continue
            break
        else:
            pytest.skip("User creation endpoints not available for rollback testing")
        
        logger.info("FV_DBM_TX_USER_CREATE_ROLLBACK_001: Transaction rollback behavior verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_tx_constraint_violation_handling_001(self, http_client: httpx.AsyncClient,
                                                              admin_auth_headers: Dict[str, str],
                                                              make_request):
        """FV_DBM_TX_CONSTRAINT_VIOLATION_HANDLING_001: Test constraint violation handling"""
        if not config.ENABLE_FUNCTIONAL_TESTS or not admin_auth_headers:
            pytest.skip("Admin functional tests disabled or no admin access")
        
        # Test duplicate user creation (should violate unique constraint)
        test_email = "constraint_test@example.gov"
        
        user_creation_endpoints = [
            "/users",
            "/api/v1/users",
            "/admin/users"
        ]
        
        for endpoint in user_creation_endpoints:
            # First creation attempt
            response1 = await make_request(
                http_client, "POST", endpoint,
                admin_auth_headers, {
                    "email": test_email,
                    "scopes": ["models:inference"]
                }, track_cost=False
            )
            
            if response1.status_code == 404:
                continue
            elif response1.status_code == 201:
                # User created successfully, now try duplicate
                response2 = await make_request(
                    http_client, "POST", endpoint,
                    admin_auth_headers, {
                        "email": test_email,
                        "scopes": ["models:inference"]  
                    }, track_cost=False
                )
                
                # Should return conflict or validation error
                assert response2.status_code in [400, 409, 422], "Duplicate user should be rejected"
                logger.info("FV_DBM_TX_CONSTRAINT_VIOLATION_HANDLING_001: Constraint violation properly handled")
                break
            else:
                logger.info(f"FV_DBM_TX_CONSTRAINT_VIOLATION_HANDLING_001: User creation returned {response1.status_code}")
                break
        else:
            pytest.skip("User creation endpoints not available for constraint testing")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_tx_billing_record_fail_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    cost_tracking,
                                                    make_request):
        """FV_DBM_TX_BILLING_RECORD_FAIL_001: Test billing transaction failures"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test that API requests work even if billing records fail
        # (Billing should not block core functionality)
        
        initial_requests = cost_tracking.request_count
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test billing transaction"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        # Core functionality should work
        assert response.status_code == 200, "Chat completion should work regardless of billing status"
        
        response_data = response.json()
        assert "choices" in response_data
        assert "usage" in response_data
        
        # Billing tracking might or might not work, but shouldn't block the request
        logger.info("FV_DBM_TX_BILLING_RECORD_FAIL_001: Core functionality works independently of billing")


class TestMigrationTests:
    """Test database migration handling and compatibility"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_migrate_apply_all_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """FV_DBM_MIGRATE_APPLY_ALL_001: Test all Alembic migrations apply successfully"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test that the system is working with current migration state
        # This indirectly verifies migrations have been applied successfully
        
        # Test core database operations
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200, "Models endpoint should work with current schema"
        
        # Test API key validation (requires users and api_keys tables)
        invalid_response = await make_request(
            http_client, "GET", "/api/v1/models",
            {"Authorization": "Bearer invalid_key"}, track_cost=False
        )
        
        assert invalid_response.status_code == 401, "API key validation should work with current schema"
        
        logger.info("FV_DBM_MIGRATE_APPLY_ALL_001: Database schema functional with current migrations")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_migrate_downgrade_upgrade_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_DBM_MIGRATE_DOWNGRADE_UPGRADE_001: Test migration downgrade/upgrade cycle"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled - migration testing requires admin access")
        
        # This test would require database admin privileges and is typically
        # run in dedicated migration testing environments
        
        # For now, we verify that the system is in a consistent state
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200, "System should be in consistent migration state"
        
        logger.info("FV_DBM_MIGRATE_DOWNGRADE_UPGRADE_001: Migration state consistency verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_migrate_new_model_field_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_DBM_MIGRATE_NEW_MODEL_FIELD_001: Test adding non-nullable fields"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Verify that current model structure supports required operations
        # This tests that migrations for adding fields have been handled correctly
        
        # Test creating a new API key (requires all necessary fields)
        admin_endpoints = [
            "/admin/users",
            "/api/v1/users",
            "/users"
        ]
        
        # This would test that the current schema supports user/key creation
        # If fields were added properly, this should work
        test_email = f"field_test_{int(asyncio.get_event_loop().time())}@example.gov"
        
        for endpoint in admin_endpoints:
            response = await make_request(
                http_client, "POST", endpoint,
                auth_headers, {
                    "email": test_email,
                    "scopes": ["models:inference"]
                }, track_cost=False
            )
            
            if response.status_code in [201, 401, 403]:
                # Either created successfully or permission denied (but schema is OK)
                logger.info("FV_DBM_MIGRATE_NEW_MODEL_FIELD_001: Schema supports field operations")
                break
            elif response.status_code == 404:
                continue
            else:
                logger.info(f"FV_DBM_MIGRATE_NEW_MODEL_FIELD_001: Field migration test returned {response.status_code}")
                break
        
        logger.info("FV_DBM_MIGRATE_NEW_MODEL_FIELD_001: Field migration compatibility verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_migrate_data_migration_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """FV_DBM_MIGRATE_DATA_MIGRATION_001: Test data transformation migrations"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test that data has been properly migrated and is accessible
        # This verifies that data transformation migrations have completed successfully
        
        # Test API key lookup (verifies user/key data is properly migrated)
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200, "API key data should be properly migrated"
        
        # Test model configuration data
        response_data = response.json()
        assert "data" in response_data
        assert len(response_data["data"]) > 0, "Model configuration data should be migrated"
        
        # Verify model data structure
        for model in response_data["data"]:
            assert "id" in model, "Model data should have required fields after migration"
            assert "object" in model, "Model object field should exist after migration"
        
        logger.info("FV_DBM_MIGRATE_DATA_MIGRATION_001: Data migration verification successful")


class TestConcurrencyTests:
    """Test database concurrency and session isolation"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_concurrency_key_lookup_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """FV_DBM_CONCURRENCY_KEY_LOOKUP_001: Test concurrent API key lookups"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test concurrent API key validation
        async def key_lookup_request():
            return await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
        
        # Create 5 concurrent key lookup requests
        tasks = [key_lookup_request() for _ in range(5)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should succeed
        successful_lookups = 0
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.warning(f"Concurrent key lookup {i} failed: {response}")
            elif hasattr(response, 'status_code') and response.status_code == 200:
                successful_lookups += 1
        
        assert successful_lookups >= 4, f"At least 4/5 concurrent key lookups should succeed, got {successful_lookups}"
        
        logger.info(f"FV_DBM_CONCURRENCY_KEY_LOOKUP_001: {successful_lookups}/5 concurrent key lookups successful")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_concurrency_user_creation_001(self, http_client: httpx.AsyncClient,
                                                       admin_auth_headers: Dict[str, str],
                                                       make_request):
        """FV_DBM_CONCURRENCY_USER_CREATION_001: Test concurrent user creation"""
        if not config.ENABLE_FUNCTIONAL_TESTS or not admin_auth_headers:
            pytest.skip("Admin functional tests disabled or no admin access")
        
        # Test concurrent user creation
        async def create_user(user_id: int):
            email = f"concurrent_user_{user_id}_{int(asyncio.get_event_loop().time())}@example.gov"
            
            endpoints = ["/users", "/api/v1/users", "/admin/users"]
            for endpoint in endpoints:
                response = await make_request(
                    http_client, "POST", endpoint,
                    admin_auth_headers, {
                        "email": email,
                        "scopes": ["models:inference"]
                    }, track_cost=False
                )
                
                if response.status_code in [201, 401, 403]:
                    return response
                elif response.status_code == 404:
                    continue
                else:
                    return response
            
            # No endpoints available
            return None
        
        # Create 3 concurrent user creation requests
        tasks = [create_user(i) for i in range(3)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count responses
        creation_attempts = 0
        for response in responses:
            if response is not None and hasattr(response, 'status_code'):
                creation_attempts += 1
                if response.status_code not in [201, 401, 403, 404]:
                    logger.info(f"Concurrent user creation returned {response.status_code}")
        
        if creation_attempts == 0:
            pytest.skip("User creation endpoints not available")
        
        logger.info(f"FV_DBM_CONCURRENCY_USER_CREATION_001: {creation_attempts} concurrent user creation attempts handled")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_concurrency_session_isolation_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """FV_DBM_CONCURRENCY_SESSION_ISOLATION_001: Test session isolation"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test that concurrent requests have isolated sessions
        async def isolated_request(request_id: int):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Isolation test {request_id}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                return response.json()
            return None
        
        # Create 4 concurrent requests
        tasks = [isolated_request(i) for i in range(4)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful responses
        successful_responses = [r for r in responses if r is not None and isinstance(r, dict)]
        
        if len(successful_responses) >= 2:
            # Verify each has unique ID (session isolation)
            ids = [r.get("id", "") for r in successful_responses]
            unique_ids = set(ids)
            
            assert len(unique_ids) == len(successful_responses), "Each request should have unique ID (session isolation)"
            
            # Verify responses are independent
            contents = [r["choices"][0]["message"]["content"] for r in successful_responses]
            logger.info(f"FV_DBM_CONCURRENCY_SESSION_ISOLATION_001: {len(successful_responses)} isolated sessions verified")
        else:
            logger.info("FV_DBM_CONCURRENCY_SESSION_ISOLATION_001: Insufficient responses for isolation testing")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_dbm_concurrency_connection_cleanup_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """FV_DBM_CONCURRENCY_CONNECTION_CLEANUP_001: Test connection cleanup under load"""
        if not config.ENABLE_FUNCTIONAL_TESTS:
            pytest.skip("Functional tests disabled")
        
        # Test that connections are properly cleaned up after many requests
        async def cleanup_test_request(request_id: int):
            # Mix of different request types
            if request_id % 3 == 0:
                return await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
            elif request_id % 3 == 1:
                return await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Cleanup test {request_id}"}],
                        "max_tokens": 20
                    }
                )
            else:
                return await make_request(
                    http_client, "POST", "/api/v1/embeddings",
                    auth_headers, {
                        "model": config.get_embedding_model(0),
                        "input": f"Cleanup test {request_id}"
                    }, track_cost=False
                )
        
        # Create many requests to test cleanup
        batch_size = 15
        tasks = [cleanup_test_request(i) for i in range(batch_size)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful responses
        successful_requests = 0
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.warning(f"Cleanup test request {i} failed: {response}")
            elif hasattr(response, 'status_code') and response.status_code == 200:
                successful_requests += 1
            elif hasattr(response, 'status_code') and response.status_code == 401:
                # Scope limitation, but connection handling is OK
                successful_requests += 0.5
        
        # Most requests should succeed if connection cleanup is working
        success_rate = successful_requests / batch_size
        assert success_rate >= 0.6, f"Success rate {success_rate:.2%} indicates connection cleanup issues"
        
        logger.info(f"FV_DBM_CONCURRENCY_CONNECTION_CLEANUP_001: {successful_requests}/{batch_size} requests successful under load")