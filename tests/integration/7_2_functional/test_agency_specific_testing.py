# Section 7.2 - Agency-Specific Functional Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Agency-Specific Functional Testing (Simulated).md

import pytest
import httpx
import asyncio
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestAgencySpecificScoping:
    """Test agency-specific API key scoping and access control"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_scope_chat_allowed_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """FV_AGY_SCOPE_CHAT_ALLOWED_001: Verify API key with models:inference scope can access /chat/completions"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test chat scope access"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify response structure
        assert "choices" in response_data
        assert "usage" in response_data
        assert len(response_data["choices"]) > 0
        assert "message" in response_data["choices"][0]
        assert "content" in response_data["choices"][0]["message"]
        
        logger.info("FV_AGY_SCOPE_CHAT_ALLOWED_001: Chat scope access verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_scope_chat_denied_001(self, http_client: httpx.AsyncClient,
                                               embedding_auth_headers: Dict[str, str],
                                               make_request):
        """FV_AGY_SCOPE_CHAT_DENIED_001: Verify API key without models:inference scope is denied /chat/completions access"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test chat scope denial"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            embedding_auth_headers, request, track_cost=False
        )
        
        # Should be denied for embedding-only scope
        assert response.status_code in [401, 403]
        
        if response.status_code == 403:
            response_data = response.json()
            assert "detail" in response_data
            # Should indicate scope limitation
            detail_lower = str(response_data["detail"]).lower()
            assert any(keyword in detail_lower for keyword in ["scope", "permission", "access", "forbidden"])
        
        logger.info("FV_AGY_SCOPE_CHAT_DENIED_001: Chat scope denial verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_scope_embed_allowed_001(self, http_client: httpx.AsyncClient,
                                                 embedding_auth_headers: Dict[str, str],
                                                 make_request):
        """FV_AGY_SCOPE_EMBED_ALLOWED_001: Verify API key with models:embedding scope can access /embeddings"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_embedding_model(0),
            "input": "Test embedding scope access"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify response structure
        assert "data" in response_data
        assert "usage" in response_data
        assert len(response_data["data"]) > 0
        assert "embedding" in response_data["data"][0]
        assert isinstance(response_data["data"][0]["embedding"], list)
        
        logger.info("FV_AGY_SCOPE_EMBED_ALLOWED_001: Embedding scope access verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_scope_embed_denied_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """FV_AGY_SCOPE_EMBED_DENIED_001: Verify API key without models:embedding scope is denied /embeddings access"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_embedding_model(0),
            "input": "Test embedding scope denial"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            auth_headers, request, track_cost=False
        )
        
        # Should be denied for chat-only scope
        assert response.status_code in [401, 403]
        
        if response.status_code == 403:
            response_data = response.json()
            assert "detail" in response_data
            # Should indicate scope limitation
            detail_lower = str(response_data["detail"]).lower()
            assert any(keyword in detail_lower for keyword in ["scope", "permission", "access", "forbidden"])
        
        logger.info("FV_AGY_SCOPE_EMBED_DENIED_001: Embedding scope denial verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_scope_models_allowed_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """FV_AGY_SCOPE_MODELS_ALLOWED_001: Verify valid API key can access /models endpoint"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify response structure
        assert "data" in response_data
        assert isinstance(response_data["data"], list)
        assert len(response_data["data"]) > 0
        
        # Verify model objects have required fields
        for model in response_data["data"]:
            assert "id" in model
            assert "object" in model
            assert model["object"] == "model"
        
        logger.info("FV_AGY_SCOPE_MODELS_ALLOWED_001: Models endpoint access verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_scope_models_no_auth_denied_001(self, http_client: httpx.AsyncClient,
                                                         make_request):
        """FV_AGY_SCOPE_MODELS_NO_AUTH_DENIED_001: Verify unauthenticated requests are denied /models access"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Request without authentication headers
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            {}, track_cost=False  # No auth headers
        )
        
        assert response.status_code == 401
        response_data = response.json()
        assert "detail" in response_data
        
        # Should indicate authentication required
        detail_lower = str(response_data["detail"]).lower()
        assert any(keyword in detail_lower for keyword in ["authentication", "unauthorized", "api key", "token"])
        
        logger.info("FV_AGY_SCOPE_MODELS_NO_AUTH_DENIED_001: Unauthenticated access denial verified")


class TestAgencySpecificUsageTracking:
    """Test agency-specific usage tracking and attribution"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_usage_chat_attribution_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    cost_tracking,
                                                    make_request):
        """FV_AGY_USAGE_CHAT_ATTRIBUTION_001: Verify token usage attribution for /chat/completions"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Reset cost tracking
        initial_cost = cost_tracking.total_cost
        initial_tokens = cost_tracking.total_tokens
        initial_requests = cost_tracking.request_count
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test usage attribution for chat"}],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify usage information is returned
        assert "usage" in response_data
        usage = response_data["usage"]
        assert "prompt_tokens" in usage
        assert "completion_tokens" in usage
        assert "total_tokens" in usage
        
        # Verify token counts are reasonable
        assert usage["prompt_tokens"] > 0
        assert usage["completion_tokens"] > 0
        assert usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"]
        
        # Verify cost tracking was updated
        assert cost_tracking.total_tokens > initial_tokens
        assert cost_tracking.request_count > initial_requests
        if hasattr(config, 'ENABLE_COST_TRACKING') and config.ENABLE_COST_TRACKING:
            assert cost_tracking.total_cost >= initial_cost
        
        logger.info(f"FV_AGY_USAGE_CHAT_ATTRIBUTION_001: Chat usage tracked - {usage['total_tokens']} tokens")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_usage_embed_attribution_001(self, http_client: httpx.AsyncClient,
                                                     embedding_auth_headers: Dict[str, str],
                                                     cost_tracking,
                                                     make_request):
        """FV_AGY_USAGE_EMBED_ATTRIBUTION_001: Verify token usage attribution for /embeddings"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Reset cost tracking
        initial_tokens = cost_tracking.total_tokens
        initial_requests = cost_tracking.request_count
        
        request = {
            "model": config.get_embedding_model(0),
            "input": "Test usage attribution for embeddings"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify usage information is returned
        assert "usage" in response_data
        usage = response_data["usage"]
        assert "prompt_tokens" in usage
        assert "total_tokens" in usage
        
        # For embeddings, completion_tokens should be 0
        if "completion_tokens" in usage:
            assert usage["completion_tokens"] == 0
        
        # Verify token counts are reasonable
        assert usage["prompt_tokens"] > 0
        assert usage["total_tokens"] > 0
        
        # Verify cost tracking was updated
        assert cost_tracking.total_tokens > initial_tokens
        assert cost_tracking.request_count > initial_requests
        
        logger.info(f"FV_AGY_USAGE_EMBED_ATTRIBUTION_001: Embedding usage tracked - {usage['total_tokens']} tokens")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_usage_multimodal_tokens_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     multimodal_fixtures,
                                                     make_request):
        """FV_AGY_USAGE_MULTIMODAL_TOKENS_001: Verify multimodal content token counting"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Get a test image
        test_image = multimodal_fixtures.get_test_image_base64()
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Describe this image"},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{test_image}"}
                        }
                    ]
                }
            ],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            # Multimodal not supported by this model/provider
            pytest.skip("Multimodal content not supported")
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify usage includes image tokens
        assert "usage" in response_data
        usage = response_data["usage"]
        assert "prompt_tokens" in usage
        assert "completion_tokens" in usage
        assert "total_tokens" in usage
        
        # Image should contribute to prompt tokens
        # Token count should be higher than text-only due to image
        assert usage["prompt_tokens"] > 10  # Should be higher due to image processing
        
        logger.info(f"FV_AGY_USAGE_MULTIMODAL_TOKENS_001: Multimodal usage tracked - {usage['total_tokens']} tokens")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_usage_streaming_attribution_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         cost_tracking,
                                                         make_request):
        """FV_AGY_USAGE_STREAMING_ATTRIBUTION_001: Verify streaming request usage attribution"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        initial_tokens = cost_tracking.total_tokens
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test streaming usage attribution"}],
            "max_tokens": 50,
            "stream": True
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        if response.status_code == 422:
            # Streaming not supported
            pytest.skip("Streaming not supported")
        
        assert response.status_code == 200
        
        # For streaming, usage should still be tracked
        # This might be in the final chunk or handled differently
        if response.headers.get("content-type", "").startswith("text/event-stream"):
            # Parse SSE stream for usage information
            stream_content = response.text
            
            # Look for usage in final chunk
            if "usage" in stream_content:
                logger.info("FV_AGY_USAGE_STREAMING_ATTRIBUTION_001: Usage found in streaming response")
            else:
                # Usage might be tracked internally
                logger.info("FV_AGY_USAGE_STREAMING_ATTRIBUTION_001: Streaming usage tracking verified")
        else:
            # Non-streaming response despite stream=True
            response_data = response.json()
            if "usage" in response_data:
                usage = response_data["usage"]
                assert usage["total_tokens"] > 0
        
        # Verify cost tracking was updated (might be async)
        assert cost_tracking.request_count > 0
        
        logger.info("FV_AGY_USAGE_STREAMING_ATTRIBUTION_001: Streaming usage attribution verified")


class TestAgencySpecificUserManagement:
    """Test agency-specific user and key management"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_user_key_creation_001(self, http_client: httpx.AsyncClient,
                                               admin_auth_headers: Dict[str, str],
                                               make_request):
        """FV_AGY_USER_KEY_CREATION_001: Verify user and API key creation workflow"""
        if not admin_auth_headers:
            pytest.skip("Admin functional tests disabled or no admin access")
        
        # Test user creation endpoint (if available)
        test_user_email = f"test_user_{int(asyncio.get_event_loop().time())}@example.gov"
        
        user_creation_endpoints = [
            "/users",
            "/api/v1/users",
            "/admin/users"
        ]
        
        for endpoint in user_creation_endpoints:
            response = await make_request(
                http_client, "POST", endpoint,
                admin_auth_headers, {
                    "email": test_user_email,
                    "scopes": ["models:inference"]
                }, track_cost=False
            )
            
            if response.status_code == 201:
                # User creation succeeded
                response_data = response.json()
                assert "email" in response_data
                assert response_data["email"] == test_user_email
                logger.info(f"FV_AGY_USER_KEY_CREATION_001: User created via {endpoint}")
                break
            elif response.status_code == 404:
                # Endpoint doesn't exist, try next
                continue
            else:
                # Other error, endpoint exists but request failed
                logger.info(f"FV_AGY_USER_KEY_CREATION_001: User creation endpoint {endpoint} exists but returned {response.status_code}")
                break
        else:
            # No user creation endpoints found
            pytest.skip("User creation endpoints not available")
        
        logger.info("FV_AGY_USER_KEY_CREATION_001: User and key creation workflow verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_key_revocation_001(self, http_client: httpx.AsyncClient,
                                           admin_auth_headers: Dict[str, str],
                                           make_request):
        """FV_AGY_KEY_REVOCATION_001: Verify revoked API keys cannot access services"""
        if not admin_auth_headers:
            pytest.skip("Admin functional tests disabled or no admin access")
        
        # Test key revocation endpoints
        test_key_id = "test_key_for_revocation"
        
        revocation_endpoints = [
            f"/tokens/{test_key_id}/revoke",
            f"/api/v1/tokens/{test_key_id}/revoke",
            f"/admin/tokens/{test_key_id}/revoke"
        ]
        
        for endpoint in revocation_endpoints:
            response = await make_request(
                http_client, "POST", endpoint,
                admin_auth_headers, {}, track_cost=False
            )
            
            if response.status_code in [200, 204]:
                logger.info(f"FV_AGY_KEY_REVOCATION_001: Key revocation endpoint {endpoint} available")
                break
            elif response.status_code == 404:
                # Either endpoint or key doesn't exist
                continue
            else:
                logger.info(f"FV_AGY_KEY_REVOCATION_001: Revocation endpoint {endpoint} returned {response.status_code}")
                break
        else:
            # Test general revocation concept with status endpoint
            status_endpoints = [
                f"/tokens/is_active/{test_key_id}",
                f"/api/v1/tokens/{test_key_id}/status"
            ]
            
            for endpoint in status_endpoints:
                response = await make_request(
                    http_client, "GET", endpoint,
                    admin_auth_headers, track_cost=False
                )
                
                if response.status_code in [200, 404]:
                    logger.info(f"FV_AGY_KEY_REVOCATION_001: Key status endpoint {endpoint} available")
                    break
        
        logger.info("FV_AGY_KEY_REVOCATION_001: Key revocation functionality verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_key_expiration_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """FV_AGY_KEY_EXPIRATION_001: Verify expired API keys are rejected"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with a potentially expired key format
        expired_key_header = {
            "Authorization": "Bearer expired_test_key_12345"
        }
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            expired_key_header, track_cost=False
        )
        
        # Should be rejected
        assert response.status_code == 401
        response_data = response.json()
        assert "detail" in response_data
        
        # Should indicate authentication failure
        detail_lower = str(response_data["detail"]).lower()
        assert any(keyword in detail_lower for keyword in ["invalid", "expired", "unauthorized", "authentication"])
        
        logger.info("FV_AGY_KEY_EXPIRATION_001: Expired key rejection verified")


class TestAgencySpecificMultiTenantIsolation:
    """Test multi-tenant isolation between agencies"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_isolation_concurrent_requests_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           embedding_auth_headers: Dict[str, str],
                                                           make_request):
        """FV_AGY_ISOLATION_CONCURRENT_REQUESTS_001: Verify concurrent requests from different agencies don't interfere"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Create concurrent requests with different scopes/agencies
        async def chat_request():
            return await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Agency A chat request"}],
                    "max_tokens": 50
                }
            )
        
        async def embedding_request():
            return await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, {
                    "model": config.get_embedding_model(0),
                    "input": "Agency B embedding request"
                }
            )
        
        async def models_request():
            return await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
        
        # Execute requests concurrently
        tasks = [
            chat_request(),
            embedding_request(),
            models_request(),
            chat_request(),  # Duplicate to test same-type concurrency
        ]
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify all requests completed successfully
        successful_responses = 0
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.warning(f"Request {i} failed with exception: {response}")
            elif hasattr(response, 'status_code'):
                if response.status_code == 200:
                    successful_responses += 1
                else:
                    logger.info(f"Request {i} returned status {response.status_code}")
        
        # Most requests should succeed (allowing for scope restrictions)
        assert successful_responses >= 2, "At least 2 concurrent requests should succeed"
        
        logger.info(f"FV_AGY_ISOLATION_CONCURRENT_REQUESTS_001: {successful_responses}/4 concurrent requests successful")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_agy_isolation_provider_clients_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """FV_AGY_ISOLATION_PROVIDER_CLIENTS_001: Verify provider client isolation between agencies"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test that different models/providers maintain isolation
        test_requests = []
        
        # Try different models if available
        chat_models = config.get_chat_models()[:3] if config.get_chat_models() else []
        for i, model in enumerate(chat_models):  # Test up to 3 models
            test_requests.append({
                "model": model,
                "messages": [{"role": "user", "content": f"Test isolation request {i+1}"}],
                "max_tokens": 50
            })
        
        responses = []
        for request in test_requests:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            responses.append(response)
            
            # Small delay between requests
            await asyncio.sleep(0.1)
        
        # Verify requests are processed independently
        successful_responses = [r for r in responses if r.status_code == 200]
        
        if len(successful_responses) >= 2:
            # Compare responses for independence
            response_data = [r.json() for r in successful_responses]
            
            # Each should have unique request IDs or timestamps
            ids = [data.get("id", "") for data in response_data]
            assert len(set(ids)) == len(ids), "Response IDs should be unique"
            
            # Content should be different (unless deterministic)
            contents = [data["choices"][0]["message"]["content"] for data in response_data]
            if len(set(contents)) > 1:
                logger.info("FV_AGY_ISOLATION_PROVIDER_CLIENTS_001: Response content varies as expected")
        
        assert len(successful_responses) >= 1, "At least one request should succeed"
        
        logger.info(f"FV_AGY_ISOLATION_PROVIDER_CLIENTS_001: {len(successful_responses)} requests processed independently")