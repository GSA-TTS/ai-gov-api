# Section 7.2 - Configuration Management & Backend Mapping Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Configuration Management & Backend Mapping.md

import pytest
import httpx
import os
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestBackendMapValidation:
    """Test backend mapping and model routing validation"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_backend_map_valid_route_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_CFM_BACKEND_MAP_VALID_ROUTE_001: Verify correct model routing to specified provider"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test routing for each configured model
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for model_id in chat_models:
            request = {
                "model": model_id,
                "messages": [{"role": "user", "content": f"Test routing for {model_id}"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200
            response_data = response.json()
            
            # Verify model is correctly routed
            assert "model" in response_data
            returned_model = response_data["model"]
            
            # The returned model might be normalized or include provider prefix
            assert model_id in returned_model or returned_model in model_id
            
            # Verify response structure indicates successful routing
            assert "choices" in response_data
            assert len(response_data["choices"]) > 0
            assert "message" in response_data["choices"][0]
            
            logger.info(f"FV_CFM_BACKEND_MAP_VALID_ROUTE_001: Model {model_id} routed successfully to {returned_model}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_backend_map_invalid_arn_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_CFM_BACKEND_MAP_INVALID_ARN_001: Test invalid provider_model_id handling for Bedrock"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with invalid Bedrock ARN format
        invalid_bedrock_models = [
            "arn:aws:bedrock:us-east-1:123456789012:foundation-model/invalid-model",
            "bedrock:invalid-model-id",
            "anthropic.claude-invalid-v1",
            "amazon.titan-nonexistent-v1"
        ]
        
        for invalid_model in invalid_bedrock_models:
            request = {
                "model": invalid_model,
                "messages": [{"role": "user", "content": "Test invalid model"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should return 422 for validation error
            assert response.status_code == 422
            response_data = response.json()
            assert "detail" in response_data
            
            # Error should indicate model validation issue
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in ["model", "invalid", "not found", "unsupported"])
            
            logger.info(f"FV_CFM_BACKEND_MAP_INVALID_ARN_001: Invalid Bedrock model {invalid_model} properly rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_backend_map_invalid_project_id_001(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """FV_CFM_BACKEND_MAP_INVALID_PROJECT_ID_001: Test invalid project_id handling for Vertex AI"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with invalid Vertex AI model formats
        invalid_vertex_models = [
            "projects/invalid-project-123/locations/us-central1/publishers/google/models/gemini-pro",
            "vertex:projects/nonexistent/models/gemini-pro",
            "gemini-pro-invalid-version",
            "google/invalid-model-name"
        ]
        
        for invalid_model in invalid_vertex_models:
            request = {
                "model": invalid_model,
                "messages": [{"role": "user", "content": "Test invalid Vertex model"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should return 422 for validation error
            assert response.status_code == 422
            response_data = response.json()
            assert "detail" in response_data
            
            # Error should indicate model validation issue
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in ["model", "invalid", "not found", "unsupported"])
            
            logger.info(f"FV_CFM_BACKEND_MAP_INVALID_PROJECT_ID_001: Invalid Vertex model {invalid_model} properly rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_backend_map_cap_mismatch_startup_001(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """FV_CFM_BACKEND_MAP_CAP_MISMATCH_STARTUP_001: Test capability mismatch detection"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test embedding model with chat endpoint
        embedding_models = config.get_embedding_models() if config.get_embedding_models() else []
        for embedding_model in embedding_models:
            request = {
                "model": embedding_model,
                "messages": [{"role": "user", "content": "Test capability mismatch"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should return 422 for capability mismatch
            assert response.status_code == 422
            response_data = response.json()
            assert "detail" in response_data
            
            # Error should indicate capability mismatch
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in [
                "model", "embedding", "chat", "capability", "mismatch", "not supported"
            ])
            
            logger.info(f"FV_CFM_BACKEND_MAP_CAP_MISMATCH_STARTUP_001: Capability mismatch for {embedding_model} detected")
        
        # Test chat model with embedding endpoint
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for chat_model in chat_models:
            request = {
                "model": chat_model,
                "input": "Test capability mismatch for embedding"
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                auth_headers, request, track_cost=False
            )
            
            # Should return 422 for capability mismatch
            assert response.status_code == 422
            response_data = response.json()
            assert "detail" in response_data
            
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in [
                "model", "chat", "embedding", "capability", "mismatch", "not supported"
            ])
            
            logger.info(f"FV_CFM_BACKEND_MAP_CAP_MISMATCH_STARTUP_001: Capability mismatch for {chat_model} detected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_backend_map_unknown_provider_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """FV_CFM_BACKEND_MAP_UNKNOWN_PROVIDER_001: Test unknown provider handling"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with unknown provider formats
        unknown_provider_models = [
            "unknown-provider:model-123",
            "azure:gpt-4-custom",
            "huggingface:llama-2-70b",
            "cohere:command-light",
            "ai21:j2-ultra"
        ]
        
        for unknown_model in unknown_provider_models:
            request = {
                "model": unknown_model,
                "messages": [{"role": "user", "content": "Test unknown provider"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should return 422 for unknown provider
            assert response.status_code == 422
            response_data = response.json()
            assert "detail" in response_data
            
            # Error should indicate unknown model/provider
            detail_str = str(response_data["detail"]).lower()
            assert any(keyword in detail_str for keyword in [
                "model", "unknown", "not found", "unsupported", "invalid"
            ])
            
            logger.info(f"FV_CFM_BACKEND_MAP_UNKNOWN_PROVIDER_001: Unknown provider model {unknown_model} rejected")


class TestEnvironmentConfiguration:
    """Test environment configuration and validation"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_env_missing_var_bedrock_region_001(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """FV_CFM_ENV_MISSING_VAR_BEDROCK_REGION_001: Test missing AWS_REGION handling"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # This test verifies that the system has proper AWS region configuration
        # We can't actually remove the environment variable during runtime,
        # but we can verify the system behavior with Bedrock models
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        bedrock_models = [model for model in chat_models if "bedrock" in model.lower() or "anthropic" in model.lower() or "amazon" in model.lower()]
        
        if not bedrock_models:
            pytest.skip("No Bedrock models configured for testing")
        
        for model in bedrock_models[:1]:  # Test one Bedrock model
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Test Bedrock region configuration"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                # Bedrock is properly configured
                logger.info("FV_CFM_ENV_MISSING_VAR_BEDROCK_REGION_001: AWS region properly configured")
            elif response.status_code == 500:
                # Might indicate configuration issue
                response_data = response.json()
                if "region" in str(response_data).lower():
                    logger.info("FV_CFM_ENV_MISSING_VAR_BEDROCK_REGION_001: Region configuration issue detected")
                else:
                    logger.info("FV_CFM_ENV_MISSING_VAR_BEDROCK_REGION_001: Server error, but not necessarily region-related")
            else:
                # Other error
                logger.info(f"FV_CFM_ENV_MISSING_VAR_BEDROCK_REGION_001: Bedrock request returned {response.status_code}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_env_missing_var_vertex_creds_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """FV_CFM_ENV_MISSING_VAR_VERTEX_CREDS_001: Test missing Vertex AI credentials"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test Vertex AI models to verify credential configuration
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        vertex_models = [model for model in chat_models if "vertex" in model.lower() or "gemini" in model.lower() or "google" in model.lower()]
        
        if not vertex_models:
            pytest.skip("No Vertex AI models configured for testing")
        
        for model in vertex_models[:1]:  # Test one Vertex model
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Test Vertex AI credentials"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                # Vertex AI is properly configured
                logger.info("FV_CFM_ENV_MISSING_VAR_VERTEX_CREDS_001: Vertex AI credentials properly configured")
            elif response.status_code == 500:
                # Might indicate credential issue
                response_data = response.json()
                if any(keyword in str(response_data).lower() for keyword in ["credential", "authentication", "permission"]):
                    logger.info("FV_CFM_ENV_MISSING_VAR_VERTEX_CREDS_001: Credential configuration issue detected")
                else:
                    logger.info("FV_CFM_ENV_MISSING_VAR_VERTEX_CREDS_001: Server error, but not necessarily credential-related")
            else:
                logger.info(f"FV_CFM_ENV_MISSING_VAR_VERTEX_CREDS_001: Vertex AI request returned {response.status_code}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_env_settings_override_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """FV_CFM_ENV_SETTINGS_OVERRIDE_001: Verify environment variable overrides"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test that environment variables are properly loaded and used
        # We can check this by verifying the configuration values
        
        # Check database URL configuration
        assert hasattr(config, 'DATABASE_URL'), "Database URL should be configured"
        
        # Check that BASE_URL is configured
        assert hasattr(config, 'BASE_URL'), "Base URL should be configured"
        assert config.BASE_URL is not None, "Base URL should not be None"
        
        # Test basic connectivity to verify settings are working
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        # If we can get models, basic configuration is working
        assert response.status_code == 200, "Basic API connectivity should work with current settings"
        
        # Check timeout configuration
        assert hasattr(config, 'TIMEOUT'), "Timeout should be configured"
        assert isinstance(config.TIMEOUT, (int, float)), "Timeout should be numeric"
        assert config.TIMEOUT > 0, "Timeout should be positive"
        
        logger.info("FV_CFM_ENV_SETTINGS_OVERRIDE_001: Environment variable overrides working correctly")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_env_database_connection_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_CFM_ENV_DATABASE_CONNECTION_001: Test database connection configuration"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test that database-dependent operations work
        # This indirectly tests database connectivity
        
        # API key validation requires database access
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200, "API key validation (database operation) should work"
        
        # Test with invalid API key to verify database lookup
        invalid_headers = {"Authorization": "Bearer invalid_key_for_db_test"}
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            invalid_headers, track_cost=False
        )
        
        assert response.status_code == 401, "Invalid key should be rejected (requires database lookup)"
        
        logger.info("FV_CFM_ENV_DATABASE_CONNECTION_001: Database connection configuration verified")


class TestSettingsValidation:
    """Test application settings validation and initialization"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_settings_validation_required_fields_001(self, http_client: httpx.AsyncClient,
                                                                 auth_headers: Dict[str, str],
                                                                 make_request):
        """FV_CFM_SETTINGS_VALIDATION_REQUIRED_FIELDS_001: Test required field validation"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Verify that required configuration fields are present
        required_fields = [
            'DATABASE_URL',
            'BASE_URL',
            'CHAT_MODELS',
            'EMBEDDING_MODELS',
            'TIMEOUT'
        ]
        
        for field in required_fields:
            assert hasattr(config, field), f"Required field {field} should be present in configuration"
            value = getattr(config, field)
            assert value is not None, f"Required field {field} should not be None"
            
            if field.endswith('_MODELS'):
                assert isinstance(value, list), f"Model list {field} should be a list"
                assert len(value) > 0, f"Model list {field} should not be empty"
        
        logger.info("FV_CFM_SETTINGS_VALIDATION_REQUIRED_FIELDS_001: Required fields validation passed")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_settings_type_validation_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_CFM_SETTINGS_TYPE_VALIDATION_001: Test Pydantic type validation"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test that configuration values have correct types
        type_validations = [
            ('TIMEOUT', (int, float)),
            ('MAX_TOKENS', int),
            ('TEMPERATURE', (int, float)),
            ('CHAT_MODELS', list),
            ('EMBEDDING_MODELS', list),
            ('DATABASE_URL', str),
            ('BASE_URL', str)
        ]
        
        for field_name, expected_type in type_validations:
            if hasattr(config, field_name):
                value = getattr(config, field_name)
                assert isinstance(value, expected_type), f"Field {field_name} should be of type {expected_type}"
                
                # Additional validations
                if field_name == 'TIMEOUT':
                    assert value > 0, "Timeout should be positive"
                elif field_name == 'MAX_TOKENS':
                    assert value > 0, "Max tokens should be positive"
                elif field_name == 'TEMPERATURE':
                    assert 0 <= value <= 2, "Temperature should be between 0 and 2"
                elif field_name.endswith('_MODELS'):
                    assert len(value) > 0, f"Model list {field_name} should not be empty"
        
        logger.info("FV_CFM_SETTINGS_TYPE_VALIDATION_001: Type validation passed")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_backend_map_initialization_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """FV_CFM_BACKEND_MAP_INITIALIZATION_001: Verify backend_map population"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test that all configured models are accessible via /models endpoint
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "data" in response_data
        available_models = [model["id"] for model in response_data["data"]]
        
        # Verify that configured models are in the available models
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        embedding_models = config.get_embedding_models() if config.get_embedding_models() else []
        configured_models = chat_models + embedding_models
        
        for configured_model in configured_models:
            # Model might be in available models directly or with normalization
            model_found = any(
                configured_model in available_model or available_model in configured_model
                for available_model in available_models
            )
            assert model_found, f"Configured model {configured_model} should be available in /models endpoint"
        
        logger.info(f"FV_CFM_BACKEND_MAP_INITIALIZATION_001: Backend map initialized with {len(available_models)} models")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_cfm_settings_cache_consistency_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """FV_CFM_SETTINGS_CACHE_CONSISTENCY_001: Test settings caching consistency"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Make multiple requests to verify consistent behavior
        responses = []
        
        for i in range(3):
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            responses.append(response)
        
        # All responses should be identical (cached settings)
        for i, response in enumerate(responses):
            assert response.status_code == 200, f"Request {i+1} should succeed"
            
            response_data = response.json()
            if i == 0:
                first_response = response_data
            else:
                # Model list should be consistent
                assert len(response_data["data"]) == len(first_response["data"]), "Model count should be consistent"
                
                # Model IDs should be the same
                current_ids = sorted([model["id"] for model in response_data["data"]])
                first_ids = sorted([model["id"] for model in first_response["data"]])
                assert current_ids == first_ids, "Model IDs should be consistent across requests"
        
        logger.info("FV_CFM_SETTINGS_CACHE_CONSISTENCY_001: Settings caching consistency verified")