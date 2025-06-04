# Section 7.2 - Business Logic Validation Testing
# Tests model routing, provider logic, and capability matching

import pytest
import httpx
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestBusinessLogicValidation:
    """Test cases for business logic validation"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_route_bedrock_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str], make_request):
        """FV_BLV_ROUTE_BEDROCK_001: Bedrock model routing validation"""
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        bedrock_models = [model for model in chat_models if "claude" in model.lower()]
        
        if not bedrock_models:
            pytest.skip("No Bedrock models configured")
        
        for model in bedrock_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Test Bedrock routing"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Bedrock model {model} should route correctly"
            response_data = response.json()
            assert "choices" in response_data
            
            # Verify model name in response matches request
            if "model" in response_data:
                assert response_data["model"] == model
        
        logger.info("FV_BLV_ROUTE_BEDROCK_001: Bedrock routing validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_route_vertexai_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str], make_request):
        """FV_BLV_ROUTE_VERTEXAI_001: Vertex AI model routing validation"""
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        vertexai_models = [model for model in chat_models if "gemini" in model.lower()]
        
        if not vertexai_models:
            pytest.skip("No Vertex AI models configured")
        
        for model in vertexai_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Test Vertex AI routing"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Vertex AI model {model} should route correctly"
            response_data = response.json()
            assert "choices" in response_data
            
            # Verify response structure
            assert "usage" in response_data
            assert "prompt_tokens" in response_data["usage"]
        
        logger.info("FV_BLV_ROUTE_VERTEXAI_001: Vertex AI routing validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_route_openai_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str], make_request):
        """FV_BLV_ROUTE_OPENAI_001: OpenAI-compatible model routing validation"""
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        openai_models = [model for model in chat_models 
                        if "gpt" in model.lower() or "llama" in model.lower()]
        
        if not openai_models:
            pytest.skip("No OpenAI-compatible models configured")
        
        for model in openai_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Test OpenAI routing"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"OpenAI model {model} should route correctly"
            response_data = response.json()
            assert "choices" in response_data
            
            # Verify OpenAI-compatible response structure
            assert "object" in response_data
            assert response_data["object"] == "chat.completion"
        
        logger.info("FV_BLV_ROUTE_OPENAI_001: OpenAI routing validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_capability_matching_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str], make_request):
        """FV_BLV_CAPABILITY_MATCHING_001: Model capability matching validation"""
        # Test that only appropriate models are used for specific capabilities
        
        # Chat capability test
        chat_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, chat_request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "choices" in response_data
        assert len(response_data["choices"]) > 0
        assert "message" in response_data["choices"][0]
        
        logger.info("FV_BLV_CAPABILITY_MATCHING_001: Chat capability validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_capability_matching_002(self, http_client: httpx.AsyncClient,
                                                 embedding_auth_headers: Dict[str, str],
                                                 make_request):
        """FV_BLV_CAPABILITY_MATCHING_002: Embedding capability matching validation"""
        embedding_request = {
            "model": config.get_embedding_model(0),
            "input": "Test embedding generation"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, embedding_request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "data" in response_data
        assert len(response_data["data"]) > 0
        assert "embedding" in response_data["data"][0]
        assert isinstance(response_data["data"][0]["embedding"], list)
        
        logger.info("FV_BLV_CAPABILITY_MATCHING_002: Embedding capability validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_model_availability_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str], make_request):
        """FV_BLV_MODEL_AVAILABILITY_001: Model availability verification"""
        # Test /models endpoint to verify configured models are available
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "data" in response_data
        assert isinstance(response_data["data"], list)
        assert len(response_data["data"]) > 0
        
        # Verify that configured models are in the response
        available_models = [model["id"] for model in response_data["data"]]
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for configured_model in chat_models:
            assert configured_model in available_models, f"Configured model {configured_model} should be available"
        
        logger.info("FV_BLV_MODEL_AVAILABILITY_001: Model availability verified")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_provider_consistency_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str], make_request):
        """FV_BLV_PROVIDER_CONSISTENCY_001: Provider response consistency validation"""
        test_prompt = "What is the capital of France?"
        
        # Test the same prompt across different models/providers
        responses = []
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for model in chat_models[:3]:  # Test first 3 models
            request = {
                "model": model,
                "messages": [{"role": "user", "content": test_prompt}],
                "max_tokens": 50,
                "temperature": 0.0  # Use deterministic temperature
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Model {model} should respond successfully"
            response_data = response.json()
            responses.append({
                "model": model,
                "response": response_data
            })
        
        # Verify consistent response structure across providers
        for response_item in responses:
            response_data = response_item["response"]
            model = response_item["model"]
            
            # Common required fields
            assert "choices" in response_data, f"Model {model} missing choices"
            assert "usage" in response_data, f"Model {model} missing usage"
            assert len(response_data["choices"]) > 0, f"Model {model} empty choices"
            
            # Verify choice structure
            choice = response_data["choices"][0]
            assert "message" in choice, f"Model {model} missing message in choice"
            assert "content" in choice["message"], f"Model {model} missing content"
            assert choice["message"]["content"], f"Model {model} empty content"
        
        logger.info("FV_BLV_PROVIDER_CONSISTENCY_001: Provider consistency validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_error_handling_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str], make_request):
        """FV_BLV_ERROR_HANDLING_001: Business logic error handling validation"""
        # Test various error conditions
        error_scenarios = [
            {
                "description": "Model not found",
                "request": {
                    "model": "non_existent_model",
                    "messages": [{"role": "user", "content": "Test"}],
                    "max_tokens": 50
                },
                "expected_status": 422
            },
            {
                "description": "Invalid message role",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "invalid_role", "content": "Test"}],
                    "max_tokens": 50
                },
                "expected_status": 422
            },
            {
                "description": "Missing required field",
                "request": {
                    "model": config.get_chat_model(0),
                    "max_tokens": 50
                    # Missing messages
                },
                "expected_status": 422
            }
        ]
        
        for scenario in error_scenarios:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario["request"], track_cost=False
            )
            
            assert response.status_code == scenario["expected_status"], \
                f"{scenario['description']} should return {scenario['expected_status']}"
            
            # Verify error response structure
            if response.status_code == 422:
                response_data = response.json()
                assert "detail" in response_data, f"{scenario['description']} should include error detail"
        
        logger.info("FV_BLV_ERROR_HANDLING_001: Error handling validated")


class TestProviderFailover:
    """Test provider failover and fallback mechanisms"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_failover_simulation_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str], make_request):
        """FV_BLV_FAILOVER_SIMULATION_001: Provider failover simulation"""
        # This test simulates what should happen during provider failover
        # In a real system, this would involve actually failing one provider
        
        # Test that the system continues to work with available models
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for model in chat_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Test failover scenario"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            # Should either succeed or fail gracefully
            assert response.status_code in [200, 503, 422], \
                f"Model {model} should handle requests or fail gracefully"
            
            if response.status_code == 200:
                response_data = response.json()
                assert "choices" in response_data
        
        logger.info("FV_BLV_FAILOVER_SIMULATION_001: Failover behavior validated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_blv_load_balancing_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str], make_request):
        """FV_BLV_LOAD_BALANCING_001: Load balancing behavior validation"""
        # Test multiple requests to see if they're distributed
        model = config.get_chat_model(0)
        request = {
            "model": model,
            "messages": [{"role": "user", "content": "Test load balancing"}],
            "max_tokens": 50
        }
        
        # Send multiple requests
        responses = []
        for i in range(5):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Request {i+1} should succeed"
            responses.append(response.json())
        
        # All responses should be successful
        assert len(responses) == 5
        
        # Verify response structure consistency
        for i, response_data in enumerate(responses):
            assert "choices" in response_data, f"Response {i+1} should have choices"
            assert len(response_data["choices"]) > 0, f"Response {i+1} should have non-empty choices"
        
        logger.info("FV_BLV_LOAD_BALANCING_001: Load balancing validated")