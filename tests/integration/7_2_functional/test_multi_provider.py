# Section 7.2 - Multi-Provider Validation Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Multi-Provider Validation.md

import pytest
import httpx
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestRequestTranslation:
    """Test request translation between OpenAI format and provider-specific formats"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_req_chat_msg_roles_bedrock_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """FV_MPV_REQ_CHAT_MSG_ROLES_BEDROCK_001: Test message role translation to Bedrock"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Find Bedrock models
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        bedrock_models = [model for model in chat_models 
                         if any(provider in model.lower() for provider in ["bedrock", "anthropic", "amazon", "claude", "titan"])]
        
        if not bedrock_models:
            pytest.skip("No Bedrock models configured")
        
        # Test various message role combinations
        role_combinations = [
            # Simple user-assistant
            [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there!"},
                {"role": "user", "content": "How are you?"}
            ],
            # With system message
            [
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": "What's the weather like?"}
            ],
            # Multi-turn conversation
            [
                {"role": "user", "content": "Tell me about AI"},
                {"role": "assistant", "content": "AI is artificial intelligence"},
                {"role": "user", "content": "What are its applications?"},
                {"role": "assistant", "content": "AI has many applications"},
                {"role": "user", "content": "Give me examples"}
            ]
        ]
        
        for i, messages in enumerate(role_combinations):
            request = {
                "model": bedrock_models[0],
                "messages": messages,
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Bedrock role combination {i+1} should succeed"
            
            response_data = response.json()
            assert "choices" in response_data
            assert len(response_data["choices"]) > 0
            
            # Verify response has correct assistant role
            choice = response_data["choices"][0]
            assert "message" in choice
            assert choice["message"]["role"] == "assistant"
            assert len(choice["message"]["content"]) > 0
            
            logger.info(f"FV_MPV_REQ_CHAT_MSG_ROLES_BEDROCK_001: Role combination {i+1} translated successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_req_chat_msg_roles_vertexai_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """FV_MPV_REQ_CHAT_MSG_ROLES_VERTEXAI_001: Test message role translation to Vertex AI"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Find Vertex AI models
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        vertex_models = [model for model in chat_models 
                        if any(provider in model.lower() for provider in ["vertex", "gemini", "bison", "google"])]
        
        if not vertex_models:
            pytest.skip("No Vertex AI models configured")
        
        # Test role combinations that work with Vertex AI
        vertex_role_tests = [
            # User-model conversation (Vertex AI format)
            [
                {"role": "user", "content": "What is machine learning?"},
                {"role": "assistant", "content": "Machine learning is a subset of AI"},
                {"role": "user", "content": "Explain further"}
            ],
            # With system instruction
            [
                {"role": "system", "content": "Be concise in your responses"},
                {"role": "user", "content": "Explain quantum computing"}
            ]
        ]
        
        for i, messages in enumerate(vertex_role_tests):
            request = {
                "model": vertex_models[0],
                "messages": messages,
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Vertex AI role combination {i+1} should succeed"
            
            response_data = response.json()
            assert "choices" in response_data
            
            choice = response_data["choices"][0]
            assert choice["message"]["role"] == "assistant"
            assert len(choice["message"]["content"]) > 0
            
            logger.info(f"FV_MPV_REQ_CHAT_MSG_ROLES_VERTEXAI_001: Role combination {i+1} translated successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_req_chat_params_bedrock_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_MPV_REQ_CHAT_PARAMS_BEDROCK_001: Test parameter translation to Bedrock"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        bedrock_models = [model for model in chat_models 
                         if any(provider in model.lower() for provider in ["bedrock", "anthropic", "amazon"])]
        
        if not bedrock_models:
            pytest.skip("No Bedrock models configured")
        
        # Test various parameter combinations for Bedrock
        parameter_tests = [
            {
                "temperature": 0.0,
                "max_tokens": 50,
                "description": "Deterministic response"
            },
            {
                "temperature": 0.7,
                "max_tokens": 100,
                "top_p": 0.9,
                "description": "Balanced creativity"
            },
            {
                "temperature": 1.0,
                "max_tokens": 75,
                "description": "High creativity"
            }
        ]
        
        for test in parameter_tests:
            description = test.pop("description")
            
            request = {
                "model": bedrock_models[0],
                "messages": [{"role": "user", "content": f"Test {description}"}],
                **test
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 422:
                # Some parameters might not be supported
                logger.info(f"FV_MPV_REQ_CHAT_PARAMS_BEDROCK_001: {description} parameters not supported")
                continue
            
            assert response.status_code == 200, f"Bedrock parameters for {description} should work"
            
            response_data = response.json()
            assert "choices" in response_data
            
            # Verify the response reflects parameter settings
            content = response_data["choices"][0]["message"]["content"]
            assert len(content) > 0, f"Should generate content with {description} parameters"
            
            logger.info(f"FV_MPV_REQ_CHAT_PARAMS_BEDROCK_001: {description} parameters translated successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_req_chat_params_vertexai_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """FV_MPV_REQ_CHAT_PARAMS_VERTEXAI_001: Test parameter translation to Vertex AI"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        vertex_models = [model for model in chat_models 
                        if any(provider in model.lower() for provider in ["vertex", "gemini", "bison"])]
        
        if not vertex_models:
            pytest.skip("No Vertex AI models configured")
        
        # Test Vertex AI specific parameter ranges
        vertex_parameter_tests = [
            {
                "temperature": 0.0,
                "max_tokens": 50,
                "description": "Zero temperature"
            },
            {
                "temperature": 0.5,
                "max_tokens": 100,
                "top_p": 0.8,
                "description": "Moderate parameters"
            },
            {
                "temperature": 1.0,
                "max_tokens": 80,
                "top_p": 1.0,
                "description": "High variability"
            }
        ]
        
        for test in vertex_parameter_tests:
            description = test.pop("description")
            
            request = {
                "model": vertex_models[0],
                "messages": [{"role": "user", "content": f"Test Vertex AI {description}"}],
                **test
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 422:
                logger.info(f"FV_MPV_REQ_CHAT_PARAMS_VERTEXAI_001: {description} parameters not supported")
                continue
            
            assert response.status_code == 200, f"Vertex AI parameters for {description} should work"
            
            response_data = response.json()
            content = response_data["choices"][0]["message"]["content"]
            assert len(content) > 0, f"Should generate content with {description} parameters"
            
            logger.info(f"FV_MPV_REQ_CHAT_PARAMS_VERTEXAI_001: {description} parameters translated successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_req_multimodal_image_bedrock_001(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          multimodal_fixtures,
                                                          make_request):
        """FV_MPV_REQ_MULTIMODAL_IMAGE_BEDROCK_001: Test image translation to Bedrock"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        bedrock_models = [model for model in chat_models 
                         if any(provider in model.lower() for provider in ["bedrock", "anthropic", "claude"])]
        
        if not bedrock_models:
            pytest.skip("No Bedrock models configured")
        
        test_image = multimodal_fixtures.get_test_image_base64()
        
        request = {
            "model": bedrock_models[0],
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
            # Multimodal might not be supported by this Bedrock model
            pytest.skip("Multimodal not supported by Bedrock model")
        
        assert response.status_code == 200, "Bedrock multimodal request should succeed"
        
        response_data = response.json()
        content = response_data["choices"][0]["message"]["content"]
        assert len(content) > 0, "Should generate description of image"
        
        # Usage should reflect image processing
        if "usage" in response_data:
            usage = response_data["usage"]
            assert usage["prompt_tokens"] > 10, "Image processing should contribute to token count"
        
        logger.info("FV_MPV_REQ_MULTIMODAL_IMAGE_BEDROCK_001: Bedrock multimodal image translated successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_req_multimodal_image_vertexai_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           multimodal_fixtures,
                                                           make_request):
        """FV_MPV_REQ_MULTIMODAL_IMAGE_VERTEXAI_001: Test image translation to Vertex AI"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        vertex_models = [model for model in chat_models 
                        if any(provider in model.lower() for provider in ["vertex", "gemini"])]
        
        if not vertex_models:
            pytest.skip("No Vertex AI models configured")
        
        test_image = multimodal_fixtures.get_test_image_base64()
        
        request = {
            "model": vertex_models[0],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What do you see in this image?"},
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
            pytest.skip("Multimodal not supported by Vertex AI model")
        
        assert response.status_code == 200, "Vertex AI multimodal request should succeed"
        
        response_data = response.json()
        content = response_data["choices"][0]["message"]["content"]
        assert len(content) > 0, "Should generate description of image"
        
        logger.info("FV_MPV_REQ_MULTIMODAL_IMAGE_VERTEXAI_001: Vertex AI multimodal image translated successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_req_embed_input_bedrock_001(self, http_client: httpx.AsyncClient,
                                                     embedding_auth_headers: Dict[str, str],
                                                     make_request):
        """FV_MPV_REQ_EMBED_INPUT_BEDROCK_001: Test embedding input translation to Bedrock"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        embedding_models = config.get_embedding_models() if config.get_embedding_models() else []
        bedrock_embed_models = [model for model in embedding_models 
                               if any(provider in model.lower() for provider in ["bedrock", "amazon", "titan", "cohere"])]
        
        if not bedrock_embed_models:
            pytest.skip("No Bedrock embedding models configured")
        
        # Test various input formats
        embedding_inputs = [
            "Single text input for Bedrock embedding",
            ["Multiple", "text", "inputs", "for", "batch", "processing"],
            "Text with special characters: @#$%^&*()_+{}[]|\\:;\"'<>,.?/~`"
        ]
        
        for i, input_data in enumerate(embedding_inputs):
            request = {
                "model": bedrock_embed_models[0],
                "input": input_data
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request
            )
            
            if response.status_code == 422 and isinstance(input_data, list):
                # Batch processing might not be supported
                logger.info(f"FV_MPV_REQ_EMBED_INPUT_BEDROCK_001: Batch input {i+1} not supported")
                continue
            
            assert response.status_code == 200, f"Bedrock embedding input {i+1} should succeed"
            
            response_data = response.json()
            assert "data" in response_data
            
            # Verify embedding structure
            expected_count = len(input_data) if isinstance(input_data, list) else 1
            assert len(response_data["data"]) == expected_count, f"Should return {expected_count} embeddings"
            
            for embedding_obj in response_data["data"]:
                assert "embedding" in embedding_obj
                embedding = embedding_obj["embedding"]
                assert isinstance(embedding, list)
                assert len(embedding) > 0
                assert all(isinstance(x, (int, float)) for x in embedding)
            
            logger.info(f"FV_MPV_REQ_EMBED_INPUT_BEDROCK_001: Bedrock embedding input {i+1} translated successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_req_embed_input_vertexai_001(self, http_client: httpx.AsyncClient,
                                                      embedding_auth_headers: Dict[str, str],
                                                      make_request):
        """FV_MPV_REQ_EMBED_INPUT_VERTEXAI_001: Test embedding input translation to Vertex AI"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        embedding_models = config.get_embedding_models() if config.get_embedding_models() else []
        vertex_embed_models = [model for model in embedding_models 
                              if any(provider in model.lower() for provider in ["vertex", "google", "textembedding"])]
        
        if not vertex_embed_models:
            pytest.skip("No Vertex AI embedding models configured")
        
        # Test Vertex AI embedding inputs
        vertex_inputs = [
            "Vertex AI embedding test input",
            "Text for semantic similarity analysis using Vertex AI"
        ]
        
        for i, input_text in enumerate(vertex_inputs):
            request = {
                "model": vertex_embed_models[0],
                "input": input_text
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request
            )
            
            assert response.status_code == 200, f"Vertex AI embedding input {i+1} should succeed"
            
            response_data = response.json()
            assert "data" in response_data
            assert len(response_data["data"]) == 1
            
            embedding_obj = response_data["data"][0]
            embedding = embedding_obj["embedding"]
            assert isinstance(embedding, list)
            assert len(embedding) > 0, "Vertex AI embedding should not be empty"
            
            logger.info(f"FV_MPV_REQ_EMBED_INPUT_VERTEXAI_001: Vertex AI embedding input {i+1} translated successfully")


class TestResponseNormalization:
    """Test response normalization from provider-specific formats to OpenAI format"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_resp_chat_content_bedrock_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_MPV_RESP_CHAT_CONTENT_BEDROCK_001: Test Bedrock response normalization"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        bedrock_models = [model for model in chat_models 
                         if any(provider in model.lower() for provider in ["bedrock", "anthropic", "claude"])]
        
        if not bedrock_models:
            pytest.skip("No Bedrock models configured")
        
        request = {
            "model": bedrock_models[0],
            "messages": [{"role": "user", "content": "Explain the concept of normalization"}],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify normalized OpenAI format
        assert "id" in response_data, "Should have normalized ID"
        assert "object" in response_data, "Should have object field"
        assert response_data["object"] == "chat.completion", "Object should be normalized"
        assert "created" in response_data, "Should have created timestamp"
        assert "model" in response_data, "Should have model field"
        assert "choices" in response_data, "Should have choices array"
        
        # Verify choice structure is normalized
        choice = response_data["choices"][0]
        assert "index" in choice, "Choice should have index"
        assert "message" in choice, "Choice should have message"
        assert "finish_reason" in choice, "Choice should have finish_reason"
        
        # Verify message structure
        message = choice["message"]
        assert message["role"] == "assistant", "Role should be normalized to assistant"
        assert "content" in message, "Message should have content"
        assert isinstance(message["content"], str), "Content should be string"
        
        logger.info("FV_MPV_RESP_CHAT_CONTENT_BEDROCK_001: Bedrock response normalized to OpenAI format")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_resp_chat_content_vertexai_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """FV_MPV_RESP_CHAT_CONTENT_VERTEXAI_001: Test Vertex AI response normalization"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        vertex_models = [model for model in chat_models 
                        if any(provider in model.lower() for provider in ["vertex", "gemini", "bison"])]
        
        if not vertex_models:
            pytest.skip("No Vertex AI models configured")
        
        request = {
            "model": vertex_models[0],
            "messages": [{"role": "user", "content": "Describe response normalization"}],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify Vertex AI response is normalized to OpenAI format
        assert response_data["object"] == "chat.completion"
        assert "choices" in response_data
        
        choice = response_data["choices"][0]
        assert choice["message"]["role"] == "assistant"
        assert "content" in choice["message"]
        assert isinstance(choice["message"]["content"], str)
        
        # Verify finish_reason is properly mapped
        if "finish_reason" in choice:
            valid_reasons = ["stop", "length", "content_filter", "tool_calls"]
            assert choice["finish_reason"] in valid_reasons or choice["finish_reason"] is None
        
        logger.info("FV_MPV_RESP_CHAT_CONTENT_VERTEXAI_001: Vertex AI response normalized to OpenAI format")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_resp_chat_usage_bedrock_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_MPV_RESP_CHAT_USAGE_BEDROCK_001: Test Bedrock usage metric normalization"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        bedrock_models = [model for model in chat_models 
                         if any(provider in model.lower() for provider in ["bedrock", "anthropic"])]
        
        if not bedrock_models:
            pytest.skip("No Bedrock models configured")
        
        request = {
            "model": bedrock_models[0],
            "messages": [{"role": "user", "content": "Calculate token usage for this request"}],
            "max_tokens": 80
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify usage metrics are normalized
        assert "usage" in response_data, "Should include normalized usage metrics"
        usage = response_data["usage"]
        
        # Standard OpenAI usage format
        assert "prompt_tokens" in usage, "Should have prompt_tokens"
        assert "completion_tokens" in usage, "Should have completion_tokens"
        assert "total_tokens" in usage, "Should have total_tokens"
        
        # Verify types and consistency
        assert isinstance(usage["prompt_tokens"], int), "Prompt tokens should be integer"
        assert isinstance(usage["completion_tokens"], int), "Completion tokens should be integer"
        assert isinstance(usage["total_tokens"], int), "Total tokens should be integer"
        
        assert usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"], \
            "Total should equal sum of prompt and completion tokens"
        
        assert usage["prompt_tokens"] > 0, "Should have positive prompt tokens"
        assert usage["completion_tokens"] > 0, "Should have positive completion tokens"
        
        logger.info(f"FV_MPV_RESP_CHAT_USAGE_BEDROCK_001: Bedrock usage normalized - {usage}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_resp_chat_usage_vertexai_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """FV_MPV_RESP_CHAT_USAGE_VERTEXAI_001: Test Vertex AI usage metric normalization"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        vertex_models = [model for model in chat_models 
                        if any(provider in model.lower() for provider in ["vertex", "gemini"])]
        
        if not vertex_models:
            pytest.skip("No Vertex AI models configured")
        
        request = {
            "model": vertex_models[0],
            "messages": [{"role": "user", "content": "Test Vertex AI usage metric normalization"}],
            "max_tokens": 80
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify Vertex AI usage is normalized to OpenAI format
        assert "usage" in response_data
        usage = response_data["usage"]
        
        assert all(field in usage for field in ["prompt_tokens", "completion_tokens", "total_tokens"])
        assert all(isinstance(usage[field], int) for field in ["prompt_tokens", "completion_tokens", "total_tokens"])
        assert usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"]
        
        logger.info(f"FV_MPV_RESP_CHAT_USAGE_VERTEXAI_001: Vertex AI usage normalized - {usage}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_resp_embed_vector_bedrock_001(self, http_client: httpx.AsyncClient,
                                                       embedding_auth_headers: Dict[str, str],
                                                       make_request):
        """FV_MPV_RESP_EMBED_VECTOR_BEDROCK_001: Test Bedrock embedding normalization"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        embedding_models = config.get_embedding_models() if config.get_embedding_models() else []
        bedrock_embed_models = [model for model in embedding_models 
                               if any(provider in model.lower() for provider in ["bedrock", "titan", "cohere"])]
        
        if not bedrock_embed_models:
            pytest.skip("No Bedrock embedding models configured")
        
        request = {
            "model": bedrock_embed_models[0],
            "input": "Test Bedrock embedding normalization"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify normalized OpenAI embedding format
        assert "object" in response_data, "Should have object field"
        assert response_data["object"] == "list", "Object should be 'list'"
        assert "data" in response_data, "Should have data array"
        assert "model" in response_data, "Should have model field"
        
        # Verify embedding data structure
        embedding_data = response_data["data"][0]
        assert "object" in embedding_data, "Embedding should have object field"
        assert embedding_data["object"] == "embedding", "Embedding object should be 'embedding'"
        assert "embedding" in embedding_data, "Should have embedding vector"
        assert "index" in embedding_data, "Should have index"
        
        # Verify embedding vector
        embedding = embedding_data["embedding"]
        assert isinstance(embedding, list), "Embedding should be list"
        assert len(embedding) > 0, "Embedding should not be empty"
        assert all(isinstance(x, (int, float)) for x in embedding), "All values should be numeric"
        
        logger.info(f"FV_MPV_RESP_EMBED_VECTOR_BEDROCK_001: Bedrock embedding normalized - {len(embedding)} dimensions")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_resp_embed_vector_vertexai_001(self, http_client: httpx.AsyncClient,
                                                        embedding_auth_headers: Dict[str, str],
                                                        make_request):
        """FV_MPV_RESP_EMBED_VECTOR_VERTEXAI_001: Test Vertex AI embedding normalization"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        embedding_models = config.get_embedding_models() if config.get_embedding_models() else []
        vertex_embed_models = [model for model in embedding_models 
                              if any(provider in model.lower() for provider in ["vertex", "textembedding"])]
        
        if not vertex_embed_models:
            pytest.skip("No Vertex AI embedding models configured")
        
        request = {
            "model": vertex_embed_models[0],
            "input": "Test Vertex AI embedding normalization"
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Verify Vertex AI embedding is normalized to OpenAI format
        assert response_data["object"] == "list"
        assert "data" in response_data
        
        embedding_data = response_data["data"][0]
        assert embedding_data["object"] == "embedding"
        assert "embedding" in embedding_data
        
        embedding = embedding_data["embedding"]
        assert isinstance(embedding, list)
        assert len(embedding) > 0
        assert all(isinstance(x, (int, float)) for x in embedding)
        
        logger.info(f"FV_MPV_RESP_EMBED_VECTOR_VERTEXAI_001: Vertex AI embedding normalized - {len(embedding)} dimensions")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_resp_error_translation_bedrock_001(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """FV_MPV_RESP_ERROR_TRANSLATION_BEDROCK_001: Test Bedrock error translation"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        bedrock_models = [model for model in chat_models 
                         if any(provider in model.lower() for provider in ["bedrock", "anthropic"])]
        
        if not bedrock_models:
            pytest.skip("No Bedrock models configured")
        
        # Trigger Bedrock-specific errors
        error_scenarios = [
            {
                "model": bedrock_models[0],
                "messages": [{"role": "user", "content": "Test error"}],
                "max_tokens": -1,  # Invalid value
                "description": "Invalid max_tokens"
            },
            {
                "model": bedrock_models[0],
                "messages": [{"role": "invalid", "content": "Test error"}],
                "max_tokens": 50,
                "description": "Invalid role"
            }
        ]
        
        for scenario in error_scenarios:
            description = scenario.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario, track_cost=False
            )
            
            assert response.status_code == 422, f"Bedrock error should be translated to 422: {description}"
            
            response_data = response.json()
            assert "detail" in response_data, f"Error should have detail field: {description}"
            
            # Verify error is properly translated to standard format
            # Should not expose Bedrock-specific error internals
            error_text = str(response_data["detail"]).lower()
            internal_terms = ["bedrock", "boto3", "aws", "exception", "traceback"]
            for term in internal_terms:
                if term in error_text and term not in ["aws", "bedrock"]:  # Provider names might be OK
                    logger.warning(f"Bedrock error might expose internal term: {term}")
            
            logger.info(f"FV_MPV_RESP_ERROR_TRANSLATION_BEDROCK_001: {description} error translated")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_resp_error_translation_vertexai_001(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """FV_MPV_RESP_ERROR_TRANSLATION_VERTEXAI_001: Test Vertex AI error translation"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        vertex_models = [model for model in chat_models 
                        if any(provider in model.lower() for provider in ["vertex", "gemini"])]
        
        if not vertex_models:
            pytest.skip("No Vertex AI models configured")
        
        # Trigger Vertex AI specific errors
        vertex_error_scenarios = [
            {
                "model": vertex_models[0],
                "messages": [{"role": "user", "content": "Test"}],
                "temperature": -1.0,  # Invalid for Vertex AI
                "max_tokens": 50,
                "description": "Invalid temperature"
            },
            {
                "model": vertex_models[0],
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 0,  # Invalid value
                "description": "Zero max_tokens"
            }
        ]
        
        for scenario in vertex_error_scenarios:
            description = scenario.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario, track_cost=False
            )
            
            assert response.status_code == 422, f"Vertex AI error should be translated: {description}"
            
            response_data = response.json()
            assert "detail" in response_data
            
            # Should not expose Vertex AI internals
            error_text = str(response_data["detail"]).lower()
            internal_terms = ["vertex", "google", "grpc", "invalidargument", "internal"]
            for term in internal_terms:
                if term in error_text and term not in ["google", "vertex"]:  # Provider names might be OK
                    logger.warning(f"Vertex AI error might expose internal term: {term}")
            
            logger.info(f"FV_MPV_RESP_ERROR_TRANSLATION_VERTEXAI_001: {description} error translated")


class TestFeatureParity:
    """Test feature parity and consistency across providers"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_feature_unsupported_param_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_MPV_FEATURE_UNSUPPORTED_PARAM_001: Test unsupported parameter handling"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test parameters that might not be supported by all providers
        unsupported_params = [
            {
                "frequency_penalty": 0.5,
                "description": "frequency_penalty"
            },
            {
                "presence_penalty": 0.3,
                "description": "presence_penalty"
            },
            {
                "logit_bias": {"50256": -100},
                "description": "logit_bias"
            },
            {
                "user": "test-user-123",
                "description": "user parameter"
            }
        ]
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for model in chat_models[:2]:  # Test first 2 models
            for param_test in unsupported_params:
                description = param_test.pop("description")
                
                request = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Test {description}"}],
                    "max_tokens": 50,
                    **param_test
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                if response.status_code == 200:
                    # Parameter supported or silently ignored
                    logger.info(f"FV_MPV_FEATURE_UNSUPPORTED_PARAM_001: {model} supports {description}")
                elif response.status_code == 422:
                    # Parameter not supported - should give clear error
                    response_data = response.json()
                    detail = str(response_data.get("detail", "")).lower()
                    assert description.lower().replace("_", "") in detail or "parameter" in detail or "unsupported" in detail, \
                        f"Error should clearly indicate unsupported parameter: {description}"
                    logger.info(f"FV_MPV_FEATURE_UNSUPPORTED_PARAM_001: {model} doesn't support {description}")
                else:
                    logger.info(f"FV_MPV_FEATURE_UNSUPPORTED_PARAM_001: {model} returned {response.status_code} for {description}")
                
                # Restore parameter for next iteration
                param_test[description] = param_test.get(description)
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_feature_stream_consistency_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """FV_MPV_FEATURE_STREAM_CONSISTENCY_001: Test streaming consistency across providers"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        streaming_results = {}
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for model in chat_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Count to 3 slowly"}],
                "max_tokens": 30,
                "stream": True
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            streaming_results[model] = {
                "status_code": response.status_code,
                "supports_streaming": False,
                "content_type": response.headers.get("content-type", "")
            }
            
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                if content_type.startswith("text/event-stream"):
                    streaming_results[model]["supports_streaming"] = True
                    logger.info(f"FV_MPV_FEATURE_STREAM_CONSISTENCY_001: {model} supports streaming")
                else:
                    logger.info(f"FV_MPV_FEATURE_STREAM_CONSISTENCY_001: {model} fallback to non-streaming")
            elif response.status_code == 422:
                logger.info(f"FV_MPV_FEATURE_STREAM_CONSISTENCY_001: {model} doesn't support streaming")
            else:
                logger.info(f"FV_MPV_FEATURE_STREAM_CONSISTENCY_001: {model} streaming returned {response.status_code}")
        
        # Analyze streaming support consistency
        streaming_models = [model for model, result in streaming_results.items() if result["supports_streaming"]]
        non_streaming_models = [model for model, result in streaming_results.items() if not result["supports_streaming"]]
        
        logger.info(f"FV_MPV_FEATURE_STREAM_CONSISTENCY_001: {len(streaming_models)} models support streaming, {len(non_streaming_models)} don't")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_model_selection_bedrock_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """FV_MPV_MODEL_SELECTION_BEDROCK_001: Test Bedrock model routing"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        bedrock_models = [model for model in chat_models 
                         if any(provider in model.lower() for provider in ["bedrock", "anthropic", "amazon", "claude", "titan"])]
        
        if not bedrock_models:
            pytest.skip("No Bedrock models configured")
        
        for model in bedrock_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": f"Test {model} routing"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Bedrock model {model} should be routable"
            
            response_data = response.json()
            returned_model = response_data.get("model", "")
            
            # Verify model routing is correct
            assert model in returned_model or returned_model in model, \
                f"Returned model {returned_model} should match requested {model}"
            
            logger.info(f"FV_MPV_MODEL_SELECTION_BEDROCK_001: {model} -> {returned_model}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_model_selection_vertexai_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """FV_MPV_MODEL_SELECTION_VERTEXAI_001: Test Vertex AI model routing"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        vertex_models = [model for model in chat_models 
                        if any(provider in model.lower() for provider in ["vertex", "gemini", "bison", "google"])]
        
        if not vertex_models:
            pytest.skip("No Vertex AI models configured")
        
        for model in vertex_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": f"Test {model} routing"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Vertex AI model {model} should be routable"
            
            response_data = response.json()
            returned_model = response_data.get("model", "")
            
            # Verify model routing
            assert model in returned_model or returned_model in model, \
                f"Returned model {returned_model} should match requested {model}"
            
            logger.info(f"FV_MPV_MODEL_SELECTION_VERTEXAI_001: {model} -> {returned_model}")


class TestProviderSpecificValidation:
    """Test provider-specific validation and behavior"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_provider_parameter_ranges_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """FV_MPV_PROVIDER_PARAMETER_RANGES_001: Test provider-specific parameter ranges"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test parameter ranges that differ between providers
        parameter_range_tests = [
            # Temperature range tests
            {"temperature": 0.0, "description": "minimum temperature"},
            {"temperature": 1.0, "description": "standard temperature"},
            {"temperature": 2.0, "description": "high temperature"},
            
            # max_tokens tests
            {"max_tokens": 1, "description": "minimum tokens"},
            {"max_tokens": 100, "description": "standard tokens"},
            {"max_tokens": 2000, "description": "high token count"},
        ]
        
        provider_results = {}
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for model in chat_models[:3]:  # Test first 3 models
            provider_results[model] = {}
            
            for test in parameter_range_tests:
                description = test["description"]
                
                request = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Test {description}"}],
                    "max_tokens": 50  # Default, will be overridden if in test
                }
                request.update({k: v for k, v in test.items() if k != "description"})
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                provider_results[model][description] = {
                    "status_code": response.status_code,
                    "supported": response.status_code == 200
                }
                
                if response.status_code == 200:
                    logger.info(f"FV_MPV_PROVIDER_PARAMETER_RANGES_001: {model} supports {description}")
                elif response.status_code == 422:
                    logger.info(f"FV_MPV_PROVIDER_PARAMETER_RANGES_001: {model} rejects {description}")
        
        # Analyze parameter support differences
        for description in [test["description"] for test in parameter_range_tests]:
            supporting_models = [model for model, results in provider_results.items() 
                               if results.get(description, {}).get("supported", False)]
            logger.info(f"FV_MPV_PROVIDER_PARAMETER_RANGES_001: {len(supporting_models)} models support {description}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_mpv_provider_consistency_validation_001(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """FV_MPV_PROVIDER_CONSISTENCY_VALIDATION_001: Test cross-provider consistency"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test same request across all providers
        consistency_prompt = "What is 2+2?"
        consistency_request = {
            "messages": [{"role": "user", "content": consistency_prompt}],
            "max_tokens": 20,
            "temperature": 0.0  # Deterministic
        }
        
        model_responses = {}
        
        chat_models = config.get_chat_models() if config.get_chat_models() else []
        for model in chat_models:
            request = {"model": model, **consistency_request}
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"].strip().lower()
                usage = response_data.get("usage", {})
                
                model_responses[model] = {
                    "content": content,
                    "usage": usage,
                    "contains_four": "4" in content or "four" in content
                }
                
                logger.info(f"FV_MPV_PROVIDER_CONSISTENCY_VALIDATION_001: {model}: '{content}' (correct: {model_responses[model]['contains_four']})")
        
        # Analyze consistency
        if len(model_responses) >= 2:
            correct_answers = sum(1 for resp in model_responses.values() if resp["contains_four"])
            logger.info(f"FV_MPV_PROVIDER_CONSISTENCY_VALIDATION_001: {correct_answers}/{len(model_responses)} models gave correct answer")
            
            # Check for reasonable consistency in simple arithmetic
            if len(model_responses) >= 2:
                consistency_rate = correct_answers / len(model_responses)
                assert consistency_rate >= 0.5, "At least half the models should get simple arithmetic correct"
        
        logger.info(f"FV_MPV_PROVIDER_CONSISTENCY_VALIDATION_001: Tested {len(model_responses)} models for consistency")