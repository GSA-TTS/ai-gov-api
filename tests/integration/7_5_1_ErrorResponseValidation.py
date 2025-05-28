# tests/integration/7_5_1_ErrorResponseValidation.py
# Tests for Error Response Validation and API Call Sequences
# Aligned with TestPlan.md Section 7.5.1 - Error Response Validation

import pytest
import httpx
import asyncio
from typing import Dict, Any, List
import time

# Live API endpoint configuration
BASE_URL = "https://api.dev.aigov.mcaas.fcs.gsa.gov/api/v1"
TEST_API_KEY = "test_adm_HwYbweaBtJmeo_Ec"  # From tests.eml

# Available models
CHAT_MODELS = ["claude_3_5_sonnet", "gemini-2.0-flash", "llama3_8b"]
EMBEDDING_MODELS = ["cohere_english_v3", "text-embedding-005"]


@pytest.fixture
def auth_headers() -> Dict[str, str]:
    """Valid authorization headers for live API."""
    return {
        "Authorization": f"Bearer {TEST_API_KEY}",
        "Content-Type": "application/json"
    }


@pytest.fixture
def http_client():
    """Create an HTTP client for making requests."""
    with httpx.Client(timeout=30.0) as client:
        yield client


class TestAPICallSequences:
    """Test cases for API call sequences and error handling"""

    # --- Model Discovery and Usage Sequences ---
    
    def test_discover_and_use_chat_model(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_MODEL_DISCOVERY_001: Discover available models and use a chat model.
        
        Expected: Successfully discover models and complete a chat request.
        """
        # Step 1: GET /api/v1/models
        response_models = http_client.get(f"{BASE_URL}/models", headers=auth_headers)
        assert response_models.status_code == 200
        models_list = response_models.json()
        assert isinstance(models_list, list)
        
        # Step 2: Identify a chat model
        chat_model = None
        for model_info in models_list:
            if model_info.get("capability") == "chat":
                chat_model = model_info
                break
        
        assert chat_model is not None, "No chat model found in /models response"
        
        # Step 3: POST /api/v1/chat/completions
        chat_payload = {
            "model": chat_model["id"],
            "messages": [{"role": "user", "content": "Say 'Hello API'"}],
            "max_tokens": 50
        }
        
        response_chat = http_client.post(
            f"{BASE_URL}/chat/completions",
            json=chat_payload,
            headers=auth_headers
        )
        
        assert response_chat.status_code == 200
        chat_data = response_chat.json()
        assert chat_data["model"] == chat_model["id"]
        assert len(chat_data["choices"]) > 0
        assert "content" in chat_data["choices"][0]["message"]

    def test_discover_and_use_embedding_model(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_MODEL_DISCOVERY_002: Discover and use an embedding model.
        
        Expected: Successfully discover models and generate embeddings.
        """
        # Step 1: GET /api/v1/models
        response_models = http_client.get(f"{BASE_URL}/models", headers=auth_headers)
        assert response_models.status_code == 200
        models_list = response_models.json()
        
        # Step 2: Identify an embedding model
        embedding_model = None
        for model_info in models_list:
            if model_info.get("capability") == "embedding":
                embedding_model = model_info
                break
        
        assert embedding_model is not None, "No embedding model found"
        
        # Step 3: POST /api/v1/embeddings
        embed_payload = {
            "model": embedding_model["id"],
            "input": "Test embedding generation"
        }
        
        response_embed = http_client.post(
            f"{BASE_URL}/embeddings",
            json=embed_payload,
            headers=auth_headers
        )
        
        assert response_embed.status_code == 200
        embed_data = response_embed.json()
        assert embed_data["model"] == embedding_model["id"]
        assert len(embed_data["data"]) > 0
        assert isinstance(embed_data["data"][0]["embedding"], list)

    def test_model_capability_mismatch_sequence(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_MODEL_DISCOVERY_003: Attempt to use chat model for embeddings.
        
        Expected: 400 Bad Request due to capability mismatch.
        """
        # Use known chat model for embedding endpoint
        embed_payload = {
            "model": CHAT_MODELS[0],  # Chat model
            "input": "Test embedding"
        }
        
        response = http_client.post(
            f"{BASE_URL}/embeddings",
            json=embed_payload,
            headers=auth_headers
        )
        
        assert response.status_code == 400
        error_data = response.json()
        assert "error" in error_data
        assert "bad request" in str(error_data).lower() or "not available" in str(error_data).lower()

    # --- Multi-Turn Conversation Sequences ---
    
    def test_multi_turn_conversation(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_CONVERSATION_001: Multi-turn conversation maintaining context.
        
        Expected: Each response should be aware of previous context.
        """
        model = CHAT_MODELS[0]
        
        # Turn 1: Initial question
        messages = [{"role": "user", "content": "My name is TestUser. What's 2+2?"}]
        
        response1 = http_client.post(
            f"{BASE_URL}/chat/completions",
            json={"model": model, "messages": messages, "max_tokens": 50},
            headers=auth_headers
        )
        
        assert response1.status_code == 200
        data1 = response1.json()
        assistant_response1 = data1["choices"][0]["message"]["content"]
        
        # Turn 2: Follow-up referencing context
        messages.append({"role": "assistant", "content": assistant_response1})
        messages.append({"role": "user", "content": "What was my name?"})
        
        response2 = http_client.post(
            f"{BASE_URL}/chat/completions",
            json={"model": model, "messages": messages, "max_tokens": 50},
            headers=auth_headers
        )
        
        assert response2.status_code == 200
        data2 = response2.json()
        assistant_response2 = data2["choices"][0]["message"]["content"]
        
        # Check context was maintained (model should reference the name)
        assert "testuser" in assistant_response2.lower() or "test" in assistant_response2.lower()

    def test_conversation_token_accumulation(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_CONVERSATION_002: Track token usage across conversation turns.
        
        Expected: Token counts should accumulate properly.
        """
        model = CHAT_MODELS[0]
        messages = []
        total_prompt_tokens = 0
        
        # Multiple turns
        for i in range(3):
            messages.append({"role": "user", "content": f"Question {i}: What is {i}+{i}?"})
            
            response = http_client.post(
                f"{BASE_URL}/chat/completions",
                json={"model": model, "messages": messages, "max_tokens": 30},
                headers=auth_headers
            )
            
            assert response.status_code == 200
            data = response.json()
            
            # Track token usage
            usage = data["usage"]
            current_prompt_tokens = usage["prompt_tokens"]
            
            # Each turn should have more prompt tokens than the last
            assert current_prompt_tokens > total_prompt_tokens
            total_prompt_tokens = current_prompt_tokens
            
            # Add assistant response to conversation
            messages.append(data["choices"][0]["message"])

    # --- Concurrent Request Handling ---
    
    @pytest.mark.asyncio
    async def test_concurrent_requests_different_models(self):
        """
        SEQ_CONCURRENT_001: Concurrent requests to different models.
        
        Expected: All requests should complete successfully.
        """
        async def make_request(client: httpx.AsyncClient, model: str, headers: dict):
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": f"Test with {model}"}],
                "max_tokens": 20
            }
            return await client.post(
                f"{BASE_URL}/chat/completions",
                json=payload,
                headers=headers
            )
        
        headers = {"Authorization": f"Bearer {TEST_API_KEY}"}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Make concurrent requests to different models
            tasks = [
                make_request(client, model, headers)
                for model in CHAT_MODELS[:2]  # Use first 2 models
            ]
            
            responses = await asyncio.gather(*tasks)
            
            # All should succeed
            for response in responses:
                assert response.status_code == 200
                data = response.json()
                assert "choices" in data

    # --- Error Sequence Testing ---
    
    def test_error_recovery_sequence(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_ERROR_001: Error followed by successful request.
        
        Expected: System should recover gracefully from errors.
        """
        # Step 1: Make an invalid request
        invalid_payload = {
            "model": "nonexistent_model",
            "messages": [{"role": "user", "content": "Test"}]
        }
        
        error_response = http_client.post(
            f"{BASE_URL}/chat/completions",
            json=invalid_payload,
            headers=auth_headers
        )
        
        assert error_response.status_code in [400, 404]
        
        # Step 2: Make a valid request immediately after
        valid_payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Test recovery"}],
            "max_tokens": 20
        }
        
        success_response = http_client.post(
            f"{BASE_URL}/chat/completions",
            json=valid_payload,
            headers=auth_headers
        )
        
        assert success_response.status_code == 200
        data = success_response.json()
        assert "choices" in data

    def test_rate_limit_behavior_sequence(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_RATE_LIMIT_001: Test rate limit behavior with rapid requests.
        
        Expected: Should handle rate limits gracefully if encountered.
        """
        model = CHAT_MODELS[0]
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "Rate limit test"}],
            "max_tokens": 10
        }
        
        responses = []
        rate_limited = False
        
        # Make 10 rapid requests
        for i in range(10):
            response = http_client.post(
                f"{BASE_URL}/chat/completions",
                json=payload,
                headers=auth_headers
            )
            
            responses.append(response)
            
            if response.status_code == 429:
                rate_limited = True
                # Check for retry-after header
                assert "retry-after" in response.headers or "Retry-After" in response.headers
                break
            
            # Small delay to be respectful but still test limits
            time.sleep(0.1)
        
        # Either all succeed or we hit rate limit properly
        for response in responses:
            assert response.status_code in [200, 429]

    # --- Model Switching Sequences ---
    
    def test_provider_switching_sequence(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_PROVIDER_SWITCH_001: Switch between different provider models.
        
        Expected: Seamless switching between providers.
        """
        # Assuming we have models from different providers
        bedrock_model = "claude_3_5_sonnet"  # AWS Bedrock
        vertex_model = "gemini-2.0-flash"    # Google Vertex AI
        
        models_to_test = [bedrock_model, vertex_model]
        
        for model in models_to_test:
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": f"Testing {model}"}],
                "max_tokens": 20
            }
            
            response = http_client.post(
                f"{BASE_URL}/chat/completions",
                json=payload,
                headers=auth_headers
            )
            
            # Both should work seamlessly
            assert response.status_code == 200
            data = response.json()
            assert data["model"] == model

    # --- Streaming Response Sequences ---
    
    def test_streaming_response_sequence(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_STREAM_001: Test streaming response handling.
        
        Expected: Properly formatted SSE stream.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Count from 1 to 3"}],
            "stream": True,
            "max_tokens": 50
        }
        
        chunks_received = []
        
        with http_client.stream("POST", f"{BASE_URL}/chat/completions",
                               json=payload, headers=auth_headers) as response:
            
            assert response.status_code == 200
            assert "text/event-stream" in response.headers.get("content-type", "")
            
            for line in response.iter_lines():
                if line.startswith("data: "):
                    chunk_data = line[6:]
                    if chunk_data == "[DONE]":
                        break
                    chunks_received.append(chunk_data)
        
        assert len(chunks_received) > 0, "Should receive stream chunks"
        
        # Verify chunks are valid JSON
        for chunk in chunks_received:
            parsed = httpx._models.json.loads(chunk)
            assert "choices" in parsed

    def test_mixed_streaming_non_streaming(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        SEQ_STREAM_002: Alternate between streaming and non-streaming requests.
        
        Expected: Both modes should work correctly.
        """
        model = CHAT_MODELS[0]
        base_payload = {
            "model": model,
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 20
        }
        
        # Non-streaming request
        response1 = http_client.post(
            f"{BASE_URL}/chat/completions",
            json={**base_payload, "stream": False},
            headers=auth_headers
        )
        assert response1.status_code == 200
        assert "choices" in response1.json()
        
        # Streaming request
        with http_client.stream("POST", f"{BASE_URL}/chat/completions",
                              json={**base_payload, "stream": True},
                              headers=auth_headers) as response2:
            assert response2.status_code == 200
            chunks = []
            for line in response2.iter_lines():
                if line.startswith("data: ") and line != "data: [DONE]":
                    chunks.append(line)
            assert len(chunks) > 0
        
        # Another non-streaming request
        response3 = http_client.post(
            f"{BASE_URL}/chat/completions",
            json={**base_payload, "stream": False},
            headers=auth_headers
        )
        assert response3.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])