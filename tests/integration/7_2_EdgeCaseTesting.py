# tests/integration/7_2_EdgeCaseTesting.py
# Tests for Edge Cases and Boundary Testing
# Aligned with TestPlan.md Section 7.2 - Functional and Validation Testing (Edge Cases)

import pytest
import httpx
from typing import Dict, Any, List, Union
import json

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


class TestEdgeCases:
    """Test cases for edge cases and boundary conditions"""

    # --- Numeric Parameter Boundaries ---
    
    def test_temperature_minimum_boundary(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_NUM_001: Test temperature at minimum valid value (0.0).
        
        Expected: Should accept and process with deterministic output.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "What is 2+2?"}],
            "temperature": 0.0,
            "max_tokens": 20
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "choices" in data
        # With temperature 0, responses should be deterministic

    def test_temperature_maximum_boundary(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_NUM_002: Test temperature at maximum valid value (2.0).
        
        Expected: Should accept and process with high randomness.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Say something random"}],
            "temperature": 2.0,
            "max_tokens": 20
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code == 200
        assert "choices" in response.json()

    def test_max_tokens_minimum_value(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_NUM_003: Test max_tokens at minimum valid value (1).
        
        Expected: Should return very short response.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Tell me a very long story"}],
            "max_tokens": 1
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "choices" in data
        # Response should be truncated
        assert data["usage"]["completion_tokens"] <= 1

    def test_max_tokens_large_value(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_NUM_004: Test max_tokens with very large value.
        
        Expected: Should cap at model's maximum or handle gracefully.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Hi"}],
            "max_tokens": 100000  # Very large value
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        # Should either accept (200) or reject with appropriate error (400/422)
        assert response.status_code in [200, 400, 422]

    def test_embedding_dimensions_edge_cases(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_NUM_005: Test dimensions parameter for embeddings.
        
        Expected: Should handle dimension requests appropriately.
        """
        # Test with small dimensions (if supported by model)
        payload = {
            "model": EMBEDDING_MODELS[0],
            "input": "Test embedding",
            "dimensions": 256  # Smaller than default
        }
        
        response = http_client.post(f"{BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        if response.status_code == 200:
            data = response.json()
            embedding = data["data"][0]["embedding"]
            # If dimensions parameter is supported, check length
            if "dimensions" in str(response.text):
                assert len(embedding) == 256
        else:
            # Model might not support dimensions parameter
            assert response.status_code in [400, 422]

    # --- Text/String Edge Cases ---

    def test_empty_message_content(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_TEXT_001: Test with empty string message content.
        
        Expected: Should handle empty content appropriately.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": ""}],
            "max_tokens": 20
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        # May accept (200) or reject (400) empty content
        assert response.status_code in [200, 400, 422]

    def test_very_long_message_content(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_TEXT_002: Test with extremely long message.
        
        Expected: Should handle or reject gracefully.
        """
        # Create a message near typical context limit
        long_content = "Hello world. " * 5000  # ~65k characters
        
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": long_content}],
            "max_tokens": 10
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        # Should either process (200) or return appropriate error
        assert response.status_code in [200, 400, 413, 422]

    def test_special_unicode_characters(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_TEXT_003: Test with special Unicode characters.
        
        Expected: Should handle Unicode properly.
        """
        special_strings = [
            "\u0000",  # Null character
            "\u200b\u200c\u200d",  # Zero-width characters
            "🔥💧🌍🌪️",  # Emojis
            "𝕳𝖊𝖑𝖑𝖔",  # Mathematical alphanumeric symbols
            "\uffff",  # Highest UTF-16 character
            "A" + "\u0301",  # Combining diacritical marks
        ]
        
        for special_str in special_strings:
            payload = {
                "model": CHAT_MODELS[0],
                "messages": [{"role": "user", "content": f"Repeat: {special_str}"}],
                "max_tokens": 50
            }
            
            response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            assert response.status_code in [200, 400]  # Should handle or reject gracefully

    # --- Array/List Edge Cases ---

    def test_single_message_conversation(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_ARRAY_001: Test with minimal single message.
        
        Expected: Should process single user message.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Hi"}],
            "max_tokens": 20
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code == 200

    def test_very_long_conversation_history(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_ARRAY_002: Test with extremely long conversation history.
        
        Expected: Should handle or truncate appropriately.
        """
        # Build a conversation with 100 turns
        messages = []
        for i in range(50):
            messages.append({"role": "user", "content": f"Question {i}"})
            messages.append({"role": "assistant", "content": f"Answer {i}"})
        
        payload = {
            "model": CHAT_MODELS[0],
            "messages": messages,
            "max_tokens": 10
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code in [200, 400, 413]

    def test_embedding_with_array_input(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_ARRAY_003: Test embeddings with array of strings.
        
        Expected: Should generate multiple embeddings.
        """
        payload = {
            "model": EMBEDDING_MODELS[0],
            "input": ["First text", "Second text", "Third text"]
        }
        
        response = http_client.post(f"{BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should return embeddings for each input
            assert len(data["data"]) == 3
            for i, embedding_obj in enumerate(data["data"]):
                assert embedding_obj["index"] == i
                assert isinstance(embedding_obj["embedding"], list)

    def test_large_batch_embeddings(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_ARRAY_004: Test embeddings with large batch.
        
        Expected: Should process or return batch size error.
        """
        # Try 100 texts
        large_batch = [f"Text number {i}" for i in range(100)]
        
        payload = {
            "model": EMBEDDING_MODELS[0],
            "input": large_batch
        }
        
        response = http_client.post(f"{BASE_URL}/embeddings", json=payload, headers=auth_headers)
        # Should either process all or return batch limit error
        assert response.status_code in [200, 400, 413]

    # --- Mixed Content Types ---

    def test_message_with_mixed_content_types(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_BODY_MIXED_001: Test message with text and image content.
        
        Expected: Should handle if model supports multimodal, otherwise error.
        """
        # Small valid image data URI
        image_uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
        
        payload = {
            "model": CHAT_MODELS[0],  # May or may not support images
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "What is in this image?"},
                    {"type": "image_url", "image_url": {"url": image_uri}}
                ]
            }],
            "max_tokens": 50
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        # Model either supports (200) or doesn't support images (400)
        assert response.status_code in [200, 400, 422]

    # --- Optional Parameter Combinations ---

    def test_all_optional_parameters(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_PARAMS_001: Test with all optional parameters set.
        
        Expected: Should handle complete parameter set.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Test"}],
            "max_tokens": 50,
            "temperature": 0.7,
            "top_p": 0.9,
            "n": 1,
            "stream": False,
            "stop": [".", "!"],
            "presence_penalty": 0.0,
            "frequency_penalty": 0.0,
            "user": "test_user_123"
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code == 200

    def test_conflicting_parameters(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_PARAMS_002: Test with potentially conflicting parameters.
        
        Expected: Should handle or validate parameter conflicts.
        """
        # Temperature and top_p both affect randomness
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Test"}],
            "temperature": 2.0,  # Maximum randomness
            "top_p": 0.1,  # Minimum token pool
            "max_tokens": 20
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        # Should handle the combination
        assert response.status_code in [200, 400]

    # --- System Message Edge Cases ---

    def test_multiple_system_messages(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_SYSTEM_001: Test with multiple system messages.
        
        Expected: Model-dependent behavior.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "system", "content": "You always respond in haiku."},
                {"role": "user", "content": "What is the weather?"}
            ],
            "max_tokens": 50
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        # Different models handle multiple system messages differently
        assert response.status_code in [200, 400]

    def test_system_message_after_user_message(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        EC_SYSTEM_002: Test system message after user message.
        
        Expected: Model-dependent validation.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "system", "content": "You are a pirate"},
                {"role": "user", "content": "How are you?"}
            ],
            "max_tokens": 50
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code in [200, 400]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])