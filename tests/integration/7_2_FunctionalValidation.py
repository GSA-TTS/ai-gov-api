# tests/integration/7_2_FunctionalValidation.py
# Tests for Functional and Validation Testing
# Aligned with TestPlan.md Section 7.2 - Functional and Validation Testing

import pytest
import httpx
from typing import Dict, Any, List
import base64

# Live API endpoint configuration
BASE_URL = "https://api.dev.aigov.mcaas.fcs.gsa.gov/api/v1"
TEST_API_KEY = "test_adm_HwYbweaBtJmeo_Ec"  # From tests.eml

# Available models from the live API
CHAT_MODELS = ["claude_3_5_sonnet", "claude_3_7_sonnet", "gemini-2.0-flash", "llama3_8b"]
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


@pytest.fixture
def valid_image_data_uri() -> str:
    """A minimal valid base64 image for testing."""
    # 1x1 transparent PNG
    return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="


class TestInputValidation:
    """Test cases for input validation as per Section 7.2 - Functional and Validation Testing"""

    # --- Chat Completions Input Validation ---
    
    def test_chat_missing_model_field(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_CHAT_001: Missing 'model' field in chat completions.
        
        Expected: 422 Unprocessable Entity with field location in error.
        """
        payload = {"messages": [{"role": "user", "content": "Hello"}]}
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"
        error_detail = response.json()["detail"]
        assert any(
            err["loc"] == ["body", "model"] and err["type"] == "missing" 
            for err in error_detail
        ), f"Expected missing model error, got: {error_detail}"

    def test_chat_missing_messages_field(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_CHAT_002: Missing 'messages' field in chat completions.
        
        Expected: 422 with missing messages error.
        """
        payload = {"model": CHAT_MODELS[0]}
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code == 422
        error_detail = response.json()["detail"]
        assert any(
            err["loc"] == ["body", "messages"] and err["type"] == "missing"
            for err in error_detail
        )

    def test_chat_empty_messages_list(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_CHAT_003: Empty messages list.
        
        Expected: 422 or 400 - messages list cannot be empty.
        """
        payload = {"model": CHAT_MODELS[0], "messages": []}
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for empty messages, got {response.status_code}"

    def test_chat_invalid_role(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_CHAT_004: Invalid message role.
        
        Expected: 422 with role validation error.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "invalid_role", "content": "Hello"}]
        }
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code == 422
        error_detail = response.json()["detail"]
        assert any(
            err["loc"] == ["body", "messages", 0, "role"] 
            for err in error_detail
        )

    def test_chat_message_missing_content(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_CHAT_005: Message missing content field.
        
        Expected: 422 with missing content error.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user"}]  # Missing content
        }
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code == 422
        error_detail = response.json()["detail"]
        assert any(
            err["loc"] == ["body", "messages", 0, "content"] and err["type"] == "missing"
            for err in error_detail
        )

    def test_chat_invalid_temperature_range(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_CHAT_006: Temperature out of valid range.
        
        Expected: 422 for values outside 0-2 range.
        """
        invalid_temperatures = [-0.1, 2.1, 5.0, -10]
        
        for temp in invalid_temperatures:
            payload = {
                "model": CHAT_MODELS[0],
                "messages": [{"role": "user", "content": "Hello"}],
                "temperature": temp
            }
            response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            assert response.status_code == 422, \
                f"Temperature {temp} should be rejected"

    def test_chat_invalid_max_tokens(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_CHAT_007: Invalid max_tokens values.
        
        Expected: 422 for negative or zero values.
        """
        invalid_max_tokens = [0, -1, -100]
        
        for max_tokens in invalid_max_tokens:
            payload = {
                "model": CHAT_MODELS[0],
                "messages": [{"role": "user", "content": "Hello"}],
                "max_tokens": max_tokens
            }
            response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            assert response.status_code == 422, \
                f"max_tokens {max_tokens} should be rejected"

    def test_chat_invalid_model_type(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_CHAT_008: Model field with wrong type.
        
        Expected: 422 for non-string model values.
        """
        invalid_models = [123, True, None, ["model"], {"model": "test"}]
        
        for model in invalid_models:
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": "Hello"}]
            }
            response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            assert response.status_code == 422, \
                f"Model type {type(model)} should be rejected"

    # --- Embeddings Input Validation ---

    def test_embeddings_missing_model(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_EMBED_001: Missing model field in embeddings.
        
        Expected: 422 with missing model error.
        """
        payload = {"input": "Test text"}
        response = http_client.post(f"{BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        assert response.status_code == 422
        error_detail = response.json()["detail"]
        assert any(
            err["loc"] == ["body", "model"] and err["type"] == "missing"
            for err in error_detail
        )

    def test_embeddings_missing_input(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_EMBED_002: Missing input field in embeddings.
        
        Expected: 422 with missing input error.
        """
        payload = {"model": EMBEDDING_MODELS[0]}
        response = http_client.post(f"{BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        assert response.status_code == 422
        error_detail = response.json()["detail"]
        assert any(
            err["loc"] == ["body", "input"] and err["type"] == "missing"
            for err in error_detail
        )

    def test_embeddings_empty_input(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_EMBED_003: Empty input string or list.
        
        Expected: 400 or specific error for empty input.
        """
        empty_inputs = ["", []]
        
        for input_val in empty_inputs:
            payload = {"model": EMBEDDING_MODELS[0], "input": input_val}
            response = http_client.post(f"{BASE_URL}/embeddings", json=payload, headers=auth_headers)
            
            assert response.status_code in [400, 422], \
                f"Empty input should be rejected, got {response.status_code}"

    # --- Model Capability Validation ---

    def test_chat_model_for_embeddings(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test using a chat model for embeddings endpoint.
        
        Expected: 400 Bad Request - model capability mismatch.
        """
        payload = {
            "model": CHAT_MODELS[0],  # Chat model
            "input": "Test embedding"
        }
        response = http_client.post(f"{BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        assert response.status_code == 400, \
            f"Expected 400 for capability mismatch, got {response.status_code}"
        
        error_data = response.json()
        assert "capability" in str(error_data).lower() or "not available" in str(error_data).lower()

    def test_embedding_model_for_chat(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test using an embedding model for chat completions.
        
        Expected: 400 Bad Request - model capability mismatch.
        """
        payload = {
            "model": EMBEDDING_MODELS[0],  # Embedding model
            "messages": [{"role": "user", "content": "Hello"}]
        }
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code == 400
        error_data = response.json()
        assert "capability" in str(error_data).lower() or "not available" in str(error_data).lower()

    # --- Boundary Testing ---

    def test_max_message_length(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test very long message content.
        
        Expected: Should handle gracefully, either process or return appropriate error.
        """
        # Create a very long message (100k characters)
        long_content = "A" * 100000
        
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": long_content}],
            "max_tokens": 10  # Small response to avoid timeout
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        # Should either process (200) or return error (400/413/422)
        assert response.status_code in [200, 400, 413, 422], \
            f"Unexpected status for long message: {response.status_code}"

    def test_many_messages_in_conversation(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test conversation with many messages.
        
        Expected: Should handle or return appropriate error.
        """
        # Create 100 alternating messages
        messages = []
        for i in range(50):
            messages.append({"role": "user", "content": f"Question {i}"})
            messages.append({"role": "assistant", "content": f"Answer {i}"})
        messages.append({"role": "user", "content": "Final question"})
        
        payload = {
            "model": CHAT_MODELS[0],
            "messages": messages,
            "max_tokens": 10
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        # Should handle gracefully
        assert response.status_code in [200, 400, 413], \
            f"Unexpected status for many messages: {response.status_code}"

    # --- Schema Evolution Testing ---

    def test_unknown_fields_ignored(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test that unknown fields are handled gracefully (forward compatibility).
        
        Expected: Should ignore unknown fields and process request.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 50,
            # Unknown fields
            "future_feature": "test",
            "experimental_param": True,
            "version": "2.0"
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        # Should process successfully, ignoring unknown fields
        assert response.status_code == 200, \
            f"Should ignore unknown fields, got {response.status_code}: {response.text}"

    # --- Special Characters and Unicode ---

    def test_unicode_in_messages(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test Unicode characters in message content.
        
        Expected: Should handle Unicode properly.
        """
        unicode_tests = [
            "Hello 世界",  # Chinese
            "Привет мир",  # Russian
            "مرحبا بالعالم",  # Arabic (RTL)
            "🌍🌎🌏",  # Emoji
            "Café ñoño",  # Accented characters
            "\u200b\u200c\u200d",  # Zero-width characters
        ]
        
        for content in unicode_tests:
            payload = {
                "model": CHAT_MODELS[0],
                "messages": [{"role": "user", "content": content}],
                "max_tokens": 50
            }
            
            response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            assert response.status_code == 200, \
                f"Failed to handle Unicode: {content}"

    # --- Image Input Validation (if supported) ---

    def test_invalid_image_uri_format(self, http_client: httpx.Client, auth_headers: Dict[str, str], 
                                    valid_image_data_uri: str):
        """
        ECV_INPUT_CUSTOM_001: Invalid image URI format.
        
        Expected: 400 Bad Request for invalid formats.
        """
        invalid_uris = [
            "http://example.com/image.jpg",  # HTTP URL instead of data URI
            "data:image/invalid;base64,abc",  # Invalid MIME type
            "data:text/plain;base64,abc",  # Wrong content type
            "notadatauri",  # Completely invalid
        ]
        
        for uri in invalid_uris:
            payload = {
                "model": CHAT_MODELS[0],  # Assuming model supports images
                "messages": [{
                    "role": "user",
                    "content": [{
                        "type": "image_url",
                        "image_url": {"url": uri}
                    }]
                }]
            }
            
            response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            # Should reject invalid image URIs
            assert response.status_code in [400, 422], \
                f"Should reject invalid image URI: {uri}"

    def test_invalid_base64_in_image_uri(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_INPUT_CUSTOM_003: Invalid base64 data in image URI.
        
        Expected: 400 for invalid base64 encoding.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "image_url",
                    "image_url": {"url": "data:image/jpeg;base64,!!!not_base64!!!"}
                }]
            }]
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code in [400, 422], \
            "Should reject invalid base64 data"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])