# tests/integration/7_2_ModelValidation.py
# Tests for Model Validation and Capability Matching
# Aligned with TestPlan.md Section 7.2 - Functional and Validation Testing

import pytest
import httpx
from typing import Dict, Any
from .config import config


@pytest.fixture
def auth_headers() -> Dict[str, str]:
    """Valid authorization headers for live API."""
    return config.get_auth_headers()


@pytest.fixture
def http_client():
    """Create an HTTP client for making requests."""
    with httpx.Client(timeout=config.TIMEOUT) as client:
        yield client


class TestModelValidation:
    """Test cases for model validation and capability matching"""

    def test_unsupported_model_id_chat_completions(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_MODEL_CHAT_001: Unsupported model ID for chat completions.
        
        Expected: 400 or 422 error indicating model is not supported.
        """
        payload = {
            "model": "non_existent_model_123_definitely_fake",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 10
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code in [400, 422], f"Expected error status, got {response.status_code}"
        
        error_data = response.json()
        error_message = str(error_data).lower()
        
        # Should indicate model is not supported/available
        assert any(keyword in error_message for keyword in [
            "not supported", "not available", "invalid model", "unknown model", "not found"
        ]), f"Error message should indicate unsupported model: {error_data}"

    def test_unsupported_model_id_embeddings(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_MODEL_EMBED_001: Unsupported model ID for embeddings.
        
        Expected: 400 or 422 error indicating model is not supported.
        """
        payload = {
            "model": "unknown_embedding_model_456_fake",
            "input": "Test embedding text"
        }
        
        response = http_client.post(f"{config.BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        assert response.status_code in [400, 422]
        
        error_data = response.json()
        error_message = str(error_data).lower()
        
        assert any(keyword in error_message for keyword in [
            "not supported", "not available", "invalid model", "unknown model", "not found"
        ])

    def test_embedding_model_for_chat_capability_mismatch(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_MODEL_CHAT_002: Using embedding model for chat completions.
        
        Expected: Error indicating capability mismatch.
        """
        payload = {
            "model": config.get_embedding_model(),  # Use actual embedding model
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 10
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code in [400, 422]
        
        error_data = response.json()
        error_message = str(error_data).lower()
        
        # Should indicate capability mismatch or that chat is not supported for this model
        assert any(keyword in error_message for keyword in [
            "capability", "not support", "chat", "embedding", "incompatible"
        ])

    def test_chat_model_for_embeddings_capability_mismatch(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_MODEL_EMBED_002: Using chat model for embeddings.
        
        Expected: Error indicating capability mismatch.
        """
        payload = {
            "model": config.get_chat_model(),  # Use actual chat model
            "input": "Test embedding text"
        }
        
        response = http_client.post(f"{config.BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        assert response.status_code in [400, 422]
        
        error_data = response.json()
        error_message = str(error_data).lower()
        
        # Should indicate capability mismatch
        assert any(keyword in error_message for keyword in [
            "capability", "not support", "embedding", "chat", "incompatible"
        ])

    def test_valid_chat_model_positive_case(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_MODEL_CHAT_003: Valid chat model should work correctly.
        
        Expected: Successful response with proper structure.
        """
        payload = {
            "model": config.get_chat_model(),
            "messages": [{"role": "user", "content": "Say 'test successful'"}],
            "max_tokens": 20
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code == 200
        
        data = response.json()
        assert "choices" in data
        assert len(data["choices"]) > 0
        assert "message" in data["choices"][0]
        assert "content" in data["choices"][0]["message"]
        assert data["model"] == config.get_chat_model()

    def test_valid_embedding_model_positive_case(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_MODEL_EMBED_003: Valid embedding model should work correctly.
        
        Expected: Successful response with proper embedding structure.
        """
        payload = {
            "model": config.get_embedding_model(),
            "input": "This is a test sentence for embedding"
        }
        
        response = http_client.post(f"{config.BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        assert response.status_code == 200
        
        data = response.json()
        assert "data" in data
        assert len(data["data"]) > 0
        assert "embedding" in data["data"][0]
        assert isinstance(data["data"][0]["embedding"], list)
        assert len(data["data"][0]["embedding"]) > 0
        
        # Flexible model name checking - API may return different format
        returned_model = data["model"]
        expected_model = config.get_embedding_model()
        
        # Check if models match or are variants (cohere_english_v3 vs cohere.embed-english-v3)
        assert (returned_model == expected_model or 
                "cohere" in returned_model.lower() and "english" in returned_model.lower() and "v3" in returned_model), \
            f"Expected model variant of {expected_model}, got {returned_model}"

    def test_model_discovery_and_validation(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test model discovery through /models endpoint and validate capabilities.
        
        Expected: Models endpoint should return valid models with correct capabilities.
        """
        # Get available models
        response = http_client.get(f"{config.BASE_URL}/models", headers=auth_headers)
        assert response.status_code == 200
        
        models = response.json()
        assert isinstance(models, list)
        assert len(models) > 0
        
        chat_models = []
        embedding_models = []
        
        # Categorize models by capability
        for model in models:
            assert "id" in model
            assert "capability" in model
            assert model["capability"] in ["chat", "embedding"]
            
            if model["capability"] == "chat":
                chat_models.append(model["id"])
            elif model["capability"] == "embedding":
                embedding_models.append(model["id"])
        
        # Verify we have both types
        assert len(chat_models) > 0, "Should have at least one chat model"
        assert len(embedding_models) > 0, "Should have at least one embedding model"
        
        # Test that configured models are in the discovered models
        assert config.get_chat_model() in chat_models, f"Configured chat model {config.get_chat_model()} not found in API"
        assert config.get_embedding_model() in embedding_models, f"Configured embedding model {config.get_embedding_model()} not found in API"

    def test_case_sensitive_model_names(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test that model names are case-sensitive.
        
        Expected: Wrong case should result in model not found error.
        """
        original_model = config.get_chat_model()
        
        # Test various case variations
        case_variations = [
            original_model.upper(),
            original_model.capitalize(),
            original_model.title()
        ]
        
        for variant in case_variations:
            if variant != original_model:  # Only test if actually different
                payload = {
                    "model": variant,
                    "messages": [{"role": "user", "content": "Test"}],
                    "max_tokens": 10
                }
                
                response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
                
                # Should fail with model not found
                assert response.status_code in [400, 422], \
                    f"Case variant {variant} should not work for {original_model}"

    def test_model_name_with_special_characters(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test model names with special characters and edge cases.
        
        Expected: Invalid model names should be rejected appropriately.
        """
        invalid_model_names = [
            "",  # Empty string
            " ",  # Whitespace
            "model with spaces",
            "model/with/slashes",
            "model-with-unicode-café",
            "model\nwith\nnewlines",
            "model\twith\ttabs",
            "model<script>alert(1)</script>",  # XSS attempt
            "'; DROP TABLE models; --",  # SQL injection attempt
            "model" + "x" * 1000,  # Very long name
        ]
        
        for invalid_model in invalid_model_names:
            payload = {
                "model": invalid_model,
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 10
            }
            
            response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            # Should reject invalid model names
            assert response.status_code in [400, 422], \
                f"Invalid model name '{invalid_model}' should be rejected"

    def test_multiple_models_same_capability(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test that multiple models with the same capability work correctly.
        
        Expected: All chat models should work for chat, all embedding models for embeddings.
        """
        # Test multiple chat models if available
        for i, chat_model in enumerate(config.CHAT_MODELS[:3]):  # Test up to 3 models
            payload = {
                "model": chat_model,
                "messages": [{"role": "user", "content": f"Test model {i+1}"}],
                "max_tokens": 10
            }
            
            response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            assert response.status_code == 200, f"Chat model {chat_model} should work"
            
            data = response.json()
            assert data["model"] == chat_model
        
        # Test multiple embedding models if available
        for i, embedding_model in enumerate(config.EMBEDDING_MODELS[:2]):  # Test up to 2 models
            payload = {
                "model": embedding_model,
                "input": f"Test embedding model {i+1}"
            }
            
            response = http_client.post(f"{config.BASE_URL}/embeddings", json=payload, headers=auth_headers)
            assert response.status_code == 200, f"Embedding model {embedding_model} should work"
            
            data = response.json()
            returned_model = data["model"]
            
            # Flexible model name checking
            assert (returned_model == embedding_model or 
                    any(part in returned_model.lower() for part in embedding_model.lower().split('_'))), \
                f"Expected model variant of {embedding_model}, got {returned_model}"

    def test_model_parameter_validation_in_complex_requests(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test model validation in requests with many parameters.
        
        Expected: Model validation should work regardless of other parameters.
        """
        complex_payload = {
            "model": "definitely_invalid_model_name_12345",
            "messages": [{"role": "user", "content": "Complex test"}],
            "max_tokens": 50,
            "temperature": 0.7,
            "top_p": 0.9,
            "frequency_penalty": 0.0,
            "presence_penalty": 0.0,
            "stop": [".", "!"],
            "user": "test_user"
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=complex_payload, headers=auth_headers)
        
        # Should fail due to invalid model, not other parameters
        assert response.status_code in [400, 422]
        
        error_message = str(response.json()).lower()
        assert "model" in error_message


if __name__ == "__main__":
    pytest.main([__file__, "-v"])