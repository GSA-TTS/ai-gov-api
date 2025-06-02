# tests/integration/7_9_DataPrivacyTesting.py
# Tests for Data Privacy and Anonymization
# Aligned with TestPlan.md Section 7.9 - Test Data Management Strategy

import pytest
import httpx
from typing import Dict, Any
from unittest.mock import patch, MagicMock
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


class TestDataPrivacyAndAnonymization:
    """Test cases for data privacy, anonymization, and PII handling"""

    def test_synthetic_pii_user_field_processing(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        TDH_ANON_001: API processes chat requests with synthetic/placeholder PII in the optional 'user' field.
        
        Expected: System should process synthetic user IDs without exposing them.
        """
        payload = {
            "model": config.get_chat_model(),
            "messages": [{"role": "user", "content": "Hello, this is a test."}],
            "user": "synthetic_user_id_abc123@test.example.com",
            "max_tokens": config.MAX_TOKENS
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "choices" in data
        
        # Verify synthetic user ID is not echoed in response
        response_text = str(data).lower()
        assert "synthetic_user_id_abc123" not in response_text
        assert "test.example.com" not in response_text

    def test_pii_placeholders_in_prompt_content(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        TDH_ANON_002: API processes chat requests with prompt content containing common PII placeholders.
        
        Expected: Placeholders should be processed as literal text, not expanded.
        """
        prompt_content = "Please assist user [NAME] regarding order [ORDER_ID] for product [PRODUCT_SKU]."
        payload = {
            "model": config.get_chat_model(),
            "messages": [{"role": "user", "content": prompt_content}],
            "max_tokens": config.MAX_TOKENS
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        response_content = data["choices"][0]["message"]["content"]
        
        # System should treat placeholders as literal text
        # Response might reference the placeholders but shouldn't expand them to real data
        assert not any(real_name in response_content.lower() 
                      for real_name in ["john", "jane", "smith", "johnson"])

    def test_pii_placeholders_in_embedding_input(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        TDH_ANON_003: API processes embedding requests with input text containing common PII placeholders.
        
        Expected: Embeddings should be generated without exposing placeholder expansion.
        """
        input_text = "User [USER_EMAIL_PLACEHOLDER] reported an issue with item [ITEM_SERIAL_NUMBER]."
        payload = {
            "model": config.get_embedding_model(),
            "input": input_text
        }
        
        response = http_client.post(f"{config.BASE_URL}/embeddings", json=payload, headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "data" in data
        assert len(data["data"]) > 0
        assert isinstance(data["data"][0]["embedding"], list)
        
        # Verify input text is not echoed in response
        response_str = str(data)
        assert "[USER_EMAIL_PLACEHOLDER]" not in response_str
        assert "[ITEM_SERIAL_NUMBER]" not in response_str

    def test_sensitive_data_not_in_error_messages(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        LEM_ANON_001: Verify sensitive data from prompts doesn't appear in error messages.
        
        Expected: Error messages should not contain user input data.
        """
        sensitive_content = "My SSN is SYNTHETIC_SSN_123456789 and my credit card is 4111-1111-1111-1111"
        
        # Send request with sensitive content to an invalid model to trigger error
        payload = {
            "model": "invalid_model_to_trigger_error",
            "messages": [{"role": "user", "content": sensitive_content}],
            "max_tokens": 10
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        # Should get an error response
        assert response.status_code in [400, 404, 422]
        
        error_data = response.json()
        error_str = str(error_data).lower()
        
        # Verify sensitive data is not in error response
        assert "synthetic_ssn_123456789" not in error_str
        assert "4111-1111-1111-1111" not in error_str
        assert "ssn" not in error_str
        assert "credit card" not in error_str

    def test_user_field_data_isolation(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test that user field data doesn't leak between requests.
        
        Expected: Each request should be isolated regardless of user field.
        """
        # First request with user A
        payload_a = {
            "model": config.get_chat_model(),
            "messages": [{"role": "user", "content": "My name is Alice"}],
            "user": "user_a_12345",
            "max_tokens": 30
        }
        
        response_a = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload_a, headers=auth_headers)
        assert response_a.status_code == 200
        
        # Second request with user B
        payload_b = {
            "model": config.get_chat_model(),
            "messages": [{"role": "user", "content": "What did the previous user say?"}],
            "user": "user_b_67890",
            "max_tokens": 30
        }
        
        response_b = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload_b, headers=auth_headers)
        assert response_b.status_code == 200
        
        response_b_content = response_b.json()["choices"][0]["message"]["content"].lower()
        
        # User B should not see User A's information
        assert "alice" not in response_b_content
        assert "user_a_12345" not in response_b_content

    def test_image_data_privacy_in_multimodal(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test that image data URIs are handled privately.
        
        Expected: Image data should not be logged or exposed in responses.
        """
        # Create a small valid image data URI
        image_uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
        
        payload = {
            "model": config.get_chat_model(),
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe this image with privacy concerns"},
                    {"type": "image_url", "image_url": {"url": image_uri}}
                ]
            }],
            "max_tokens": 50
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        # Model may or may not support images, both scenarios are valid
        if response.status_code == 200:
            data = response.json()
            response_str = str(data)
            
            # Verify base64 image data is not echoed in response
            assert "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=" not in response_str
        elif response.status_code in [400, 422]:
            # Model doesn't support images - this is acceptable
            pass
        else:
            pytest.fail(f"Unexpected status code: {response.status_code}")

    def test_conversation_history_privacy(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test privacy in multi-turn conversations with sensitive data.
        
        Expected: Previous sensitive data should not leak inappropriately.
        """
        # Start conversation with sensitive data
        messages = [
            {"role": "user", "content": "My account number is ACCT_123456789_TEST"},
            {"role": "assistant", "content": "I understand you have an account."},
            {"role": "user", "content": "Can you help me without mentioning my account details?"}
        ]
        
        payload = {
            "model": config.get_chat_model(),
            "messages": messages,
            "max_tokens": 50
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code == 200
        
        response_content = response.json()["choices"][0]["message"]["content"]
        
        # Assistant should not repeat the account number unnecessarily
        assert "ACCT_123456789_TEST" not in response_content
        assert "123456789" not in response_content

    def test_embedding_batch_data_isolation(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test data isolation in batch embedding requests.
        
        Expected: No cross-contamination between batch items.
        """
        # Mix sensitive and non-sensitive data in batch
        batch_inputs = [
            "Public information about weather",
            "SENSITIVE_DATA_USER_999",
            "General query about services",
            "CONFIDENTIAL_INFO_ABC123"
        ]
        
        payload = {
            "model": config.get_embedding_model(),
            "input": batch_inputs
        }
        
        response = http_client.post(f"{config.BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Verify embeddings are generated for each input
            assert len(data["data"]) == len(batch_inputs)
            
            # Verify sensitive data is not echoed in response
            response_str = str(data)
            assert "SENSITIVE_DATA_USER_999" not in response_str
            assert "CONFIDENTIAL_INFO_ABC123" not in response_str
        else:
            # Some models may not support batch processing
            assert response.status_code in [400, 422]

    def test_api_key_privacy_in_logs(self, http_client: httpx.Client):
        """
        Test that API keys are not exposed in error responses.
        
        Expected: API keys should never appear in response bodies.
        """
        # Make request with invalid endpoint to potentially trigger logging
        fake_headers = {"Authorization": f"Bearer {config.API_KEY}", "Content-Type": "application/json"}
        
        response = http_client.get(f"{config.BASE_URL}/invalid_endpoint", headers=fake_headers)
        
        assert response.status_code == 404
        error_response = str(response.json())
        
        # API key should not appear in error response
        assert config.API_KEY not in error_response
        assert "Bearer" not in error_response or config.API_KEY not in error_response


if __name__ == "__main__":
    pytest.main([__file__, "-v"])