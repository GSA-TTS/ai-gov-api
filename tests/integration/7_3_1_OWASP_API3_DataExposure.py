# tests/integration/7_3_1_OWASP_API3_DataExposure.py
# Tests for OWASP API3: Broken Object Property Level Authorization - Data Exposure
# Aligned with TestPlan.md Section 7.3.1 - OWASP API Security Top 10 (2023) Testing

import pytest
import httpx
import json
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


class TestOWASPAPI3DataExposure:
    """Test cases for API3: Broken Object Property Level Authorization - Excessive Data Exposure"""

    @pytest.mark.asyncio
    async def test_models_endpoint_no_sensitive_data(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        DE_API_RESPONSE_SUCCESS_001: Verify /api/v1/models response does not expose sensitive backend configuration.
        
        Expected: Response should only contain id, name, and capability fields.
        No internal ARNs, project IDs, or backend configuration should be exposed.
        """
        response = http_client.get(f"{config.BASE_URL}/models", headers=auth_headers)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        models = response.json()
        
        assert isinstance(models, list), "Response should be a list of models"
        assert len(models) > 0, "Should return at least one model"
        
        # Check each model for proper field exposure
        for model in models:
            # Verify only expected fields are present
            assert set(model.keys()) == {"id", "name", "capability"}, \
                f"Model should only expose id, name, capability. Got: {model.keys()}"
            
            # Verify field types
            assert isinstance(model["id"], str), "Model ID should be a string"
            assert isinstance(model["name"], str), "Model name should be a string"
            assert model["capability"] in ["chat", "embedding"], \
                f"Capability should be 'chat' or 'embedding', got: {model['capability']}"
            
            # Check for sensitive data leakage in values
            for field, value in model.items():
                value_str = str(value).lower()
                # AWS ARNs
                assert "arn:aws:" not in value_str, f"AWS ARN exposed in {field}: {value}"
                assert "bedrock" not in value_str, f"Bedrock reference exposed in {field}: {value}"
                # GCP project paths
                assert "projects/" not in value_str, f"GCP project path exposed in {field}: {value}"
                assert "locations/" not in value_str, f"GCP location exposed in {field}: {value}"
                # API keys or secrets
                assert "api_key" not in value_str, f"API key reference in {field}: {value}"
                assert "secret" not in value_str, f"Secret reference in {field}: {value}"
                # Internal identifiers
                assert "internal_" not in value_str, f"Internal identifier in {field}: {value}"
                assert "_id" not in value_str or field == "id", f"Internal ID exposed in {field}: {value}"

    @pytest.mark.asyncio
    async def test_chat_completion_response_schema_compliance(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        DE_API_RESPONSE_SUCCESS_002: Verify /chat/completions response adheres to schema with no extra data.
        
        Expected: Response follows OpenAI schema exactly with no additional fields that could expose internals.
        """
        payload = {
            "model": config.get_chat_model(),
            "messages": [{"role": "user", "content": "Hello, how are you?"}],
            "max_tokens": config.MAX_TOKENS,
            "temperature": config.TEMPERATURE
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        
        # Verify top-level schema compliance
        expected_top_keys = {"id", "object", "created", "model", "choices", "usage"}
        actual_top_keys = set(data.keys())
        assert actual_top_keys == expected_top_keys, \
            f"Unexpected top-level keys. Expected: {expected_top_keys}, Got: {actual_top_keys}"
        
        # Verify field types and values
        assert data["object"] == "chat.completion", f"Object should be 'chat.completion', got: {data['object']}"
        assert isinstance(data["created"], int), "Created timestamp should be an integer"
        assert data["model"] == CHAT_MODELS[0], f"Model mismatch: {data['model']} != {CHAT_MODELS[0]}"
        assert isinstance(data["choices"], list) and len(data["choices"]) > 0, "Choices should be a non-empty list"
        
        # Check choice structure
        choice = data["choices"][0]
        expected_choice_keys = {"index", "message", "finish_reason"}
        assert set(choice.keys()) == expected_choice_keys, \
            f"Unexpected choice keys. Expected: {expected_choice_keys}, Got: {set(choice.keys())}"
        
        # Check message structure
        message = choice["message"]
        expected_message_keys = {"role", "content"}
        actual_message_keys = set(message.keys())
        # Allow 'name' as optional field per OpenAI spec
        assert actual_message_keys <= {"role", "content", "name"}, \
            f"Unexpected message keys: {actual_message_keys - {'role', 'content', 'name'}}"
        assert message["role"] == "assistant", f"Expected assistant role, got: {message['role']}"
        
        # Check usage structure
        usage = data["usage"]
        expected_usage_keys = {"prompt_tokens", "completion_tokens", "total_tokens"}
        assert set(usage.keys()) == expected_usage_keys, \
            f"Unexpected usage keys. Expected: {expected_usage_keys}, Got: {set(usage.keys())}"
        
        # Verify no sensitive internal data exposed
        sensitive_patterns = [
            "internal_", "debug_", "raw_", "provider_response", "backend_",
            "trace_", "stack", "error_detail", "implementation"
        ]
        
        json_str = json.dumps(data).lower()
        for pattern in sensitive_patterns:
            assert pattern not in json_str, f"Sensitive pattern '{pattern}' found in response"

    @pytest.mark.asyncio
    async def test_embeddings_response_no_input_echo(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        DE_API_RESPONSE_SUCCESS_003: Verify /embeddings response does not echo input text.
        
        Expected: Response contains embeddings but not the original input text.
        """
        sensitive_input = "My SSN is 123-45-6789 and credit card is 4111-1111-1111-1111"
        payload = {
            "model": EMBEDDING_MODELS[0],  # Use first available embedding model
            "input": sensitive_input
        }
        
        response = http_client.post(f"{BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        
        # Verify schema compliance
        assert "object" in data and data["object"] == "list", "Object should be 'list'"
        assert "data" in data and isinstance(data["data"], list), "Data should be a list"
        assert len(data["data"]) > 0, "Should return at least one embedding"
        
        # Check embedding structure
        embedding_obj = data["data"][0]
        expected_keys = {"object", "embedding", "index"}
        assert set(embedding_obj.keys()) == expected_keys, \
            f"Unexpected embedding keys: {set(embedding_obj.keys())}"
        
        assert embedding_obj["object"] == "embedding", "Object type should be 'embedding'"
        assert isinstance(embedding_obj["embedding"], list), "Embedding should be a list of floats"
        assert len(embedding_obj["embedding"]) > 0, "Embedding vector should not be empty"
        
        # Ensure input is not echoed anywhere in response
        response_str = json.dumps(data)
        assert sensitive_input not in response_str, "Original input text should not be in response"
        assert "123-45-6789" not in response_str, "SSN should not be in response"
        assert "4111-1111-1111-1111" not in response_str, "Credit card should not be in response"

    @pytest.mark.asyncio
    async def test_error_response_no_sensitive_details(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        DE_API_RESPONSE_ERROR_001: Verify error responses don't expose sensitive implementation details.
        
        Expected: Error messages should be generic without stack traces or internal paths.
        """
        # Test with invalid model to trigger error
        payload = {
            "model": "invalid_model_that_does_not_exist",
            "messages": [{"role": "user", "content": "Hello"}]
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        # Should get an error response
        assert response.status_code in [400, 404, 422], \
            f"Expected error status, got {response.status_code}: {response.text}"
        
        error_data = response.json()
        error_str = json.dumps(error_data).lower()
        
        # Check for sensitive information in error
        sensitive_patterns = [
            "traceback", "stack trace", "file \"", "line ",
            "/usr/", "/home/", "/app/", "/var/",  # File paths
            "postgres", "database", "connection",  # DB details
            "bedrock", "vertex", "provider",  # Provider details
            "api_key", "secret", "credential",  # Credentials
            "internal server", "nullpointer", "exception"  # Implementation details
        ]
        
        for pattern in sensitive_patterns:
            assert pattern not in error_str, \
                f"Sensitive pattern '{pattern}' found in error response: {error_data}"

    @pytest.mark.asyncio
    async def test_streaming_response_no_metadata_leakage(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test that streaming responses don't leak internal metadata or provider details.
        
        Expected: Stream chunks should only contain expected SSE fields.
        """
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": "Count from 1 to 5"}],
            "stream": True,
            "max_tokens": 50
        }
        
        chunks = []
        with httpx.Client(timeout=30.0) as client:
            with client.stream("POST", f"{BASE_URL}/chat/completions", 
                             json=payload, headers=auth_headers) as response:
                
                assert response.status_code == 200, \
                    f"Expected 200, got {response.status_code}"
                
                for line in response.iter_lines():
                    if line.startswith("data: "):
                        chunk_data = line[6:]  # Remove "data: " prefix
                        if chunk_data == "[DONE]":
                            break
                        chunks.append(json.loads(chunk_data))
        
        assert len(chunks) > 0, "Should receive at least one chunk"
        
        # Check each chunk for proper structure and no leakage
        for chunk in chunks:
            # Verify only expected fields
            allowed_keys = {"id", "object", "created", "model", "choices"}
            actual_keys = set(chunk.keys())
            assert actual_keys <= allowed_keys, \
                f"Unexpected keys in chunk: {actual_keys - allowed_keys}"
            
            # Check for sensitive data in chunk
            chunk_str = json.dumps(chunk).lower()
            assert "provider" not in chunk_str, "Provider details leaked in stream"
            assert "internal" not in chunk_str, "Internal details leaked in stream"
            assert "backend" not in chunk_str, "Backend details leaked in stream"

    @pytest.mark.asyncio
    async def test_cross_agency_data_isolation(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test that responses don't contain data from other agencies/users.
        
        Expected: Each response should only contain data relevant to the requesting API key.
        """
        # Make multiple requests with unique identifiers
        unique_id = f"test_isolation_{pytest.current_test_id}"
        
        payload = {
            "model": CHAT_MODELS[0],
            "messages": [{"role": "user", "content": f"My unique ID is {unique_id}"}],
            "max_tokens": 50
        }
        
        response = http_client.post(f"{BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        
        # Verify response doesn't contain references to other test runs or agencies
        response_str = json.dumps(data).lower()
        
        # Common test patterns that shouldn't appear
        other_patterns = [
            "other_user", "different_agency", "previous_test",
            "agency_id", "user_id", "tenant_id"  # Multi-tenancy identifiers
        ]
        
        for pattern in other_patterns:
            assert pattern not in response_str, \
                f"Potential cross-agency data leak: '{pattern}' found in response"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])