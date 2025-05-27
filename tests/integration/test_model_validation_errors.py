# tests/integration/test_model_validation_errors.py
import pytest
import requests
from .conftest import BASE_URL, valid_headers, minimal_chat_payload, minimal_embedding_payload, configured_chat_model_id, configured_embedding_model_id

@pytest.mark.asyncio
async def test_ecv_model_chat_001_unsupported_model_id(valid_headers, minimal_chat_payload):
    """ECV_MODEL_CHAT_001: Unsupported 'model_id' for Chat Completions."""
    payload = minimal_chat_payload.copy()
    payload["model"] = "non_existent_model_123"
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 422
    assert response.json()["detail"] == "Model 'non_existent_model_123' is not supported by this API."

@pytest.mark.asyncio
async def test_ecv_model_embed_001_unsupported_model_id(valid_headers, minimal_embedding_payload):
    """ECV_MODEL_EMBED_001: Unsupported 'model_id' for Embeddings."""
    payload = minimal_embedding_payload.copy()
    payload["model"] = "unknown_embedding_model_456"
    response = requests.post(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    assert response.status_code == 422
    assert response.json()["detail"] == "Model 'unknown_embedding_model_456' is not supported by this API."

@pytest.mark.asyncio
async def test_ecv_model_chat_002_incompatible_capability(valid_headers, minimal_chat_payload, configured_embedding_model_id):
    """ECV_MODEL_CHAT_002: Incompatible Model Capability for Chat (Using Embedding Model)."""
    payload = minimal_chat_payload.copy()
    payload["model"] = configured_embedding_model_id # Using an embedding model for chat
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 422
    assert response.json()["detail"] == f"This endpoint not does support chat with the model '{configured_embedding_model_id}'."

@pytest.mark.asyncio
async def test_ecv_model_embed_002_incompatible_capability(valid_headers, minimal_embedding_payload, configured_chat_model_id):
    """ECV_MODEL_EMBED_002: Incompatible Model Capability for Embeddings (Using Chat Model)."""
    payload = minimal_embedding_payload.copy()
    payload["model"] = configured_chat_model_id # Using a chat model for embeddings
    response = requests.post(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    assert response.status_code == 422
    assert response.json()["detail"] == f"This endpoint not does support embedding with the model '{configured_chat_model_id}'."

# Positive tests ECV_MODEL_CHAT_003 and ECV_MODEL_EMBED_003 are implicitly covered by other successful test runs
# that use correctly configured models for their respective capabilities.
# For example, test_ecv_auth_009_valid_key_chat_positive in test_auth_errors.py
# and test_ecv_auth_010_valid_key_embeddings_positive in test_auth_errors.py

