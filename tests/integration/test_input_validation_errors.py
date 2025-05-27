# tests/integration/test_input_validation_errors.py
import pytest
import requests
from .conftest import BASE_URL, valid_headers, configured_chat_model_id, configured_embedding_model_id, valid_image_data_uri, valid_file_data_base64

# --- Chat Completions Input Validation ---

@pytest.mark.asyncio
async def test_ecv_input_chat_001_missing_model(valid_headers):
    """ECV_INPUT_CHAT_001: Missing 'model' field in chat completions."""
    payload = {"messages": [{"role": "user", "content": "Hello"}]}
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 422
    # Example check, Pydantic's exact error message can vary slightly
    assert any(err["loc"] == ["body", "model"] and err["type"] == "missing" for err in response.json()["detail"])

@pytest.mark.asyncio
async def test_ecv_input_chat_002_missing_messages(valid_headers, configured_chat_model_id):
    """ECV_INPUT_CHAT_002: Missing 'messages' field in chat completions."""
    payload = {"model": configured_chat_model_id}
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 422
    assert any(err["loc"] == ["body", "messages"] and err["type"] == "missing" for err in response.json()["detail"])

@pytest.mark.asyncio
async def test_ecv_input_chat_003_messages_empty_list(valid_headers, configured_chat_model_id):
    """ECV_INPUT_CHAT_003: 'messages' as empty list."""
    payload = {"model": configured_chat_model_id, "messages": []}
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 422 # Pydantic default for sequence with no min_length might allow empty
                                       # but the OpenAI spec implies at least one message.
                                       # If your Pydantic schema for messages has min_length=1, this will be 422.
                                       # Otherwise, this test might need to expect a different error later or pass.
                                       # For now, assuming Pydantic schema requires at least one message.
    assert any(err["loc"] == ["body", "messages"] for err in response.json()["detail"])


@pytest.mark.asyncio
async def test_ecv_input_chat_004_invalid_role(valid_headers, configured_chat_model_id):
    """ECV_INPUT_CHAT_004: 'messages' with invalid role."""
    payload = {"model": configured_chat_model_id, "messages": [{"role": "invalid_role", "content": "Hello"}]}
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 422
    assert any(err["loc"] == ["body", "messages", 0, "role"] and "literal_error" in err["type"] for err in response.json()["detail"])

# Add other ECV_INPUT_CHAT cases (005-019) here, following the pattern...
# Example for a custom validation error:
@pytest.mark.asyncio
async def test_ecv_input_custom_001_invalid_image_uri_prefix(valid_headers, configured_chat_model_id):
    """ECV_INPUT_CUSTOM_001: Invalid Image Data URI format (wrong prefix)."""
    payload = {
        "model": configured_chat_model_id, # Ensure this model supports images if applicable, or use a general one
        "messages": [{
            "role": "user",
            "content": [{
                "type": "image_url",
                "image_url": {"url": "http://example.com/image.jpg"}
            }]
        }]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 400
    json_resp = response.json()
    assert json_resp["error"] == "Bad Request"
    assert "Invalid or unsupported image data URI format" in json_resp["message"]

@pytest.mark.asyncio
async def test_ecv_input_custom_002_invalid_image_uri_type(valid_headers, configured_chat_model_id):
    """ECV_INPUT_CUSTOM_002: Invalid Image Data URI format (unsupported image type)."""
    payload = {
        "model": configured_chat_model_id,
        "messages": [{
            "role": "user",
            "content": [{
                "type": "image_url",
                "image_url": {"url": "data:image/tiff;base64,somebase64data"}
            }]
        }]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 400
    json_resp = response.json()
    assert json_resp["error"] == "Bad Request"
    assert "Invalid or unsupported image data URI format" in json_resp["message"]

@pytest.mark.asyncio
async def test_ecv_input_custom_003_invalid_base64_image_data(valid_headers, configured_chat_model_id):
    """ECV_INPUT_CUSTOM_003: Invalid Base64 Data in Image URI."""
    payload = {
        "model": configured_chat_model_id,
        "messages": [{
            "role": "user",
            "content": [{
                "type": "image_url",
                "image_url": {"url": "data:image/jpeg;base64,!!!not_base64!!!"}
            }]
        }]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 400
    json_resp = response.json()
    assert json_resp["error"] == "Bad Request"
    assert "Invalid Base64 data" in json_resp["message"]


# --- Embeddings Input Validation ---

@pytest.mark.asyncio
async def test_ecv_input_embed_001_missing_model(valid_headers):
    """ECV_INPUT_EMBED_001: Missing 'model' field in embeddings."""
    payload = {"input": "test"}
    response = requests.post(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    assert response.status_code == 422
    assert any(err["loc"] == ["body", "model"] and err["type"] == "missing" for err in response.json()["detail"])

@pytest.mark.asyncio
async def test_ecv_input_embed_002_missing_input(valid_headers, configured_embedding_model_id):
    """ECV_INPUT_EMBED_002: Missing 'input' field in embeddings."""
    payload = {"model": configured_embedding_model_id}
    response = requests.post(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    assert response.status_code == 422
    assert any(err["loc"] == ["body", "input"] and err["type"] == "missing" for err in response.json()["detail"])

# Add other ECV_INPUT_EMBED cases (003-009) here...
@pytest.mark.asyncio
async def test_ecv_input_embed_006_invalid_encoding_format(valid_headers, configured_embedding_model_id):
    """ECV_INPUT_EMBED_006: Invalid 'encoding_format' enum."""
    payload = {"model": configured_embedding_model_id, "input": "test", "encoding_format": "int32"}
    response = requests.post(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    assert response.status_code == 422
    assert any(err["loc"] == ["body", "encoding_format"] and "literal_error" in err["type"] for err in response.json()["detail"])


# Positive tests for valid image and file data
@pytest.mark.asyncio
async def test_valid_image_data_uri(valid_headers, configured_chat_model_id, valid_image_data_uri):
    """Positive test: Valid Image Data URI."""
    payload = {
        "model": configured_chat_model_id,
        "messages": [{
            "role": "user",
            "content": [{
                "type": "image_url",
                "image_url": {"url": valid_image_data_uri, "detail": "auto"}
            }]
        }]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200 # Assuming model and backend handle it
    # Further assertions on response content if necessary

@pytest.mark.asyncio
async def test_valid_file_data_base64(valid_headers, configured_chat_model_id, valid_file_data_base64):
    """Positive test: Valid File Data (Base64)."""
    payload = {
        "model": configured_chat_model_id,
        "messages": [{
            "role": "user",
            "content": [{
                "type": "file",
                "file": {"file_data": valid_file_data_base64}
            }]
        }]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200 # Assuming model and backend handle it
    # Further assertions on response content if necessary

