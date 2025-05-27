# tests/integration/test_edge_cases_negative_testing.py
import pytest
import requests
import json
import base64
import asyncio
from typing import Dict, Any, List, Union
from unittest.mock import patch, AsyncMock

from .conftest import (
    BASE_URL,
    valid_headers, # Assumes a key with broad scopes
    configured_chat_model_id,
    configured_embedding_model_id,
    minimal_chat_payload,
    minimal_embedding_payload,
    valid_image_data_uri,
    valid_file_data_base64
)
from app.providers.core.chat_schema import ChatRepsonse as CoreChatResponse, Response as CoreChoice, CompletionUsage as CoreCompletionUsage
from app.providers.core.embed_schema import EmbeddingResponse as CoreEmbeddingResponse, EmbeddingData as CoreEmbeddingData, EmbeddingUsage as CoreEmbeddingUsage
from datetime import datetime, timezone

# Assume USE_MOCK_PROVIDERS=true in .env for these tests

# Helper to construct chat payload
def make_chat_payload(model_id: str, messages: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    payload = {"model": model_id, "messages": messages}
    payload.update(kwargs)
    return payload

# Helper to construct embedding payload
def make_embedding_payload(model_id: str, input_data: Union[str, List[str]], **kwargs) -> Dict[str, Any]:
    payload = {"model": model_id, "input": input_data}
    payload.update(kwargs)
    return payload

# --- A. Edge Cases for Request Body Fields (Category: EC_BODY) ---

# Sub-Category: Numeric Parameter Boundaries & Extremes (EC_BODY_NUMERIC)
@pytest.mark.asyncio
async def test_ec_body_num_001_temp_min(valid_headers, configured_chat_model_id):
    """EC_BODY_NUM_001: Test temperature at minimum valid value (0.0) for chat."""
    payload = make_chat_payload(configured_chat_model_id, [{"role": "user", "content": "Test"}], temperature=0.0)
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200
    assert "choices" in response.json() # Mock should handle temperature=0.0

@pytest.mark.asyncio
async def test_ec_body_num_002_temp_max(valid_headers, configured_chat_model_id):
    """EC_BODY_NUM_002: Test temperature at maximum valid value (2.0) for chat."""
    payload = make_chat_payload(configured_chat_model_id, [{"role": "user", "content": "Test"}], temperature=2.0)
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200
    assert "choices" in response.json() # Mock should handle temperature=2.0

@pytest.mark.asyncio
async def test_ec_body_num_003_max_tokens_min(valid_headers, configured_chat_model_id):
    """EC_BODY_NUM_003: Test max_tokens at a very low valid value (1) for chat."""
    payload = make_chat_payload(configured_chat_model_id, [{"role": "user", "content": "Tell me a very long story"}], max_tokens=1)
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200
    resp_json = response.json()
    assert "choices" in resp_json
    # Mock provider should respect max_tokens crudely (e.g., word count or by adding "...")
    content_words = resp_json["choices"][0]["message"]["content"].split()
    assert len(content_words) <= 5 or "..." in resp_json["choices"][0]["message"]["content"] # Mock specific check

@pytest.mark.asyncio
async def test_ec_body_num_005_dimensions_min_supported(valid_headers, configured_embedding_model_id):
    """EC_BODY_NUM_005: Test dimensions for embeddings at a small valid value (e.g., 1 if model supports)."""
    # This depends on the mock embedding model's behavior for dimensions. Let's assume it accepts any positive int.
    test_dimensions = 1 # Smallest positive integer
    payload = make_embedding_payload(configured_embedding_model_id, "test", dimensions=test_dimensions)
    response = requests.post(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    assert response.status_code == 200
    resp_json = response.json()
    assert "data" in resp_json and len(resp_json["data"]) > 0
    assert len(resp_json["data"][0]["embedding"]) == test_dimensions

# Sub-Category: String and List Lengths & Content (EC_BODY_STR_LIST)
@pytest.mark.asyncio
async def test_ec_body_str_list_001_chat_empty_content(valid_headers, configured_chat_model_id):
    """EC_BODY_STR_LIST_001: ChatCompletionRequest.messages[].content.text is an empty string."""
    payload = make_chat_payload(configured_chat_model_id, [{"role": "user", "content": ""}])
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200 # Mock LLM should handle empty content
    assert "choices" in response.json()

@pytest.mark.asyncio
async def test_ec_body_str_list_002_embed_empty_input_string(valid_headers, configured_embedding_model_id):
    """EC_BODY_STR_LIST_002: EmbeddingRequest.input is an empty string."""
    payload = make_embedding_payload(configured_embedding_model_id, "")
    response = requests.post(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    # Behavior for empty string embedding can vary by provider. Mock should succeed.
    # Real providers might error or return a specific vector for empty string.
    assert response.status_code == 200
    assert "data" in response.json()

@pytest.mark.asyncio
async def test_ec_body_str_list_004_chat_very_long_content(valid_headers, configured_chat_model_id):
    """EC_BODY_STR_LIST_004: Chat message content with very long string (within reasonable HTTP limits)."""
    # Test with a string that's large but should still be parsable by HTTP server and Pydantic.
    # Focus is on API framework handling, not necessarily LLM token limits for this specific test.
    long_string = "word " * 10000  # Approx 50KB
    payload = make_chat_payload(configured_chat_model_id, [{"role": "user", "content": long_string}])
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200 # Mock should handle it. Real LLM might error on token limit.
    assert "choices" in response.json()

# Sub-Category: Content Types and Structures (EC_BODY_CONTENT)
@pytest.mark.asyncio
async def test_ec_body_content_001_chat_starts_with_assistant(valid_headers, configured_chat_model_id):
    """EC_BODY_CONTENT_001: Chat messages starts with an assistant message."""
    payload = make_chat_payload(configured_chat_model_id, [
        {"role": "assistant", "content": "I am an assistant."},
        {"role": "user", "content": "Hello assistant."}
    ])
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200 # Most LLMs accept this format.
    assert "choices" in response.json()

@pytest.mark.asyncio
async def test_ec_body_content_002_chat_image_only_message(valid_headers, valid_image_data_uri):
    """EC_BODY_CONTENT_002: Chat message content with only an ImageContentPart (no text)."""
    # Use a model ID that the mock handles as multimodal, e.g., gemini-2.0-flash
    payload = make_chat_payload("gemini-2.0-flash", [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": valid_image_data_uri}}]}])
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200
    resp_json = response.json()
    assert "choices" in resp_json
    assert "Image input acknowledged" in resp_json["choices"][0]["message"]["content"]

# Sub-Category: Optional Fields and Defaults (EC_BODY_OPTIONAL)
@pytest.mark.asyncio
async def test_ec_body_optional_001_chat_no_optional_params(valid_headers, configured_chat_model_id):
    """EC_BODY_OPTIONAL_001: ChatCompletionRequest with no optional parameters set."""
    payload = make_chat_payload(configured_chat_model_id, [{"role": "user", "content": "Test defaults"}])
    # Remove any default optionals that make_chat_payload might add if it were more complex
    for key in ["temperature", "top_p", "max_tokens", "stream", "stop", "presence_penalty", "frequency_penalty", "user"]:
        payload.pop(key, None)
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200
    assert "choices" in response.json() # Mock LLM uses its defaults

# Sub-Category: Special Characters & Unicode (EC_BODY_UNICODE)
@pytest.mark.asyncio
async def test_ec_body_unicode_001_chat_diverse_unicode(valid_headers, configured_chat_model_id):
    """EC_BODY_UNICODE_001: Chat message content with diverse Unicode."""
    unicode_content = "Hello 😊 你好 Привет saluto مرحبا"
    payload = make_chat_payload(configured_chat_model_id, [{"role": "user", "content": unicode_content}])
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200
    resp_json = response.json()
    assert "choices" in resp_json
    # Mock should echo back unicode content correctly
    assert unicode_content in resp_json["choices"][0]["message"]["content"]

# --- B. Negative Scenarios (Beyond Simple Validation Failures) (Category: EC_NEGATIVE) ---

# Sub-Category: Resource Exhaustion Probes (EC_NEGATIVE_RESOURCE)
@pytest.mark.asyncio
async def test_ec_negative_resource_001_chat_excessive_messages(valid_headers, configured_chat_model_id):
    """EC_NEGATIVE_RESOURCE_001: ChatCompletionRequest with a very large number of message objects."""
    # Note: This might hit HTTP client/server limits before application logic if too large.
    # Let's try a moderately large number that Pydantic should still parse.
    # The mock provider itself doesn't have hard limits on message count.
    messages = [{"role": "user", "content": f"Message {i}"} for i in range(200)] # 200 messages
    payload = make_chat_payload(configured_chat_model_id, messages)
    
    try:
        response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers, timeout=20)
        # If USE_MOCK_PROVIDERS=true, mock should succeed if request is parsable
        assert response.status_code == 200
        assert "choices" in response.json()
        # If testing against a real provider, this would likely error due to token limits.
    except requests.exceptions.ReadTimeout:
        pytest.fail("Request timed out for large number of messages.")
    except Exception as e:
        # Could be 413 from server, or other errors if payload is too large for some layer
        print(f"Received error for large messages: {e}, Response: {getattr(e, 'response', 'N/A')}")
        assert response.status_code in [413, 400, 422, 500, 503] # Expect some form of error

# Sub-Category: Rapid Requests (EC_NEGATIVE_RAPID) - Hard to test true concurrency impact without load testing tools
@pytest.mark.asyncio
async def test_ec_negative_rapid_001_burst_chat_requests(valid_headers, configured_chat_model_id):
    """EC_NEGATIVE_RAPID_001: Send a small burst of valid chat requests."""
    payload = make_chat_payload(configured_chat_model_id, [{"role": "user", "content": "Burst test"}])
    responses: List[requests.Response] = []
    
    # This isn't true concurrency but rapid succession.
    # For true concurrency, asyncio.gather with an async HTTP client would be better.
    for _ in range(5): # Send 5 requests quickly
        responses.append(requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers))
        await asyncio.sleep(0.05) # Small delay to allow some processing

    for response in responses:
        assert response.status_code == 200 # Mock should handle these fine.
                                           # Real provider might hit rate limits (429).
        assert "choices" in response.json()

# Sub-Category: Image/File Data Content Edge Cases (EC_NEGATIVE_CONTENT)
@pytest.mark.asyncio
async def test_ec_negative_content_001_image_type_mismatch(valid_headers, valid_image_data_uri):
    """EC_NEGATIVE_CONTENT_001: Image data URI says image/jpeg but base64 is PNG."""
    # Assuming valid_image_data_uri is a PNG. Change its prefix to jpeg.
    png_data_uri_parts = valid_image_data_uri.split(",", 1)
    jpeg_uri_with_png_data = f"data:image/jpeg;base64,{png_data_uri_parts[1]}"
    
    payload = make_chat_payload(
        "gemini-2.0-flash", # Mock multimodal model
        [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": jpeg_uri_with_png_data}}]}]
    )
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    # parse_data_uri in utils.py uses the declared format.
    # The mock LLM will just acknowledge "Image input acknowledged."
    # A real LLM might error if it can't decode JPEG data that's actually PNG.
    assert response.status_code == 200
    assert "Image input acknowledged" in response.json()["choices"][0]["message"]["content"]

# Sub-Category: Unexpected LLM Provider Responses (EC_NEGATIVE_PROVIDER)
@pytest.mark.asyncio
@patch('app.providers.mocks.MockBedRockBackend.invoke_model', new_callable=AsyncMock)
async def test_ec_negative_provider_001_mock_malformed_success_response(
    mock_invoke_model, valid_headers, configured_chat_model_id, minimal_chat_payload
):
    """EC_NEGATIVE_PROVIDER_001: Mock LLM provider returns 200 OK but malformed JSON (missing 'choices')."""
    # This test assumes configured_chat_model_id is served by MockBedRockBackend when mocks are on.
    # We are patching the mock itself to return something its adapter can't handle.
    
    # This mock response is invalid because core_chat_response_to_openai expects certain fields
    # that the adapter_to_core.bedrock_chat_response_to_core would usually ensure are present
    # if it got a valid ConverseResponse.
    # Here, we simulate the BedRockBackend's invoke_model returning a bad CoreChatResponse.
    malformed_core_response = CoreChatResponse(
        created=datetime.now(timezone.utc),
        model=configured_chat_model_id,
        choices=[], # Valid choices, but let's make it more problematic by making it not a list
        usage=CoreCompletionUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2)
    )
    # To truly test the adapter *from* the provider, we'd mock the provider's raw response.
    # This test is more about how the router handles an error from the backend's method.
    # Let's make the mock backend's method raise an error like Pydantic validation would
    # if it received a bad response from the actual LLM.
    
    # Let's patch the *adapter that converts from provider to core*
    # to simulate it receiving bad data from the (mocked) provider.
    # No, the goal is to test API's handling if provider's adapter itself fails.
    # So, we make the mock provider's method return something that the
    # app.providers.open_ai.adapter_from_core.core_chat_response_to_openai would fail on.

    # Let's make the mock backend's invoke_model raise an AttributeError,
    # as if it failed to parse the (hypothetical) raw provider response.
    mock_invoke_model.side_effect = AttributeError("Simulated parsing failure of provider response")

    payload = minimal_chat_payload.copy()
    payload["model"] = configured_chat_model_id # Ensure this is a Bedrock mock model
    
    if "claude" not in payload["model"] and "llama" not in payload["model"]:
         pytest.skip("Skipping test, model not handled by MockBedRockBackend in this test's patch")


    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 500 # Caught by generic exception handler in main.py
    json_response = response.json()
    assert json_response["detail"] == "Internal Server Error"
    assert "request_id" in json_response

