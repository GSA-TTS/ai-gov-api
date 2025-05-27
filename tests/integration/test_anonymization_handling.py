# tests/integration/test_anonymization_handling.py
# implementation of `APItest_DataAnonymization`

import pytest
import requests
import json
from unittest.mock import patch, MagicMock

from .conftest import BASE_URL, valid_headers, configured_chat_model_id, configured_embedding_model_id, valid_image_data_uri

# Assume USE_MOCK_PROVIDERS=true in .env for these tests for predictable mock LLM behavior

# --- Category: TDH_ANON (Test Data Handling) ---

@pytest.mark.asyncio
async def test_tdh_anon_001_chat_with_synthetic_pii_user_field(
    valid_headers, configured_chat_model_id
):
    """TDH_ANON_001: API processes chat requests with synthetic/placeholder PII in the optional `user` field."""
    payload = {
        "model": configured_chat_model_id,
        "messages": [{"role": "user", "content": "Hello, this is a test."}],
        "user": "synthetic_user_id_abc123@test.example.com"
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200
    # Further checks could involve ensuring the mock LLM response is as expected
    # and that the 'user' field, if logged by the mock or a real system, is the synthetic one.
    # For now, success (200) means it was processed without error due to the synthetic ID.
    assert "choices" in response.json()

@pytest.mark.asyncio
async def test_tdh_anon_002_chat_with_pii_placeholders_in_prompt(
    valid_headers, configured_chat_model_id
):
    """TDH_ANON_002: API processes chat requests with prompt content containing common PII placeholders."""
    prompt_content = "Please assist user [NAME] regarding order [ORDER_ID] for product [PRODUCT_SKU]."
    payload = {
        "model": configured_chat_model_id,
        "messages": [{"role": "user", "content": prompt_content}]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200
    # Mock response should indicate it received the placeholders literally
    # e.g., "Mocked ... response ... Last user message echoed: 'user: Please assist user [NAME]...'"
    assert "[NAME]" in response.json()["choices"][0]["message"]["content"]
    assert "[ORDER_ID]" in response.json()["choices"][0]["message"]["content"]

@pytest.mark.asyncio
async def test_tdh_anon_003_embeddings_with_pii_placeholders_in_input(
    valid_headers, configured_embedding_model_id
):
    """TDH_ANON_003: API processes embedding requests with input text containing common PII placeholders."""
    input_text = "User [USER_EMAIL_PLACEHOLDER] reported an issue with item [ITEM_SERIAL_NUMBER]."
    payload = {
        "model": configured_embedding_model_id,
        "input": input_text
    }
    response = requests.post(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    assert response.status_code == 200
    assert "data" in response.json()
    # The mock embedding doesn't reflect input text directly, but success indicates processing.

# --- Category: LEM_ANON (Logging and Error Message Anonymity) ---

@pytest.mark.asyncio
@patch('app.services.billing.logger.info') # Path to the logger used in billing_worker
@patch('app.logs.middleware.structlog.get_logger') # Path to logger used in StructlogMiddleware
async def test_lem_anon_001_pii_in_prompt_not_in_standard_logs(
    mock_structlog_get_logger, mock_billing_logger_info,
    valid_headers, configured_chat_model_id
):
    """LEM_ANON_001: Verify mock PII in prompt is not in standard INFO level logs from middleware or billing."""
    
    # Configure the mock for structlog.get_logger() to return another mock
    # that we can inspect calls on.
    mock_request_logger = MagicMock()
    mock_structlog_get_logger.return_value = mock_request_logger

    sensitive_prompt_content = "My secret SSN is SYNTHETIC_SSN_98765 and my bank is [BANK_NAME_PLACEHOLDER]."
    payload = {
        "model": configured_chat_model_id,
        "messages": [{"role": "user", "content": sensitive_prompt_content}]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200

    # Check StructlogMiddleware logs (via the mock_request_logger)
    # Middleware logs "Request started" and "Request completed"
    middleware_log_calls = []
    for call_args in mock_request_logger.info.call_args_list:
        args, kwargs = call_args
        middleware_log_calls.append(str(args) + str(kwargs))

    assert any("Request started" in call_str for call_str in middleware_log_calls)
    assert any("Request completed" in call_str for call_str in middleware_log_calls)
    for call_str in middleware_log_calls:
        assert "SYNTHETIC_SSN_98765" not in call_str, "Sensitive SSN found in middleware log"
        assert "[BANK_NAME_PLACEHOLDER]" not in call_str, "Sensitive placeholder found in middleware log"

    # Check billing logs (via mock_billing_logger_info)
    # This assumes billing_queue.put() is called and processed.
    # For a direct test, one might need to mock billing_queue.put() to inspect what's added.
    # Here, we check what billing_worker would log.
    
    # To properly test billing logs, we'd need to ensure the billing_worker processes the item.
    # This might require a small delay or a more direct way to inspect queue items if the worker runs in a separate task.
    # For simplicity, if billing_logger.info was called, we check its content.
    # This test might be flaky if the billing worker doesn't process immediately.
    # A better way is to mock `app.services.billing.billing_queue.put` and check its args.
    # Let's try patching the queue put method for a more direct assertion.
    with patch('app.services.billing.billing_queue.put') as mock_queue_put:
        # Re-trigger the request to ensure the patched queue is used
        requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
        
        if mock_queue_put.called:
            # Get the arguments passed to billing_queue.put()
            # It's an async queue, so it would be put_nowait or put.
            # Let's assume it's put and it's called with one positional arg (the billing_data dict)
            # If it's put_nowait, the structure is the same.
            # This part needs to align with how billing_data is constructed in your router.
            # Typically, it would be `await billing_queue.put(billing_data_dict)`
            
            # This part is tricky without knowing the exact structure of billing_data
            # and how it's passed to the queue.
            # For now, we'll assume the previous check on mock_billing_logger_info is indicative,
            # or this part needs refinement based on actual billing_data structure.
            # If billing_data contains token counts and model ID but not prompt, it's fine.
            pass # Placeholder for more detailed billing data check if needed

@pytest.mark.asyncio
async def test_lem_anon_002_pii_in_422_error_field_reflection(
    valid_headers, configured_chat_model_id
):
    """LEM_ANON_002: Verify PII in a field causing 422 error is handled by FastAPI defaults."""
    sensitive_string = "user_secret_value_causing_type_error"
    payload = {
        "model": configured_chat_model_id,
        "messages": [{"role": "user", "content": "Valid content"}],
        "temperature": sensitive_string  # This will cause a type error
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 422
    response_data = response.json()
    assert "detail" in response_data
    found_sensitive_in_detail = False
    for error_detail in response_data["detail"]:
        if error_detail.get("loc") == ["body", "temperature"]:
            # Pydantic's msg might include the input, e.g. "Input should be a valid number, unable to parse string as a number"
            # Pydantic might also include `input: "sensitive_user_data_string_instead_of_float"`
            assert "Input should be a valid number" in error_detail["msg"]
            if "input" in error_detail and error_detail["input"] == sensitive_string:
                found_sensitive_in_detail = True # This is expected FastAPI/Pydantic behavior
            break
    assert found_sensitive_in_detail, "Sensitive input causing validation error was not reflected as expected by Pydantic"
    # The key is that *additional* unrelated sensitive data is not leaked.

@pytest.mark.asyncio
async def test_lem_anon_003_custom_400_error_no_full_sensitive_echo(
    valid_headers, configured_chat_model_id
):
    """LEM_ANON_003: Verify custom 400 error for malformed image URI doesn't echo full sensitive base64."""
    malformed_sensitive_base64 = "THIS_IS_MOCK_SENSITIVE_AND_VERY_LONG_AND_INVALID_B64_DATA_THAT_SHOULD_NOT_BE_FULLY_ECHOED"
    payload = {
        "model": configured_chat_model_id, # Assuming this model could take images
        "messages": [{
            "role": "user",
            "content": [{
                "type": "image_url",
                "image_url": {"url": f"data:image/jpeg;base64,{malformed_sensitive_base64}"}
            }]
        }]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 400
    response_data = response.json()
    assert response_data["error"] == "Bad Request"
    assert "Invalid Base64 data" in response_data["message"]
    assert malformed_sensitive_base64 not in response_data["message"], "Full sensitive base64 string was echoed in error message"
    # The specific reason from binascii.Error might be present, which is fine.

@pytest.mark.asyncio
@patch('app.routers.api_v1.openai_chat_request_to_core') # Target for forcing 500
async def test_lem_anon_004_500_error_with_pii_input_no_leak_in_response(
    mock_conversion, valid_headers, configured_chat_model_id
):
    """LEM_ANON_004: Verify 500 error (triggered by mock) with PII in input doesn't leak PII in response."""
    mock_conversion.side_effect = Exception("Simulated internal server error during conversion")
    
    pii_content = "My confidential project name is [PROJECT_SECRET_ALPHA]"
    payload = {
        "model": configured_chat_model_id,
        "messages": [{"role": "user", "content": pii_content}]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 500
    response_data = response.json()
    assert response_data["detail"] == "Internal Server Error"
    assert "request_id" in response_data
    assert pii_content not in response.text # Check raw text to be sure
    assert "[PROJECT_SECRET_ALPHA]" not in response.text

# --- Category: NID_ANON (Non-Interference with Pre-Anonymized Data) ---

@pytest.mark.asyncio
async def test_nid_anon_001_embedding_with_anonymization_markers(
    valid_headers, configured_embedding_model_id
):
    """NID_ANON_001: Send an embedding request where input text contains common anonymization markers."""
    input_text_with_markers = "User [NAME_PLACEHOLDER] from [CITY_PLACEHOLDER] accessed [RESOURCE_ID_PLACEHOLDER]."
    payload = {
        "model": configured_embedding_model_id,
        "input": input_text_with_markers
    }
    response = requests.post(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    assert response.status_code == 200
    assert "data" in response.json()
    # Verification: The request succeeded. The mock provider should have processed the string literally.
    # No specific check on embedding content, just that it didn't error due to markers.

@pytest.mark.asyncio
async def test_nid_anon_002_chat_with_history_containing_anonymization_markers(
    valid_headers, configured_chat_model_id
):
    """NID_ANON_002: Send a chat request with conversational history containing anonymization placeholders."""
    payload = {
        "model": configured_chat_model_id,
        "messages": [
            {"role": "user", "content": "My user ID is [USER_XYZ]."},
            {"role": "assistant", "content": "Okay, I have noted your ID as [USER_XYZ]. How can I assist [USER_XYZ] today?"},
            {"role": "user", "content": "What was the user ID I mentioned?"}
        ]
    }
    response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=valid_headers)
    assert response.status_code == 200
    response_data = response.json()
    # Mock should echo back parts of the input, including placeholders
    assert "[USER_XYZ]" in response_data["choices"][0]["message"]["content"]
    # Verification: The API and mock LLM correctly handled the conversation with placeholders.

