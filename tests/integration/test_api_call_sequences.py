# tests/integration/test_api_call_sequences.py
import pytest
import requests
import json
from unittest.mock import patch, call, ANY # ANY is useful for some mock assertions
from typing import List, Dict, Any

from .conftest import (
    BASE_URL,
    valid_api_key_all_scopes, # Assumes this key has both inference and embedding scopes
    valid_api_key_inference_only,
    valid_api_key_embedding_only,
    valid_api_key_no_scopes,
    minimal_chat_payload,
    minimal_embedding_payload,
    valid_image_data_uri,
    # Add these to conftest.py if not present, or use actual configured IDs
    # that map to your mock providers.
    # For SEQ_PROVIDER_SWITCH, we need distinct model IDs that are known
    # to be handled by different mock backends.
    # Let's assume these are defined in conftest.py or directly here for clarity:
    MOCK_BEDROCK_CHAT_MODEL_ID, # e.g., "claude_3_5_sonnet"
    MOCK_VERTEX_CHAT_MODEL_ID,  # e.g., "gemini-2.0-flash"
    MOCK_BEDROCK_EMBED_MODEL_ID, # e.g., "cohere_english_v3"
    MOCK_VERTEX_EMBED_MODEL_ID,  # e.g., "text-embedding-005"
)
from app.providers.mocks import MOCK_CLAUDE_CHAT, MOCK_GEMINI_MULTIMODAL_CHAT, MOCK_COHERE_EMBED, MOCK_VERTEX_TEXT_EMBED # To get model IDs

# If these are not in conftest.py, define them here for the tests:
# These should match the IDs used in your app/providers/mocks.py and app/config/settings.py for mock setup
MOCK_BEDROCK_CHAT_MODEL_ID = MOCK_CLAUDE_CHAT.id
MOCK_VERTEX_CHAT_MODEL_ID = MOCK_GEMINI_MULTIMODAL_CHAT.id
MOCK_BEDROCK_EMBED_MODEL_ID = MOCK_COHERE_EMBED.id
MOCK_VERTEX_EMBED_MODEL_ID = MOCK_VERTEX_TEXT_EMBED.id


# Helper to make headers
def make_headers(api_key: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

# --- A. Model Discovery and Usage Sequence (Category: SEQ_MODEL_DISCOVERY) ---

@pytest.mark.asyncio
async def test_seq_model_discovery_001_discover_and_use_chat_model(valid_api_key_all_scopes):
    """SEQ_MODEL_DISCOVERY_001: Discover and Use Chat Model."""
    headers = make_headers(valid_api_key_all_scopes)
    
    # 1. GET /api/v1/models
    response_models = requests.get(f"{BASE_URL}/models", headers=headers)
    assert response_models.status_code == 200
    models_list = response_models.json()
    assert isinstance(models_list, list)

    # 2. Identify a chat model
    chat_model_id = None
    for model_info in models_list:
        if model_info.get("id") == MOCK_BEDROCK_CHAT_MODEL_ID and model_info.get("capability") == "chat":
            chat_model_id = model_info["id"]
            break
    assert chat_model_id is not None, f"Mock chat model {MOCK_BEDROCK_CHAT_MODEL_ID} not found in /models response"

    # 3. POST /api/v1/chat/completions
    chat_payload = minimal_chat_payload().copy()
    chat_payload["model"] = chat_model_id
    response_chat = requests.post(f"{BASE_URL}/chat/completions", json=chat_payload, headers=headers)
    assert response_chat.status_code == 200
    chat_data = response_chat.json()
    assert chat_data["model"] == chat_model_id
    assert len(chat_data["choices"]) > 0
    assert "Mocked Bedrock response" in chat_data["choices"][0]["message"]["content"] # Mock specific

@pytest.mark.asyncio
async def test_seq_model_discovery_002_discover_and_use_embedding_model(valid_api_key_all_scopes):
    """SEQ_MODEL_DISCOVERY_002: Discover and Use Embedding Model."""
    headers = make_headers(valid_api_key_all_scopes)

    # 1. GET /api/v1/models
    response_models = requests.get(f"{BASE_URL}/models", headers=headers)
    assert response_models.status_code == 200
    models_list = response_models.json()

    # 2. Identify an embedding model
    embedding_model_id = None
    for model_info in models_list:
        if model_info.get("id") == MOCK_BEDROCK_EMBED_MODEL_ID and model_info.get("capability") == "embedding":
            embedding_model_id = model_info["id"]
            break
    assert embedding_model_id is not None, f"Mock embedding model {MOCK_BEDROCK_EMBED_MODEL_ID} not found"

    # 3. POST /api/v1/embeddings
    embed_payload = minimal_embedding_payload().copy()
    embed_payload["model"] = embedding_model_id
    response_embed = requests.post(f"{BASE_URL}/embeddings", json=embed_payload, headers=headers)
    assert response_embed.status_code == 200
    embed_data = response_embed.json()
    assert embed_data["model"] == embedding_model_id
    assert len(embed_data["data"]) > 0
    assert isinstance(embed_data["data"][0]["embedding"], list)

@pytest.mark.asyncio
async def test_seq_model_discovery_003_use_chat_model_for_embeddings(valid_api_key_all_scopes):
    """SEQ_MODEL_DISCOVERY_003: Attempt to Use Chat Model for Embeddings (Negative)."""
    headers = make_headers(valid_api_key_all_scopes) # Key needs embedding scope for endpoint access
    chat_model_id_to_test = MOCK_BEDROCK_CHAT_MODEL_ID 

    # (Optional Step 1 & 2: Discover chat_model_id - assume we know it for this negative test)
    embed_payload = minimal_embedding_payload().copy()
    embed_payload["model"] = chat_model_id_to_test
    
    # 3. POST /api/v1/embeddings with chat model ID
    response_embed = requests.post(f"{BASE_URL}/embeddings", json=embed_payload, headers=headers)
    assert response_embed.status_code == 422
    assert response_embed.json()["detail"] == f"This endpoint not does support embedding with the model '{chat_model_id_to_test}'."

@pytest.mark.asyncio
async def test_seq_model_discovery_004_use_embedding_model_for_chat(valid_api_key_all_scopes):
    """SEQ_MODEL_DISCOVERY_004: Attempt to Use Embedding Model for Chat (Negative)."""
    headers = make_headers(valid_api_key_all_scopes) # Key needs inference scope
    embedding_model_id_to_test = MOCK_BEDROCK_EMBED_MODEL_ID

    chat_payload = minimal_chat_payload().copy()
    chat_payload["model"] = embedding_model_id_to_test

    # 3. POST /api/v1/chat/completions with embedding model ID
    response_chat = requests.post(f"{BASE_URL}/chat/completions", json=chat_payload, headers=headers)
    assert response_chat.status_code == 422
    assert response_chat.json()["detail"] == f"This endpoint not does support chat with the model '{embedding_model_id_to_test}'."


# --- B. Conversational Chat Sequence (Category: SEQ_CONVERSATION) ---

@pytest.mark.asyncio
async def test_seq_conversation_001_basic_multi_turn(valid_api_key_all_scopes):
    """SEQ_CONVERSATION_001: Basic Multi-Turn Conversation."""
    headers = make_headers(valid_api_key_all_scopes)
    model_id = MOCK_BEDROCK_CHAT_MODEL_ID # Or any mock chat model

    # 1. First turn
    payload1 = {
        "model": model_id,
        "messages": [{"role": "user", "content": "Hello, my name is Alex."}]
    }
    response1 = requests.post(f"{BASE_URL}/chat/completions", json=payload1, headers=headers)
    assert response1.status_code == 200
    assistant_response_1 = response1.json()["choices"][0]["message"]["content"]
    assert "Alex" in assistant_response_1 # Mock should echo input

    # 2. Second turn
    payload2 = {
        "model": model_id,
        "messages": [
            {"role": "user", "content": "Hello, my name is Alex."},
            {"role": "assistant", "content": assistant_response_1},
            {"role": "user", "content": "What is my name?"}
        ]
    }
    response2 = requests.post(f"{BASE_URL}/chat/completions", json=payload2, headers=headers)
    assert response2.status_code == 200
    assistant_response_2 = response2.json()["choices"][0]["message"]["content"]
    # Mock should have access to "Alex" from the echoed history
    assert "Alex" in assistant_response_2 or "your name" in assistant_response_2.lower()

@pytest.mark.asyncio
async def test_seq_conversation_002_system_prompt_maintained(valid_api_key_all_scopes):
    """SEQ_CONVERSATION_002: Conversation with System Prompt Maintained."""
    headers = make_headers(valid_api_key_all_scopes)
    model_id = MOCK_BEDROCK_CHAT_MODEL_ID

    # 1. First turn with system prompt
    system_prompt = "You are a pirate captain."
    payload1 = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Greetings!"}
        ]
    }
    response1 = requests.post(f"{BASE_URL}/chat/completions", json=payload1, headers=headers)
    assert response1.status_code == 200
    assistant_response_1 = response1.json()["choices"][0]["message"]["content"]
    assert "System prompt(s) acknowledged" in assistant_response_1 # Mock specific
    assert system_prompt in assistant_response_1

    # 2. Second turn, system prompt should still be in effect (passed again by client)
    payload2 = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Greetings!"},
            {"role": "assistant", "content": assistant_response_1},
            {"role": "user", "content": "Where be the treasure?"}
        ]
    }
    response2 = requests.post(f"{BASE_URL}/chat/completions", json=payload2, headers=headers)
    assert response2.status_code == 200
    assistant_response_2 = response2.json()["choices"][0]["message"]["content"]
    assert "System prompt(s) acknowledged" in assistant_response_2 # Mock specific
    assert system_prompt in assistant_response_2
    assert "treasure" in assistant_response_2.lower() # Mock should echo some part of user message

@pytest.mark.asyncio
async def test_seq_conversation_003_multimodal_follow_up(valid_api_key_all_scopes, valid_image_data_uri):
    """SEQ_CONVERSATION_003: Conversation with Image and Follow-up Text."""
    headers = make_headers(valid_api_key_all_scopes)
    model_id = MOCK_VERTEX_CHAT_MODEL_ID # Mock Gemini

    # 1. First turn: image + question
    messages1 = [{
        "role": "user",
        "content": [
            {"type": "text", "text": "What is in this image?"},
            {"type": "image_url", "image_url": {"url": valid_image_data_uri}}
        ]
    }]
    payload1 = {"model": model_id, "messages": messages1}
    response1 = requests.post(f"{BASE_URL}/chat/completions", json=payload1, headers=headers)
    assert response1.status_code == 200
    assistant_response_1 = response1.json()["choices"][0]["message"]["content"]
    assert "Image input acknowledged" in assistant_response_1 # Mock specific

    # 2. Second turn: follow-up question
    messages2 = messages1 + [
        {"role": "assistant", "content": assistant_response_1},
        {"role": "user", "content": "Tell me more about the main color."}
    ]
    payload2 = {"model": model_id, "messages": messages2}
    response2 = requests.post(f"{BASE_URL}/chat/completions", json=payload2, headers=headers)
    assert response2.status_code == 200
    assistant_response_2 = response2.json()["choices"][0]["message"]["content"]
    # Mock should acknowledge image again as it's in history, and echo "color"
    assert "Image input acknowledged" in assistant_response_2
    assert "color" in assistant_response_2.lower()


# --- C. API Key Scope Usage Sequence (Category: SEQ_AUTH_SCOPE) ---

@pytest.mark.asyncio
async def test_seq_auth_scope_001_chat_scope_then_embed_fail(
    valid_api_key_inference_only, minimal_chat_payload, minimal_embedding_payload
):
    """SEQ_AUTH_SCOPE_001: Key with Chat Scope - Chat Success, Embedding Fail."""
    chat_headers = make_headers(valid_api_key_inference_only)
    
    # 1. Chat (Success)
    chat_payload_copy = minimal_chat_payload.copy()
    chat_payload_copy["model"] = MOCK_BEDROCK_CHAT_MODEL_ID
    response_chat = requests.post(f"{BASE_URL}/chat/completions", json=chat_payload_copy, headers=chat_headers)
    assert response_chat.status_code == 200

    # 2. Embeddings (Fail)
    embed_payload_copy = minimal_embedding_payload.copy()
    embed_payload_copy["model"] = MOCK_BEDROCK_EMBED_MODEL_ID
    response_embed = requests.post(f"{BASE_URL}/embeddings", json=embed_payload_copy, headers=chat_headers) # Using same key
    assert response_embed.status_code == 401
    assert response_embed.json()["detail"] == "Not Authorized"

@pytest.mark.asyncio
async def test_seq_auth_scope_002_embed_scope_then_chat_fail(
    valid_api_key_embedding_only, minimal_chat_payload, minimal_embedding_payload
):
    """SEQ_AUTH_SCOPE_002: Key with Embedding Scope - Embedding Success, Chat Fail."""
    embed_headers = make_headers(valid_api_key_embedding_only)

    # 1. Embeddings (Success)
    embed_payload_copy = minimal_embedding_payload.copy()
    embed_payload_copy["model"] = MOCK_BEDROCK_EMBED_MODEL_ID
    response_embed = requests.post(f"{BASE_URL}/embeddings", json=embed_payload_copy, headers=embed_headers)
    assert response_embed.status_code == 200

    # 2. Chat (Fail)
    chat_payload_copy = minimal_chat_payload.copy()
    chat_payload_copy["model"] = MOCK_BEDROCK_CHAT_MODEL_ID
    response_chat = requests.post(f"{BASE_URL}/chat/completions", json=chat_payload_copy, headers=embed_headers) # Using same key
    assert response_chat.status_code == 401
    assert response_chat.json()["detail"] == "Not Authorized"

@pytest.mark.asyncio
async def test_seq_auth_scope_003_no_model_scopes_models_ok_others_fail(
    valid_api_key_no_scopes, minimal_chat_payload, minimal_embedding_payload
):
    """SEQ_AUTH_SCOPE_003: Key with No Specific Model Scopes - Models List Success, Chat/Embedding Fail."""
    headers = make_headers(valid_api_key_no_scopes)

    # 1. List Models (Success)
    response_models = requests.get(f"{BASE_URL}/models", headers=headers)
    assert response_models.status_code == 200

    # 2. Chat (Fail)
    chat_payload_copy = minimal_chat_payload.copy()
    chat_payload_copy["model"] = MOCK_BEDROCK_CHAT_MODEL_ID
    response_chat = requests.post(f"{BASE_URL}/chat/completions", json=chat_payload_copy, headers=headers)
    assert response_chat.status_code == 401
    assert response_chat.json()["detail"] == "Not Authorized"

    # 3. Embeddings (Fail)
    embed_payload_copy = minimal_embedding_payload.copy()
    embed_payload_copy["model"] = MOCK_BEDROCK_EMBED_MODEL_ID
    response_embed = requests.post(f"{BASE_URL}/embeddings", json=embed_payload_copy, headers=headers)
    assert response_embed.status_code == 401
    assert response_embed.json()["detail"] == "Not Authorized"


# --- D. Sequential Use of Different Model Providers (Category: SEQ_PROVIDER_SWITCH) ---

@pytest.mark.asyncio
async def test_seq_provider_switch_001_chat_bedrock_then_vertex(valid_api_key_all_scopes):
    """SEQ_PROVIDER_SWITCH_001: Chat with Bedrock Model then Vertex Model."""
    headers = make_headers(valid_api_key_all_scopes)

    # 1. Chat with Bedrock Mock Model
    payload_bedrock = minimal_chat_payload().copy()
    payload_bedrock["model"] = MOCK_BEDROCK_CHAT_MODEL_ID
    payload_bedrock["messages"] = [{"role": "user", "content": "Query for Bedrock"}]
    response_bedrock = requests.post(f"{BASE_URL}/chat/completions", json=payload_bedrock, headers=headers)
    assert response_bedrock.status_code == 200
    bedrock_content = response_bedrock.json()["choices"][0]["message"]["content"]
    assert "Mocked Bedrock response" in bedrock_content
    assert MOCK_BEDROCK_CHAT_MODEL_ID in bedrock_content

    # 2. Chat with Vertex Mock Model
    payload_vertex = minimal_chat_payload().copy()
    payload_vertex["model"] = MOCK_VERTEX_CHAT_MODEL_ID
    payload_vertex["messages"] = [{"role": "user", "content": "Query for Vertex"}]
    response_vertex = requests.post(f"{BASE_URL}/chat/completions", json=payload_vertex, headers=headers)
    assert response_vertex.status_code == 200
    vertex_content = response_vertex.json()["choices"][0]["message"]["content"]
    assert "Mocked Vertex AI response" in vertex_content
    assert MOCK_VERTEX_CHAT_MODEL_ID in vertex_content
    assert bedrock_content != vertex_content # Ensure responses are different

# (SEQ_PROVIDER_SWITCH_002 for embeddings would be similar)

# --- E. Billing Service Interaction Sequence (Category: SEQ_BILLING) ---

@pytest.mark.asyncio
@patch('app.services.billing.billing_queue.put') # Patch asyncio.Queue.put
async def test_seq_billing_001_multiple_calls_trigger_billing_events(
    mock_billing_queue_put, valid_api_key_all_scopes,
    minimal_chat_payload, minimal_embedding_payload
):
    """SEQ_BILLING_001: Multiple Successful Calls Triggering Billing Events."""
    headers = make_headers(valid_api_key_all_scopes)
    
    # Call 1: Chat
    chat_payload1 = minimal_chat_payload().copy()
    chat_payload1["model"] = MOCK_BEDROCK_CHAT_MODEL_ID
    response_chat1 = requests.post(f"{BASE_URL}/chat/completions", json=chat_payload1, headers=headers)
    assert response_chat1.status_code == 200
    usage1 = response_chat1.json()["usage"]

    # Call 2: Embeddings
    embed_payload = minimal_embedding_payload().copy()
    embed_payload["model"] = MOCK_BEDROCK_EMBED_MODEL_ID
    response_embed = requests.post(f"{BASE_URL}/embeddings", json=embed_payload, headers=headers)
    assert response_embed.status_code == 200
    usage2 = response_embed.json()["usage"]

    # Call 3: Chat again (different model for variety)
    chat_payload2 = minimal_chat_payload().copy()
    chat_payload2["model"] = MOCK_VERTEX_CHAT_MODEL_ID
    response_chat2 = requests.post(f"{BASE_URL}/chat/completions", json=chat_payload2, headers=headers)
    assert response_chat2.status_code == 200
    usage3 = response_chat2.json()["usage"]

    # Allow time for async queue puts to be called if they are awaited in the endpoint
    await asyncio.sleep(0.1)


    assert mock_billing_queue_put.call_count == 3
    
    # Inspect arguments of each call to billing_queue.put
    # Note: The actual structure of billing_data depends on how it's created in your routers.
    # This assumes it's a dictionary passed as the first positional argument.
    
    # Call 1 data
    billing_data1 = mock_billing_queue_put.call_args_list[0].args[0]
    assert billing_data1["model_id"] == MOCK_BEDROCK_CHAT_MODEL_ID
    assert billing_data1["prompt_tokens"] == usage1["prompt_tokens"]
    assert billing_data1["completion_tokens"] == usage1["completion_tokens"]
    assert "api_key_id" in billing_data1 # Assuming this is included
    assert "manager_id" in billing_data1

    # Call 2 data
    billing_data2 = mock_billing_queue_put.call_args_list[1].args[0]
    assert billing_data2["model_id"] == MOCK_BEDROCK_EMBED_MODEL_ID
    assert billing_data2["prompt_tokens"] == usage2["prompt_tokens"]
    assert "completion_tokens" not in billing_data2 # Embeddings don't have completion tokens
    assert "api_key_id" in billing_data2
    assert "manager_id" in billing_data2

    # Call 3 data
    billing_data3 = mock_billing_queue_put.call_args_list[2].args[0]
    assert billing_data3["model_id"] == MOCK_VERTEX_CHAT_MODEL_ID
    assert billing_data3["prompt_tokens"] == usage3["prompt_tokens"]
    assert billing_data3["completion_tokens"] == usage3["completion_tokens"]
    assert "api_key_id" in billing_data3
    assert "manager_id" in billing_data3

