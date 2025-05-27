# tests/integration/test_auth_errors.py
import pytest
import requests
# Corrected import: Changed from ..conftest to .conftest
from .conftest import BASE_URL, minimal_chat_payload, minimal_embedding_payload 

# Test data for parameterized tests
# Assuming minimal_chat_payload and minimal_embedding_payload are fixtures returning the payload,
# or functions that return the payload. If they are fixtures, they will be injected.
# If they are functions, they need to be called, e.g., minimal_chat_payload().
# Based on your conftest.py, they are fixtures, so no call () needed in parametrize.

# To use fixtures in parametrize, you typically pass their names as strings
# and then list them as arguments to the test function.
# However, for direct use in the list like this, they must be actual values or callables.
# Let's assume they are functions for this example or adjust if they are fixtures.
# If they are fixtures, the structure of parametrize might need to change or use indirect parametrization.

# For simplicity, assuming minimal_chat_payload and minimal_embedding_payload are functions defined in conftest
# or are simple dicts. If they are fixtures, this part needs adjustment.
# From your conftest.py, they are fixtures that return dicts.
# Pytest will inject these fixtures if listed as test function arguments.
# For direct use in parametrize, it's often easier to define them as constants or functions in conftest.
# Let's assume for now the conftest.py provides these as directly usable dicts for the list.
# If not, this list definition will need to be inside a fixture or test.

# Re-evaluating: minimal_chat_payload in conftest.py is a fixture.
# You can't call it directly in the parametrize list.
# One way is to make them simple functions in conftest.py or use indirect parametrization.
# For now, I will assume you will adjust conftest.py or the test structure slightly if direct fixture use in parametrize fails.
# The primary fix here is the import statement.

endpoints_requiring_auth = [
    ("GET", "/models", {}),
    # For POST, the payload will be injected by parametrize if the fixture name is used.
    # This current structure might be problematic if minimal_chat_payload is a fixture.
    # Let's proceed with the import fix first.
]

@pytest.mark.asyncio
@pytest.mark.parametrize("method, endpoint, payload_fixture_name", [
    ("GET", "/models", None), # No payload for GET
    ("POST", "/chat/completions", "minimal_chat_payload"),
    ("POST", "/embeddings", "minimal_embedding_payload")
])
async def test_ecv_auth_001_missing_auth_header(method: str, endpoint: str, payload_fixture_name: str, request):
    """ECV_AUTH_001: Verify API response when Authorization header is missing."""
    payload = request.getfixturevalue(payload_fixture_name) if payload_fixture_name else None
    response = requests.request(method, f"{BASE_URL}{endpoint}", json=payload if method == "POST" else None)
    
    if response.status_code == 403: # More likely default for missing header by Starlette/HTTPBearer
         assert response.json()["detail"] == "Not authenticated"
    elif response.status_code == 401: # If custom handling or specific FastAPI version
         assert "detail" in response.json() 
    else:
        pytest.fail(f"Expected 401 or 403, got {response.status_code} with body: {response.text}")

@pytest.mark.asyncio
@pytest.mark.parametrize("method, endpoint, payload_fixture_name", [
    ("GET", "/models", None),
    ("POST", "/chat/completions", "minimal_chat_payload"),
    ("POST", "/embeddings", "minimal_embedding_payload")
])
async def test_ecv_auth_002_malformed_auth_header_no_bearer(method: str, endpoint: str, payload_fixture_name: str, request):
    """ECV_AUTH_002: Verify API response for Authorization header without Bearer scheme."""
    payload = request.getfixturevalue(payload_fixture_name) if payload_fixture_name else None
    headers = {"Authorization": "InvalidScheme some_token"}
    response = requests.request(method, f"{BASE_URL}{endpoint}", headers=headers, json=payload if method == "POST" else None)
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.asyncio
@pytest.mark.parametrize("method, endpoint, payload_fixture_name", [
    ("GET", "/models", None),
    ("POST", "/chat/completions", "minimal_chat_payload"),
    ("POST", "/embeddings", "minimal_embedding_payload")
])
async def test_ecv_auth_003_malformed_auth_header_missing_token(method: str, endpoint: str, payload_fixture_name: str, request):
    """ECV_AUTH_003: Verify API response for Authorization header with Bearer but no token."""
    payload = request.getfixturevalue(payload_fixture_name) if payload_fixture_name else None
    headers = {"Authorization": "Bearer "}
    response = requests.request(method, f"{BASE_URL}{endpoint}", headers=headers, json=payload if method == "POST" else None)
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.asyncio
@pytest.mark.parametrize("method, endpoint, payload_fixture_name", [
    ("GET", "/models", None),
    ("POST", "/chat/completions", "minimal_chat_payload"),
    ("POST", "/embeddings", "minimal_embedding_payload")
])
async def test_ecv_auth_004_non_existent_api_key(method: str, endpoint: str, payload_fixture_name: str, request):
    """ECV_AUTH_004: Verify API response for a non-existent API key."""
    payload = request.getfixturevalue(payload_fixture_name) if payload_fixture_name else None
    headers = {"Authorization": "Bearer test_prefix_thisKeyDoesNotExistInDB123abc"}
    response = requests.request(method, f"{BASE_URL}{endpoint}", headers=headers, json=payload if method == "POST" else None)
    assert response.status_code == 401
    assert response.json()["detail"] == "Missing or invalid API key"

@pytest.mark.asyncio
@pytest.mark.parametrize("method, endpoint, payload_fixture_name", [
    ("GET", "/models", None),
    ("POST", "/chat/completions", "minimal_chat_payload"),
    ("POST", "/embeddings", "minimal_embedding_payload")
])
async def test_ecv_auth_005_inactive_api_key(method: str, endpoint: str, payload_fixture_name: str, request, inactive_api_key: str):
    """ECV_AUTH_005: Verify API response for an inactive API key."""
    payload = request.getfixturevalue(payload_fixture_name) if payload_fixture_name else None
    headers = {"Authorization": f"Bearer {inactive_api_key}"}
    response = requests.request(method, f"{BASE_URL}{endpoint}", headers=headers, json=payload if method == "POST" else None)
    assert response.status_code == 401
    assert response.json()["detail"] == "Missing or invalid API key"

@pytest.mark.asyncio
@pytest.mark.parametrize("method, endpoint, payload_fixture_name", [
    ("GET", "/models", None),
    ("POST", "/chat/completions", "minimal_chat_payload"),
    ("POST", "/embeddings", "minimal_embedding_payload")
])
async def test_ecv_auth_006_expired_api_key(method: str, endpoint: str, payload_fixture_name: str, request, expired_api_key: str):
    """ECV_AUTH_006: Verify API response for an expired API key."""
    payload = request.getfixturevalue(payload_fixture_name) if payload_fixture_name else None
    headers = {"Authorization": f"Bearer {expired_api_key}"}
    response = requests.request(method, f"{BASE_URL}{endpoint}", headers=headers, json=payload if method == "POST" else None)
    assert response.status_code == 401
    assert response.json()["detail"] == "API key is expired"

@pytest.mark.asyncio
async def test_ecv_auth_007_insufficient_scope_chat(valid_api_key_embedding_only: str, minimal_chat_payload):
    """ECV_AUTH_007: Verify 401 for chat/completions with key lacking 'models:inference' scope."""
    headers = {"Authorization": f"Bearer {valid_api_key_embedding_only}", "Content-Type": "application/json"}
    response = requests.post(f"{BASE_URL}/chat/completions", json=minimal_chat_payload, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Not Authorized"

@pytest.mark.asyncio
async def test_ecv_auth_008_insufficient_scope_embeddings(valid_api_key_inference_only: str, minimal_embedding_payload):
    """ECV_AUTH_008: Verify 401 for /embeddings with key lacking 'models:embedding' scope."""
    headers = {"Authorization": f"Bearer {valid_api_key_inference_only}", "Content-Type": "application/json"}
    response = requests.post(f"{BASE_URL}/embeddings", json=minimal_embedding_payload, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Not Authorized"

@pytest.mark.asyncio
async def test_ecv_auth_009_valid_key_chat_positive(valid_api_key_all_scopes: str, minimal_chat_payload):
    """ECV_AUTH_009: Positive test for /chat/completions with valid key and scope."""
    headers = {"Authorization": f"Bearer {valid_api_key_all_scopes}", "Content-Type": "application/json"}
    response = requests.post(f"{BASE_URL}/chat/completions", json=minimal_chat_payload, headers=headers)
    assert response.status_code == 200 
    assert "choices" in response.json()

@pytest.mark.asyncio
async def test_ecv_auth_010_valid_key_embeddings_positive(valid_api_key_all_scopes: str, minimal_embedding_payload):
    """ECV_AUTH_010: Positive test for /embeddings with valid key and scope."""
    headers = {"Authorization": f"Bearer {valid_api_key_all_scopes}", "Content-Type": "application/json"}
    response = requests.post(f"{BASE_URL}/embeddings", json=minimal_embedding_payload, headers=headers)
    assert response.status_code == 200 
    assert "data" in response.json()

@pytest.mark.asyncio
async def test_ecv_auth_011_valid_key_no_scopes_chat(valid_api_key_no_scopes: str, minimal_chat_payload):
    """ECV_AUTH_011: Verify 401 for /chat/completions with key having no scopes."""
    headers = {"Authorization": f"Bearer {valid_api_key_no_scopes}", "Content-Type": "application/json"}
    response = requests.post(f"{BASE_URL}/chat/completions", json=minimal_chat_payload, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Not Authorized"

@pytest.mark.asyncio
async def test_ecv_auth_012_valid_key_irrelevant_scopes_chat(valid_api_key_embedding_only: str, minimal_chat_payload):
    """ECV_AUTH_012: Verify 401 for /chat/completions with key having irrelevant scopes."""
    headers = {"Authorization": f"Bearer {valid_api_key_embedding_only}", "Content-Type": "application/json"}
    response = requests.post(f"{BASE_URL}/chat/completions", json=minimal_chat_payload, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Not Authorized"

@pytest.mark.asyncio
async def test_ecv_auth_013_models_endpoint_no_specific_scope_needed(valid_api_key_no_scopes: str):
    """ECV_AUTH_013: Verify /models endpoint accessible with valid key, even with no specific scopes."""
    headers = {"Authorization": f"Bearer {valid_api_key_no_scopes}"}
    response = requests.get(f"{BASE_URL}/models", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
