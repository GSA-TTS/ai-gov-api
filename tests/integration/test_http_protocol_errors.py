# tests/integration/test_http_protocol_errors.py
import pytest
import requests
from .conftest import BASE_URL, valid_headers, minimal_chat_payload, minimal_embedding_payload, configured_embedding_model_id

@pytest.mark.asyncio
async def test_ecv_http_001_resource_not_found_invalid_path(valid_headers):
    """ECV_HTTP_001: Verify 404 for a path that doesn't exist."""
    response = requests.get(f"{BASE_URL}/thispathdoesnotexist", headers=valid_headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "Not Found"

@pytest.mark.asyncio
async def test_ecv_http_002_resource_not_found_invalid_subpath(valid_headers):
    """ECV_HTTP_002: Verify 404 for an invalid sub-path."""
    response = requests.get(f"{BASE_URL}/models/someinvalidextension", headers=valid_headers)
    assert response.status_code == 404 # This assumes /models/{anything} is not a valid route pattern
    assert response.json()["detail"] == "Not Found"

@pytest.mark.asyncio
async def test_ecv_http_003_method_not_allowed_models(valid_headers):
    """ECV_HTTP_003: Verify 405 for POST to /models."""
    response = requests.post(f"{BASE_URL}/models", json={}, headers=valid_headers)
    assert response.status_code == 405
    assert response.json()["detail"] == "Method Not Allowed"

@pytest.mark.asyncio
async def test_ecv_http_004_method_not_allowed_chat(valid_headers):
    """ECV_HTTP_004: Verify 405 for GET to /chat/completions."""
    response = requests.get(f"{BASE_URL}/chat/completions", headers=valid_headers)
    assert response.status_code == 405
    assert response.json()["detail"] == "Method Not Allowed"

@pytest.mark.asyncio
async def test_ecv_http_005_method_not_allowed_embeddings(valid_headers, configured_embedding_model_id):
    """ECV_HTTP_005: Verify 405 for PUT to /embeddings."""
    payload = {"model": configured_embedding_model_id, "input": "test"}
    response = requests.put(f"{BASE_URL}/embeddings", json=payload, headers=valid_headers)
    assert response.status_code == 405
    assert response.json()["detail"] == "Method Not Allowed"

@pytest.mark.asyncio
async def test_ecv_http_006_accessing_root_path():
    """ECV_HTTP_006: Verify 404 for root path / if not defined."""
    # Remove BASE_URL part that includes /api/v1
    root_url = BASE_URL.replace("/api/v1", "")
    response = requests.get(f"{root_url}/")
    assert response.status_code == 404 # FastAPI default if no route for /
    assert response.json()["detail"] == "Not Found"

@pytest.mark.asyncio
async def test_ecv_http_007_accessing_api_path():
    """ECV_HTTP_007: Verify 404 for /api/ path if not defined."""
    api_root_url = BASE_URL.replace("/v1", "") # e.g. http://localhost:8000/api
    response = requests.get(f"{api_root_url}/")
    assert response.status_code == 404 # FastAPI default if no route for /api/
    assert response.json()["detail"] == "Not Found"

