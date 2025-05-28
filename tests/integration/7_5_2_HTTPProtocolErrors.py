# tests/integration/7_5_2_HTTPProtocolErrors.py
# Tests for HTTP Protocol Error Handling
# Aligned with TestPlan.md Section 7.5 - Reliability and Error Handling Testing

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


class TestHTTPProtocolErrors:
    """Test cases for HTTP protocol error handling"""

    def test_resource_not_found_invalid_path(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_HTTP_001: Verify 404 for a path that doesn't exist.
        
        Expected: 404 Not Found with appropriate error message.
        """
        response = http_client.get(f"{config.BASE_URL}/thispathdoesnotexist", headers=auth_headers)
        
        assert response.status_code == 404
        error_data = response.json()
        assert "detail" in error_data
        assert "not found" in str(error_data["detail"]).lower()

    def test_resource_not_found_invalid_subpath(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_HTTP_002: Verify 404 for an invalid sub-path under models.
        
        Expected: 404 Not Found for non-existent model endpoints.
        """
        response = http_client.get(f"{config.BASE_URL}/models/someinvalidextension", headers=auth_headers)
        
        assert response.status_code == 404
        error_data = response.json()
        assert "detail" in error_data

    def test_method_not_allowed_models_post(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_HTTP_003: Verify 405 for POST to /models endpoint.
        
        Expected: 405 Method Not Allowed - models endpoint only supports GET.
        """
        response = http_client.post(f"{config.BASE_URL}/models", json={}, headers=auth_headers)
        
        assert response.status_code == 405
        error_data = response.json()
        assert "detail" in error_data
        assert "method not allowed" in str(error_data["detail"]).lower() or "405" in str(error_data)

    def test_method_not_allowed_chat_get(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_HTTP_004: Verify 405 for GET to /chat/completions endpoint.
        
        Expected: 405 Method Not Allowed - chat completions only supports POST.
        """
        response = http_client.get(f"{config.BASE_URL}/chat/completions", headers=auth_headers)
        
        assert response.status_code == 405
        error_data = response.json()
        assert "detail" in error_data

    def test_method_not_allowed_embeddings_put(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_HTTP_005: Verify 405 for PUT to /embeddings endpoint.
        
        Expected: 405 Method Not Allowed - embeddings only supports POST.
        """
        payload = {
            "model": config.get_embedding_model(),
            "input": "test"
        }
        
        response = http_client.put(f"{config.BASE_URL}/embeddings", json=payload, headers=auth_headers)
        
        assert response.status_code == 405
        error_data = response.json()
        assert "detail" in error_data

    def test_method_not_allowed_embeddings_delete(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        ECV_HTTP_006: Verify 405 for DELETE to /embeddings endpoint.
        
        Expected: 405 Method Not Allowed - embeddings doesn't support DELETE.
        """
        response = http_client.delete(f"{config.BASE_URL}/embeddings", headers=auth_headers)
        
        assert response.status_code == 405
        error_data = response.json()
        assert "detail" in error_data

    def test_accessing_root_path(self, http_client: httpx.Client):
        """
        ECV_HTTP_007: Verify behavior for root path access.
        
        Expected: Should return appropriate response (404 or redirect to docs).
        """
        # Extract base URL without /api/v1
        root_url = config.BASE_URL.replace("/api/v1", "")
        
        response = http_client.get(f"{root_url}/")
        
        # Could be 404 (no root route) or 200 (docs/health check)
        assert response.status_code in [200, 404]
        
        if response.status_code == 404:
            error_data = response.json()
            assert "detail" in error_data

    def test_accessing_api_path_without_version(self, http_client: httpx.Client):
        """
        ECV_HTTP_008: Verify behavior for /api/ path without version.
        
        Expected: 404 Not Found or redirect to versioned API.
        """
        api_root_url = config.BASE_URL.replace("/v1", "")  # Remove version
        
        response = http_client.get(f"{api_root_url}/")
        
        assert response.status_code in [200, 404, 301, 302]  # Various redirect/error responses
        
        if response.status_code == 404:
            error_data = response.json()
            assert "detail" in error_data

    def test_unsupported_http_methods(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test various unsupported HTTP methods on different endpoints.
        
        Expected: 405 Method Not Allowed for all unsupported methods.
        """
        endpoints_and_unsupported_methods = [
            ("/models", ["POST", "PUT", "DELETE", "PATCH"]),
            ("/chat/completions", ["GET", "PUT", "DELETE", "PATCH"]),
            ("/embeddings", ["GET", "PUT", "DELETE", "PATCH"])
        ]
        
        for endpoint, unsupported_methods in endpoints_and_unsupported_methods:
            for method in unsupported_methods:
                response = http_client.request(
                    method,
                    f"{config.BASE_URL}{endpoint}",
                    headers=auth_headers,
                    json={"test": "data"} if method in ["POST", "PUT", "PATCH"] else None
                )
                
                assert response.status_code == 405, \
                    f"Expected 405 for {method} {endpoint}, got {response.status_code}"

    def test_invalid_content_type_for_post_endpoints(self, http_client: httpx.Client):
        """
        Test POST endpoints with invalid content types.
        
        Expected: 400 or 415 for unsupported content types.
        """
        endpoints = ["/chat/completions", "/embeddings"]
        invalid_content_types = [
            "text/plain",
            "application/xml",
            "multipart/form-data",
            "application/x-www-form-urlencoded"
        ]
        
        for endpoint in endpoints:
            for content_type in invalid_content_types:
                headers = {
                    **config.get_auth_headers(),
                    "Content-Type": content_type
                }
                
                # Send some data appropriate for the content type
                if content_type == "text/plain":
                    data = "test data"
                elif content_type == "application/xml":
                    data = "<xml>test</xml>"
                else:
                    data = "key=value"
                
                response = http_client.post(
                    f"{config.BASE_URL}{endpoint}",
                    headers=headers,
                    content=data
                )
                
                # Should reject with 400 or 415
                assert response.status_code in [400, 415, 422], \
                    f"Expected error for {content_type} on {endpoint}, got {response.status_code}"

    def test_options_method_support(self, http_client: httpx.Client):
        """
        Test OPTIONS method support for CORS preflight requests.
        
        Expected: Should support OPTIONS for CORS or return 405.
        """
        endpoints = ["/models", "/chat/completions", "/embeddings"]
        
        for endpoint in endpoints:
            response = http_client.options(f"{config.BASE_URL}{endpoint}")
            
            # Either supports OPTIONS (200/204) or returns 405
            assert response.status_code in [200, 204, 405]
            
            if response.status_code in [200, 204]:
                # Should include CORS headers if CORS is enabled
                headers = response.headers
                # Common CORS headers
                cors_headers = ["access-control-allow-origin", "access-control-allow-methods"]
                # At least some CORS headers might be present
                pass  # CORS headers are optional depending on configuration

    def test_head_method_support(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test HEAD method support on GET endpoints.
        
        Expected: HEAD should work on /models or return 405.
        """
        response = http_client.head(f"{config.BASE_URL}/models", headers=auth_headers)
        
        # Either supports HEAD (200) or returns 405
        assert response.status_code in [200, 405]
        
        if response.status_code == 200:
            # HEAD should return same headers as GET but no body
            assert len(response.content) == 0

    def test_case_sensitivity_of_paths(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test case sensitivity of API paths.
        
        Expected: Paths should be case-sensitive (404 for wrong case).
        """
        case_variations = [
            "/Models",  # Capital M
            "/MODELS",  # All caps
            "/chat/Completions",  # Capital C
            "/Chat/Completions",  # Capital C in both
            "/EMBEDDINGS"  # All caps
        ]
        
        for path in case_variations:
            response = http_client.get(f"{config.BASE_URL}{path}", headers=auth_headers)
            
            # Should be case-sensitive and return 404
            assert response.status_code == 404, \
                f"Path {path} should return 404 for case mismatch"

    def test_trailing_slash_handling(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test handling of trailing slashes in paths.
        
        Expected: Should handle gracefully (redirect or accept).
        """
        paths_with_trailing_slash = [
            "/models/",
            "/chat/completions/",
            "/embeddings/"
        ]
        
        for path in paths_with_trailing_slash:
            response = http_client.get(f"{config.BASE_URL}{path}", headers=auth_headers)
            
            # Should either work (200), redirect (301/302), or return 404
            assert response.status_code in [200, 301, 302, 404]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])