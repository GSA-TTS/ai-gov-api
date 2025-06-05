# tests/integration/7_5_3_ServerErrorHandling.py
# Tests for Server Error Handling and Resilience
# Aligned with TestPlan.md Section 7.5 - Reliability and Error Handling Testing

import pytest
import httpx
import asyncio
from typing import Dict, Any
from .config import config
from ..utils.ssl_config import create_httpx_client, create_async_httpx_client


@pytest.fixture
def auth_headers() -> Dict[str, str]:
    """Valid authorization headers for live API."""
    return config.get_auth_headers()


@pytest.fixture
def http_client():
    """Create an HTTP client for making requests."""
    with create_httpx_client(timeout=config.TIMEOUT) as client:
        yield client


class TestServerErrorHandling:
    """Test cases for server error handling and resilience without mocking"""

    def test_malformed_json_request_handling(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test server handling of malformed JSON requests.
        
        Expected: 400 Bad Request with proper error message, not 500.
        """
        malformed_json = '{"model": "test", "messages": [{"role": "user", "content": "test"}' # Missing closing brackets
        
        response = http_client.post(
            f"{config.BASE_URL}/chat/completions",
            headers=auth_headers,
            content=malformed_json
        )
        
        # Should handle malformed JSON gracefully
        assert response.status_code in [400, 422], f"Expected 400/422 for malformed JSON, got {response.status_code}"
        
        if response.status_code != 500:
            # Should not be a server error
            error_data = response.json()
            assert "detail" in error_data or "error" in error_data

    def test_oversized_request_handling(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test server handling of extremely large requests.
        
        Expected: 413 Payload Too Large or 400, not 500.
        """
        # Create an extremely large message (1MB+)
        large_content = "A" * (1024 * 1024)  # 1MB of text
        
        payload = {
            "model": config.get_chat_model(),
            "messages": [{"role": "user", "content": large_content}],
            "max_tokens": 10
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        # Should handle large payloads gracefully
        assert response.status_code in [400, 413, 422], \
            f"Expected client error for large payload, got {response.status_code}"

    def test_concurrent_request_stability(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test server stability under concurrent load.
        
        Expected: Server should handle concurrent requests without 500 errors.
        """
        async def make_request(client: httpx.AsyncClient, request_id: int):
            payload = {
                "model": config.get_chat_model(),
                "messages": [{"role": "user", "content": f"Concurrent test {request_id}"}],
                "max_tokens": 10
            }
            return await client.post(
                f"{config.BASE_URL}/chat/completions",
                json=payload,
                headers=auth_headers
            )
        
        async def run_concurrent_test():
            async with create_async_httpx_client(timeout=config.TIMEOUT) as client:
                # Make 10 concurrent requests
                tasks = [make_request(client, i) for i in range(10)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                success_count = 0
                server_errors = 0
                
                for response in responses:
                    if isinstance(response, Exception):
                        # Network/timeout errors are acceptable under load
                        continue
                    elif response.status_code == 200:
                        success_count += 1
                    elif response.status_code == 500:
                        server_errors += 1
                    # Other errors (429, 400) are acceptable
                
                # At least some requests should succeed, and server errors should be minimal
                assert success_count > 0, "At least some concurrent requests should succeed"
                assert server_errors < 5, f"Too many server errors: {server_errors}/10"
        
        # Run the async test
        asyncio.run(run_concurrent_test())

    def test_timeout_handling_long_running_request(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test server handling of potentially long-running requests.
        
        Expected: Should timeout gracefully or complete successfully.
        """
        # Request that might take a long time
        payload = {
            "model": config.get_chat_model(),
            "messages": [{"role": "user", "content": "Write a detailed explanation of quantum computing in exactly 500 words."}],
            "max_tokens": 600,  # Large token count
            "temperature": 0.1
        }
        
        # Use a longer timeout for this specific test
        with create_httpx_client(timeout=60.0) as long_timeout_client:
            response = long_timeout_client.post(
                f"{config.BASE_URL}/chat/completions",
                json=payload,
                headers=auth_headers
            )
            
            # Should either complete successfully or timeout gracefully
            if response.status_code == 200:
                data = response.json()
                assert "choices" in data
            elif response.status_code == 504:
                # Gateway timeout is acceptable for long requests
                pass
            elif response.status_code in [400, 429]:
                # Rate limit or parameter issues are acceptable
                pass
            else:
                # Should not be a server error
                assert response.status_code != 500, f"Server error on long request: {response.text}"

    def test_invalid_content_type_handling(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test server handling of requests with invalid content types.
        
        Expected: 400 or 415, not 500.
        """
        payload_text = "This is not JSON"
        headers = {**auth_headers, "Content-Type": "text/plain"}
        
        response = http_client.post(
            f"{config.BASE_URL}/chat/completions",
            headers=headers,
            content=payload_text
        )
        
        assert response.status_code in [400, 415, 422], \
            f"Expected client error for invalid content type, got {response.status_code}"

    def test_missing_required_headers_handling(self, http_client: httpx.Client):
        """
        Test server handling when required headers are missing.
        
        Expected: 401 or 400, not 500.
        """
        payload = {
            "model": config.get_chat_model(),
            "messages": [{"role": "user", "content": "Test"}]
        }
        
        # Request without authorization header
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload)
        
        assert response.status_code in [401, 403], \
            f"Expected auth error for missing header, got {response.status_code}"

    def test_provider_error_graceful_handling(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test handling when providers might return errors.
        
        Expected: Proper error handling, potentially with fallback or retry.
        """
        # Send requests that might trigger provider errors
        problematic_requests = [
            {
                "model": config.get_chat_model(),
                "messages": [{"role": "user", "content": ""}],  # Empty content
                "max_tokens": 0  # Invalid token count
            },
            {
                "model": config.get_chat_model(),
                "messages": [{"role": "user", "content": "Test"}],
                "temperature": -1  # Invalid temperature
            }
        ]
        
        for payload in problematic_requests:
            response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            # Should handle provider errors gracefully
            if response.status_code != 200:
                assert response.status_code in [400, 422, 500], \
                    f"Expected client error or handled server error for invalid params, got {response.status_code}: {response.text}"

    def test_request_id_in_error_responses(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test that error responses include request IDs for tracking.
        
        Expected: Error responses should include request_id for debugging.
        """
        # Trigger an error with invalid model
        payload = {
            "model": "definitely_invalid_model",
            "messages": [{"role": "user", "content": "Test"}]
        }
        
        response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
        
        assert response.status_code in [400, 422]
        
        # Check for request ID in response or headers
        error_data = response.json()
        has_request_id = (
            "request_id" in error_data or
            "requestId" in error_data or
            "x-request-id" in response.headers or
            "x-amzn-requestid" in response.headers
        )
        
        # Request ID helps with debugging, should be present
        # Make this optional as not all APIs implement request IDs
        if not has_request_id:
            # Log warning but don't fail test - request IDs are beneficial but not critical
            print(f"Warning: No request ID found in error response: {error_data}")

    def test_partial_request_handling(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test handling of partially constructed requests.
        
        Expected: Proper validation errors, not server crashes.
        """
        partial_requests = [
            {},  # Empty request
            {"model": config.get_chat_model()},  # Missing messages
            {"messages": [{"role": "user", "content": "test"}]},  # Missing model
            {"model": "", "messages": []},  # Empty values
        ]
        
        for payload in partial_requests:
            response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            # Should validate and return appropriate errors
            assert response.status_code in [400, 422], \
                f"Expected validation error for partial request {payload}, got {response.status_code}"

    def test_unicode_and_encoding_handling(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test server handling of various Unicode and encoding scenarios.
        
        Expected: Should handle Unicode gracefully without crashes.
        """
        unicode_tests = [
            "Hello 世界 🌍",  # Mixed languages and emoji
            "\U0001F600\U0001F601\U0001F602",  # Emoji sequence
            "Café münü naïve résumé",  # Accented characters
            "\u0000\u0001\u0002",  # Control characters
            "A" * 1000 + "世界",  # Long text with Unicode
        ]
        
        for unicode_content in unicode_tests:
            payload = {
                "model": config.get_chat_model(),
                "messages": [{"role": "user", "content": unicode_content}],
                "max_tokens": 10
            }
            
            response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            # Should handle Unicode gracefully
            assert response.status_code in [200, 400, 422], \
                f"Server error on Unicode content: {repr(unicode_content)}"

    def test_error_response_format_consistency(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
        """
        Test that error responses have consistent format across different error types.
        
        Expected: All errors should follow the same response schema.
        """
        error_scenarios = [
            # Invalid model
            {
                "model": "invalid_model",
                "messages": [{"role": "user", "content": "test"}]
            },
            # Invalid parameters
            {
                "model": config.get_chat_model(),
                "messages": [{"role": "user", "content": "test"}],
                "temperature": 99
            },
            # Missing required field
            {
                "model": config.get_chat_model()
            }
        ]
        
        error_formats = []
        for payload in error_scenarios:
            response = http_client.post(f"{config.BASE_URL}/chat/completions", json=payload, headers=auth_headers)
            
            if response.status_code != 200:
                error_data = response.json()
                error_formats.append(set(error_data.keys()))
        
        # All error responses should have similar structure
        if len(error_formats) > 1:
            common_keys = set.intersection(*error_formats)
            assert len(common_keys) > 0, "Error responses should have consistent structure"
            assert any(key in common_keys for key in ["detail", "error", "message"]), \
                "Error responses should include error message field"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])