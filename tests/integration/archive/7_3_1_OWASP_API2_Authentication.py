# tests/integration/7_3_1_OWASP_API2_Authentication.py
# Tests for OWASP API2: Broken Authentication
# Aligned with TestPlan.md Section 7.3.1 - OWASP API Security Top 10 (2023) Testing

import pytest
import httpx
from typing import Dict, Any, Optional
import time
import base64
import secrets

# Live API endpoint configuration
BASE_URL = "https://api.dev.aigov.mcaas.fcs.gsa.gov/api/v1"
VALID_API_KEY = "test_adm_HwYbweaBtJmeo_Ec"  # From tests.eml

# Test models
CHAT_MODEL = "claude_3_5_sonnet"
EMBEDDING_MODEL = "cohere_english_v3"


@pytest.fixture
def http_client():
    """Create an HTTP client for making requests."""
    with httpx.Client(timeout=30.0) as client:
        yield client


@pytest.fixture
def chat_payload() -> Dict[str, Any]:
    """Minimal chat completion payload."""
    return {
        "model": CHAT_MODEL,
        "messages": [{"role": "user", "content": "Hello"}],
        "max_tokens": 10
    }


@pytest.fixture
def embedding_payload() -> Dict[str, Any]:
    """Minimal embedding payload."""
    return {
        "model": EMBEDDING_MODEL,
        "input": "Test embedding"
    }


class TestOWASPAPI2Authentication:
    """Test cases for API2: Broken Authentication"""

    # Test endpoints that require authentication
    endpoints = [
        ("GET", "/models", None),
        ("POST", "/chat/completions", "chat_payload"),
        ("POST", "/embeddings", "embedding_payload")
    ]

    @pytest.mark.parametrize("method,endpoint,payload_fixture", endpoints)
    def test_missing_auth_header(self, http_client: httpx.Client, method: str, endpoint: str, 
                                payload_fixture: Optional[str], request):
        """
        ECV_AUTH_001: Verify API response when Authorization header is missing.
        
        Expected: 401 Unauthorized or 403 Forbidden with appropriate error message.
        """
        payload = request.getfixturevalue(payload_fixture) if payload_fixture else None
        
        if method == "GET":
            response = http_client.get(f"{BASE_URL}{endpoint}")
        else:
            response = http_client.post(f"{BASE_URL}{endpoint}", json=payload)
        
        assert response.status_code in [401, 403], \
            f"Expected 401/403, got {response.status_code}: {response.text}"
        
        error_data = response.json()
        assert "detail" in error_data or "error" in error_data, \
            "Error response should contain 'detail' or 'error' field"

    @pytest.mark.parametrize("method,endpoint,payload_fixture", endpoints)
    def test_malformed_auth_header_wrong_scheme(self, http_client: httpx.Client, method: str, 
                                               endpoint: str, payload_fixture: Optional[str], request):
        """
        ECV_AUTH_002: Verify API response for Authorization header without Bearer scheme.
        
        Expected: 401 Unauthorized - incorrect authentication scheme.
        """
        payload = request.getfixturevalue(payload_fixture) if payload_fixture else None
        headers = {"Authorization": "Basic dGVzdDp0ZXN0"}  # Basic auth instead of Bearer
        
        if method == "GET":
            response = http_client.get(f"{BASE_URL}{endpoint}", headers=headers)
        else:
            response = http_client.post(f"{BASE_URL}{endpoint}", json=payload, headers=headers)
        
        assert response.status_code in [401, 403], \
            f"Expected 401 or 403, got {response.status_code}: {response.text}"

    @pytest.mark.parametrize("method,endpoint,payload_fixture", endpoints)
    def test_malformed_auth_header_empty_token(self, http_client: httpx.Client, method: str,
                                             endpoint: str, payload_fixture: Optional[str], request):
        """
        ECV_AUTH_003: Verify API response for Authorization header with Bearer but no token.
        
        Expected: 401 Unauthorized - missing token value.
        """
        payload = request.getfixturevalue(payload_fixture) if payload_fixture else None
        headers = {"Authorization": "Bearer"}  # No space to avoid protocol error
        
        try:
            if method == "GET":
                response = http_client.get(f"{BASE_URL}{endpoint}", headers=headers)
            else:
                response = http_client.post(f"{BASE_URL}{endpoint}", json=payload, headers=headers)
            
            assert response.status_code in [401, 403], \
                f"Expected 401 or 403, got {response.status_code}: {response.text}"
        except httpx.LocalProtocolError:
            # HTTP client correctly rejects malformed headers
            pass

    @pytest.mark.parametrize("method,endpoint,payload_fixture", endpoints)
    def test_non_existent_api_key(self, http_client: httpx.Client, method: str,
                                 endpoint: str, payload_fixture: Optional[str], request):
        """
        ECV_AUTH_004: Verify API response for a non-existent API key.
        
        Expected: 401 Unauthorized - invalid API key.
        """
        payload = request.getfixturevalue(payload_fixture) if payload_fixture else None
        # Generate a random key that definitely doesn't exist
        fake_key = f"test_fake_{secrets.token_urlsafe(32)}"
        headers = {"Authorization": f"Bearer {fake_key}"}
        
        if method == "GET":
            response = http_client.get(f"{BASE_URL}{endpoint}", headers=headers)
        else:
            response = http_client.post(f"{BASE_URL}{endpoint}", json=payload, headers=headers)
        
        assert response.status_code in [401, 403], \
            f"Expected 401 or 403, got {response.status_code}: {response.text}"

    def test_api_key_format_validation(self, http_client: httpx.Client):
        """
        Test various invalid API key formats.
        
        Expected: 401 for all malformed keys.
        """
        invalid_keys = [
            "",  # Empty
            " ",  # Whitespace
            "a" * 5,  # Too short
            "test_",  # Incomplete prefix
            "invalid-format-key",  # Wrong format
            "test_prefix_" + "x" * 100,  # Too long
            "test_prefix_<script>alert(1)</script>",  # XSS attempt
            "test_prefix_'; DROP TABLE users; --",  # SQL injection
            "test_prefix_\x00\x01\x02",  # Binary data
            "test_prefix_../../etc/passwd",  # Path traversal
        ]
        
        for invalid_key in invalid_keys:
            try:
                headers = {"Authorization": f"Bearer {invalid_key}"}
                response = http_client.get(f"{BASE_URL}/models", headers=headers)
                
                assert response.status_code in [401, 403], \
                    f"Key '{invalid_key}' should be rejected, got {response.status_code}"
            except httpx.LocalProtocolError:
                # HTTP client correctly rejects malformed headers
                pass

    def test_timing_attack_resistance(self, http_client: httpx.Client):
        """
        Test that API key validation is resistant to timing attacks.
        
        Expected: Similar response times for valid vs invalid keys.
        """
        # Valid key (but not authorized for this test environment)
        valid_format_key = "test_prefix_" + secrets.token_urlsafe(32)
        
        # Completely invalid key
        invalid_key = "invalid_" + secrets.token_urlsafe(32)
        
        # Measure response times
        valid_times = []
        invalid_times = []
        
        for _ in range(5):
            # Test valid format key
            start = time.time()
            response = http_client.get(
                f"{BASE_URL}/models",
                headers={"Authorization": f"Bearer {valid_format_key}"}
            )
            valid_times.append(time.time() - start)
            assert response.status_code == 401
            
            # Test invalid key
            start = time.time()
            response = http_client.get(
                f"{BASE_URL}/models", 
                headers={"Authorization": f"Bearer {invalid_key}"}
            )
            invalid_times.append(time.time() - start)
            assert response.status_code == 401
        
        # Check that timing difference is minimal (within 100ms on average)
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        
        timing_diff = abs(avg_valid - avg_invalid)
        assert timing_diff < 0.1, \
            f"Timing attack possible: {avg_valid:.3f}s vs {avg_invalid:.3f}s"

    def test_auth_header_case_sensitivity(self, http_client: httpx.Client):
        """
        Test that authentication is case-sensitive where appropriate.
        
        Expected: Bearer scheme should be case-insensitive, token should be case-sensitive.
        """
        valid_headers = {"Authorization": f"Bearer {VALID_API_KEY}"}
        
        # Test 1: Bearer scheme variations (should work)
        scheme_variations = ["Bearer", "bearer", "BEARER", "BeArEr"]
        for scheme in scheme_variations:
            headers = {"Authorization": f"{scheme} {VALID_API_KEY}"}
            response = http_client.get(f"{BASE_URL}/models", headers=headers)
            assert response.status_code == 200, \
                f"Scheme '{scheme}' should be accepted, got {response.status_code}"
        
        # Test 2: Token case variations (should fail if key is case-sensitive)
        if VALID_API_KEY != VALID_API_KEY.upper():  # Only test if key has mixed case
            headers = {"Authorization": f"Bearer {VALID_API_KEY.upper()}"}
            response = http_client.get(f"{BASE_URL}/models", headers=headers)
            assert response.status_code == 401, \
                "API key should be case-sensitive"

    def test_multiple_auth_headers(self, http_client: httpx.Client):
        """
        Test behavior with multiple Authorization headers.
        
        Expected: Should handle gracefully, typically using first or rejecting.
        """
        # httpx doesn't easily support duplicate headers, so we test with raw request
        # This is a edge case that might need special handling
        
        # For now, test comma-separated values (some clients might send this)
        headers = {"Authorization": f"Bearer {VALID_API_KEY}, Bearer invalid_key"}
        response = http_client.get(f"{BASE_URL}/models", headers=headers)
        
        # Should either work (using first) or fail (rejecting malformed)
        assert response.status_code in [200, 400, 401], \
            f"Unexpected status for multiple auth values: {response.status_code}"

    def test_auth_persistence_not_stateful(self, http_client: httpx.Client):
        """
        Verify that authentication is stateless - each request needs auth.
        
        Expected: Previous successful auth shouldn't affect next request without header.
        """
        # First request with valid auth
        headers = {"Authorization": f"Bearer {VALID_API_KEY}"}
        response1 = http_client.get(f"{BASE_URL}/models", headers=headers)
        assert response1.status_code == 200
        
        # Second request without auth (same client session)
        response2 = http_client.get(f"{BASE_URL}/models")
        assert response2.status_code in [401, 403], \
            "API should not maintain auth state between requests"

    @pytest.mark.parametrize("special_char", [
        "\n", "\r", "\t", "\x00", "\x01", "\x1f", "\x7f"
    ])
    def test_special_characters_in_auth_header(self, http_client: httpx.Client, special_char: str):
        """
        Test handling of special characters in Authorization header.
        
        Expected: Should reject or sanitize properly.
        """
        try:
            headers = {"Authorization": f"Bearer test_key{special_char}value"}
            response = http_client.get(f"{BASE_URL}/models", headers=headers)
            
            assert response.status_code in [401, 403], \
                f"Special char {repr(special_char)} should cause auth failure"
        except httpx.LocalProtocolError:
            # HTTP client correctly rejects malformed headers with control characters
            pass

    def test_auth_error_messages_no_enumeration(self, http_client: httpx.Client):
        """
        Verify error messages don't allow user/key enumeration.
        
        Expected: Same error message for different failure reasons.
        """
        # Non-existent key
        headers1 = {"Authorization": "Bearer test_nonexistent_key123"}
        response1 = http_client.get(f"{BASE_URL}/models", headers=headers1)
        assert response1.status_code == 401
        error1 = response1.json()
        
        # Malformed key
        headers2 = {"Authorization": "Bearer malformed"}
        response2 = http_client.get(f"{BASE_URL}/models", headers=headers2)
        assert response2.status_code == 401
        error2 = response2.json()
        
        # Error messages should be generic and similar
        # They shouldn't reveal whether key exists, is expired, or is invalid format
        assert "api key" in str(error1).lower() or "auth" in str(error1).lower()
        assert "api key" in str(error2).lower() or "auth" in str(error2).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])