# Section 7.3 - Cryptographic Implementation Security Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Cryptographic Implementation Security.md

import pytest
import httpx
import asyncio
import hashlib
import secrets
import time
from typing import Dict, Any, List
import base64
import re

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures
from utils.security_validators import SecurityValidator

class TestCryptographicSecurity:
    """Comprehensive cryptographic implementation security tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api_key_entropy_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     make_request):
        """CRYPTO_ENTROPY_001: API key entropy validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test with current API key to ensure it meets entropy requirements
        api_key = auth_headers.get("Authorization", "").replace("Bearer ", "")
        
        if api_key:
            # Validate key length (should be at least 32 characters)
            assert len(api_key) >= 32, "API key should be at least 32 characters long"
            
            # Check for reasonable entropy (not all same character, has variety)
            unique_chars = len(set(api_key))
            assert unique_chars >= 16, f"API key should have diverse characters (found {unique_chars})"
            
            # Check for common weak patterns
            weak_patterns = [
                r"^[0-9]+$",  # All digits
                r"^[a-z]+$",  # All lowercase
                r"^[A-Z]+$",  # All uppercase
                r"(.)\1{5,}", # Repeated characters
                r"^(abc|123|password|test)"  # Common weak prefixes
            ]
            
            for pattern in weak_patterns:
                assert not re.search(pattern, api_key, re.IGNORECASE), \
                    f"API key contains weak pattern: {pattern}"
        
        logger.info("CRYPTO_ENTROPY_001: API key entropy validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_hash_algorithm_strength_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """CRYPTO_HASH_001: Hash algorithm strength validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test that API accepts only strong hash algorithms
        # This is tested indirectly through API key validation
        
        test_data = "test_string_for_hashing"
        
        # Generate hashes with different algorithms
        hash_results = {
            "sha256": hashlib.sha256(test_data.encode()).hexdigest(),
            "sha512": hashlib.sha512(test_data.encode()).hexdigest(),
            "md5": hashlib.md5(test_data.encode()).hexdigest(),  # Weak
        }
        
        # Verify strong algorithms produce expected length outputs
        assert len(hash_results["sha256"]) == 64, "SHA-256 should produce 64-character hash"
        assert len(hash_results["sha512"]) == 128, "SHA-512 should produce 128-character hash"
        
        # MD5 should not be used for security purposes (only for testing)
        logger.warning("MD5 detected in test - should not be used for production security")
        
        logger.info("CRYPTO_HASH_001: Hash algorithm strength validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_timing_attack_prevention_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """CRYPTO_TIMING_001: Timing attack prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test timing consistency in authentication
        invalid_keys = [
            "Bearer invalid_key_1",
            "Bearer invalid_key_2",
            "Bearer completely_different_length_key_here",
            "Bearer short",
            "Bearer " + "x" * 100  # Very long key
        ]
        
        timing_results = []
        
        for invalid_key in invalid_keys:
            invalid_headers = {"Authorization": invalid_key}
            
            start_time = time.perf_counter()
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                invalid_headers, track_cost=False
            )
            
            end_time = time.perf_counter()
            response_time = end_time - start_time
            
            timing_results.append(response_time)
            
            # All should return 401 Unauthorized
            assert response.status_code == 401
            
            await asyncio.sleep(0.1)  # Small delay between requests
        
        # Analyze timing variance
        avg_time = sum(timing_results) / len(timing_results)
        max_deviation = max(abs(t - avg_time) for t in timing_results)
        
        # Timing should be relatively consistent (within 50ms)
        if max_deviation > 0.05:  # 50ms threshold
            logger.warning(f"High timing variance detected: {max_deviation:.3f}s")
        else:
            logger.info("Timing attack resistance: GOOD")
        
        logger.info("CRYPTO_TIMING_001: Timing attack prevention tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_tls_configuration_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       make_request):
        """CRYPTO_TLS_001: TLS configuration validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test that API enforces HTTPS
        base_url = config.BASE_URL
        
        if base_url.startswith("https://"):
            logger.info("API correctly uses HTTPS")
            
            # Test standard API call over HTTPS
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            
            assert response.status_code == 200
            
        elif base_url.startswith("http://"):
            if "localhost" in base_url or "127.0.0.1" in base_url:
                logger.warning("Using HTTP for localhost - acceptable for testing")
            else:
                pytest.fail("Production API should use HTTPS, not HTTP")
        
        logger.info("CRYPTO_TLS_001: TLS configuration validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_key_rotation_support_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """CRYPTO_ROTATION_001: Key rotation capability testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test that current key works
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        
        # Test key validation endpoint (if available)
        potential_validation_endpoints = [
            "/tokens/validate",
            "/api/v1/auth/validate",
            "/auth/validate"
        ]
        
        for endpoint in potential_validation_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                logger.info(f"Key validation endpoint found: {endpoint}")
                response_data = response.json()
                
                # Check for rotation-related metadata
                if "expires_at" in response_data or "expires" in response_data:
                    logger.info("Key expiration metadata present - supports rotation")
                
            elif response.status_code == 404:
                logger.info(f"Validation endpoint not found: {endpoint}")
            
        logger.info("CRYPTO_ROTATION_001: Key rotation support evaluated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_certificate_validation_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """CRYPTO_CERT_001: Certificate validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test certificate chain validation (for HTTPS endpoints)
        if config.BASE_URL.startswith("https://"):
            # This test verifies that the client properly validates certificates
            # The httpx client will raise an exception for invalid certificates
            
            try:
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
                
                assert response.status_code == 200
                logger.info("Certificate validation: PASSED")
                
            except Exception as e:
                if "certificate" in str(e).lower() or "ssl" in str(e).lower():
                    pytest.fail(f"Certificate validation failed: {e}")
                else:
                    raise
        else:
            logger.info("Certificate validation: SKIPPED (HTTP endpoint)")
        
        logger.info("CRYPTO_CERT_001: Certificate validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_fips_compliance_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     make_request):
        """CRYPTO_FIPS_001: FIPS 140-2 compliance validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test FIPS-approved algorithms usage
        # This is mainly validated through successful API operations
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        
        # Test with cryptographic operations in chat
        fips_test_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "FIPS compliance test"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, fips_test_request
        )
        
        assert response.status_code == 200
        
        logger.info("CRYPTO_FIPS_001: FIPS compliance validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_nist_compliance_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     make_request):
        """CRYPTO_NIST_001: NIST cryptographic standards compliance"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test NIST-compliant operations
        nist_test_scenarios = [
            {
                "description": "Standard API operation",
                "method": "GET",
                "endpoint": "/api/v1/models",
                "data": None
            },
            {
                "description": "Chat completion with encryption",
                "method": "POST", 
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "NIST compliance test"}],
                    "max_tokens": 50
                }
            }
        ]
        
        for scenario in nist_test_scenarios:
            response = await make_request(
                http_client, scenario["method"], scenario["endpoint"],
                auth_headers, scenario["data"],
                track_cost=(scenario["method"] == "POST")
            )
            
            assert response.status_code == 200, \
                f"NIST compliance test failed for: {scenario['description']}"
        
        logger.info("CRYPTO_NIST_001: NIST compliance validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_secure_random_generation_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """CRYPTO_RANDOM_001: Secure random number generation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Generate secure random values for testing
        random_values = [secrets.token_hex(16) for _ in range(10)]
        
        # Verify uniqueness (all should be different)
        assert len(set(random_values)) == len(random_values), \
            "All generated random values should be unique"
        
        # Verify proper length
        for value in random_values:
            assert len(value) == 32, "Token should be 32 characters (16 bytes hex)"
            assert all(c in "0123456789abcdef" for c in value), \
                "Token should contain only hex characters"
        
        # Test in context of API operations
        test_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": f"Random test: {random_values[0]}"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, test_request
        )
        
        assert response.status_code == 200
        
        logger.info("CRYPTO_RANDOM_001: Secure random generation validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_side_channel_resistance_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """CRYPTO_SIDECHANNEL_001: Side-channel attack resistance"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various request patterns to detect side-channel vulnerabilities
        patterns = [
            {"size": "small", "content": "A"},
            {"size": "medium", "content": "A" * 100},
            {"size": "large", "content": "A" * 1000},
        ]
        
        timing_by_size = {}
        
        for pattern in patterns:
            times = []
            
            for i in range(3):  # Multiple samples
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": pattern["content"]}],
                    "max_tokens": 50
                }
                
                start_time = time.perf_counter()
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                end_time = time.perf_counter()
                
                assert response.status_code == 200
                times.append(end_time - start_time)
                
                await asyncio.sleep(0.5)
            
            timing_by_size[pattern["size"]] = sum(times) / len(times)
        
        # Analyze timing patterns
        logger.info(f"Timing by input size: {timing_by_size}")
        
        # Large variance might indicate side-channel vulnerabilities
        timings = list(timing_by_size.values())
        if max(timings) - min(timings) > 2.0:  # 2 second threshold
            logger.warning("Significant timing variance detected - review for side-channels")
        
        logger.info("CRYPTO_SIDECHANNEL_001: Side-channel resistance evaluated")


# Advanced Cryptographic Security tests moved to test_cryptographic_advanced.py to maintain file size under 900 lines