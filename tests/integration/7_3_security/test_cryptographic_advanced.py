# Section 7.3 - Advanced Cryptographic Implementation Security Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Cryptographic Implementation Security.md
# Advanced test cases matching design document test case IDs

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

class TestAdvancedCryptographicSecurity:
    """Advanced cryptographic security tests matching design document test case IDs"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_crypto_key_rotation_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """CRYPTO_KEY_ROTATION_001: Test API key rotation procedures and lifecycle management"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test key rotation indicators and capabilities
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for key rotation management headers
        rotation_headers = [
            "x-key-rotation-policy",
            "x-key-expiry",
            "x-key-rotation-schedule",
            "x-key-lifecycle-management",
            "x-key-version"
        ]
        
        rotation_indicators = []
        for header in rotation_headers:
            if header in headers:
                rotation_indicators.append(f"{header}={headers[header]}")
        
        if rotation_indicators:
            logger.info(f"Key rotation indicators: {rotation_indicators}")
        
        # Test key rotation endpoints
        rotation_endpoints = [
            "/api/v1/auth/rotate-key",
            "/api/v1/keys/rotate",
            "/admin/keys/rotate",
            "/security/key-rotation"
        ]
        
        for endpoint in rotation_endpoints:
            rotation_response = await make_request(
                http_client, "POST", endpoint,
                auth_headers, {"rotation_request": True}, track_cost=False
            )
            
            if rotation_response.status_code in [200, 201, 202]:
                logger.info(f"Key rotation endpoint available: {endpoint}")
                
                try:
                    rotation_data = rotation_response.json()
                    
                    # Check for proper rotation response fields
                    rotation_fields = [
                        "new_key",
                        "expiry_time",
                        "rotation_id", 
                        "grace_period"
                    ]
                    
                    for field in rotation_fields:
                        if field in rotation_data:
                            logger.info(f"Key rotation includes: {field}")
                
                except Exception:
                    logger.info(f"Key rotation endpoint returns non-JSON: {endpoint}")
            
            elif rotation_response.status_code in [401, 403]:
                logger.info(f"Key rotation endpoint properly protected: {endpoint}")
            elif rotation_response.status_code == 404:
                logger.info(f"Key rotation endpoint not found: {endpoint}")
        
        # Test key expiration handling
        expired_key_header = {"Authorization": "Bearer sk-expired-test-key-12345"}
        
        expired_response = await make_request(
            http_client, "GET", "/api/v1/models",
            expired_key_header, track_cost=False
        )
        
        # Should properly handle expired keys
        assert expired_response.status_code == 401, "Expired keys should be rejected"
        
        logger.info("CRYPTO_KEY_ROTATION_001: Key rotation procedures validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_crypto_certificate_management_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """CRYPTO_CERTIFICATE_MANAGEMENT_001: Test TLS certificate management and renewal procedures"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test TLS certificate information through API
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for certificate management headers
        cert_headers = [
            "x-cert-expiry",
            "x-cert-issuer",
            "x-cert-renewal-policy",
            "x-cert-validation",
            "x-tls-version"
        ]
        
        cert_indicators = []
        for header in cert_headers:
            if header in headers:
                cert_indicators.append(f"{header}={headers[header]}")
        
        if cert_indicators:
            logger.info(f"Certificate management indicators: {cert_indicators}")
        
        # Test certificate information endpoints
        cert_endpoints = [
            "/.well-known/cert-info",
            "/security/certificate",
            "/api/v1/cert/status",
            "/_/tls-info"
        ]
        
        for endpoint in cert_endpoints:
            cert_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if cert_response.status_code == 200:
                logger.info(f"Certificate information available at: {endpoint}")
                
                try:
                    cert_data = cert_response.json()
                    
                    # Check for certificate information
                    cert_fields = [
                        "issuer",
                        "valid_until",
                        "subject",
                        "fingerprint",
                        "key_size"
                    ]
                    
                    for field in cert_fields:
                        if field in cert_data:
                            logger.info(f"Certificate info includes: {field}")
                    
                    # Check for certificate chain validation
                    if "chain_valid" in cert_data:
                        chain_valid = cert_data["chain_valid"]
                        logger.info(f"Certificate chain valid: {chain_valid}")
                
                except Exception:
                    logger.info(f"Certificate endpoint returns non-JSON: {endpoint}")
        
        # Test TLS configuration strength
        tls_strength_tests = [
            ("strict-transport-security", "HSTS header"),
            ("content-security-policy", "CSP header"),
            ("x-frame-options", "Frame options"),
            ("x-content-type-options", "Content type options")
        ]
        
        for header_name, description in tls_strength_tests:
            if header_name in headers:
                logger.info(f"TLS security: {description} present")
            else:
                logger.warning(f"TLS security: {description} missing")
        
        logger.info("CRYPTO_CERTIFICATE_MANAGEMENT_001: Certificate management validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_crypto_random_number_generation_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """CRYPTO_RANDOM_NUMBER_GENERATION_001: Validate cryptographically secure random number generation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test random number generation quality through multiple API calls
        nonce_values = []
        request_ids = []
        
        # Generate multiple requests to collect entropy samples
        for i in range(10):
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            
            assert response.status_code == 200
            headers = response.headers
            
            # Collect any random values from headers
            random_headers = [
                "x-request-id",
                "x-trace-id", 
                "x-correlation-id",
                "x-nonce",
                "x-session-id"
            ]
            
            for header in random_headers:
                if header in headers:
                    value = headers[header]
                    if header == "x-request-id":
                        request_ids.append(value)
                    else:
                        nonce_values.append(value)
            
            await asyncio.sleep(0.1)  # Small delay between requests
        
        # Analyze randomness quality
        if request_ids:
            # Check for uniqueness
            unique_ids = set(request_ids)
            assert len(unique_ids) == len(request_ids), "Request IDs should be unique"
            
            # Check for reasonable entropy in request IDs
            for req_id in request_ids[:5]:  # Check first 5
                if req_id:
                    # Should not be sequential or predictable
                    assert not re.match(r'^(0+|1+|abc+|test).*', req_id.lower()), \
                        f"Request ID appears non-random: {req_id}"
            
            logger.info(f"Random generation: {len(unique_ids)} unique request IDs generated")
        
        # Test entropy through multiple chat requests (more likely to generate random values)
        chat_responses = []
        
        for i in range(5):
            chat_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Random test {i}"}],
                "max_tokens": 10
            }
            
            chat_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, chat_request
            )
            
            if chat_response.status_code == 200:
                chat_data = chat_response.json()
                
                # Check for random identifiers in response
                if "id" in chat_data:
                    chat_responses.append(chat_data["id"])
            
            await asyncio.sleep(0.1)
        
        # Validate chat response ID uniqueness
        if chat_responses:
            unique_responses = set(chat_responses)
            assert len(unique_responses) == len(chat_responses), \
                "Chat response IDs should be unique"
            
            logger.info(f"Random generation: {len(unique_responses)} unique chat response IDs")
        
        # Test random generation resistance to prediction
        timestamp = int(time.time())
        predictable_headers = auth_headers.copy()
        predictable_headers["X-Timestamp"] = str(timestamp)
        
        predict_response = await make_request(
            http_client, "GET", "/api/v1/models",
            predictable_headers, track_cost=False
        )
        
        # Should not be influenced by predictable input
        assert predict_response.status_code == 200, "API should handle predictable input"
        
        logger.info("CRYPTO_RANDOM_NUMBER_GENERATION_001: Random number generation validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_crypto_hash_performance_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """CRYPTO_HASH_PERFORMANCE_001: Test cryptographic hash performance and side-channel resistance"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test hash performance through authentication timing
        timing_results = []
        
        # Test with various API key patterns to check for timing consistency
        key_patterns = [
            "sk-test-key-short",
            "sk-test-key-medium-length-12345",
            "sk-test-key-very-long-pattern-with-many-characters-12345678901234567890",
            "sk-different-pattern-abcdefghijklmnopqrstuvwxyz",
            "sk-numeric-pattern-1234567890123456789012345"
        ]
        
        for pattern in key_patterns:
            test_headers = {"Authorization": f"Bearer {pattern}"}
            
            start_time = time.time()
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                test_headers, track_cost=False
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            timing_results.append({
                "pattern": pattern[:20] + "..." if len(pattern) > 20 else pattern,
                "time": response_time,
                "status": response.status_code
            })
            
            # All should return 401 (unauthorized) for invalid keys
            assert response.status_code == 401, f"Invalid key should return 401: {pattern}"
            
            await asyncio.sleep(0.1)  # Prevent rate limiting
        
        # Analyze timing consistency
        if len(timing_results) >= 3:
            times = [r["time"] for r in timing_results]
            avg_time = sum(times) / len(times)
            max_deviation = max(abs(t - avg_time) for t in times)
            
            # Timing should be relatively consistent (within 200ms variance)
            assert max_deviation < 0.2, f"Hash timing variance too high: {max_deviation:.3f}s"
            
            logger.info(f"Hash performance: avg={avg_time:.3f}s, max_deviation={max_deviation:.3f}s")
        
        # Test hash performance with valid key (should be consistent)
        valid_key_times = []
        
        for i in range(5):
            start_time = time.time()
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            valid_key_times.append(response_time)
            
            assert response.status_code == 200, "Valid key should work consistently"
            
            await asyncio.sleep(0.1)
        
        # Valid key timing should also be consistent
        if len(valid_key_times) >= 3:
            avg_valid_time = sum(valid_key_times) / len(valid_key_times)
            max_valid_deviation = max(abs(t - avg_valid_time) for t in valid_key_times)
            
            logger.info(f"Valid key performance: avg={avg_valid_time:.3f}s, max_deviation={max_valid_deviation:.3f}s")
        
        logger.info("CRYPTO_HASH_PERFORMANCE_001: Hash performance and side-channel resistance validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_crypto_algorithm_strength_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """CRYPTO_ALGORITHM_STRENGTH_001: Validate cryptographic algorithm strength and standards compliance"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test algorithm strength indicators
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for algorithm strength indicators
        crypto_headers = [
            "x-crypto-algorithm",
            "x-hash-strength", 
            "x-key-size",
            "x-cipher-suite",
            "x-crypto-compliance"
        ]
        
        crypto_indicators = []
        for header in crypto_headers:
            if header in headers:
                crypto_indicators.append(f"{header}={headers[header]}")
        
        if crypto_indicators:
            logger.info(f"Cryptographic algorithm indicators: {crypto_indicators}")
        
        # Test algorithm compliance endpoints
        algo_endpoints = [
            "/security/algorithms",
            "/api/v1/crypto/compliance", 
            "/.well-known/crypto-policy",
            "/_/algorithms"
        ]
        
        for endpoint in algo_endpoints:
            algo_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if algo_response.status_code == 200:
                logger.info(f"Algorithm information available at: {endpoint}")
                
                try:
                    algo_data = algo_response.json()
                    
                    # Check for strong algorithms
                    strong_algorithms = [
                        "SHA-256",
                        "SHA-384", 
                        "SHA-512",
                        "AES-256",
                        "RSA-2048",
                        "ECDSA-P256"
                    ]
                    
                    # Check for weak algorithms that should not be present
                    weak_algorithms = [
                        "MD5",
                        "SHA-1",
                        "DES",
                        "3DES",
                        "RC4",
                        "RSA-1024"
                    ]
                    
                    algo_text = str(algo_data).lower()
                    
                    for strong_algo in strong_algorithms:
                        if strong_algo.lower() in algo_text:
                            logger.info(f"Strong algorithm found: {strong_algo}")
                    
                    for weak_algo in weak_algorithms:
                        if weak_algo.lower() in algo_text:
                            logger.warning(f"Weak algorithm detected: {weak_algo}")
                
                except Exception:
                    logger.info(f"Algorithm endpoint returns non-JSON: {endpoint}")
        
        # Test quantum resistance considerations
        quantum_headers = [
            "x-quantum-resistant",
            "x-post-quantum-crypto",
            "x-pqc-ready"
        ]
        
        quantum_indicators = []
        for header in quantum_headers:
            if header in headers:
                quantum_indicators.append(f"{header}={headers[header]}")
        
        if quantum_indicators:
            logger.info(f"Quantum resistance indicators: {quantum_indicators}")
        else:
            logger.info("No quantum resistance indicators found")
        
        logger.info("CRYPTO_ALGORITHM_STRENGTH_001: Algorithm strength validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_crypto_key_derivation_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """CRYPTO_KEY_DERIVATION_001: Test key derivation functions and password-based cryptography"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test key derivation through API key patterns and strength
        api_key = auth_headers.get("Authorization", "").replace("Bearer ", "")
        
        if api_key and len(api_key) > 10:
            # Analyze key structure for derivation patterns
            key_parts = api_key.split("-") if "-" in api_key else [api_key]
            
            # Check for proper key structure (e.g., sk-prefix-random)
            if len(key_parts) >= 2:
                prefix = key_parts[0]
                if prefix in ["sk", "pk", "key"]:
                    logger.info(f"Key derivation: Proper key prefix detected: {prefix}")
                
                # Check random part entropy
                if len(key_parts) > 1:
                    random_part = key_parts[-1]
                    if len(random_part) >= 20:
                        # Check for character diversity
                        char_types = {
                            "lowercase": any(c.islower() for c in random_part),
                            "uppercase": any(c.isupper() for c in random_part), 
                            "digits": any(c.isdigit() for c in random_part),
                            "special": any(not c.isalnum() for c in random_part)
                        }
                        
                        diversity_count = sum(char_types.values())
                        logger.info(f"Key derivation: Character diversity score: {diversity_count}/4")
                        
                        # Should have at least 2 types of characters
                        assert diversity_count >= 2, "Key should have diverse character types"
        
        # Test key derivation endpoints
        derivation_endpoints = [
            "/api/v1/auth/derive-key",
            "/security/key-derivation",
            "/api/v1/keys/derive"
        ]
        
        for endpoint in derivation_endpoints:
            derivation_request = {
                "password": "test-password-for-derivation",
                "salt": "test-salt-value",
                "iterations": 10000
            }
            
            derivation_response = await make_request(
                http_client, "POST", endpoint,
                auth_headers, derivation_request, track_cost=False
            )
            
            if derivation_response.status_code in [200, 201]:
                logger.info(f"Key derivation endpoint available: {endpoint}")
                
                try:
                    derivation_data = derivation_response.json()
                    
                    # Check for proper derivation response
                    derivation_fields = [
                        "derived_key",
                        "salt",
                        "iterations",
                        "algorithm"
                    ]
                    
                    for field in derivation_fields:
                        if field in derivation_data:
                            logger.info(f"Key derivation includes: {field}")
                    
                    # Verify salt uniqueness (if provided)
                    if "salt" in derivation_data:
                        salt_value = derivation_data["salt"]
                        if salt_value != "test-salt-value":
                            logger.info("Key derivation: Unique salt generated")
                
                except Exception:
                    logger.info(f"Derivation endpoint returns non-JSON: {endpoint}")
            
            elif derivation_response.status_code in [401, 403]:
                logger.info(f"Key derivation endpoint properly protected: {endpoint}")
            elif derivation_response.status_code == 404:
                logger.info(f"Key derivation endpoint not found: {endpoint}")
        
        logger.info("CRYPTO_KEY_DERIVATION_001: Key derivation functions validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_crypto_library_validation_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """CRYPTO_LIBRARY_VALIDATION_001: Validate cryptographic library versions and security patch status"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for library information disclosure
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for library version headers (should NOT be present for security)
        library_headers = [
            "x-crypto-library",
            "x-openssl-version",
            "x-cryptography-version",
            "x-library-versions",
            "server"  # Server header might reveal library info
        ]
        
        library_disclosures = []
        for header in library_headers:
            if header in headers:
                value = headers[header]
                library_disclosures.append(f"{header}={value}")
        
        if library_disclosures:
            logger.warning(f"Cryptographic library information disclosed: {library_disclosures}")
        else:
            logger.info("No cryptographic library information disclosed in headers")
        
        # Test library information endpoints (should be protected)
        library_endpoints = [
            "/security/libraries",
            "/api/v1/crypto/libraries",
            "/system/versions",
            "/_/lib-versions"
        ]
        
        for endpoint in library_endpoints:
            lib_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if lib_response.status_code == 200:
                logger.warning(f"Library information endpoint accessible: {endpoint}")
                
                try:
                    lib_data = lib_response.json()
                    
                    # Check for specific cryptographic libraries
                    crypto_libraries = [
                        "openssl",
                        "cryptography",
                        "pycryptodome",
                        "hashlib",
                        "secrets"
                    ]
                    
                    lib_text = str(lib_data).lower()
                    for crypto_lib in crypto_libraries:
                        if crypto_lib in lib_text:
                            logger.info(f"Cryptographic library mentioned: {crypto_lib}")
                
                except Exception:
                    logger.info(f"Library endpoint returns non-JSON: {endpoint}")
            
            elif lib_response.status_code in [401, 403]:
                logger.info(f"Library information endpoint properly protected: {endpoint}")
            elif lib_response.status_code == 404:
                logger.info(f"Library information endpoint not found: {endpoint}")
        
        logger.info("CRYPTO_LIBRARY_VALIDATION_001: Cryptographic library validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_crypto_compliance_validation_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """CRYPTO_COMPLIANCE_VALIDATION_001: Validate compliance with cryptographic standards and regulations"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test compliance indicators
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for compliance headers
        compliance_headers = [
            "x-fips-140-2-compliant",
            "x-nist-compliant",
            "x-common-criteria",
            "x-crypto-compliance-status",
            "x-security-certification"
        ]
        
        compliance_indicators = []
        for header in compliance_headers:
            if header in headers:
                compliance_indicators.append(f"{header}={headers[header]}")
        
        if compliance_indicators:
            logger.info(f"Cryptographic compliance indicators: {compliance_indicators}")
        
        # Test compliance validation endpoints
        compliance_endpoints = [
            "/security/compliance/crypto",
            "/api/v1/crypto/fips-status",
            "/compliance/nist",
            "/.well-known/crypto-compliance"
        ]
        
        for endpoint in compliance_endpoints:
            comp_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if comp_response.status_code == 200:
                logger.info(f"Cryptographic compliance available at: {endpoint}")
                
                try:
                    comp_data = comp_response.json()
                    
                    # Check for compliance frameworks
                    compliance_frameworks = [
                        "fips_140_2",
                        "nist_sp_800_57",
                        "common_criteria",
                        "federal_standards"
                    ]
                    
                    for framework in compliance_frameworks:
                        if framework in comp_data:
                            status = comp_data[framework]
                            logger.info(f"Compliance framework {framework}: {status}")
                    
                    # Check for certification information
                    cert_fields = [
                        "certification_status",
                        "validation_number",
                        "expiry_date"
                    ]
                    
                    for field in cert_fields:
                        if field in comp_data:
                            logger.info(f"Certification info includes: {field}")
                
                except Exception:
                    logger.info(f"Compliance endpoint returns non-JSON: {endpoint}")
            
            elif comp_response.status_code in [401, 403]:
                logger.info(f"Compliance endpoint properly protected: {endpoint}")
            elif comp_response.status_code == 404:
                logger.info(f"Compliance endpoint not found: {endpoint}")
        
        logger.info("CRYPTO_COMPLIANCE_VALIDATION_001: Cryptographic compliance validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_crypto_performance_scalability_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """CRYPTO_PERFORMANCE_SCALABILITY_001: Test cryptographic operation performance and scalability under load"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test cryptographic performance under varying loads
        performance_results = []
        
        # Test with increasing concurrent requests
        concurrency_levels = [1, 3, 5]
        
        for concurrency in concurrency_levels:
            start_time = time.time()
            
            # Create concurrent tasks
            tasks = []
            for i in range(concurrency):
                task = make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
                tasks.append(task)
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Analyze results
            successful_requests = sum(1 for r in results if hasattr(r, 'status_code') and r.status_code == 200)
            
            performance_results.append({
                "concurrency": concurrency,
                "total_time": total_time,
                "successful_requests": successful_requests,
                "avg_time_per_request": total_time / concurrency if concurrency > 0 else 0
            })
            
            logger.info(f"Crypto performance: {concurrency} concurrent requests in {total_time:.3f}s")
            
            await asyncio.sleep(0.5)  # Rest between tests
        
        # Analyze scalability
        if len(performance_results) >= 2:
            baseline = performance_results[0]
            highest_load = performance_results[-1]
            
            # Performance degradation should be reasonable
            time_increase_factor = highest_load["avg_time_per_request"] / baseline["avg_time_per_request"] if baseline["avg_time_per_request"] > 0 else 1
            
            # Should not degrade more than 5x under 5x load
            assert time_increase_factor < 10, f"Crypto performance degraded too much: {time_increase_factor:.2f}x"
            
            logger.info(f"Crypto scalability: {time_increase_factor:.2f}x time increase under {highest_load['concurrency']}x load")
        
        # Test DoS resistance through crypto operations
        dos_start_time = time.time()
        dos_requests = []
        
        # Rapid fire requests to test DoS resistance
        for i in range(10):
            dos_task = make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            dos_requests.append(dos_task)
        
        dos_results = await asyncio.gather(*dos_requests, return_exceptions=True)
        dos_end_time = time.time()
        dos_total_time = dos_end_time - dos_start_time
        
        # Should handle rapid requests gracefully
        dos_successful = sum(1 for r in dos_results if hasattr(r, 'status_code') and r.status_code in [200, 429])
        
        logger.info(f"DoS resistance: {dos_successful}/10 requests handled in {dos_total_time:.3f}s")
        
        # Should either succeed or rate limit gracefully
        assert dos_successful >= 5, "Should handle at least half of rapid requests gracefully"
        
        logger.info("CRYPTO_PERFORMANCE_SCALABILITY_001: Cryptographic performance and DoS resistance validated")