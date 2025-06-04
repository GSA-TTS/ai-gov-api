# Section 7.3 - Advanced OWASP API2:2023 Broken Authentication Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API2_2023 - Broken Authentication.md
# Implements missing test cases for advanced authentication security

import pytest
import httpx
import os
import hashlib
import secrets
from typing import Dict, Any, List
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.security_fixtures import SecurityFixtures
from utils.security_validators import SecurityValidator


class TestOWASPAPI2AuthenticationAdvanced:
    """Advanced tests for OWASP API2:2023 - Broken Authentication"""
    
    @pytest.mark.security
    @pytest.mark.owasp_api2
    @pytest.mark.asyncio
    async def test_api2_key_state_lifecycle_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               security_validator: SecurityValidator,
                                               make_request):
        """API2_KEY_STATE_001: API Key State and Lifecycle Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test API key state and lifecycle scenarios
        key_state_tests = [
            {
                "description": "Inactive API key (is_active = False)",
                "key_state": "inactive",
                "manipulation": "set_inactive_flag",
                "expected_status": [401, 403]
            },
            {
                "description": "Expired API key (expires_at validation)",
                "key_state": "expired",
                "manipulation": "set_expired_timestamp",
                "expected_status": [401, 403]
            },
            {
                "description": "Revoked API key",
                "key_state": "revoked",
                "manipulation": "set_revoked_status",
                "expected_status": [401, 403]
            },
            {
                "description": "Suspended API key",
                "key_state": "suspended",
                "manipulation": "set_suspended_status",
                "expected_status": [401, 403]
            }
        ]
        
        for test_case in key_state_tests:
            # Generate API key with specified state
            test_headers = security_validator.generate_api_key_with_state(
                auth_headers, test_case["key_state"]
            )
            
            # Test models endpoint
            response = await http_client.get("/api/v1/models", headers=test_headers)
            
            assert response.status_code in test_case["expected_status"], \
                f"API key in {test_case['key_state']} state should be rejected: {test_case['description']}"
            
            # Test chat completions endpoint
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test inactive key"}],
                "max_tokens": 10
            }
            
            chat_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                test_headers, request_data
            )
            
            assert chat_response.status_code in test_case["expected_status"], \
                f"Chat request with {test_case['key_state']} key should be rejected: {test_case['description']}"
            
            # Validate error response doesn't leak key state information
            if chat_response.status_code in [401, 403]:
                error_data = chat_response.json()
                state_leak_check = security_validator.validate_key_state_error_exposure(
                    test_case["key_state"], error_data
                )
                assert state_leak_check["is_secure"], \
                    f"Error should not leak key state info: {test_case['description']}"
        
        logger.info("API2_KEY_STATE_001: API key state and lifecycle tested")

    @pytest.mark.security
    @pytest.mark.owasp_api2
    @pytest.mark.asyncio
    async def test_api2_key_tampering_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        security_validator: SecurityValidator,
                                        make_request):
        """API2_TAMPERING_001: API Key Tampering and Hash Mismatch Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various API key tampering scenarios
        tampering_tests = [
            {
                "description": "Modified API key prefix",
                "tampering_type": "prefix_modification",
                "manipulation": "change_prefix"
            },
            {
                "description": "Modified API key suffix",
                "tampering_type": "suffix_modification", 
                "manipulation": "change_suffix"
            },
            {
                "description": "Single character change",
                "tampering_type": "character_substitution",
                "manipulation": "single_char_change"
            },
            {
                "description": "Hash collision attempt",
                "tampering_type": "hash_collision",
                "manipulation": "attempt_collision"
            },
            {
                "description": "Length manipulation",
                "tampering_type": "length_change",
                "manipulation": "modify_length"
            },
            {
                "description": "Encoding manipulation",
                "tampering_type": "encoding_change",
                "manipulation": "change_encoding"
            }
        ]
        
        for test_case in tampering_tests:
            # Generate tampered API key
            tampered_headers = security_validator.generate_tampered_api_key(
                auth_headers, test_case["tampering_type"]
            )
            
            # Test access with tampered key
            response = await http_client.get("/api/v1/models", headers=tampered_headers)
            
            # Tampered keys should be rejected
            assert response.status_code in [401, 403], \
                f"Tampered API key should be rejected: {test_case['description']}"
            
            # Test with chat endpoint
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test tampered key"}],
                "max_tokens": 10
            }
            
            chat_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                tampered_headers, request_data
            )
            
            assert chat_response.status_code in [401, 403], \
                f"Chat with tampered key should be rejected: {test_case['description']}"
            
            # Validate error handling for tampering
            if chat_response.status_code in [401, 403]:
                error_data = chat_response.json()
                tampering_validation = security_validator.validate_tampering_detection(
                    test_case["tampering_type"], error_data
                )
                assert tampering_validation["is_detected"], \
                    f"Key tampering should be detected: {test_case['description']}"
        
        logger.info("API2_TAMPERING_001: API key tampering detection tested")

    @pytest.mark.security
    @pytest.mark.owasp_api2
    @pytest.mark.asyncio
    async def test_api2_key_generation_entropy_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  security_validator: SecurityValidator,
                                                  make_request):
        """API2_ENTROPY_001: API Key Generation Entropy and Randomness Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test API key generation security properties
        entropy_tests = [
            {
                "description": "Predictable key patterns",
                "test_type": "pattern_detection",
                "predictable_keys": [
                    "sk-" + "1234567890" * 4,  # Repeated pattern
                    "sk-" + "abcdefghij" * 4,  # Sequential pattern
                    "sk-" + "0000000000" * 4,  # Zero pattern
                    "sk-" + "1111111111" * 4,  # Repeated digit
                ]
            },
            {
                "description": "Weak entropy keys",
                "test_type": "entropy_analysis",
                "weak_keys": [
                    "sk-" + "a" * 40,  # Low entropy
                    "sk-" + "12345" * 8,  # Predictable sequence
                    "sk-" + "test" * 10,  # Dictionary word repetition
                ]
            },
            {
                "description": "Time-based predictable keys",
                "test_type": "temporal_prediction",
                "time_based_keys": [
                    f"sk-{str(int(1234567890) + i).zfill(40)}" for i in range(5)
                ]
            }
        ]
        
        for test_scenario in entropy_tests:
            if test_scenario["test_type"] == "pattern_detection":
                test_keys = test_scenario["predictable_keys"]
            elif test_scenario["test_type"] == "entropy_analysis":
                test_keys = test_scenario["weak_keys"]
            else:
                test_keys = test_scenario["time_based_keys"]
            
            for weak_key in test_keys:
                # Test access with potentially weak key
                weak_headers = {"Authorization": f"Bearer {weak_key}"}
                
                response = await http_client.get("/api/v1/models", headers=weak_headers)
                
                # Weak/predictable keys should be rejected
                assert response.status_code in [401, 403], \
                    f"Weak key should be rejected: {weak_key[:20]}..."
                
                # Validate entropy checking
                entropy_validation = security_validator.validate_key_entropy(
                    weak_key, test_scenario["test_type"]
                )
                assert entropy_validation["is_secure"], \
                    f"Key entropy should be validated: {test_scenario['description']}"
        
        logger.info("API2_ENTROPY_001: API key entropy and randomness tested")

    @pytest.mark.security
    @pytest.mark.owasp_api2
    @pytest.mark.asyncio
    async def test_api2_secure_storage_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         security_validator: SecurityValidator,
                                         make_request):
        """API2_STORAGE_001: Secure Key Storage and Hashing Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test secure storage implementation
        storage_tests = [
            {
                "description": "Plain text key attempt",
                "storage_type": "plaintext",
                "test_key": "sk-plaintext_key_should_not_work_123456789",
                "expected_rejection": True
            },
            {
                "description": "Weak hash algorithm attempt",
                "storage_type": "weak_hash",
                "test_key": "sk-md5_hash_" + hashlib.md5(b"weak").hexdigest(),
                "expected_rejection": True
            },
            {
                "description": "No salt hash attempt",
                "storage_type": "no_salt",
                "test_key": "sk-nosalt_" + hashlib.sha256(b"test").hexdigest()[:32],
                "expected_rejection": True
            },
            {
                "description": "Timing attack probe",
                "storage_type": "timing_attack",
                "timing_test": True,
                "test_keys": [
                    "sk-timing_test_key_1_" + "a" * 20,
                    "sk-timing_test_key_2_" + "b" * 20,
                    "sk-timing_test_key_3_" + "c" * 20
                ]
            }
        ]
        
        for test_case in storage_tests:
            if test_case.get("timing_test"):
                # Timing attack test - measure response times
                import time
                timing_results = []
                
                for test_key in test_case["test_keys"]:
                    headers = {"Authorization": f"Bearer {test_key}"}
                    
                    start_time = time.time()
                    response = await http_client.get("/api/v1/models", headers=headers)
                    end_time = time.time()
                    
                    timing_results.append({
                        "key": test_key[:20] + "...",
                        "response_time": end_time - start_time,
                        "status_code": response.status_code
                    })
                
                # Validate timing attack resistance
                timing_validation = security_validator.validate_timing_attack_resistance(
                    timing_results
                )
                assert timing_validation["is_resistant"], \
                    f"System should resist timing attacks: {test_case['description']}"
                
            else:
                # Regular storage security test
                headers = {"Authorization": f"Bearer {test_case['test_key']}"}
                
                response = await http_client.get("/api/v1/models", headers=headers)
                
                if test_case["expected_rejection"]:
                    assert response.status_code in [401, 403], \
                        f"Insecure key should be rejected: {test_case['description']}"
                
                # Validate storage security implementation
                storage_validation = security_validator.validate_secure_storage(
                    test_case["storage_type"], test_case["test_key"], response.status_code
                )
                assert storage_validation["is_secure"], \
                    f"Storage should be secure: {test_case['description']}"
        
        logger.info("API2_STORAGE_001: Secure key storage and hashing tested")

    @pytest.mark.security
    @pytest.mark.owasp_api2
    @pytest.mark.asyncio
    async def test_api2_privilege_escalation_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                security_validator: SecurityValidator,
                                                make_request):
        """API2_PRIVILEGE_001: Privilege Escalation Through User Management"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test privilege escalation attempts
        escalation_tests = [
            {
                "description": "Admin endpoint access attempt",
                "endpoint": "/api/v1/admin/users",
                "method": "GET",
                "escalation_type": "admin_access"
            },
            {
                "description": "User management endpoint access",
                "endpoint": "/api/v1/users",
                "method": "GET",
                "escalation_type": "user_management"
            },
            {
                "description": "Key management endpoint access",
                "endpoint": "/api/v1/keys",
                "method": "GET",
                "escalation_type": "key_management"
            },
            {
                "description": "System configuration access",
                "endpoint": "/api/v1/config",
                "method": "GET",
                "escalation_type": "config_access"
            },
            {
                "description": "Create admin user attempt",
                "endpoint": "/api/v1/users",
                "method": "POST",
                "request_data": {
                    "username": "new_admin",
                    "role": "admin",
                    "permissions": ["all"]
                },
                "escalation_type": "create_admin"
            }
        ]
        
        for test_case in escalation_tests:
            if test_case["method"] == "GET":
                response = await http_client.get(test_case["endpoint"], headers=auth_headers)
            else:
                request_data = test_case.get("request_data", {})
                response = await make_request(
                    http_client, test_case["method"], test_case["endpoint"],
                    auth_headers, request_data
                )
            
            # Privilege escalation should be prevented
            assert response.status_code in [401, 403, 404], \
                f"Privilege escalation should be prevented: {test_case['description']}"
            
            # Validate privilege escalation prevention
            escalation_validation = security_validator.validate_privilege_escalation_prevention(
                test_case["escalation_type"], response.status_code,
                response.json() if response.status_code not in [204] else {}
            )
            assert escalation_validation["is_prevented"], \
                f"Privilege escalation should be prevented: {test_case['description']}"
            
            # Error should not reveal privilege structure
            if response.status_code in [401, 403]:
                error_data = response.json()
                privilege_leak_check = security_validator.validate_privilege_error_exposure(
                    test_case["escalation_type"], error_data
                )
                assert privilege_leak_check["is_secure"], \
                    f"Error should not leak privilege info: {test_case['description']}"
        
        logger.info("API2_PRIVILEGE_001: Privilege escalation prevention tested")

    @pytest.mark.security
    @pytest.mark.owasp_api2
    @pytest.mark.asyncio
    async def test_api2_scope_validation_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           security_validator: SecurityValidator,
                                           make_request):
        """API2_SCOPE_001: Scope Validation (models:inference vs models:embedding)"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test scope validation scenarios
        scope_tests = [
            {
                "description": "Embedding scope accessing chat endpoint",
                "key_scope": "models:embedding",
                "endpoint": "/api/v1/chat/completions",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test scope violation"}],
                    "max_tokens": 10
                },
                "should_be_rejected": True
            },
            {
                "description": "Inference scope accessing embedding endpoint",
                "key_scope": "models:inference",
                "endpoint": "/api/v1/embeddings",
                "request_data": {
                    "model": config.get_embedding_models()[0] if config.get_embedding_models() else "test-embedding",
                    "input": "test scope violation"
                },
                "should_be_rejected": True
            },
            {
                "description": "No scope accessing any endpoint",
                "key_scope": "none",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "should_be_rejected": True
            },
            {
                "description": "Invalid scope format",
                "key_scope": "invalid:scope:format",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "should_be_rejected": True
            }
        ]
        
        for test_case in scope_tests:
            # Generate API key with specific scope
            scoped_headers = security_validator.generate_scoped_api_key(
                auth_headers, test_case["key_scope"]
            )
            
            if test_case.get("method") == "GET":
                response = await http_client.get(test_case["endpoint"], headers=scoped_headers)
            else:
                response = await make_request(
                    http_client, "POST", test_case["endpoint"],
                    scoped_headers, test_case["request_data"]
                )
            
            if test_case["should_be_rejected"]:
                assert response.status_code in [401, 403], \
                    f"Scope violation should be rejected: {test_case['description']}"
                
                # Validate scope validation implementation
                scope_validation = security_validator.validate_scope_enforcement(
                    test_case["key_scope"], test_case["endpoint"], response.status_code
                )
                assert scope_validation["is_enforced"], \
                    f"Scope should be enforced: {test_case['description']}"
                
                # Error should not leak scope details
                if response.status_code in [401, 403]:
                    error_data = response.json()
                    scope_leak_check = security_validator.validate_scope_error_exposure(
                        test_case["key_scope"], error_data
                    )
                    assert scope_leak_check["is_secure"], \
                        f"Error should not leak scope info: {test_case['description']}"
        
        logger.info("API2_SCOPE_001: Scope validation tested")

    @pytest.mark.security
    @pytest.mark.owasp_api2
    @pytest.mark.asyncio
    async def test_api2_concurrent_auth_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          security_validator: SecurityValidator,
                                          make_request):
        """API2_CONCURRENT_001: Concurrent Authentication Handling"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        import asyncio
        
        # Test concurrent authentication scenarios
        concurrent_auth_tests = [
            {
                "description": "Multiple concurrent requests with same key",
                "test_type": "same_key_concurrent",
                "concurrent_count": 10,
                "key_type": "valid"
            },
            {
                "description": "Concurrent requests with different keys",
                "test_type": "different_keys_concurrent",
                "concurrent_count": 5,
                "key_type": "mixed"
            },
            {
                "description": "Concurrent auth failure scenarios",
                "test_type": "auth_failure_concurrent",
                "concurrent_count": 8,
                "key_type": "invalid"
            }
        ]
        
        for test_scenario in concurrent_auth_tests:
            # Prepare concurrent requests
            async def make_auth_request(request_id):
                if test_scenario["key_type"] == "valid":
                    headers = auth_headers
                elif test_scenario["key_type"] == "invalid":
                    headers = {"Authorization": f"Bearer sk-invalid_key_{request_id}"}
                else:  # mixed
                    if request_id % 2 == 0:
                        headers = auth_headers
                    else:
                        headers = {"Authorization": f"Bearer sk-mixed_invalid_{request_id}"}
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"concurrent auth test {request_id}"}],
                    "max_tokens": 10
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    headers, request_data
                )
                
                return {
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "headers_used": "valid" if headers == auth_headers else "invalid",
                    "response_data": response.json() if response.status_code == 200 else None
                }
            
            # Execute concurrent requests
            tasks = [make_auth_request(i) for i in range(test_scenario["concurrent_count"])]
            concurrent_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions
            valid_results = [r for r in concurrent_results if not isinstance(r, Exception)]
            
            # Validate concurrent authentication handling
            # Determine expected behavior based on key type
            if test_scenario["key_type"] == "valid":
                expected_behavior = "all_succeed"
            elif test_scenario["key_type"] == "invalid":
                expected_behavior = "none_succeed"
            else:  # mixed
                expected_behavior = "some_succeed"
            
            validation_result = security_validator.validate_concurrent_authentication(
                valid_results, expected_behavior
            )
            
            assert validation_result["validation_passed"], \
                f"Concurrent authentication should be handled correctly: {test_scenario['description']}"
            
            # Check that valid keys still work under concurrent load
            if test_scenario["key_type"] in ["valid", "mixed"]:
                valid_responses = [r for r in valid_results if r["headers_used"] == "valid"]
                successful_valid = sum(1 for r in valid_responses if r["status_code"] == 200)
                
                assert successful_valid > 0, \
                    f"Valid authentication should work under concurrent load: {test_scenario['description']}"
            
            # Check that invalid keys are consistently rejected
            if test_scenario["key_type"] in ["invalid", "mixed"]:
                invalid_responses = [r for r in valid_results if r["headers_used"] == "invalid"]
                rejected_invalid = sum(1 for r in invalid_responses if r["status_code"] in [401, 403])
                
                assert rejected_invalid == len(invalid_responses), \
                    f"Invalid authentication should be consistently rejected: {test_scenario['description']}"
        
        logger.info("API2_CONCURRENT_001: Concurrent authentication handling tested")

    @pytest.mark.security
    @pytest.mark.owasp_api2
    @pytest.mark.asyncio
    async def test_api2_auth_state_persistence_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  security_validator: SecurityValidator,
                                                  make_request):
        """API2_STATE_001: Authentication State Persistence and Isolation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test authentication state persistence scenarios
        state_persistence_tests = [
            {
                "description": "Session state isolation between requests",
                "test_type": "session_isolation",
                "sequence": [
                    {"request": "first", "expected": "isolated"},
                    {"request": "second", "expected": "isolated"},
                    {"request": "third", "expected": "isolated"}
                ]
            },
            {
                "description": "Authentication context preservation",
                "test_type": "context_preservation",
                "sequence": [
                    {"request": "establish_context", "user_context": "user1"},
                    {"request": "verify_context", "user_context": "user1"},
                    {"request": "different_context", "user_context": "user2"}
                ]
            }
        ]
        
        for test_case in state_persistence_tests:
            sequence_results = []
            
            for step in test_case["sequence"]:
                # Prepare request with context
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"State test: {step['request']}"}],
                    "max_tokens": 10
                }
                
                # Add user context if specified
                if "user_context" in step:
                    request_data["user"] = step["user_context"]
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                sequence_results.append({
                    "step": step["request"],
                    "status_code": response.status_code,
                    "user_context": step.get("user_context"),
                    "response_data": response.json() if response.status_code == 200 else None
                })
            
            # Validate state persistence and isolation
            validation_result = security_validator.validate_auth_state_persistence(
                test_case, sequence_results
            )
            
            assert validation_result["is_properly_isolated"], \
                f"Authentication state should be properly managed: {test_case['description']}"
            
            # Check that different user contexts are properly isolated
            if test_case["test_type"] == "context_preservation":
                user1_responses = [r for r in sequence_results if r.get("user_context") == "user1"]
                user2_responses = [r for r in sequence_results if r.get("user_context") == "user2"]
                
                if user1_responses and user2_responses:
                    context_isolation = security_validator.validate_user_context_isolation(
                        user1_responses, user2_responses
                    )
                    assert context_isolation["is_isolated"], \
                        f"User contexts should be isolated: {test_case['description']}"
        
        logger.info("API2_STATE_001: Authentication state persistence and isolation tested")

    @pytest.mark.security
    @pytest.mark.owasp_api2
    @pytest.mark.asyncio
    async def test_api2_parameter_pollution_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               security_validator: SecurityValidator,
                                               make_request):
        """API2_POLLUTION_001: Parameter Pollution and Injection Attacks"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test parameter pollution attacks on authentication
        pollution_tests = [
            {
                "description": "Multiple Authorization headers",
                "pollution_type": "header_pollution",
                "malicious_headers": {
                    "Authorization": ["Bearer valid_key", "Bearer malicious_key"],
                }
            },
            {
                "description": "Authorization parameter injection",
                "pollution_type": "parameter_injection",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "authorization": "Bearer injected_key",
                    "api_key": "sk-injected_parameter_key",
                    "max_tokens": 10
                }
            },
            {
                "description": "Mixed authentication methods",
                "pollution_type": "mixed_auth",
                "malicious_headers": {
                    "Authorization": "Bearer valid_key",
                    "X-API-Key": "malicious_direct_key",
                    "X-Auth-Token": "alternative_token"
                }
            },
            {
                "description": "Authentication bypass attempt",
                "pollution_type": "bypass_attempt",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "bypass test"}],
                    "authenticated": True,
                    "skip_auth": True,
                    "admin_override": True,
                    "max_tokens": 10
                }
            }
        ]
        
        for test_case in pollution_tests:
            # Prepare polluted request
            test_headers = auth_headers.copy()
            
            if "malicious_headers" in test_case:
                # Handle multiple header values or additional headers
                for header, value in test_case["malicious_headers"].items():
                    if isinstance(value, list):
                        # Multiple values for same header (HTTP pollution)
                        test_headers[header] = value[0]  # Most clients take first value
                    else:
                        test_headers[header] = value
            
            request_data = test_case.get("request_data", {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "pollution test"}],
                "max_tokens": 10
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                test_headers, request_data
            )
            
            # Validate parameter pollution handling
            validation_result = security_validator.validate_parameter_pollution_resistance(
                test_case, response.status_code,
                response.json() if response.status_code != 204 else {}
            )
            
            assert validation_result["is_resistant"], \
                f"Parameter pollution should be resisted: {test_case['description']}"
            
            # Authentication should work correctly despite pollution attempts
            if test_case["pollution_type"] in ["header_pollution", "mixed_auth"]:
                # Should either work with valid auth or fail consistently
                assert response.status_code in [200, 401, 403], \
                    f"Pollution should not cause unexpected behavior: {test_case['description']}"
            
            elif test_case["pollution_type"] in ["parameter_injection", "bypass_attempt"]:
                # Should ignore malicious parameters and use proper authentication
                if auth_headers.get("Authorization"):
                    # If we have valid auth, request should succeed
                    assert response.status_code == 200, \
                        f"Valid auth should work despite parameter pollution: {test_case['description']}"
        
        logger.info("API2_POLLUTION_001: Parameter pollution and injection resistance tested")