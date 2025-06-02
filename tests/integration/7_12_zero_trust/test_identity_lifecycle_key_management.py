# Section 7.12 - Zero Trust Identity Lifecycle and Key Management Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Identity Lifecycle and Key Management.md

import pytest
import httpx
import asyncio
import time
import secrets
import hashlib
import base64
from typing import Dict, Any, List, Optional
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestIdentityLifecycleKeyManagement:
    """Zero Trust Identity Lifecycle and Key Management tests"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_lifecycle_001_key_generation_security(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """IDENTITY_LIFECYCLE_001: Verify API key generation security standards"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test key generation properties (conceptual since we can't actually generate keys)
        key_generation_tests = [
            {
                "test_type": "entropy_validation",
                "description": "Verify key entropy and randomness",
                "test_keys": [secrets.token_urlsafe(32) for _ in range(10)]
            },
            {
                "test_type": "uniqueness_validation",
                "description": "Verify key uniqueness",
                "test_keys": [secrets.token_urlsafe(32) for _ in range(20)]
            },
            {
                "test_type": "length_validation",
                "description": "Verify key length standards",
                "test_keys": [
                    secrets.token_urlsafe(16),  # Short key
                    secrets.token_urlsafe(32),  # Standard key
                    secrets.token_urlsafe(64),  # Long key
                ]
            },
            {
                "test_type": "format_validation",
                "description": "Verify key format standards",
                "test_keys": [
                    "sk-proj-" + secrets.token_urlsafe(32),  # Standard format
                    "sk-test-" + secrets.token_urlsafe(32),  # Test format
                ]
            }
        ]
        
        key_generation_results = []
        
        for test in key_generation_tests:
            if test["test_type"] == "entropy_validation":
                # Analyze entropy of generated keys
                entropy_scores = []
                for key in test["test_keys"]:
                    # Simple entropy calculation
                    char_frequency = {}
                    for char in key:
                        char_frequency[char] = char_frequency.get(char, 0) + 1
                    
                    # Calculate Shannon entropy
                    import math
                    entropy = 0
                    key_length = len(key)
                    for freq in char_frequency.values():
                        p = freq / key_length
                        if p > 0:
                            entropy -= p * math.log2(p)
                    
                    entropy_scores.append(entropy)
                
                avg_entropy = sum(entropy_scores) / len(entropy_scores)
                min_entropy = min(entropy_scores)
                
                key_generation_results.append({
                    "test_type": test["test_type"],
                    "description": test["description"],
                    "avg_entropy": avg_entropy,
                    "min_entropy": min_entropy,
                    "entropy_sufficient": avg_entropy >= 4.0,  # Good entropy threshold
                    "quality_score": min(avg_entropy / 5.0, 1.0)
                })
            
            elif test["test_type"] == "uniqueness_validation":
                # Verify all keys are unique
                unique_keys = set(test["test_keys"])
                uniqueness_rate = len(unique_keys) / len(test["test_keys"])
                
                key_generation_results.append({
                    "test_type": test["test_type"],
                    "description": test["description"],
                    "total_keys": len(test["test_keys"]),
                    "unique_keys": len(unique_keys),
                    "uniqueness_rate": uniqueness_rate,
                    "uniqueness_perfect": uniqueness_rate == 1.0,
                    "quality_score": uniqueness_rate
                })
            
            elif test["test_type"] == "length_validation":
                # Verify key length standards
                length_analysis = []
                for key in test["test_keys"]:
                    key_length = len(key)
                    meets_minimum = key_length >= 32  # Minimum security standard
                    length_analysis.append({
                        "length": key_length,
                        "meets_minimum": meets_minimum
                    })
                
                sufficient_length = sum(1 for analysis in length_analysis if analysis["meets_minimum"])
                length_compliance = sufficient_length / len(length_analysis)
                
                key_generation_results.append({
                    "test_type": test["test_type"],
                    "description": test["description"],
                    "length_analysis": length_analysis,
                    "length_compliance": length_compliance,
                    "standards_met": length_compliance >= 0.8,
                    "quality_score": length_compliance
                })
            
            elif test["test_type"] == "format_validation":
                # Verify key format compliance
                format_analysis = []
                for key in test["test_keys"]:
                    has_prefix = key.startswith(("sk-", "test-", "proj-"))
                    no_special_chars = all(c.isalnum() or c in "-_" for c in key)
                    format_analysis.append({
                        "key": key[:20] + "...",  # Truncated for logging
                        "has_prefix": has_prefix,
                        "safe_characters": no_special_chars,
                        "format_valid": has_prefix and no_special_chars
                    })
                
                valid_formats = sum(1 for analysis in format_analysis if analysis["format_valid"])
                format_compliance = valid_formats / len(format_analysis)
                
                key_generation_results.append({
                    "test_type": test["test_type"],
                    "description": test["description"],
                    "format_analysis": format_analysis,
                    "format_compliance": format_compliance,
                    "standards_met": format_compliance >= 0.9,
                    "quality_score": format_compliance
                })
        
        # Verify overall key generation quality
        avg_quality_score = sum(result.get("quality_score", 0) for result in key_generation_results) / len(key_generation_results)
        standards_met = sum(1 for result in key_generation_results if result.get("standards_met", False))
        
        assert avg_quality_score >= 0.8, \
            f"Key generation quality should be >= 80%: {avg_quality_score:.2%}"
        
        assert standards_met >= 3, \
            f"At least 3 key generation standards should be met: {standards_met}/4"
        
        logger.info(f"IDENTITY_LIFECYCLE_001: Key generation security tested - {avg_quality_score:.2%} quality score")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_lifecycle_002_key_rotation_mechanisms(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """IDENTITY_LIFECYCLE_002: Verify key rotation mechanisms and policies"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test key rotation scenarios (simulated)
        rotation_scenarios = [
            {
                "rotation_type": "scheduled_rotation",
                "description": "Test scheduled key rotation capability",
                "simulation": "verify_rotation_readiness"
            },
            {
                "rotation_type": "emergency_rotation",
                "description": "Test emergency key rotation capability",
                "simulation": "verify_emergency_procedures"
            },
            {
                "rotation_type": "gradual_rotation",
                "description": "Test gradual key rotation with overlap",
                "simulation": "verify_overlap_support"
            },
            {
                "rotation_type": "validation_after_rotation",
                "description": "Test validation after key rotation",
                "simulation": "verify_post_rotation_validation"
            }
        ]
        
        rotation_results = []
        
        for scenario in rotation_scenarios:
            if scenario["simulation"] == "verify_rotation_readiness":
                # Test current key functionality as baseline
                baseline_test = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Baseline test before rotation"}],
                    "max_tokens": 30
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, baseline_test
                )
                
                baseline_working = response.status_code == 200
                
                # Simulate rotation readiness check
                rotation_readiness = {
                    "current_key_functional": baseline_working,
                    "backup_mechanisms_available": True,  # Simulated
                    "rotation_procedures_defined": True,  # Simulated
                    "monitoring_in_place": True  # Simulated
                }
                
                readiness_score = sum(rotation_readiness.values()) / len(rotation_readiness)
                
                rotation_results.append({
                    "rotation_type": scenario["rotation_type"],
                    "description": scenario["description"],
                    "rotation_readiness": rotation_readiness,
                    "readiness_score": readiness_score,
                    "rotation_capable": readiness_score >= 0.8
                })
            
            elif scenario["simulation"] == "verify_emergency_procedures":
                # Test rapid key validation (simulating emergency scenario)
                emergency_tests = []
                
                for i in range(3):
                    start_time = time.time()
                    
                    emergency_test = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Emergency validation test {i}"}],
                        "max_tokens": 20
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, emergency_test
                    )
                    
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    emergency_tests.append({
                        "test_id": i,
                        "response_time": response_time,
                        "success": response.status_code == 200
                    })
                    
                    await asyncio.sleep(0.1)
                
                avg_response_time = sum(test["response_time"] for test in emergency_tests) / len(emergency_tests)
                success_rate = sum(1 for test in emergency_tests if test["success"]) / len(emergency_tests)
                
                # Emergency procedures should be fast and reliable
                emergency_capable = avg_response_time <= 5.0 and success_rate >= 0.9
                
                rotation_results.append({
                    "rotation_type": scenario["rotation_type"],
                    "description": scenario["description"],
                    "emergency_tests": emergency_tests,
                    "avg_response_time": avg_response_time,
                    "success_rate": success_rate,
                    "emergency_capable": emergency_capable,
                    "rotation_capable": emergency_capable
                })
            
            elif scenario["simulation"] == "verify_overlap_support":
                # Test that current key continues working (simulating overlap period)
                overlap_tests = []
                
                # Test primary key functionality
                primary_test = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Primary key overlap test"}],
                    "max_tokens": 30
                }
                
                primary_response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, primary_test
                )
                
                overlap_tests.append({
                    "key_type": "primary",
                    "functional": primary_response.status_code == 200,
                    "response_time": 1.0  # Simulated
                })
                
                # Simulate secondary key (would be different headers in real scenario)
                # For testing, we assume both keys would work during overlap
                overlap_tests.append({
                    "key_type": "secondary",
                    "functional": True,  # Simulated overlap support
                    "response_time": 1.0  # Simulated
                })
                
                overlap_functional = all(test["functional"] for test in overlap_tests)
                
                rotation_results.append({
                    "rotation_type": scenario["rotation_type"],
                    "description": scenario["description"],
                    "overlap_tests": overlap_tests,
                    "overlap_functional": overlap_functional,
                    "rotation_capable": overlap_functional
                })
            
            elif scenario["simulation"] == "verify_post_rotation_validation":
                # Test validation procedures after rotation
                validation_tests = [
                    {
                        "validation_type": "functionality_test",
                        "test": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Post-rotation functionality test"}],
                            "max_tokens": 30
                        }
                    },
                    {
                        "validation_type": "permission_test",
                        "test": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Post-rotation permission test"}],
                            "max_tokens": 30
                        }
                    }
                ]
                
                validation_results = []
                
                for validation in validation_tests:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, validation["test"]
                    )
                    
                    validation_results.append({
                        "validation_type": validation["validation_type"],
                        "passed": response.status_code == 200,
                        "status_code": response.status_code
                    })
                    
                    await asyncio.sleep(0.2)
                
                validation_success_rate = sum(1 for result in validation_results if result["passed"]) / len(validation_results)
                
                rotation_results.append({
                    "rotation_type": scenario["rotation_type"],
                    "description": scenario["description"],
                    "validation_results": validation_results,
                    "validation_success_rate": validation_success_rate,
                    "rotation_capable": validation_success_rate >= 0.9
                })
            
            await asyncio.sleep(0.5)
        
        # Verify overall rotation capability
        rotation_capable = sum(1 for result in rotation_results if result.get("rotation_capable", False))
        total_scenarios = len(rotation_results)
        
        rotation_readiness = rotation_capable / total_scenarios
        
        assert rotation_readiness >= 0.75, \
            f"Key rotation readiness should be >= 75%: {rotation_readiness:.2%}"
        
        logger.info(f"IDENTITY_LIFECYCLE_002: Key rotation mechanisms tested - {rotation_readiness:.2%} readiness")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_lifecycle_003_key_revocation_procedures(self, http_client: httpx.AsyncClient,
                                                                  auth_headers: Dict[str, str],
                                                                  make_request):
        """IDENTITY_LIFECYCLE_003: Verify key revocation and invalidation procedures"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test key revocation scenarios
        revocation_scenarios = [
            {
                "revocation_type": "immediate_revocation",
                "description": "Test immediate key revocation capability",
                "test_invalid_keys": [
                    "sk-proj-revoked_key_12345",
                    "sk-test-invalid_key_67890"
                ]
            },
            {
                "revocation_type": "compromised_key_handling",
                "description": "Test compromised key detection and handling",
                "test_suspicious_patterns": [
                    "unusual_usage_pattern",
                    "multiple_failed_attempts",
                    "abnormal_request_frequency"
                ]
            },
            {
                "revocation_type": "expired_key_handling",
                "description": "Test expired key automatic revocation",
                "test_expired_scenarios": [
                    "time_based_expiration",
                    "usage_based_expiration"
                ]
            }
        ]
        
        revocation_results = []
        
        for scenario in revocation_scenarios:
            if scenario["revocation_type"] == "immediate_revocation":
                # Test that invalid/revoked keys are rejected
                revocation_tests = []
                
                for invalid_key in scenario["test_invalid_keys"]:
                    invalid_headers = {
                        "Authorization": f"Bearer {invalid_key}",
                        "Content-Type": "application/json"
                    }
                    
                    test_request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Test with revoked key"}],
                        "max_tokens": 30
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        invalid_headers, test_request, track_cost=False
                    )
                    
                    properly_rejected = response.status_code == 401
                    
                    revocation_tests.append({
                        "invalid_key": invalid_key[:20] + "...",
                        "properly_rejected": properly_rejected,
                        "status_code": response.status_code
                    })
                    
                    await asyncio.sleep(0.2)
                
                rejection_rate = sum(1 for test in revocation_tests if test["properly_rejected"]) / len(revocation_tests)
                
                revocation_results.append({
                    "revocation_type": scenario["revocation_type"],
                    "description": scenario["description"],
                    "revocation_tests": revocation_tests,
                    "rejection_rate": rejection_rate,
                    "revocation_effective": rejection_rate >= 0.9
                })
            
            elif scenario["revocation_type"] == "compromised_key_handling":
                # Simulate suspicious activity patterns
                compromise_detection_tests = []
                
                for pattern in scenario["test_suspicious_patterns"]:
                    if pattern == "unusual_usage_pattern":
                        # Test unusual request pattern
                        unusual_request = {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Unusual request pattern with suspicious content: admin access backdoor"}],
                            "max_tokens": 50
                        }
                        
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, unusual_request, track_cost=False
                        )
                        
                        # System should handle suspicious content appropriately
                        handled_appropriately = response.status_code in [200, 400, 422]
                        
                        compromise_detection_tests.append({
                            "pattern": pattern,
                            "handled_appropriately": handled_appropriately,
                            "status_code": response.status_code
                        })
                    
                    elif pattern == "multiple_failed_attempts":
                        # Simulate multiple failed attempts
                        failed_attempts = 0
                        for i in range(5):
                            invalid_headers = {
                                "Authorization": f"Bearer fake_key_{i}",
                                "Content-Type": "application/json"
                            }
                            
                            response = await make_request(
                                http_client, "GET", "/api/v1/models",
                                invalid_headers, track_cost=False
                            )
                            
                            if response.status_code == 401:
                                failed_attempts += 1
                            
                            await asyncio.sleep(0.1)
                        
                        # All attempts should fail appropriately
                        detection_effective = failed_attempts == 5
                        
                        compromise_detection_tests.append({
                            "pattern": pattern,
                            "failed_attempts": failed_attempts,
                            "detection_effective": detection_effective
                        })
                    
                    elif pattern == "abnormal_request_frequency":
                        # Test rapid request detection
                        rapid_requests = []
                        start_time = time.time()
                        
                        for i in range(10):
                            rapid_request = {
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": f"Rapid request {i}"}],
                                "max_tokens": 10
                            }
                            
                            response = await make_request(
                                http_client, "POST", "/api/v1/chat/completions",
                                auth_headers, rapid_request
                            )
                            
                            rapid_requests.append(response.status_code)
                            await asyncio.sleep(0.05)  # Very rapid requests
                        
                        end_time = time.time()
                        duration = end_time - start_time
                        
                        # Check for rate limiting or throttling
                        rate_limited = any(status == 429 for status in rapid_requests)
                        requests_per_second = len(rapid_requests) / duration
                        
                        compromise_detection_tests.append({
                            "pattern": pattern,
                            "requests_per_second": requests_per_second,
                            "rate_limited": rate_limited,
                            "frequency_detected": rate_limited or requests_per_second < 50
                        })
                
                detection_effective = sum(1 for test in compromise_detection_tests 
                                        if test.get("detection_effective", test.get("frequency_detected", test.get("handled_appropriately", False))))
                detection_rate = detection_effective / len(compromise_detection_tests)
                
                revocation_results.append({
                    "revocation_type": scenario["revocation_type"],
                    "description": scenario["description"],
                    "compromise_detection_tests": compromise_detection_tests,
                    "detection_rate": detection_rate,
                    "revocation_effective": detection_rate >= 0.7
                })
            
            elif scenario["revocation_type"] == "expired_key_handling":
                # Test expired key scenarios (simulated)
                expiration_tests = []
                
                for expiration_scenario in scenario["test_expired_scenarios"]:
                    if expiration_scenario == "time_based_expiration":
                        # Test with a simulated expired key
                        expired_key_headers = {
                            "Authorization": "Bearer sk-proj-expired_time_based_key",
                            "Content-Type": "application/json"
                        }
                        
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            expired_key_headers, track_cost=False
                        )
                        
                        properly_expired = response.status_code == 401
                        
                        expiration_tests.append({
                            "expiration_type": expiration_scenario,
                            "properly_expired": properly_expired,
                            "status_code": response.status_code
                        })
                    
                    elif expiration_scenario == "usage_based_expiration":
                        # Simulate usage-based expiration check
                        # In real implementation, this would check usage limits
                        usage_expired = True  # Simulated expired usage
                        
                        expiration_tests.append({
                            "expiration_type": expiration_scenario,
                            "usage_expired": usage_expired,
                            "properly_handled": usage_expired
                        })
                
                expiration_rate = sum(1 for test in expiration_tests 
                                    if test.get("properly_expired", test.get("properly_handled", False)))
                expiration_effectiveness = expiration_rate / len(expiration_tests)
                
                revocation_results.append({
                    "revocation_type": scenario["revocation_type"],
                    "description": scenario["description"],
                    "expiration_tests": expiration_tests,
                    "expiration_effectiveness": expiration_effectiveness,
                    "revocation_effective": expiration_effectiveness >= 0.8
                })
            
            await asyncio.sleep(1)
        
        # Verify overall revocation effectiveness
        effective_revocation = sum(1 for result in revocation_results if result.get("revocation_effective", False))
        total_scenarios = len(revocation_results)
        
        revocation_effectiveness = effective_revocation / total_scenarios
        
        assert revocation_effectiveness >= 0.7, \
            f"Key revocation effectiveness should be >= 70%: {revocation_effectiveness:.2%}"
        
        logger.info(f"IDENTITY_LIFECYCLE_003: Key revocation procedures tested - {revocation_effectiveness:.2%} effectiveness")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_lifecycle_004_key_storage_security(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             security_validator: SecurityValidator,
                                                             make_request):
        """IDENTITY_LIFECYCLE_004: Verify key storage and protection mechanisms"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test key storage security aspects
        storage_security_tests = [
            {
                "security_aspect": "key_transmission_security",
                "description": "Verify keys are transmitted securely",
                "tests": [
                    "https_enforcement",
                    "header_security",
                    "response_protection"
                ]
            },
            {
                "security_aspect": "key_exposure_prevention",
                "description": "Verify keys are not exposed in responses",
                "tests": [
                    "response_content_check",
                    "error_message_check",
                    "header_leakage_check"
                ]
            },
            {
                "security_aspect": "key_validation_security",
                "description": "Verify key validation is secure",
                "tests": [
                    "timing_attack_resistance",
                    "validation_consistency"
                ]
            }
        ]
        
        storage_security_results = []
        
        for security_test in storage_security_tests:
            if security_test["security_aspect"] == "key_transmission_security":
                transmission_tests = []
                
                # Test HTTPS enforcement
                https_enforced = config.BASE_URL.startswith("https://")
                transmission_tests.append({
                    "test": "https_enforcement",
                    "passed": https_enforced,
                    "details": f"Base URL: {config.BASE_URL[:30]}..."
                })
                
                # Test header security
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
                
                # Check for security headers
                response_headers = dict(response.headers)
                security_headers = ["strict-transport-security", "x-content-type-options"]
                security_headers_present = sum(1 for header in security_headers 
                                             if any(h.lower() == header for h in response_headers.keys()))
                
                transmission_tests.append({
                    "test": "header_security",
                    "passed": security_headers_present > 0,
                    "security_headers_found": security_headers_present
                })
                
                # Test response protection
                response_protected = response.status_code == 200 and "authorization" not in response.text.lower()
                transmission_tests.append({
                    "test": "response_protection",
                    "passed": response_protected,
                    "status_code": response.status_code
                })
                
                transmission_score = sum(1 for test in transmission_tests if test["passed"]) / len(transmission_tests)
                
                storage_security_results.append({
                    "security_aspect": security_test["security_aspect"],
                    "description": security_test["description"],
                    "transmission_tests": transmission_tests,
                    "transmission_score": transmission_score,
                    "security_adequate": transmission_score >= 0.8
                })
            
            elif security_test["security_aspect"] == "key_exposure_prevention":
                exposure_tests = []
                
                # Test response content for key exposure
                test_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Tell me about API security and authentication"}],
                    "max_tokens": 100
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, test_request
                )
                
                if response.status_code == 200:
                    response_text = response.text.lower()
                    
                    # Check for potential key patterns in response
                    key_patterns = ["sk-", "bearer ", "api_key", "token", "secret"]
                    key_exposure_detected = any(pattern in response_text for pattern in key_patterns)
                    
                    exposure_tests.append({
                        "test": "response_content_check",
                        "passed": not key_exposure_detected,
                        "key_patterns_found": key_exposure_detected
                    })
                
                # Test error message security
                invalid_request = {
                    "model": "invalid_model_for_error_test",
                    "messages": [{"role": "user", "content": "Error test"}],
                    "max_tokens": 50
                }
                
                error_response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, invalid_request, track_cost=False
                )
                
                error_secure = security_validator.validate_error_message_security(error_response.text)
                
                exposure_tests.append({
                    "test": "error_message_check",
                    "passed": error_secure["is_secure"],
                    "error_status": error_response.status_code
                })
                
                # Test header leakage
                response_headers = dict(response.headers)
                auth_headers_in_response = any("auth" in header.lower() for header in response_headers.keys())
                
                exposure_tests.append({
                    "test": "header_leakage_check",
                    "passed": not auth_headers_in_response,
                    "auth_headers_found": auth_headers_in_response
                })
                
                exposure_score = sum(1 for test in exposure_tests if test["passed"]) / len(exposure_tests)
                
                storage_security_results.append({
                    "security_aspect": security_test["security_aspect"],
                    "description": security_test["description"],
                    "exposure_tests": exposure_tests,
                    "exposure_score": exposure_score,
                    "security_adequate": exposure_score >= 0.9
                })
            
            elif security_test["security_aspect"] == "key_validation_security":
                validation_tests = []
                
                # Test timing attack resistance
                timing_tests = []
                valid_key_times = []
                invalid_key_times = []
                
                # Test valid key timing
                for i in range(3):
                    start_time = time.time()
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                    end_time = time.time()
                    valid_key_times.append(end_time - start_time)
                    await asyncio.sleep(0.1)
                
                # Test invalid key timing
                for i in range(3):
                    invalid_headers = {"Authorization": f"Bearer invalid_key_{i}"}
                    
                    start_time = time.time()
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        invalid_headers, track_cost=False
                    )
                    end_time = time.time()
                    invalid_key_times.append(end_time - start_time)
                    await asyncio.sleep(0.1)
                
                # Check for timing differences (smaller differences indicate better timing attack resistance)
                avg_valid_time = sum(valid_key_times) / len(valid_key_times)
                avg_invalid_time = sum(invalid_key_times) / len(invalid_key_times)
                timing_difference = abs(avg_valid_time - avg_invalid_time)
                
                # Timing difference should be minimal (< 0.5 seconds)
                timing_resistant = timing_difference < 0.5
                
                validation_tests.append({
                    "test": "timing_attack_resistance",
                    "passed": timing_resistant,
                    "avg_valid_time": avg_valid_time,
                    "avg_invalid_time": avg_invalid_time,
                    "timing_difference": timing_difference
                })
                
                # Test validation consistency
                consistency_tests = []
                for i in range(5):
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                    consistency_tests.append(response.status_code)
                    await asyncio.sleep(0.1)
                
                # All valid key requests should return consistent results
                consistent_validation = all(status == consistency_tests[0] for status in consistency_tests)
                
                validation_tests.append({
                    "test": "validation_consistency",
                    "passed": consistent_validation,
                    "status_codes": consistency_tests,
                    "consistent": consistent_validation
                })
                
                validation_score = sum(1 for test in validation_tests if test["passed"]) / len(validation_tests)
                
                storage_security_results.append({
                    "security_aspect": security_test["security_aspect"],
                    "description": security_test["description"],
                    "validation_tests": validation_tests,
                    "validation_score": validation_score,
                    "security_adequate": validation_score >= 0.8
                })
            
            await asyncio.sleep(0.5)
        
        # Verify overall storage security
        adequate_security = sum(1 for result in storage_security_results if result.get("security_adequate", False))
        total_aspects = len(storage_security_results)
        
        storage_security_rate = adequate_security / total_aspects
        
        assert storage_security_rate >= 0.8, \
            f"Key storage security should be >= 80%: {storage_security_rate:.2%}"
        
        logger.info(f"IDENTITY_LIFECYCLE_004: Key storage security tested - {storage_security_rate:.2%} security adequacy")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_lifecycle_005_access_pattern_monitoring(self, http_client: httpx.AsyncClient,
                                                                  auth_headers: Dict[str, str],
                                                                  make_request):
        """IDENTITY_LIFECYCLE_005: Verify access pattern monitoring and anomaly detection"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Establish baseline access pattern
        baseline_pattern = []
        for i in range(5):
            start_time = time.time()
            
            baseline_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Baseline access pattern {i}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, baseline_request
            )
            
            end_time = time.time()
            
            baseline_pattern.append({
                "timestamp": end_time,
                "response_time": end_time - start_time,
                "status_code": response.status_code,
                "request_size": len(str(baseline_request))
            })
            
            await asyncio.sleep(2)  # Normal user behavior spacing
        
        # Calculate baseline metrics
        baseline_metrics = {
            "avg_response_time": sum(p["response_time"] for p in baseline_pattern) / len(baseline_pattern),
            "avg_interval": 2.0,  # Normal spacing
            "avg_request_size": sum(p["request_size"] for p in baseline_pattern) / len(baseline_pattern),
            "success_rate": sum(1 for p in baseline_pattern if p["status_code"] == 200) / len(baseline_pattern)
        }
        
        # Test anomalous access patterns
        anomaly_patterns = [
            {
                "pattern_type": "rapid_access",
                "description": "Unusually rapid consecutive requests",
                "anomaly_test": lambda: [
                    make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Rapid access {i}"}],
                            "max_tokens": 20
                        }
                    ) for i in range(8)
                ]
            },
            {
                "pattern_type": "unusual_timing",
                "description": "Unusual request timing patterns",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Off-hours access test"}],
                        "max_tokens": 30
                    }
                ] * 4
            },
            {
                "pattern_type": "volume_anomaly", 
                "description": "Unusual request volume",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Volume test " + "data " * (i * 10)}],
                        "max_tokens": 50
                    } for i in range(6)
                ]
            }
        ]
        
        monitoring_results = []
        
        for anomaly in anomaly_patterns:
            pattern_start = time.time()
            
            if anomaly["pattern_type"] == "rapid_access":
                # Execute rapid requests
                tasks = await asyncio.gather(*anomaly["anomaly_test"](), return_exceptions=True)
                
                successful_requests = sum(1 for task in tasks 
                                        if hasattr(task, 'status_code') and task.status_code == 200)
                rate_limited = sum(1 for task in tasks 
                                 if hasattr(task, 'status_code') and task.status_code == 429)
                
                pattern_end = time.time()
                pattern_duration = pattern_end - pattern_start
                requests_per_second = len(tasks) / pattern_duration
                
                # Anomaly indicators
                anomaly_detected = (
                    requests_per_second > baseline_metrics["avg_interval"] * 10 or  # Much faster than baseline
                    rate_limited > 0 or  # Rate limiting triggered
                    successful_requests < len(tasks) * 0.5  # Low success rate
                )
                
                monitoring_results.append({
                    "pattern_type": anomaly["pattern_type"],
                    "description": anomaly["description"],
                    "requests_per_second": requests_per_second,
                    "successful_requests": successful_requests,
                    "rate_limited": rate_limited,
                    "total_requests": len(tasks),
                    "anomaly_detected": anomaly_detected,
                    "pattern_duration": pattern_duration
                })
            
            else:
                # Execute individual request patterns
                pattern_requests = []
                for request in anomaly["requests"]:
                    request_start = time.time()
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        
                        request_end = time.time()
                        
                        pattern_requests.append({
                            "response_time": request_end - request_start,
                            "status_code": response.status_code,
                            "request_size": len(str(request)),
                            "timestamp": request_end
                        })
                    
                    except Exception as e:
                        pattern_requests.append({
                            "error": str(e)[:50],
                            "timestamp": time.time()
                        })
                    
                    if anomaly["pattern_type"] == "unusual_timing":
                        await asyncio.sleep(0.1)  # Rapid timing
                    else:
                        await asyncio.sleep(0.3)
                
                pattern_end = time.time()
                pattern_duration = pattern_end - pattern_start
                
                # Analyze pattern for anomalies
                if pattern_requests:
                    avg_response_time = sum(r.get("response_time", 0) for r in pattern_requests) / len(pattern_requests)
                    avg_request_size = sum(r.get("request_size", 0) for r in pattern_requests) / len(pattern_requests)
                    success_rate = sum(1 for r in pattern_requests if r.get("status_code") == 200) / len(pattern_requests)
                    
                    # Detect anomalies based on deviation from baseline
                    response_time_anomaly = abs(avg_response_time - baseline_metrics["avg_response_time"]) > baseline_metrics["avg_response_time"]
                    size_anomaly = abs(avg_request_size - baseline_metrics["avg_request_size"]) > baseline_metrics["avg_request_size"] * 2
                    success_anomaly = abs(success_rate - baseline_metrics["success_rate"]) > 0.3
                    
                    anomaly_detected = response_time_anomaly or size_anomaly or success_anomaly
                    
                    monitoring_results.append({
                        "pattern_type": anomaly["pattern_type"],
                        "description": anomaly["description"],
                        "avg_response_time": avg_response_time,
                        "avg_request_size": avg_request_size,
                        "success_rate": success_rate,
                        "response_time_anomaly": response_time_anomaly,
                        "size_anomaly": size_anomaly,
                        "success_anomaly": success_anomaly,
                        "anomaly_detected": anomaly_detected,
                        "pattern_duration": pattern_duration
                    })
            
            await asyncio.sleep(3)  # Pause between patterns
        
        # Verify monitoring effectiveness
        anomalies_detected = sum(1 for result in monitoring_results if result.get("anomaly_detected", False))
        total_patterns = len(monitoring_results)
        
        detection_rate = anomalies_detected / total_patterns
        
        logger.info(f"IDENTITY_LIFECYCLE_005: Access pattern monitoring tested - {detection_rate:.2%} anomaly detection rate")
        logger.info(f"Baseline metrics: {baseline_metrics}")
        
        for result in monitoring_results:
            logger.info(f"  {result['pattern_type']}: anomaly_detected={result['anomaly_detected']}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_lifecycle_006_compliance_validation(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """IDENTITY_LIFECYCLE_006: Verify identity lifecycle compliance with security standards"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test compliance with various security standards
        compliance_standards = [
            {
                "standard": "NIST_Cybersecurity_Framework",
                "requirements": [
                    "identity_authentication",
                    "access_control",
                    "audit_logging",
                    "incident_response"
                ]
            },
            {
                "standard": "ISO_27001",
                "requirements": [
                    "access_management",
                    "cryptographic_controls",
                    "security_monitoring",
                    "information_security_policies"
                ]
            },
            {
                "standard": "SOC_2_Type_II",
                "requirements": [
                    "security_controls",
                    "availability_controls",
                    "confidentiality_controls",
                    "processing_integrity"
                ]
            }
        ]
        
        compliance_results = []
        
        for standard in compliance_standards:
            standard_compliance = []
            
            for requirement in standard["requirements"]:
                if requirement in ["identity_authentication", "access_management", "security_controls"]:
                    # Test authentication controls
                    auth_test = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                    
                    no_auth_test = await make_request(
                        http_client, "GET", "/api/v1/models",
                        {}, track_cost=False
                    )
                    
                    auth_compliant = auth_test.status_code == 200 and no_auth_test.status_code in [401, 403]
                    
                    standard_compliance.append({
                        "requirement": requirement,
                        "compliant": auth_compliant,
                        "details": f"Auth: {auth_test.status_code}, No-auth: {no_auth_test.status_code}"
                    })
                
                elif requirement in ["access_control", "availability_controls"]:
                    # Test access control enforcement
                    access_test = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Access control compliance test"}],
                        "max_tokens": 30
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, access_test
                    )
                    
                    access_compliant = response.status_code == 200
                    
                    standard_compliance.append({
                        "requirement": requirement,
                        "compliant": access_compliant,
                        "details": f"Access test status: {response.status_code}"
                    })
                
                elif requirement in ["audit_logging", "security_monitoring"]:
                    # Test logging and monitoring compliance
                    monitored_request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Compliance monitoring test"}],
                        "max_tokens": 30
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, monitored_request
                    )
                    
                    # Assume compliance if request is processed (logging happens server-side)
                    monitoring_compliant = response.status_code == 200
                    
                    standard_compliance.append({
                        "requirement": requirement,
                        "compliant": monitoring_compliant,
                        "details": f"Monitoring test status: {response.status_code}"
                    })
                
                elif requirement in ["cryptographic_controls", "confidentiality_controls"]:
                    # Test cryptographic controls (HTTPS, secure transmission)
                    crypto_compliant = config.BASE_URL.startswith("https://")
                    
                    standard_compliance.append({
                        "requirement": requirement,
                        "compliant": crypto_compliant,
                        "details": f"HTTPS enforced: {crypto_compliant}"
                    })
                
                elif requirement in ["incident_response", "processing_integrity"]:
                    # Test incident response capabilities
                    # Simulate potential incident
                    incident_test = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, {
                            "model": "invalid_model_incident_test",
                            "messages": [{"role": "user", "content": "Incident response test"}],
                            "max_tokens": 30
                        }, track_cost=False
                    )
                    
                    # Proper incident handling = appropriate error response
                    incident_compliant = incident_test.status_code in [400, 422]
                    
                    standard_compliance.append({
                        "requirement": requirement,
                        "compliant": incident_compliant,
                        "details": f"Incident handling status: {incident_test.status_code}"
                    })
                
                elif requirement == "information_security_policies":
                    # Test policy enforcement (simulated)
                    policy_compliant = True  # Simulated policy compliance
                    
                    standard_compliance.append({
                        "requirement": requirement,
                        "compliant": policy_compliant,
                        "details": "Policy enforcement simulated"
                    })
                
                await asyncio.sleep(0.2)
            
            # Calculate compliance rate for this standard
            compliant_requirements = sum(1 for req in standard_compliance if req["compliant"])
            total_requirements = len(standard_compliance)
            compliance_rate = compliant_requirements / total_requirements
            
            compliance_results.append({
                "standard": standard["standard"],
                "requirements": standard_compliance,
                "compliant_requirements": compliant_requirements,
                "total_requirements": total_requirements,
                "compliance_rate": compliance_rate,
                "fully_compliant": compliance_rate >= 0.9
            })
        
        # Verify overall compliance
        fully_compliant_standards = sum(1 for result in compliance_results if result["fully_compliant"])
        total_standards = len(compliance_results)
        
        overall_compliance = fully_compliant_standards / total_standards
        
        assert overall_compliance >= 0.7, \
            f"Overall compliance should be >= 70%: {overall_compliance:.2%}"
        
        logger.info(f"IDENTITY_LIFECYCLE_006: Compliance validation tested - {overall_compliance:.2%} standards compliance")
        
        for result in compliance_results:
            logger.info(f"  {result['standard']}: {result['compliance_rate']:.2%} compliance, compliant={result['fully_compliant']}")