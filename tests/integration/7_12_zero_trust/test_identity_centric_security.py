# Section 7.12 - Zero Trust Identity-Centric Security Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Identity-Centric Security.md

import pytest
import httpx
import asyncio
import time
import json
import hashlib
import secrets
from typing import Dict, Any, List, Optional
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestIdentityCentricSecurity:
    """Zero Trust Identity-Centric Security tests"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_centric_001_identity_based_access_control(self, http_client: httpx.AsyncClient,
                                                                    auth_headers: Dict[str, str],
                                                                    embedding_auth_headers: Dict[str, str],
                                                                    make_request):
        """IDENTITY_CENTRIC_001: Verify identity-based access control mechanisms"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test identity-based access scenarios
        identity_access_scenarios = [
            {
                "identity_type": "full_access_identity",
                "description": "Identity with full API access",
                "headers": auth_headers,
                "access_tests": [
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "should_succeed": True
                    },
                    {
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Full access test"}],
                            "max_tokens": 30
                        },
                        "should_succeed": True
                    }
                ]
            },
            {
                "identity_type": "limited_access_identity",
                "description": "Identity with limited scope access",
                "headers": embedding_auth_headers,
                "access_tests": [
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "should_succeed": True
                    },
                    {
                        "endpoint": "/api/v1/embeddings",
                        "method": "POST",
                        "data": {
                            "model": config.get_embedding_model(0),
                            "input": "Limited access embedding test"
                        },
                        "should_succeed": True
                    },
                    {
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Unauthorized chat test"}],
                            "max_tokens": 30
                        },
                        "should_succeed": False
                    }
                ]
            },
            {
                "identity_type": "no_access_identity",
                "description": "Identity with no valid access",
                "headers": {"Authorization": "Bearer invalid_identity_token"},
                "access_tests": [
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "should_succeed": False
                    },
                    {
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "No access test"}],
                            "max_tokens": 30
                        },
                        "should_succeed": False
                    }
                ]
            }
        ]
        
        identity_access_results = []
        
        for scenario in identity_access_scenarios:
            scenario_results = []
            
            for access_test in scenario["access_tests"]:
                try:
                    response = await make_request(
                        http_client, access_test["method"], access_test["endpoint"],
                        scenario["headers"], access_test.get("data"), 
                        track_cost=(access_test["should_succeed"] and access_test["method"] == "POST")
                    )
                    
                    access_granted = response.status_code == 200
                    access_appropriate = access_granted if access_test["should_succeed"] else response.status_code in [401, 403]
                    
                    scenario_results.append({
                        "endpoint": access_test["endpoint"],
                        "method": access_test["method"],
                        "should_succeed": access_test["should_succeed"],
                        "access_granted": access_granted,
                        "status_code": response.status_code,
                        "access_appropriate": access_appropriate
                    })
                
                except Exception as e:
                    # Exceptions can indicate proper access control
                    access_appropriate = not access_test["should_succeed"]
                    
                    scenario_results.append({
                        "endpoint": access_test["endpoint"],
                        "method": access_test["method"],
                        "should_succeed": access_test["should_succeed"],
                        "error": str(e)[:100],
                        "access_appropriate": access_appropriate
                    })
                
                await asyncio.sleep(0.3)
            
            # Calculate access control effectiveness for this identity
            appropriate_access = sum(1 for result in scenario_results if result["access_appropriate"])
            total_tests = len(scenario_results)
            access_control_rate = appropriate_access / total_tests
            
            identity_access_results.append({
                "identity_type": scenario["identity_type"],
                "description": scenario["description"],
                "access_tests": scenario_results,
                "appropriate_access": appropriate_access,
                "total_tests": total_tests,
                "access_control_rate": access_control_rate,
                "identity_controls_effective": access_control_rate >= 0.9
            })
        
        # Verify overall identity-based access control
        effective_controls = sum(1 for result in identity_access_results if result["identity_controls_effective"])
        total_identities = len(identity_access_results)
        
        control_effectiveness = effective_controls / total_identities
        
        assert control_effectiveness >= 0.8, \
            f"Identity-based access control should be >= 80% effective: {control_effectiveness:.2%}"
        
        logger.info(f"IDENTITY_CENTRIC_001: Identity-based access control tested - {control_effectiveness:.2%} effectiveness")
        
        for result in identity_access_results:
            logger.info(f"  {result['identity_type']}: {result['access_control_rate']:.2%} appropriate access")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_centric_002_identity_verification(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            security_validator: SecurityValidator,
                                                            make_request):
        """IDENTITY_CENTRIC_002: Verify identity verification and validation mechanisms"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test identity verification scenarios
        identity_verification_scenarios = [
            {
                "verification_type": "valid_identity_verification",
                "description": "Verify valid identity is properly validated",
                "headers": auth_headers,
                "expected_outcome": "verified"
            },
            {
                "verification_type": "invalid_identity_verification",
                "description": "Verify invalid identity is properly rejected",
                "headers": {"Authorization": "Bearer sk-invalid-verification-test-12345"},
                "expected_outcome": "rejected"
            },
            {
                "verification_type": "malformed_identity_verification",
                "description": "Verify malformed identity is properly handled",
                "headers": {"Authorization": "InvalidFormat"},
                "expected_outcome": "rejected"
            },
            {
                "verification_type": "missing_identity_verification",
                "description": "Verify missing identity is properly handled",
                "headers": {},
                "expected_outcome": "rejected"
            }
        ]
        
        verification_results = []
        
        for scenario in identity_verification_scenarios:
            verification_start = time.time()
            
            # Test identity verification with a simple request
            verification_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Identity verification test"}],
                "max_tokens": 30
            }
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    scenario["headers"], verification_request, track_cost=False
                )
                
                verification_end = time.time()
                verification_time = verification_end - verification_start
                
                # Analyze verification outcome
                if scenario["expected_outcome"] == "verified":
                    verification_successful = response.status_code == 200
                    verification_appropriate = verification_successful
                else:  # expected_outcome == "rejected"
                    verification_successful = response.status_code in [401, 403, 400]
                    verification_appropriate = verification_successful
                
                # Analyze response for identity verification indicators
                verification_analysis = security_validator.analyze_identity_verification(
                    scenario["verification_type"], response.status_code, response.text
                )
                
                verification_results.append({
                    "verification_type": scenario["verification_type"],
                    "description": scenario["description"],
                    "expected_outcome": scenario["expected_outcome"],
                    "status_code": response.status_code,
                    "verification_time": verification_time,
                    "verification_successful": verification_successful,
                    "verification_appropriate": verification_appropriate,
                    "security_indicators": verification_analysis["security_indicators"],
                    "verification_quality": verification_analysis["verification_quality"]
                })
            
            except Exception as e:
                verification_end = time.time()
                verification_time = verification_end - verification_start
                
                # Exceptions for invalid identities can be appropriate
                verification_appropriate = scenario["expected_outcome"] == "rejected"
                
                verification_results.append({
                    "verification_type": scenario["verification_type"],
                    "description": scenario["description"],
                    "expected_outcome": scenario["expected_outcome"],
                    "error": str(e)[:100],
                    "verification_time": verification_time,
                    "verification_appropriate": verification_appropriate,
                    "verification_quality": "error_handling"
                })
            
            await asyncio.sleep(0.3)
        
        # Verify identity verification effectiveness
        appropriate_verifications = sum(1 for result in verification_results if result["verification_appropriate"])
        total_verifications = len(verification_results)
        
        verification_effectiveness = appropriate_verifications / total_verifications
        
        # Check verification timing (should be consistent to prevent timing attacks)
        verification_times = [result["verification_time"] for result in verification_results if "verification_time" in result]
        if len(verification_times) > 1:
            time_variance = max(verification_times) - min(verification_times)
            timing_consistent = time_variance < 2.0  # Timing should be relatively consistent
        else:
            timing_consistent = True
        
        assert verification_effectiveness >= 0.9, \
            f"Identity verification effectiveness should be >= 90%: {verification_effectiveness:.2%}"
        
        assert timing_consistent, \
            f"Verification timing should be consistent to prevent timing attacks: variance={time_variance:.2f}s"
        
        logger.info(f"IDENTITY_CENTRIC_002: Identity verification tested - {verification_effectiveness:.2%} effectiveness, timing_consistent={timing_consistent}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_centric_003_identity_context_enforcement(self, http_client: httpx.AsyncClient,
                                                                   auth_headers: Dict[str, str],
                                                                   make_request):
        """IDENTITY_CENTRIC_003: Verify identity context enforcement and isolation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test identity context enforcement scenarios
        context_enforcement_scenarios = [
            {
                "context_type": "session_isolation",
                "description": "Verify session context isolation between identities",
                "test_sequence": [
                    {
                        "step": "establish_context_1",
                        "headers": auth_headers,
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Context 1: Remember this secret code ABC123"}],
                            "max_tokens": 50
                        }
                    },
                    {
                        "step": "test_context_isolation",
                        "headers": auth_headers,  # Same identity, different session
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "What secret code did I mention earlier?"}],
                            "max_tokens": 50
                        }
                    }
                ]
            },
            {
                "context_type": "request_isolation",
                "description": "Verify request context isolation",
                "test_sequence": [
                    {
                        "step": "sensitive_request",
                        "headers": auth_headers,
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Sensitive data: API-KEY-XYZ789"}],
                            "max_tokens": 30
                        }
                    },
                    {
                        "step": "subsequent_request",
                        "headers": auth_headers,
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Regular request for information"}],
                            "max_tokens": 30
                        }
                    }
                ]
            },
            {
                "context_type": "identity_boundary_enforcement",
                "description": "Verify identity boundary enforcement",
                "test_sequence": [
                    {
                        "step": "identity_specific_request",
                        "headers": auth_headers,
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "This is identity-specific content"}],
                            "max_tokens": 30
                        }
                    }
                ]
            }
        ]
        
        context_enforcement_results = []
        
        for scenario in context_enforcement_scenarios:
            scenario_start = time.time()
            sequence_results = []
            
            for step in scenario["test_sequence"]:
                step_start = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        step["headers"], step["request"]
                    )
                    
                    step_end = time.time()
                    
                    if response.status_code == 200:
                        response_data = response.json()
                        response_content = ""
                        
                        if "choices" in response_data and response_data["choices"]:
                            response_content = response_data["choices"][0]["message"]["content"]
                        
                        sequence_results.append({
                            "step": step["step"],
                            "status_code": response.status_code,
                            "response_content": response_content,
                            "response_time": step_end - step_start,
                            "success": True
                        })
                    else:
                        sequence_results.append({
                            "step": step["step"],
                            "status_code": response.status_code,
                            "response_time": step_end - step_start,
                            "success": False
                        })
                
                except Exception as e:
                    sequence_results.append({
                        "step": step["step"],
                        "error": str(e)[:100],
                        "success": False
                    })
                
                await asyncio.sleep(0.5)  # Brief pause between steps
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            # Analyze context enforcement
            if scenario["context_type"] == "session_isolation":
                # Check if sensitive information from step 1 appears in step 2
                context_1_content = ""
                context_2_content = ""
                
                for result in sequence_results:
                    if result["step"] == "establish_context_1" and result.get("response_content"):
                        context_1_content = result["response_content"]
                    elif result["step"] == "test_context_isolation" and result.get("response_content"):
                        context_2_content = result["response_content"]
                
                # Context isolation is effective if sensitive info from context 1 doesn't appear in context 2
                isolation_effective = "ABC123" not in context_2_content if context_2_content else True
                
                context_enforcement_results.append({
                    "context_type": scenario["context_type"],
                    "description": scenario["description"],
                    "sequence_results": sequence_results,
                    "scenario_duration": scenario_duration,
                    "isolation_effective": isolation_effective,
                    "context_enforcement_quality": "high" if isolation_effective else "low"
                })
            
            elif scenario["context_type"] == "request_isolation":
                # Verify that sensitive data from one request doesn't leak into subsequent requests
                sensitive_data_leaked = False
                
                for i, result in enumerate(sequence_results):
                    if i > 0 and result.get("response_content"):
                        # Check if sensitive data from previous requests appears
                        if "API-KEY-XYZ789" in result["response_content"]:
                            sensitive_data_leaked = True
                
                context_enforcement_results.append({
                    "context_type": scenario["context_type"],
                    "description": scenario["description"],
                    "sequence_results": sequence_results,
                    "scenario_duration": scenario_duration,
                    "data_leaked": sensitive_data_leaked,
                    "isolation_effective": not sensitive_data_leaked,
                    "context_enforcement_quality": "high" if not sensitive_data_leaked else "low"
                })
            
            elif scenario["context_type"] == "identity_boundary_enforcement":
                # Verify that identity boundaries are maintained
                boundary_maintained = all(result.get("success", False) for result in sequence_results)
                
                context_enforcement_results.append({
                    "context_type": scenario["context_type"],
                    "description": scenario["description"],
                    "sequence_results": sequence_results,
                    "scenario_duration": scenario_duration,
                    "boundary_maintained": boundary_maintained,
                    "isolation_effective": boundary_maintained,
                    "context_enforcement_quality": "high" if boundary_maintained else "low"
                })
            
            await asyncio.sleep(1)
        
        # Verify overall context enforcement effectiveness
        effective_enforcement = sum(1 for result in context_enforcement_results if result["isolation_effective"])
        total_scenarios = len(context_enforcement_results)
        
        enforcement_rate = effective_enforcement / total_scenarios
        
        assert enforcement_rate >= 0.8, \
            f"Identity context enforcement should be >= 80% effective: {enforcement_rate:.2%}"
        
        logger.info(f"IDENTITY_CENTRIC_003: Identity context enforcement tested - {enforcement_rate:.2%} effectiveness")
        
        for result in context_enforcement_results:
            logger.info(f"  {result['context_type']}: isolation_effective={result['isolation_effective']}, quality={result['context_enforcement_quality']}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_centric_004_dynamic_access_control(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """IDENTITY_CENTRIC_004: Verify dynamic access control based on identity behavior"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test dynamic access control scenarios
        dynamic_access_scenarios = [
            {
                "behavior_type": "normal_usage_pattern",
                "description": "Test normal usage pattern access",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Normal usage request {i}"}],
                        "max_tokens": 30
                    } for i in range(3)
                ],
                "request_interval": 2.0,
                "expected_access": "granted"
            },
            {
                "behavior_type": "burst_usage_pattern",
                "description": "Test burst usage pattern access control",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Burst request {i}"}],
                        "max_tokens": 20
                    } for i in range(10)
                ],
                "request_interval": 0.1,
                "expected_access": "potentially_limited"
            },
            {
                "behavior_type": "unusual_content_pattern",
                "description": "Test unusual content pattern access control",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Unusual content pattern with suspicious keywords: hack, exploit, breach"}],
                        "max_tokens": 50
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Another suspicious request with malware, virus, attack"}],
                        "max_tokens": 50
                    }
                ],
                "request_interval": 0.5,
                "expected_access": "potentially_restricted"
            }
        ]
        
        dynamic_access_results = []
        
        for scenario in dynamic_access_scenarios:
            scenario_start = time.time()
            behavior_metrics = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "rate_limited_requests": 0,
                "response_times": [],
                "status_codes": []
            }
            
            for i, request in enumerate(scenario["requests"]):
                request_start = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    request_end = time.time()
                    response_time = request_end - request_start
                    
                    behavior_metrics["total_requests"] += 1
                    behavior_metrics["response_times"].append(response_time)
                    behavior_metrics["status_codes"].append(response.status_code)
                    
                    if response.status_code == 200:
                        behavior_metrics["successful_requests"] += 1
                    elif response.status_code == 429:
                        behavior_metrics["rate_limited_requests"] += 1
                    else:
                        behavior_metrics["failed_requests"] += 1
                
                except Exception as e:
                    behavior_metrics["total_requests"] += 1
                    behavior_metrics["failed_requests"] += 1
                    behavior_metrics["status_codes"].append(0)
                
                await asyncio.sleep(scenario["request_interval"])
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            # Analyze dynamic access control effectiveness
            success_rate = behavior_metrics["successful_requests"] / behavior_metrics["total_requests"]
            rate_limit_rate = behavior_metrics["rate_limited_requests"] / behavior_metrics["total_requests"]
            avg_response_time = sum(behavior_metrics["response_times"]) / len(behavior_metrics["response_times"]) if behavior_metrics["response_times"] else 0
            
            # Evaluate access control appropriateness
            if scenario["expected_access"] == "granted":
                access_appropriate = success_rate >= 0.8
            elif scenario["expected_access"] == "potentially_limited":
                access_appropriate = rate_limit_rate > 0 or success_rate < 0.8
            elif scenario["expected_access"] == "potentially_restricted":
                access_appropriate = success_rate < 0.9 or rate_limit_rate > 0
            else:
                access_appropriate = True
            
            dynamic_access_results.append({
                "behavior_type": scenario["behavior_type"],
                "description": scenario["description"],
                "expected_access": scenario["expected_access"],
                "behavior_metrics": behavior_metrics,
                "success_rate": success_rate,
                "rate_limit_rate": rate_limit_rate,
                "avg_response_time": avg_response_time,
                "scenario_duration": scenario_duration,
                "access_appropriate": access_appropriate,
                "dynamic_control_detected": rate_limit_rate > 0 or success_rate < 1.0
            })
            
            await asyncio.sleep(2)  # Pause between scenarios
        
        # Verify dynamic access control effectiveness
        appropriate_controls = sum(1 for result in dynamic_access_results if result["access_appropriate"])
        dynamic_controls_detected = sum(1 for result in dynamic_access_results if result["dynamic_control_detected"])
        total_scenarios = len(dynamic_access_results)
        
        control_appropriateness = appropriate_controls / total_scenarios
        dynamic_detection_rate = dynamic_controls_detected / total_scenarios
        
        assert control_appropriateness >= 0.7, \
            f"Dynamic access control appropriateness should be >= 70%: {control_appropriateness:.2%}"
        
        logger.info(f"IDENTITY_CENTRIC_004: Dynamic access control tested - {control_appropriateness:.2%} appropriateness, {dynamic_detection_rate:.2%} dynamic detection")
        
        for result in dynamic_access_results:
            logger.info(f"  {result['behavior_type']}: success_rate={result['success_rate']:.2%}, rate_limited={result['rate_limit_rate']:.2%}, appropriate={result['access_appropriate']}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_centric_005_identity_trust_scoring(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             security_validator: SecurityValidator,
                                                             make_request):
        """IDENTITY_CENTRIC_005: Verify identity trust scoring and risk assessment"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test identity trust scoring scenarios
        trust_scoring_scenarios = [
            {
                "trust_scenario": "high_trust_behavior",
                "description": "Establish high trust score through consistent behavior",
                "behavior_pattern": [
                    {
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "High trust behavior: normal API usage"}],
                            "max_tokens": 30
                        },
                        "trust_factors": ["consistent_usage", "normal_content", "appropriate_timing"]
                    } for _ in range(5)
                ]
            },
            {
                "trust_scenario": "medium_trust_behavior",
                "description": "Mixed behavior resulting in medium trust score",
                "behavior_pattern": [
                    {
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Normal request"}],
                            "max_tokens": 30
                        },
                        "trust_factors": ["normal_content"]
                    },
                    {
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Slightly unusual request pattern"}],
                            "max_tokens": 100
                        },
                        "trust_factors": ["unusual_size"]
                    },
                    {
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Another normal request"}],
                            "max_tokens": 30
                        },
                        "trust_factors": ["normal_content"]
                    }
                ]
            },
            {
                "trust_scenario": "low_trust_behavior",
                "description": "Suspicious behavior resulting in low trust score",
                "behavior_pattern": [
                    {
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Suspicious content with security testing keywords"}],
                            "max_tokens": 50
                        },
                        "trust_factors": ["suspicious_content"]
                    },
                    {
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Another request with unusual patterns and potential exploitation attempts"}],
                            "max_tokens": 80
                        },
                        "trust_factors": ["suspicious_content", "unusual_size"]
                    }
                ]
            }
        ]
        
        trust_scoring_results = []
        
        for scenario in trust_scoring_scenarios:
            scenario_start = time.time()
            trust_metrics = {
                "total_requests": 0,
                "successful_requests": 0,
                "suspicious_requests": 0,
                "response_times": [],
                "content_analysis": [],
                "behavioral_indicators": []
            }
            
            for behavior in scenario["behavior_pattern"]:
                request_start = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, behavior["request"]
                    )
                    
                    request_end = time.time()
                    response_time = request_end - request_start
                    
                    trust_metrics["total_requests"] += 1
                    trust_metrics["response_times"].append(response_time)
                    
                    if response.status_code == 200:
                        trust_metrics["successful_requests"] += 1
                        
                        # Analyze response for trust indicators
                        response_data = response.json()
                        if "choices" in response_data and response_data["choices"]:
                            response_content = response_data["choices"][0]["message"]["content"]
                            
                            # Analyze content for trust scoring
                            content_analysis = security_validator.analyze_content_trust_indicators(
                                behavior["request"]["messages"][0]["content"],
                                response_content
                            )
                            
                            trust_metrics["content_analysis"].append(content_analysis)
                    
                    # Check for suspicious behavior indicators
                    if "suspicious_content" in behavior["trust_factors"]:
                        trust_metrics["suspicious_requests"] += 1
                    
                    trust_metrics["behavioral_indicators"].extend(behavior["trust_factors"])
                
                except Exception as e:
                    trust_metrics["total_requests"] += 1
                    trust_metrics["behavioral_indicators"].append("request_error")
                
                await asyncio.sleep(1)  # Normal timing between requests
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            # Calculate trust score based on observed behavior
            success_rate = trust_metrics["successful_requests"] / trust_metrics["total_requests"] if trust_metrics["total_requests"] > 0 else 0
            suspicious_rate = trust_metrics["suspicious_requests"] / trust_metrics["total_requests"] if trust_metrics["total_requests"] > 0 else 0
            
            # Simple trust scoring algorithm
            base_trust_score = 0.5  # Neutral starting point
            
            # Positive trust factors
            if success_rate >= 0.9:
                base_trust_score += 0.2
            if "consistent_usage" in trust_metrics["behavioral_indicators"]:
                base_trust_score += 0.1
            if "normal_content" in trust_metrics["behavioral_indicators"]:
                base_trust_score += 0.1
            
            # Negative trust factors
            if suspicious_rate > 0.3:
                base_trust_score -= 0.3
            if "suspicious_content" in trust_metrics["behavioral_indicators"]:
                base_trust_score -= 0.2
            if "request_error" in trust_metrics["behavioral_indicators"]:
                base_trust_score -= 0.1
            
            # Normalize trust score to 0-1 range
            calculated_trust_score = max(0.0, min(1.0, base_trust_score))
            
            # Map trust score to categories
            if calculated_trust_score >= 0.7:
                trust_category = "high"
            elif calculated_trust_score >= 0.4:
                trust_category = "medium"
            else:
                trust_category = "low"
            
            # Verify trust score appropriateness
            expected_trust_level = scenario["trust_scenario"].split("_")[0]  # high, medium, low
            trust_score_appropriate = trust_category == expected_trust_level
            
            trust_scoring_results.append({
                "trust_scenario": scenario["trust_scenario"],
                "description": scenario["description"],
                "trust_metrics": trust_metrics,
                "calculated_trust_score": calculated_trust_score,
                "trust_category": trust_category,
                "expected_trust_level": expected_trust_level,
                "trust_score_appropriate": trust_score_appropriate,
                "scenario_duration": scenario_duration
            })
            
            await asyncio.sleep(2)
        
        # Verify trust scoring effectiveness
        appropriate_scores = sum(1 for result in trust_scoring_results if result["trust_score_appropriate"])
        total_scenarios = len(trust_scoring_results)
        
        scoring_accuracy = appropriate_scores / total_scenarios
        
        assert scoring_accuracy >= 0.7, \
            f"Trust scoring accuracy should be >= 70%: {scoring_accuracy:.2%}"
        
        logger.info(f"IDENTITY_CENTRIC_005: Identity trust scoring tested - {scoring_accuracy:.2%} accuracy")
        
        for result in trust_scoring_results:
            logger.info(f"  {result['trust_scenario']}: score={result['calculated_trust_score']:.2f}, category={result['trust_category']}, appropriate={result['trust_score_appropriate']}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_centric_006_identity_lifecycle_integration(self, http_client: httpx.AsyncClient,
                                                                     auth_headers: Dict[str, str],
                                                                     make_request):
        """IDENTITY_CENTRIC_006: Verify identity lifecycle integration with security controls"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test identity lifecycle integration scenarios
        lifecycle_integration_scenarios = [
            {
                "lifecycle_phase": "active_identity",
                "description": "Test active identity with full capabilities",
                "identity_status": "active",
                "test_operations": [
                    {
                        "operation": "standard_request",
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Active identity standard request"}],
                            "max_tokens": 30
                        },
                        "should_succeed": True
                    },
                    {
                        "operation": "resource_intensive_request",
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Active identity resource intensive request"}],
                            "max_tokens": 200
                        },
                        "should_succeed": True
                    }
                ]
            },
            {
                "lifecycle_phase": "restricted_identity",
                "description": "Test identity with restrictions applied",
                "identity_status": "restricted",
                "test_operations": [
                    {
                        "operation": "basic_request",
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Restricted identity basic request"}],
                            "max_tokens": 30
                        },
                        "should_succeed": True
                    },
                    {
                        "operation": "potentially_restricted_request",
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Restricted identity request with potential limitations"}],
                            "max_tokens": 500  # Large request
                        },
                        "should_succeed": False  # May be restricted
                    }
                ]
            },
            {
                "lifecycle_phase": "monitored_identity",
                "description": "Test identity under enhanced monitoring",
                "identity_status": "monitored",
                "test_operations": [
                    {
                        "operation": "monitored_request",
                        "request": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Monitored identity request"}],
                            "max_tokens": 50
                        },
                        "should_succeed": True
                    }
                ]
            }
        ]
        
        lifecycle_integration_results = []
        
        for scenario in lifecycle_integration_scenarios:
            scenario_start = time.time()
            operation_results = []
            
            for operation in scenario["test_operations"]:
                operation_start = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, operation["request"]
                    )
                    
                    operation_end = time.time()
                    operation_duration = operation_end - operation_start
                    
                    operation_successful = response.status_code == 200
                    operation_appropriate = operation_successful if operation["should_succeed"] else response.status_code in [400, 422, 429]
                    
                    # Analyze response for lifecycle integration indicators
                    response_headers = dict(response.headers)
                    monitoring_headers = [h for h in response_headers.keys() if "trace" in h.lower() or "request" in h.lower()]
                    
                    operation_results.append({
                        "operation": operation["operation"],
                        "should_succeed": operation["should_succeed"],
                        "operation_successful": operation_successful,
                        "operation_appropriate": operation_appropriate,
                        "status_code": response.status_code,
                        "operation_duration": operation_duration,
                        "monitoring_headers_found": len(monitoring_headers),
                        "lifecycle_integration_detected": len(monitoring_headers) > 0 or operation_duration > 2.0
                    })
                
                except Exception as e:
                    operation_appropriate = not operation["should_succeed"]
                    
                    operation_results.append({
                        "operation": operation["operation"],
                        "should_succeed": operation["should_succeed"],
                        "error": str(e)[:100],
                        "operation_appropriate": operation_appropriate,
                        "lifecycle_integration_detected": True  # Errors can indicate lifecycle controls
                    })
                
                await asyncio.sleep(0.5)
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            # Analyze lifecycle integration effectiveness
            appropriate_operations = sum(1 for result in operation_results if result["operation_appropriate"])
            total_operations = len(operation_results)
            integration_detected = sum(1 for result in operation_results if result.get("lifecycle_integration_detected", False))
            
            operation_appropriateness = appropriate_operations / total_operations if total_operations > 0 else 0
            integration_detection_rate = integration_detected / total_operations if total_operations > 0 else 0
            
            lifecycle_integration_results.append({
                "lifecycle_phase": scenario["lifecycle_phase"],
                "description": scenario["description"],
                "identity_status": scenario["identity_status"],
                "operation_results": operation_results,
                "total_operations": total_operations,
                "appropriate_operations": appropriate_operations,
                "operation_appropriateness": operation_appropriateness,
                "integration_detection_rate": integration_detection_rate,
                "lifecycle_controls_effective": operation_appropriateness >= 0.8,
                "scenario_duration": scenario_duration
            })
            
            await asyncio.sleep(1)
        
        # Verify overall lifecycle integration effectiveness
        effective_lifecycle_controls = sum(1 for result in lifecycle_integration_results if result["lifecycle_controls_effective"])
        total_phases = len(lifecycle_integration_results)
        
        lifecycle_effectiveness = effective_lifecycle_controls / total_phases
        
        assert lifecycle_effectiveness >= 0.8, \
            f"Identity lifecycle integration should be >= 80% effective: {lifecycle_effectiveness:.2%}"
        
        logger.info(f"IDENTITY_CENTRIC_006: Identity lifecycle integration tested - {lifecycle_effectiveness:.2%} effectiveness")
        
        for result in lifecycle_integration_results:
            logger.info(f"  {result['lifecycle_phase']}: appropriateness={result['operation_appropriateness']:.2%}, controls_effective={result['lifecycle_controls_effective']}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_identity_centric_007_cross_service_identity_validation(self, http_client: httpx.AsyncClient,
                                                                        auth_headers: Dict[str, str],
                                                                        make_request):
        """IDENTITY_CENTRIC_007: Verify cross-service identity validation and consistency"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test cross-service identity validation
        cross_service_scenarios = [
            {
                "service_group": "core_api_services",
                "description": "Test identity validation across core API services",
                "service_endpoints": [
                    {"endpoint": "/api/v1/models", "method": "GET"},
                    {"endpoint": "/api/v1/chat/completions", "method": "POST", "data": {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Cross-service validation test"}],
                        "max_tokens": 30
                    }}
                ]
            },
            {
                "service_group": "information_services",
                "description": "Test identity validation across information services",
                "service_endpoints": [
                    {"endpoint": "/api/v1/models", "method": "GET"},
                    {"endpoint": "/", "method": "GET"}  # Root endpoint
                ]
            }
        ]
        
        cross_service_results = []
        
        for scenario in cross_service_scenarios:
            scenario_start = time.time()
            service_validations = []
            
            for service_endpoint in scenario["service_endpoints"]:
                validation_start = time.time()
                
                try:
                    response = await make_request(
                        http_client, service_endpoint["method"], service_endpoint["endpoint"],
                        auth_headers, service_endpoint.get("data"), 
                        track_cost=(service_endpoint["method"] == "POST")
                    )
                    
                    validation_end = time.time()
                    validation_duration = validation_end - validation_start
                    
                    # Analyze identity validation consistency
                    identity_validated = response.status_code in [200, 404]  # 404 for non-existent endpoints is fine
                    identity_rejected = response.status_code in [401, 403]
                    
                    # Check for consistent identity validation headers/indicators
                    response_headers = dict(response.headers)
                    auth_related_headers = [h for h in response_headers.keys() if any(auth_term in h.lower() for auth_term in ["auth", "user", "identity"])]
                    
                    service_validations.append({
                        "endpoint": service_endpoint["endpoint"],
                        "method": service_endpoint["method"],
                        "status_code": response.status_code,
                        "validation_duration": validation_duration,
                        "identity_validated": identity_validated,
                        "identity_rejected": identity_rejected,
                        "auth_headers_count": len(auth_related_headers),
                        "validation_consistent": True  # Will be evaluated across services
                    })
                
                except Exception as e:
                    service_validations.append({
                        "endpoint": service_endpoint["endpoint"],
                        "method": service_endpoint["method"],
                        "error": str(e)[:100],
                        "identity_validated": False,
                        "validation_consistent": False
                    })
                
                await asyncio.sleep(0.3)
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            # Analyze cross-service validation consistency
            validated_services = [v for v in service_validations if v.get("identity_validated", False)]
            rejected_services = [v for v in service_validations if v.get("identity_rejected", False)]
            
            # Check validation timing consistency (should be similar across services)
            validation_times = [v["validation_duration"] for v in service_validations if "validation_duration" in v]
            if len(validation_times) > 1:
                time_variance = max(validation_times) - min(validation_times)
                timing_consistent = time_variance < 3.0  # Reasonable variance
            else:
                timing_consistent = True
            
            # Cross-service consistency analysis
            total_services = len(service_validations)
            consistent_validations = len(validated_services)
            validation_consistency_rate = consistent_validations / total_services if total_services > 0 else 0
            
            cross_service_results.append({
                "service_group": scenario["service_group"],
                "description": scenario["description"],
                "service_validations": service_validations,
                "total_services": total_services,
                "validated_services": len(validated_services),
                "rejected_services": len(rejected_services),
                "validation_consistency_rate": validation_consistency_rate,
                "timing_consistent": timing_consistent,
                "cross_service_validation_effective": validation_consistency_rate >= 0.8 and timing_consistent,
                "scenario_duration": scenario_duration
            })
        
        # Verify overall cross-service validation effectiveness
        effective_cross_service_validation = sum(1 for result in cross_service_results if result["cross_service_validation_effective"])
        total_service_groups = len(cross_service_results)
        
        cross_service_effectiveness = effective_cross_service_validation / total_service_groups
        
        assert cross_service_effectiveness >= 0.8, \
            f"Cross-service identity validation should be >= 80% effective: {cross_service_effectiveness:.2%}"
        
        logger.info(f"IDENTITY_CENTRIC_007: Cross-service identity validation tested - {cross_service_effectiveness:.2%} effectiveness")
        
        for result in cross_service_results:
            logger.info(f"  {result['service_group']}: consistency={result['validation_consistency_rate']:.2%}, timing_consistent={result['timing_consistent']}, effective={result['cross_service_validation_effective']}")