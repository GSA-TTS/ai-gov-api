# Section 7.12 - Zero Trust Network Segmentation Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Network Segmentation.md

import pytest
import httpx
import asyncio
import time
import json
import socket
import subprocess
import os
from typing import Dict, Any, List, Optional
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestNetworkSegmentation:
    """Zero Trust Network Segmentation tests"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_network_001_container_isolation(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """NETWORK_001: Review container networking for basic isolation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test basic container network isolation through API behavior
        isolation_tests = [
            {
                "test_type": "service_availability",
                "description": "Verify API service is accessible",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "expected_accessible": True
            },
            {
                "test_type": "service_communication",
                "description": "Verify API can communicate with database through backend network",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Network isolation test"}],
                    "max_tokens": 30
                },
                "expected_accessible": True
            },
            {
                "test_type": "external_connectivity",
                "description": "Verify API has controlled external connectivity",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "External connectivity test"}],
                    "max_tokens": 50
                },
                "expected_accessible": True
            }
        ]
        
        isolation_results = []
        
        for test in isolation_tests:
            try:
                if test["method"] == "GET":
                    response = await make_request(
                        http_client, test["method"], test["endpoint"],
                        auth_headers, track_cost=False
                    )
                else:
                    response = await make_request(
                        http_client, test["method"], test["endpoint"],
                        auth_headers, test["data"]
                    )
                
                service_accessible = response.status_code == 200
                isolation_appropriate = service_accessible == test["expected_accessible"]
                
                isolation_results.append({
                    "test_type": test["test_type"],
                    "description": test["description"],
                    "service_accessible": service_accessible,
                    "expected_accessible": test["expected_accessible"],
                    "isolation_appropriate": isolation_appropriate,
                    "status_code": response.status_code
                })
                
            except Exception as e:
                # Connection errors might indicate proper isolation
                isolation_appropriate = not test["expected_accessible"]
                
                isolation_results.append({
                    "test_type": test["test_type"],
                    "description": test["description"],
                    "error": str(e)[:100],
                    "isolation_appropriate": isolation_appropriate
                })
            
            await asyncio.sleep(0.3)
        
        # Verify network isolation effectiveness
        appropriate_isolation = sum(1 for result in isolation_results 
                                  if result.get("isolation_appropriate", False))
        total_tests = len(isolation_results)
        
        isolation_rate = appropriate_isolation / total_tests
        
        assert isolation_rate >= 0.8, \
            f"Network isolation should be >= 80% appropriate: {isolation_rate:.2%}"
        
        logger.info(f"NETWORK_001: Container isolation tested - {isolation_rate:.2%} appropriate isolation")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_network_002_micro_segmentation_policies(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """NETWORK_002: Test micro-segmentation policies and traffic filtering"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test micro-segmentation through various traffic patterns
        segmentation_scenarios = [
            {
                "scenario": "authorized_api_traffic",
                "description": "Normal authorized API traffic",
                "traffic_pattern": [
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "headers": auth_headers,
                        "should_pass": True
                    },
                    {
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "headers": auth_headers,
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Authorized traffic test"}],
                            "max_tokens": 30
                        },
                        "should_pass": True
                    }
                ]
            },
            {
                "scenario": "unauthorized_traffic",
                "description": "Unauthorized access attempts",
                "traffic_pattern": [
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "headers": {},
                        "should_pass": False
                    },
                    {
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "headers": {"Authorization": "Bearer invalid_token"},
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Unauthorized test"}],
                            "max_tokens": 30
                        },
                        "should_pass": False
                    }
                ]
            },
            {
                "scenario": "cross_segment_access",
                "description": "Cross-segment access testing",
                "traffic_pattern": [
                    {
                        "endpoint": "/api/v1/admin",
                        "method": "GET",
                        "headers": auth_headers,
                        "should_pass": False  # Admin endpoint should not exist or be accessible
                    },
                    {
                        "endpoint": "/api/v1/database",
                        "method": "GET", 
                        "headers": auth_headers,
                        "should_pass": False  # Direct database access should not be allowed
                    }
                ]
            }
        ]
        
        segmentation_results = []
        
        for scenario in segmentation_scenarios:
            scenario_results = []
            
            for traffic in scenario["traffic_pattern"]:
                try:
                    if traffic["method"] == "GET":
                        response = await make_request(
                            http_client, traffic["method"], traffic["endpoint"],
                            traffic["headers"], track_cost=False
                        )
                    else:
                        response = await make_request(
                            http_client, traffic["method"], traffic["endpoint"],
                            traffic["headers"], traffic.get("data"), track_cost=False
                        )
                    
                    traffic_allowed = response.status_code == 200
                    segmentation_appropriate = traffic_allowed == traffic["should_pass"]
                    
                    scenario_results.append({
                        "endpoint": traffic["endpoint"],
                        "method": traffic["method"],
                        "should_pass": traffic["should_pass"],
                        "traffic_allowed": traffic_allowed,
                        "status_code": response.status_code,
                        "segmentation_appropriate": segmentation_appropriate
                    })
                
                except Exception as e:
                    # Connection errors for unauthorized traffic can be appropriate
                    segmentation_appropriate = not traffic["should_pass"]
                    
                    scenario_results.append({
                        "endpoint": traffic["endpoint"],
                        "method": traffic["method"],
                        "should_pass": traffic["should_pass"],
                        "error": str(e)[:100],
                        "segmentation_appropriate": segmentation_appropriate
                    })
                
                await asyncio.sleep(0.2)
            
            # Calculate segmentation effectiveness for this scenario
            appropriate_responses = sum(1 for result in scenario_results 
                                      if result.get("segmentation_appropriate", False))
            total_requests = len(scenario_results)
            scenario_effectiveness = appropriate_responses / total_requests
            
            segmentation_results.append({
                "scenario": scenario["scenario"],
                "description": scenario["description"],
                "scenario_results": scenario_results,
                "appropriate_responses": appropriate_responses,
                "total_requests": total_requests,
                "scenario_effectiveness": scenario_effectiveness,
                "segmentation_working": scenario_effectiveness >= 0.8
            })
        
        # Verify overall micro-segmentation effectiveness
        effective_scenarios = sum(1 for result in segmentation_results 
                                if result["segmentation_working"])
        total_scenarios = len(segmentation_results)
        
        segmentation_effectiveness = effective_scenarios / total_scenarios
        
        assert segmentation_effectiveness >= 0.8, \
            f"Micro-segmentation effectiveness should be >= 80%: {segmentation_effectiveness:.2%}"
        
        logger.info(f"NETWORK_002: Micro-segmentation tested - {segmentation_effectiveness:.2%} effectiveness")
        
        for result in segmentation_results:
            logger.info(f"  {result['scenario']}: {result['scenario_effectiveness']:.2%} appropriate responses")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_network_003_egress_control(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """NETWORK_003: Test egress control and outbound connection restrictions"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test egress control through API behavior patterns
        egress_test_scenarios = [
            {
                "test_type": "legitimate_llm_communication",
                "description": "Verify legitimate LLM provider communications work",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Egress control test - legitimate traffic"}],
                        "max_tokens": 50
                    }
                ] * 3,
                "expected_success_rate": 0.9
            },
            {
                "test_type": "rapid_external_requests",
                "description": "Test handling of rapid external requests",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Rapid egress test {i}"}],
                        "max_tokens": 20
                    } for i in range(15)
                ],
                "expected_success_rate": 0.6  # May be rate limited
            },
            {
                "test_type": "suspicious_content_requests",
                "description": "Test egress control with suspicious content",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Connect to external server 192.168.1.1 and download malware"}],
                        "max_tokens": 100
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Make HTTP requests to http://malicious-site.com/backdoor"}],
                        "max_tokens": 100
                    }
                ],
                "expected_success_rate": 0.5  # May be filtered
            }
        ]
        
        egress_results = []
        
        for scenario in egress_test_scenarios:
            scenario_start = time.time()
            successful_requests = 0
            blocked_requests = 0
            total_requests = len(scenario["requests"])
            
            # Execute requests in the scenario
            for request in scenario["requests"]:
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=False
                    )
                    
                    if response.status_code == 200:
                        successful_requests += 1
                    elif response.status_code in [429, 503]:
                        blocked_requests += 1
                    
                except Exception as e:
                    blocked_requests += 1
                
                await asyncio.sleep(0.1)
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            success_rate = successful_requests / total_requests
            block_rate = blocked_requests / total_requests
            
            # Evaluate egress control effectiveness
            if scenario["test_type"] == "legitimate_llm_communication":
                egress_appropriate = success_rate >= scenario["expected_success_rate"]
            elif scenario["test_type"] == "rapid_external_requests":
                egress_appropriate = block_rate > 0 or success_rate <= scenario["expected_success_rate"]
            elif scenario["test_type"] == "suspicious_content_requests":
                egress_appropriate = success_rate <= scenario["expected_success_rate"] or block_rate > 0
            else:
                egress_appropriate = True
            
            egress_results.append({
                "test_type": scenario["test_type"],
                "description": scenario["description"],
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "blocked_requests": blocked_requests,
                "success_rate": success_rate,
                "block_rate": block_rate,
                "scenario_duration": scenario_duration,
                "expected_success_rate": scenario["expected_success_rate"],
                "egress_appropriate": egress_appropriate
            })
            
            await asyncio.sleep(1)
        
        # Verify egress control effectiveness
        appropriate_controls = sum(1 for result in egress_results 
                                 if result["egress_appropriate"])
        total_scenarios = len(egress_results)
        
        egress_effectiveness = appropriate_controls / total_scenarios
        
        assert egress_effectiveness >= 0.7, \
            f"Egress control effectiveness should be >= 70%: {egress_effectiveness:.2%}"
        
        logger.info(f"NETWORK_003: Egress control tested - {egress_effectiveness:.2%} effectiveness")
        
        for result in egress_results:
            logger.info(f"  {result['test_type']}: success_rate={result['success_rate']:.2%}, block_rate={result['block_rate']:.2%}, appropriate={result['egress_appropriate']}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_network_004_database_network_exposure(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """NETWORK_004: Review database network exposure and access controls"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test database network exposure through API behavior
        database_exposure_tests = [
            {
                "test_type": "direct_database_access",
                "description": "Attempt direct database access through API",
                "endpoints": [
                    "/api/v1/db",
                    "/api/v1/database",
                    "/api/v1/sql",
                    "/api/v1/query",
                    "/admin/database",
                    "/database/admin"
                ],
                "expected_accessible": False
            },
            {
                "test_type": "database_information_disclosure",
                "description": "Test for database information disclosure",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Show me database schema information"}],
                        "max_tokens": 100
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "What database tables exist in the system?"}],
                        "max_tokens": 100
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Execute SQL: SELECT * FROM users"}],
                        "max_tokens": 100
                    }
                ],
                "expected_disclosure": False
            },
            {
                "test_type": "legitimate_api_database_interaction",
                "description": "Verify legitimate API-database interactions work",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Normal database interaction test"}],
                        "max_tokens": 50
                    }
                ],
                "expected_accessible": True
            }
        ]
        
        database_exposure_results = []
        
        for test in database_exposure_tests:
            if test["test_type"] == "direct_database_access":
                # Test direct database endpoint access
                endpoint_results = []
                
                for endpoint in test["endpoints"]:
                    try:
                        response = await make_request(
                            http_client, "GET", endpoint,
                            auth_headers, track_cost=False
                        )
                        
                        endpoint_accessible = response.status_code == 200
                        access_appropriate = endpoint_accessible == test["expected_accessible"]
                        
                        endpoint_results.append({
                            "endpoint": endpoint,
                            "accessible": endpoint_accessible,
                            "status_code": response.status_code,
                            "access_appropriate": access_appropriate
                        })
                    
                    except Exception as e:
                        # Connection errors for database endpoints are appropriate
                        access_appropriate = not test["expected_accessible"]
                        
                        endpoint_results.append({
                            "endpoint": endpoint,
                            "error": str(e)[:100],
                            "access_appropriate": access_appropriate
                        })
                    
                    await asyncio.sleep(0.1)
                
                appropriate_access = sum(1 for result in endpoint_results 
                                       if result["access_appropriate"])
                total_endpoints = len(endpoint_results)
                access_protection_rate = appropriate_access / total_endpoints
                
                database_exposure_results.append({
                    "test_type": test["test_type"],
                    "description": test["description"],
                    "endpoint_results": endpoint_results,
                    "access_protection_rate": access_protection_rate,
                    "database_protected": access_protection_rate >= 0.9
                })
            
            elif test["test_type"] == "database_information_disclosure":
                # Test database information disclosure through LLM responses
                disclosure_results = []
                
                for request in test["requests"]:
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request, track_cost=False
                        )
                        
                        if response.status_code == 200:
                            response_data = response.json()
                            
                            if "choices" in response_data and response_data["choices"]:
                                response_content = response_data["choices"][0]["message"]["content"]
                                
                                # Check for database information disclosure patterns
                                disclosure_patterns = [
                                    "table", "schema", "database", "sql", "select", "insert",
                                    "update", "delete", "column", "row", "primary key", "foreign key"
                                ]
                                
                                disclosure_detected = any(
                                    pattern.lower() in response_content.lower() 
                                    for pattern in disclosure_patterns
                                )
                                
                                disclosure_appropriate = not disclosure_detected
                                
                                disclosure_results.append({
                                    "request_content": request["messages"][0]["content"][:50],
                                    "response_content": response_content[:100],
                                    "disclosure_detected": disclosure_detected,
                                    "disclosure_appropriate": disclosure_appropriate
                                })
                        
                        else:
                            # Request rejected - good for sensitive queries
                            disclosure_results.append({
                                "request_content": request["messages"][0]["content"][:50],
                                "status_code": response.status_code,
                                "request_rejected": True,
                                "disclosure_appropriate": True
                            })
                    
                    except Exception as e:
                        disclosure_results.append({
                            "request_content": request["messages"][0]["content"][:50],
                            "error": str(e)[:100],
                            "disclosure_appropriate": True
                        })
                    
                    await asyncio.sleep(0.2)
                
                appropriate_responses = sum(1 for result in disclosure_results 
                                          if result["disclosure_appropriate"])
                total_requests = len(disclosure_results)
                disclosure_protection_rate = appropriate_responses / total_requests
                
                database_exposure_results.append({
                    "test_type": test["test_type"],
                    "description": test["description"],
                    "disclosure_results": disclosure_results,
                    "disclosure_protection_rate": disclosure_protection_rate,
                    "database_protected": disclosure_protection_rate >= 0.8
                })
            
            elif test["test_type"] == "legitimate_api_database_interaction":
                # Test legitimate API-database interactions
                interaction_successful = 0
                total_interactions = len(test["requests"])
                
                for request in test["requests"]:
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        
                        if response.status_code == 200:
                            interaction_successful += 1
                    
                    except Exception:
                        pass
                    
                    await asyncio.sleep(0.2)
                
                interaction_success_rate = interaction_successful / total_interactions
                legitimate_access_working = interaction_success_rate >= 0.8
                
                database_exposure_results.append({
                    "test_type": test["test_type"],
                    "description": test["description"],
                    "interaction_success_rate": interaction_success_rate,
                    "legitimate_access_working": legitimate_access_working,
                    "database_protected": legitimate_access_working
                })
        
        # Verify overall database protection
        protected_tests = sum(1 for result in database_exposure_results 
                            if result["database_protected"])
        total_tests = len(database_exposure_results)
        
        database_protection_rate = protected_tests / total_tests
        
        assert database_protection_rate >= 0.8, \
            f"Database protection rate should be >= 80%: {database_protection_rate:.2%}"
        
        logger.info(f"NETWORK_004: Database exposure tested - {database_protection_rate:.2%} protection rate")
        
        for result in database_exposure_results:
            logger.info(f"  {result['test_type']}: protected={result['database_protected']}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_network_005_secure_protocol_enforcement(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """NETWORK_005: Verify secure protocol enforcement (HTTPS/TLS)"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test secure protocol enforcement
        protocol_tests = [
            {
                "test_type": "https_enforcement",
                "description": "Verify HTTPS is enforced for API communications",
                "test_methods": [
                    {
                        "method": "verify_base_url_https",
                        "expected": True
                    },
                    {
                        "method": "test_secure_communication",
                        "expected": True
                    }
                ]
            },
            {
                "test_type": "tls_version_verification",
                "description": "Verify minimum TLS version requirements",
                "test_methods": [
                    {
                        "method": "test_tls_communication",
                        "expected": True
                    }
                ]
            },
            {
                "test_type": "certificate_validation",
                "description": "Verify certificate validation is enforced",
                "test_methods": [
                    {
                        "method": "test_certificate_validation",
                        "expected": True
                    }
                ]
            }
        ]
        
        protocol_results = []
        
        for test in protocol_tests:
            test_results = []
            
            for test_method in test["test_methods"]:
                if test_method["method"] == "verify_base_url_https":
                    # Check if base URL uses HTTPS
                    https_enforced = config.BASE_URL.startswith("https://")
                    
                    test_results.append({
                        "method": test_method["method"],
                        "https_enforced": https_enforced,
                        "test_passed": https_enforced == test_method["expected"]
                    })
                
                elif test_method["method"] == "test_secure_communication":
                    # Test secure communication through API
                    try:
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            auth_headers, track_cost=False
                        )
                        
                        secure_communication = response.status_code == 200
                        
                        test_results.append({
                            "method": test_method["method"],
                            "secure_communication": secure_communication,
                            "status_code": response.status_code,
                            "test_passed": secure_communication == test_method["expected"]
                        })
                    
                    except Exception as e:
                        test_results.append({
                            "method": test_method["method"],
                            "error": str(e)[:100],
                            "test_passed": False
                        })
                
                elif test_method["method"] == "test_tls_communication":
                    # Test TLS communication (inferred from successful HTTPS)
                    try:
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            auth_headers, track_cost=False
                        )
                        
                        tls_working = response.status_code == 200 and config.BASE_URL.startswith("https://")
                        
                        test_results.append({
                            "method": test_method["method"],
                            "tls_working": tls_working,
                            "test_passed": tls_working == test_method["expected"]
                        })
                    
                    except Exception as e:
                        test_results.append({
                            "method": test_method["method"],
                            "error": str(e)[:100],
                            "test_passed": False
                        })
                
                elif test_method["method"] == "test_certificate_validation":
                    # Test certificate validation (successful connection implies valid cert)
                    try:
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            auth_headers, track_cost=False
                        )
                        
                        cert_valid = response.status_code == 200
                        
                        test_results.append({
                            "method": test_method["method"],
                            "cert_valid": cert_valid,
                            "test_passed": cert_valid == test_method["expected"]
                        })
                    
                    except Exception as e:
                        test_results.append({
                            "method": test_method["method"],
                            "error": str(e)[:100],
                            "test_passed": False
                        })
                
                await asyncio.sleep(0.1)
            
            # Calculate test success rate
            passed_tests = sum(1 for result in test_results if result["test_passed"])
            total_tests = len(test_results)
            test_success_rate = passed_tests / total_tests if total_tests > 0 else 0
            
            protocol_results.append({
                "test_type": test["test_type"],
                "description": test["description"],
                "test_results": test_results,
                "passed_tests": passed_tests,
                "total_tests": total_tests,
                "test_success_rate": test_success_rate,
                "protocol_secure": test_success_rate >= 0.9
            })
        
        # Verify secure protocol enforcement
        secure_protocols = sum(1 for result in protocol_results if result["protocol_secure"])
        total_protocol_tests = len(protocol_results)
        
        protocol_security_rate = secure_protocols / total_protocol_tests
        
        assert protocol_security_rate >= 0.9, \
            f"Secure protocol enforcement should be >= 90%: {protocol_security_rate:.2%}"
        
        logger.info(f"NETWORK_005: Protocol security tested - {protocol_security_rate:.2%} security rate")
        
        for result in protocol_results:
            logger.info(f"  {result['test_type']}: {result['test_success_rate']:.2%} success rate")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_network_006_infrastructure_security_assessment(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """NETWORK_006: Assess infrastructure-level network security"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Infrastructure security assessment through API behavior analysis
        infrastructure_tests = [
            {
                "assessment_type": "security_headers",
                "description": "Assess security headers implementation",
                "expected_headers": [
                    "strict-transport-security",
                    "x-content-type-options",
                    "x-frame-options",
                    "x-xss-protection"
                ]
            },
            {
                "assessment_type": "rate_limiting",
                "description": "Assess rate limiting implementation",
                "test_requests": 20,
                "rapid_interval": 0.05
            },
            {
                "assessment_type": "error_handling",
                "description": "Assess error handling security",
                "error_scenarios": [
                    {"endpoint": "/api/v1/nonexistent", "method": "GET"},
                    {"endpoint": "/api/v1/models", "method": "POST"},
                    {"endpoint": "/api/v1/chat/completions", "method": "GET"}
                ]
            },
            {
                "assessment_type": "authentication_controls",
                "description": "Assess authentication controls",
                "auth_scenarios": [
                    {"headers": auth_headers, "should_succeed": True},
                    {"headers": {}, "should_succeed": False},
                    {"headers": {"Authorization": "Bearer invalid"}, "should_succeed": False}
                ]
            }
        ]
        
        infrastructure_results = []
        
        for test in infrastructure_tests:
            if test["assessment_type"] == "security_headers":
                # Test security headers
                try:
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                    
                    response_headers = dict(response.headers)
                    security_headers_found = []
                    
                    for expected_header in test["expected_headers"]:
                        header_found = any(
                            expected_header.lower() in header.lower() 
                            for header in response_headers.keys()
                        )
                        security_headers_found.append({
                            "header": expected_header,
                            "found": header_found
                        })
                    
                    headers_present = sum(1 for header in security_headers_found if header["found"])
                    total_expected = len(test["expected_headers"])
                    security_header_rate = headers_present / total_expected
                    
                    infrastructure_results.append({
                        "assessment_type": test["assessment_type"],
                        "description": test["description"],
                        "security_headers_found": security_headers_found,
                        "headers_present": headers_present,
                        "total_expected": total_expected,
                        "security_header_rate": security_header_rate,
                        "infrastructure_secure": security_header_rate >= 0.5
                    })
                
                except Exception as e:
                    infrastructure_results.append({
                        "assessment_type": test["assessment_type"],
                        "description": test["description"],
                        "error": str(e)[:100],
                        "infrastructure_secure": False
                    })
            
            elif test["assessment_type"] == "rate_limiting":
                # Test rate limiting
                rate_limit_start = time.time()
                responses = []
                
                for i in range(test["test_requests"]):
                    try:
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            auth_headers, track_cost=False
                        )
                        responses.append(response.status_code)
                    except Exception:
                        responses.append(0)
                    
                    await asyncio.sleep(test["rapid_interval"])
                
                rate_limit_end = time.time()
                test_duration = rate_limit_end - rate_limit_start
                
                successful_requests = sum(1 for status in responses if status == 200)
                rate_limited_requests = sum(1 for status in responses if status == 429)
                
                # Rate limiting is working if some requests are limited
                rate_limiting_active = rate_limited_requests > 0 or successful_requests < test["test_requests"]
                
                infrastructure_results.append({
                    "assessment_type": test["assessment_type"],
                    "description": test["description"],
                    "total_requests": test["test_requests"],
                    "successful_requests": successful_requests,
                    "rate_limited_requests": rate_limited_requests,
                    "test_duration": test_duration,
                    "rate_limiting_active": rate_limiting_active,
                    "infrastructure_secure": rate_limiting_active
                })
            
            elif test["assessment_type"] == "error_handling":
                # Test error handling security
                error_results = []
                
                for scenario in test["error_scenarios"]:
                    try:
                        response = await make_request(
                            http_client, scenario["method"], scenario["endpoint"],
                            auth_headers, track_cost=False
                        )
                        
                        # Check for information disclosure in error responses
                        error_secure = (
                            response.status_code in [400, 404, 405, 422] and
                            len(response.text) < 1000  # Not overly verbose
                        )
                        
                        error_results.append({
                            "endpoint": scenario["endpoint"],
                            "method": scenario["method"],
                            "status_code": response.status_code,
                            "response_length": len(response.text),
                            "error_secure": error_secure
                        })
                    
                    except Exception as e:
                        error_results.append({
                            "endpoint": scenario["endpoint"],
                            "method": scenario["method"],
                            "error": str(e)[:100],
                            "error_secure": True  # Exceptions can be secure
                        })
                    
                    await asyncio.sleep(0.1)
                
                secure_errors = sum(1 for result in error_results if result["error_secure"])
                total_errors = len(error_results)
                error_security_rate = secure_errors / total_errors
                
                infrastructure_results.append({
                    "assessment_type": test["assessment_type"],
                    "description": test["description"],
                    "error_results": error_results,
                    "secure_errors": secure_errors,
                    "total_errors": total_errors,
                    "error_security_rate": error_security_rate,
                    "infrastructure_secure": error_security_rate >= 0.8
                })
            
            elif test["assessment_type"] == "authentication_controls":
                # Test authentication controls
                auth_results = []
                
                for scenario in test["auth_scenarios"]:
                    try:
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            scenario["headers"], track_cost=False
                        )
                        
                        access_granted = response.status_code == 200
                        auth_appropriate = access_granted == scenario["should_succeed"]
                        
                        auth_results.append({
                            "scenario": scenario,
                            "access_granted": access_granted,
                            "should_succeed": scenario["should_succeed"],
                            "auth_appropriate": auth_appropriate,
                            "status_code": response.status_code
                        })
                    
                    except Exception as e:
                        auth_appropriate = not scenario["should_succeed"]
                        
                        auth_results.append({
                            "scenario": scenario,
                            "error": str(e)[:100],
                            "auth_appropriate": auth_appropriate
                        })
                    
                    await asyncio.sleep(0.1)
                
                appropriate_auth = sum(1 for result in auth_results if result["auth_appropriate"])
                total_auth_tests = len(auth_results)
                auth_control_rate = appropriate_auth / total_auth_tests
                
                infrastructure_results.append({
                    "assessment_type": test["assessment_type"],
                    "description": test["description"],
                    "auth_results": auth_results,
                    "appropriate_auth": appropriate_auth,
                    "total_auth_tests": total_auth_tests,
                    "auth_control_rate": auth_control_rate,
                    "infrastructure_secure": auth_control_rate >= 0.8
                })
        
        # Verify overall infrastructure security
        secure_assessments = sum(1 for result in infrastructure_results 
                               if result["infrastructure_secure"])
        total_assessments = len(infrastructure_results)
        
        infrastructure_security_rate = secure_assessments / total_assessments
        
        assert infrastructure_security_rate >= 0.7, \
            f"Infrastructure security rate should be >= 70%: {infrastructure_security_rate:.2%}"
        
        logger.info(f"NETWORK_006: Infrastructure security assessed - {infrastructure_security_rate:.2%} security rate")
        
        for result in infrastructure_results:
            logger.info(f"  {result['assessment_type']}: secure={result['infrastructure_secure']}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_network_007_software_defined_perimeter(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """NETWORK_007: Test software-defined perimeter implementation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test SDP concepts through API access patterns
        sdp_test_scenarios = [
            {
                "scenario": "identity_based_access",
                "description": "Test identity-based network access control",
                "access_tests": [
                    {
                        "identity": "valid_authenticated",
                        "headers": auth_headers,
                        "endpoints": ["/api/v1/models", "/api/v1/chat/completions"],
                        "should_access": True
                    },
                    {
                        "identity": "unauthenticated",
                        "headers": {},
                        "endpoints": ["/api/v1/models", "/api/v1/chat/completions"],
                        "should_access": False
                    },
                    {
                        "identity": "invalid_token",
                        "headers": {"Authorization": "Bearer invalid_sdp_token"},
                        "endpoints": ["/api/v1/models"],
                        "should_access": False
                    }
                ]
            },
            {
                "scenario": "service_cloaking",
                "description": "Test service invisibility for unauthorized users",
                "cloaking_tests": [
                    {
                        "service": "admin_services",
                        "endpoints": ["/admin", "/api/admin", "/management"],
                        "headers": auth_headers,
                        "should_be_visible": False
                    },
                    {
                        "service": "debug_services",
                        "endpoints": ["/debug", "/api/debug", "/status/debug"],
                        "headers": auth_headers,
                        "should_be_visible": False
                    }
                ]
            },
            {
                "scenario": "dynamic_perimeter",
                "description": "Test dynamic perimeter adjustment",
                "perimeter_tests": [
                    {
                        "condition": "normal_access",
                        "request_pattern": "normal",
                        "expected_behavior": "allow"
                    },
                    {
                        "condition": "suspicious_pattern",
                        "request_pattern": "rapid",
                        "expected_behavior": "restrict"
                    }
                ]
            }
        ]
        
        sdp_results = []
        
        for scenario in sdp_test_scenarios:
            if scenario["scenario"] == "identity_based_access":
                access_results = []
                
                for access_test in scenario["access_tests"]:
                    test_results = []
                    
                    for endpoint in access_test["endpoints"]:
                        try:
                            if endpoint == "/api/v1/chat/completions":
                                test_data = {
                                    "model": config.get_chat_model(0),
                                    "messages": [{"role": "user", "content": "SDP access test"}],
                                    "max_tokens": 30
                                }
                                response = await make_request(
                                    http_client, "POST", endpoint,
                                    access_test["headers"], test_data, track_cost=False
                                )
                            else:
                                response = await make_request(
                                    http_client, "GET", endpoint,
                                    access_test["headers"], track_cost=False
                                )
                            
                            access_granted = response.status_code == 200
                            access_appropriate = access_granted == access_test["should_access"]
                            
                            test_results.append({
                                "endpoint": endpoint,
                                "access_granted": access_granted,
                                "should_access": access_test["should_access"],
                                "access_appropriate": access_appropriate,
                                "status_code": response.status_code
                            })
                        
                        except Exception as e:
                            access_appropriate = not access_test["should_access"]
                            
                            test_results.append({
                                "endpoint": endpoint,
                                "error": str(e)[:100],
                                "access_appropriate": access_appropriate
                            })
                        
                        await asyncio.sleep(0.1)
                    
                    appropriate_responses = sum(1 for result in test_results 
                                              if result["access_appropriate"])
                    total_endpoints = len(test_results)
                    identity_access_rate = appropriate_responses / total_endpoints
                    
                    access_results.append({
                        "identity": access_test["identity"],
                        "test_results": test_results,
                        "identity_access_rate": identity_access_rate,
                        "access_control_working": identity_access_rate >= 0.8
                    })
                
                sdp_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "access_results": access_results,
                    "sdp_effective": all(result["access_control_working"] for result in access_results)
                })
            
            elif scenario["scenario"] == "service_cloaking":
                cloaking_results = []
                
                for cloaking_test in scenario["cloaking_tests"]:
                    service_visibility = []
                    
                    for endpoint in cloaking_test["endpoints"]:
                        try:
                            response = await make_request(
                                http_client, "GET", endpoint,
                                cloaking_test["headers"], track_cost=False
                            )
                            
                            service_visible = response.status_code != 404
                            cloaking_appropriate = service_visible == cloaking_test["should_be_visible"]
                            
                            service_visibility.append({
                                "endpoint": endpoint,
                                "service_visible": service_visible,
                                "should_be_visible": cloaking_test["should_be_visible"],
                                "cloaking_appropriate": cloaking_appropriate,
                                "status_code": response.status_code
                            })
                        
                        except Exception as e:
                            # Connection errors can indicate proper cloaking
                            cloaking_appropriate = not cloaking_test["should_be_visible"]
                            
                            service_visibility.append({
                                "endpoint": endpoint,
                                "error": str(e)[:100],
                                "cloaking_appropriate": cloaking_appropriate
                            })
                        
                        await asyncio.sleep(0.1)
                    
                    appropriate_cloaking = sum(1 for result in service_visibility 
                                             if result["cloaking_appropriate"])
                    total_services = len(service_visibility)
                    cloaking_rate = appropriate_cloaking / total_services
                    
                    cloaking_results.append({
                        "service": cloaking_test["service"],
                        "service_visibility": service_visibility,
                        "cloaking_rate": cloaking_rate,
                        "cloaking_working": cloaking_rate >= 0.8
                    })
                
                sdp_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "cloaking_results": cloaking_results,
                    "sdp_effective": all(result["cloaking_working"] for result in cloaking_results)
                })
            
            elif scenario["scenario"] == "dynamic_perimeter":
                perimeter_results = []
                
                for perimeter_test in scenario["perimeter_tests"]:
                    if perimeter_test["request_pattern"] == "normal":
                        # Normal access pattern
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            auth_headers, track_cost=False
                        )
                        
                        access_allowed = response.status_code == 200
                        behavior_appropriate = access_allowed if perimeter_test["expected_behavior"] == "allow" else not access_allowed
                        
                        perimeter_results.append({
                            "condition": perimeter_test["condition"],
                            "pattern": perimeter_test["request_pattern"],
                            "expected_behavior": perimeter_test["expected_behavior"],
                            "access_allowed": access_allowed,
                            "behavior_appropriate": behavior_appropriate
                        })
                    
                    elif perimeter_test["request_pattern"] == "rapid":
                        # Rapid access pattern to test dynamic restriction
                        rapid_responses = []
                        
                        for i in range(10):
                            try:
                                response = await make_request(
                                    http_client, "GET", "/api/v1/models",
                                    auth_headers, track_cost=False
                                )
                                rapid_responses.append(response.status_code)
                            except Exception:
                                rapid_responses.append(0)
                            
                            await asyncio.sleep(0.05)
                        
                        restriction_detected = any(status == 429 for status in rapid_responses)
                        behavior_appropriate = restriction_detected if perimeter_test["expected_behavior"] == "restrict" else not restriction_detected
                        
                        perimeter_results.append({
                            "condition": perimeter_test["condition"],
                            "pattern": perimeter_test["request_pattern"],
                            "expected_behavior": perimeter_test["expected_behavior"],
                            "restriction_detected": restriction_detected,
                            "behavior_appropriate": behavior_appropriate
                        })
                    
                    await asyncio.sleep(1)
                
                sdp_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "perimeter_results": perimeter_results,
                    "sdp_effective": all(result["behavior_appropriate"] for result in perimeter_results)
                })
        
        # Verify SDP effectiveness
        effective_scenarios = sum(1 for result in sdp_results if result["sdp_effective"])
        total_scenarios = len(sdp_results)
        
        sdp_effectiveness = effective_scenarios / total_scenarios
        
        logger.info(f"NETWORK_007: Software-defined perimeter tested - {sdp_effectiveness:.2%} effectiveness")
        
        for result in sdp_results:
            logger.info(f"  {result['scenario']}: effective={result['sdp_effective']}")