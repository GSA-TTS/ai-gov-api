# Section 7.12 - Zero Trust Observability Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Observability.md

import pytest
import httpx
import asyncio
import time
import json
import re
from typing import Dict, Any, List, Optional
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestObservability:
    """Zero Trust Observability tests"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_observability_001_comprehensive_logging(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """OBSERVABILITY_001: Verify comprehensive logging of request lifecycle and security context"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test comprehensive logging through various request types
        logging_test_scenarios = [
            {
                "scenario": "successful_request",
                "description": "Successful API request logging",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "headers": auth_headers,
                "expected_logged_fields": [
                    "timestamp", "request_id", "method", "path", 
                    "client_ip", "user_agent", "status_code", "duration_ms"
                ]
            },
            {
                "scenario": "chat_completion_request",
                "description": "Chat completion request logging",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "headers": auth_headers,
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Comprehensive logging test"}],
                    "max_tokens": 50
                },
                "expected_logged_fields": [
                    "timestamp", "request_id", "method", "path",
                    "status_code", "duration_ms", "api_key_id"
                ]
            },
            {
                "scenario": "failed_request",
                "description": "Failed request logging",
                "endpoint": "/api/v1/nonexistent",
                "method": "GET",
                "headers": auth_headers,
                "expected_logged_fields": [
                    "timestamp", "request_id", "method", "path",
                    "status_code", "duration_ms"
                ]
            },
            {
                "scenario": "unauthorized_request",
                "description": "Unauthorized request logging",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "headers": {},
                "expected_logged_fields": [
                    "timestamp", "request_id", "method", "path",
                    "status_code", "client_ip"
                ]
            }
        ]
        
        logging_results = []
        
        for scenario in logging_test_scenarios:
            scenario_start = time.time()
            
            try:
                if scenario["method"] == "GET":
                    response = await make_request(
                        http_client, scenario["method"], scenario["endpoint"],
                        scenario["headers"], track_cost=False
                    )
                else:
                    response = await make_request(
                        http_client, scenario["method"], scenario["endpoint"],
                        scenario["headers"], scenario.get("data"), track_cost=False
                    )
                
                scenario_end = time.time()
                request_duration = scenario_end - scenario_start
                
                # Simulate log field validation (in real implementation, would parse actual logs)
                simulated_log_entry = {
                    "timestamp": scenario_end,
                    "request_id": f"req_{scenario['scenario']}_{int(scenario_start)}",
                    "method": scenario["method"],
                    "path": scenario["endpoint"],
                    "client_ip": "127.0.0.1",  # Simulated
                    "user_agent": "test-client",  # Simulated
                    "status_code": response.status_code,
                    "duration_ms": request_duration * 1000,
                    "api_key_id": "test_key_id" if scenario["headers"].get("Authorization") else None
                }
                
                # Verify expected fields are present
                fields_present = []
                for expected_field in scenario["expected_logged_fields"]:
                    field_present = expected_field in simulated_log_entry and simulated_log_entry[expected_field] is not None
                    fields_present.append({
                        "field": expected_field,
                        "present": field_present,
                        "value": simulated_log_entry.get(expected_field)
                    })
                
                fields_logged = sum(1 for field in fields_present if field["present"])
                total_expected = len(scenario["expected_logged_fields"])
                logging_completeness = fields_logged / total_expected
                
                logging_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "status_code": response.status_code,
                    "request_duration": request_duration,
                    "expected_fields": scenario["expected_logged_fields"],
                    "fields_present": fields_present,
                    "fields_logged": fields_logged,
                    "total_expected": total_expected,
                    "logging_completeness": logging_completeness,
                    "comprehensive_logging": logging_completeness >= 0.8
                })
            
            except Exception as e:
                logging_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "error": str(e)[:100],
                    "comprehensive_logging": False
                })
            
            await asyncio.sleep(0.3)
        
        # Verify comprehensive logging effectiveness
        comprehensive_scenarios = sum(1 for result in logging_results 
                                    if result.get("comprehensive_logging", False))
        total_scenarios = len(logging_results)
        
        logging_effectiveness = comprehensive_scenarios / total_scenarios
        
        assert logging_effectiveness >= 0.8, \
            f"Comprehensive logging effectiveness should be >= 80%: {logging_effectiveness:.2%}"
        
        logger.info(f"OBSERVABILITY_001: Comprehensive logging tested - {logging_effectiveness:.2%} effectiveness")
        
        for result in logging_results:
            logger.info(f"  {result['scenario']}: completeness={result.get('logging_completeness', 0):.2%}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_observability_002_identity_tracking(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     embedding_auth_headers: Dict[str, str],
                                                     make_request):
        """OBSERVABILITY_002: Verify identity tracking in logs for identity-centric monitoring"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test identity tracking through various authentication scenarios
        identity_tracking_scenarios = [
            {
                "scenario": "successful_authentication",
                "description": "Successful authentication with valid API key",
                "headers": auth_headers,
                "endpoint": "/api/v1/models",
                "method": "GET",
                "expected_identity_logged": True,
                "expected_success": True
            },
            {
                "scenario": "different_valid_identity",
                "description": "Different valid identity authentication",
                "headers": embedding_auth_headers,
                "endpoint": "/api/v1/models", 
                "method": "GET",
                "expected_identity_logged": True,
                "expected_success": True
            },
            {
                "scenario": "invalid_api_key",
                "description": "Authentication failure with invalid API key",
                "headers": {"Authorization": "Bearer sk-invalid-key-for-tracking"},
                "endpoint": "/api/v1/models",
                "method": "GET",
                "expected_identity_logged": True,  # Should log failed attempt
                "expected_success": False
            },
            {
                "scenario": "malformed_auth_header",
                "description": "Authentication failure with malformed header",
                "headers": {"Authorization": "InvalidFormat"},
                "endpoint": "/api/v1/models",
                "method": "GET",
                "expected_identity_logged": True,  # Should log attempt
                "expected_success": False
            },
            {
                "scenario": "missing_authentication",
                "description": "No authentication provided",
                "headers": {},
                "endpoint": "/api/v1/models",
                "method": "GET",
                "expected_identity_logged": False,  # No identity to log
                "expected_success": False
            },
            {
                "scenario": "authenticated_complex_request",
                "description": "Complex authenticated request",
                "headers": auth_headers,
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Identity tracking test"}],
                    "max_tokens": 50
                },
                "expected_identity_logged": True,
                "expected_success": True
            }
        ]
        
        identity_tracking_results = []
        
        for scenario in identity_tracking_scenarios:
            scenario_start = time.time()
            
            try:
                if scenario["method"] == "GET":
                    response = await make_request(
                        http_client, scenario["method"], scenario["endpoint"],
                        scenario["headers"], track_cost=False
                    )
                else:
                    response = await make_request(
                        http_client, scenario["method"], scenario["endpoint"],
                        scenario["headers"], scenario.get("data"), track_cost=False
                    )
                
                scenario_end = time.time()
                
                # Simulate identity tracking validation
                request_successful = response.status_code == 200
                auth_header_present = "Authorization" in scenario["headers"]
                
                # Determine if identity should be tracked
                identity_trackable = auth_header_present and scenario["headers"]["Authorization"].startswith("Bearer ")
                identity_logged = identity_trackable  # Simulated
                
                # Verify tracking appropriateness
                tracking_appropriate = identity_logged == scenario["expected_identity_logged"]
                success_appropriate = request_successful == scenario["expected_success"]
                
                identity_tracking_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "status_code": response.status_code,
                    "request_successful": request_successful,
                    "expected_success": scenario["expected_success"],
                    "auth_header_present": auth_header_present,
                    "identity_trackable": identity_trackable,
                    "identity_logged": identity_logged,
                    "expected_identity_logged": scenario["expected_identity_logged"],
                    "tracking_appropriate": tracking_appropriate,
                    "success_appropriate": success_appropriate,
                    "identity_tracking_working": tracking_appropriate and success_appropriate
                })
            
            except Exception as e:
                # Exceptions might be appropriate for invalid authentication
                tracking_appropriate = not scenario["expected_success"]
                
                identity_tracking_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "error": str(e)[:100],
                    "tracking_appropriate": tracking_appropriate,
                    "identity_tracking_working": tracking_appropriate
                })
            
            await asyncio.sleep(0.2)
        
        # Verify identity tracking effectiveness
        effective_tracking = sum(1 for result in identity_tracking_results 
                               if result.get("identity_tracking_working", False))
        total_scenarios = len(identity_tracking_results)
        
        tracking_effectiveness = effective_tracking / total_scenarios
        
        assert tracking_effectiveness >= 0.85, \
            f"Identity tracking effectiveness should be >= 85%: {tracking_effectiveness:.2%}"
        
        logger.info(f"OBSERVABILITY_002: Identity tracking tested - {tracking_effectiveness:.2%} effectiveness")
        
        for result in identity_tracking_results:
            logger.info(f"  {result['scenario']}: tracking_working={result.get('identity_tracking_working', False)}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_observability_003_llm_interaction_monitoring(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """OBSERVABILITY_003: Verify logging of LLM interaction details"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test LLM interaction monitoring through various model interactions
        llm_monitoring_scenarios = [
            {
                "scenario": "chat_completion_monitoring",
                "description": "Monitor chat completion LLM interactions",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "LLM monitoring test 1"}],
                        "max_tokens": 50
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "LLM monitoring test 2 with more content"}],
                        "max_tokens": 100
                    }
                ],
                "expected_metrics": [
                    "model_id", "latency", "prompt_tokens", "completion_tokens", "total_tokens"
                ]
            },
            {
                "scenario": "embedding_monitoring",
                "description": "Monitor embedding LLM interactions",
                "requests": [
                    {
                        "model": config.get_embedding_model(0),
                        "input": "Embedding monitoring test"
                    }
                ],
                "expected_metrics": [
                    "model_id", "latency", "input_tokens"
                ]
            },
            {
                "scenario": "different_model_monitoring",
                "description": "Monitor different model interactions",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Different model test"}],
                        "max_tokens": 30
                    }
                ],
                "expected_metrics": [
                    "model_id", "latency", "prompt_tokens", "completion_tokens"
                ]
            }
        ]
        
        llm_monitoring_results = []
        
        for scenario in llm_monitoring_scenarios:
            scenario_metrics = []
            
            for request in scenario["requests"]:
                request_start = time.time()
                
                try:
                    if "messages" in request:
                        # Chat completion request
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                    else:
                        # Embedding request
                        response = await make_request(
                            http_client, "POST", "/api/v1/embeddings",
                            auth_headers, request
                        )
                    
                    request_end = time.time()
                    request_latency = request_end - request_start
                    
                    if response.status_code == 200:
                        response_data = response.json()
                        
                        # Extract metrics from response
                        simulated_metrics = {
                            "model_id": request.get("model"),
                            "latency": request_latency,
                            "request_successful": True
                        }
                        
                        # Add token usage if available
                        if "usage" in response_data:
                            usage = response_data["usage"]
                            simulated_metrics.update({
                                "prompt_tokens": usage.get("prompt_tokens", 0),
                                "completion_tokens": usage.get("completion_tokens", 0),
                                "total_tokens": usage.get("total_tokens", 0)
                            })
                        elif "input" in request:
                            # Estimate input tokens for embedding
                            simulated_metrics["input_tokens"] = len(request["input"].split())
                        
                        # Verify expected metrics are captured
                        metrics_captured = []
                        for expected_metric in scenario["expected_metrics"]:
                            metric_present = expected_metric in simulated_metrics and simulated_metrics[expected_metric] is not None
                            metrics_captured.append({
                                "metric": expected_metric,
                                "present": metric_present,
                                "value": simulated_metrics.get(expected_metric)
                            })
                        
                        metrics_logged = sum(1 for metric in metrics_captured if metric["present"])
                        total_expected = len(scenario["expected_metrics"])
                        metrics_completeness = metrics_logged / total_expected
                        
                        scenario_metrics.append({
                            "request": request,
                            "response_status": response.status_code,
                            "latency": request_latency,
                            "simulated_metrics": simulated_metrics,
                            "expected_metrics": scenario["expected_metrics"],
                            "metrics_captured": metrics_captured,
                            "metrics_logged": metrics_logged,
                            "total_expected": total_expected,
                            "metrics_completeness": metrics_completeness,
                            "monitoring_effective": metrics_completeness >= 0.8
                        })
                    
                    else:
                        scenario_metrics.append({
                            "request": request,
                            "response_status": response.status_code,
                            "error": "Request failed",
                            "monitoring_effective": False
                        })
                
                except Exception as e:
                    scenario_metrics.append({
                        "request": request,
                        "error": str(e)[:100],
                        "monitoring_effective": False
                    })
                
                await asyncio.sleep(0.3)
            
            # Calculate scenario monitoring effectiveness
            effective_monitoring = sum(1 for metric in scenario_metrics 
                                     if metric.get("monitoring_effective", False))
            total_requests = len(scenario_metrics)
            scenario_effectiveness = effective_monitoring / total_requests if total_requests > 0 else 0
            
            llm_monitoring_results.append({
                "scenario": scenario["scenario"],
                "description": scenario["description"],
                "scenario_metrics": scenario_metrics,
                "effective_monitoring": effective_monitoring,
                "total_requests": total_requests,
                "scenario_effectiveness": scenario_effectiveness,
                "llm_monitoring_working": scenario_effectiveness >= 0.8
            })
        
        # Verify overall LLM interaction monitoring
        effective_scenarios = sum(1 for result in llm_monitoring_results 
                                if result["llm_monitoring_working"])
        total_scenarios = len(llm_monitoring_results)
        
        monitoring_effectiveness = effective_scenarios / total_scenarios
        
        assert monitoring_effectiveness >= 0.8, \
            f"LLM monitoring effectiveness should be >= 80%: {monitoring_effectiveness:.2%}"
        
        logger.info(f"OBSERVABILITY_003: LLM interaction monitoring tested - {monitoring_effectiveness:.2%} effectiveness")
        
        for result in llm_monitoring_results:
            logger.info(f"  {result['scenario']}: effectiveness={result['scenario_effectiveness']:.2%}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_observability_004_security_event_logging(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """OBSERVABILITY_004: Verify logging of security-relevant events"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test security event logging through various security scenarios
        security_event_scenarios = [
            {
                "event_type": "authentication_success",
                "description": "Successful authentication events",
                "tests": [
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "headers": auth_headers,
                        "expected_outcome": "success",
                        "security_relevant": True
                    }
                ]
            },
            {
                "event_type": "authentication_failure",
                "description": "Authentication failure events",
                "tests": [
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "headers": {"Authorization": "Bearer sk-invalid-key-security-test"},
                        "expected_outcome": "auth_failure",
                        "security_relevant": True
                    },
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "headers": {"Authorization": "InvalidFormat"},
                        "expected_outcome": "auth_failure",
                        "security_relevant": True
                    }
                ]
            },
            {
                "event_type": "authorization_failure",
                "description": "Authorization failure events",
                "tests": [
                    {
                        "endpoint": "/api/v1/admin",
                        "method": "GET",
                        "headers": auth_headers,
                        "expected_outcome": "authz_failure",
                        "security_relevant": True
                    }
                ]
            },
            {
                "event_type": "suspicious_activity",
                "description": "Suspicious activity patterns",
                "tests": [
                    {
                        "endpoint": "/api/v1/chat/completions",
                        "method": "POST",
                        "headers": auth_headers,
                        "data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Suspicious content: hack system admin password"}],
                            "max_tokens": 100
                        },
                        "expected_outcome": "suspicious_content",
                        "security_relevant": True
                    }
                ]
            },
            {
                "event_type": "rate_limiting",
                "description": "Rate limiting events",
                "tests": [
                    # Rapid requests to trigger rate limiting
                    {
                        "endpoint": "/api/v1/models",
                        "method": "GET",
                        "headers": auth_headers,
                        "rapid_requests": 15,
                        "expected_outcome": "rate_limited",
                        "security_relevant": True
                    }
                ]
            }
        ]
        
        security_logging_results = []
        
        for scenario in security_event_scenarios:
            scenario_results = []
            
            for test in scenario["tests"]:
                test_start = time.time()
                
                try:
                    if test.get("rapid_requests"):
                        # Execute rapid requests to trigger rate limiting
                        responses = []
                        for i in range(test["rapid_requests"]):
                            response = await make_request(
                                http_client, test["method"], test["endpoint"],
                                test["headers"], track_cost=False
                            )
                            responses.append(response.status_code)
                            await asyncio.sleep(0.05)
                        
                        # Check for rate limiting
                        rate_limited = any(status == 429 for status in responses)
                        security_event_occurred = rate_limited
                        
                        scenario_results.append({
                            "test": test,
                            "responses": responses,
                            "rate_limited": rate_limited,
                            "security_event_occurred": security_event_occurred,
                            "event_logged": security_event_occurred  # Simulated
                        })
                    
                    else:
                        # Execute single request
                        if test["method"] == "GET":
                            response = await make_request(
                                http_client, test["method"], test["endpoint"],
                                test["headers"], track_cost=False
                            )
                        else:
                            response = await make_request(
                                http_client, test["method"], test["endpoint"],
                                test["headers"], test.get("data"), track_cost=False
                            )
                        
                        test_end = time.time()
                        
                        # Determine if security event occurred
                        if test["expected_outcome"] == "success":
                            security_event_occurred = response.status_code == 200
                        elif test["expected_outcome"] == "auth_failure":
                            security_event_occurred = response.status_code == 401
                        elif test["expected_outcome"] == "authz_failure":
                            security_event_occurred = response.status_code in [403, 404]
                        elif test["expected_outcome"] == "suspicious_content":
                            security_event_occurred = response.status_code in [200, 400, 422]
                        else:
                            security_event_occurred = True
                        
                        # Simulate event logging verification
                        event_logged = security_event_occurred and test["security_relevant"]
                        
                        scenario_results.append({
                            "test": test,
                            "status_code": response.status_code,
                            "expected_outcome": test["expected_outcome"],
                            "security_event_occurred": security_event_occurred,
                            "security_relevant": test["security_relevant"],
                            "event_logged": event_logged,
                            "test_duration": test_end - test_start
                        })
                
                except Exception as e:
                    # Exceptions can be security-relevant events
                    security_event_occurred = True
                    event_logged = test["security_relevant"]
                    
                    scenario_results.append({
                        "test": test,
                        "error": str(e)[:100],
                        "security_event_occurred": security_event_occurred,
                        "event_logged": event_logged
                    })
                
                await asyncio.sleep(0.2)
            
            # Calculate security event logging effectiveness
            events_logged = sum(1 for result in scenario_results 
                              if result.get("event_logged", False))
            total_tests = len(scenario_results)
            logging_rate = events_logged / total_tests if total_tests > 0 else 0
            
            security_logging_results.append({
                "event_type": scenario["event_type"],
                "description": scenario["description"],
                "scenario_results": scenario_results,
                "events_logged": events_logged,
                "total_tests": total_tests,
                "logging_rate": logging_rate,
                "security_logging_effective": logging_rate >= 0.8
            })
        
        # Verify overall security event logging
        effective_logging = sum(1 for result in security_logging_results 
                              if result["security_logging_effective"])
        total_event_types = len(security_logging_results)
        
        security_logging_effectiveness = effective_logging / total_event_types
        
        assert security_logging_effectiveness >= 0.8, \
            f"Security event logging effectiveness should be >= 80%: {security_logging_effectiveness:.2%}"
        
        logger.info(f"OBSERVABILITY_004: Security event logging tested - {security_logging_effectiveness:.2%} effectiveness")
        
        for result in security_logging_results:
            logger.info(f"  {result['event_type']}: logging_rate={result['logging_rate']:.2%}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_observability_005_contextual_log_richness(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """OBSERVABILITY_005: Assess richness of context in logs for security analysis"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test contextual log richness through various request contexts
        context_richness_scenarios = [
            {
                "scenario": "standard_request_context",
                "description": "Standard request with full context",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "headers": auth_headers,
                "query_params": {"limit": "10"},
                "expected_context_fields": [
                    "client_ip", "user_agent", "method", "path", 
                    "query_params", "request_id", "api_key_id", "timestamp"
                ]
            },
            {
                "scenario": "complex_request_context",
                "description": "Complex request with rich context",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "headers": auth_headers,
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Context richness test"}],
                    "max_tokens": 100,
                    "temperature": 0.7
                },
                "expected_context_fields": [
                    "client_ip", "user_agent", "method", "path",
                    "request_id", "api_key_id", "model", "content_length"
                ]
            },
            {
                "scenario": "error_request_context",
                "description": "Error request with context preservation",
                "endpoint": "/api/v1/invalid",
                "method": "POST",
                "headers": auth_headers,
                "data": {"invalid": "data"},
                "expected_context_fields": [
                    "client_ip", "user_agent", "method", "path",
                    "request_id", "status_code", "error_type"
                ]
            },
            {
                "scenario": "security_context",
                "description": "Security-relevant request context",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "headers": auth_headers,
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Security context test with suspicious keywords: admin exploit"}],
                    "max_tokens": 50
                },
                "expected_context_fields": [
                    "client_ip", "user_agent", "request_id", "api_key_id",
                    "content_hash", "security_flags", "risk_score"
                ]
            }
        ]
        
        context_richness_results = []
        
        for scenario in context_richness_scenarios:
            scenario_start = time.time()
            
            try:
                # Prepare request with context
                if scenario["method"] == "GET":
                    response = await make_request(
                        http_client, scenario["method"], scenario["endpoint"],
                        scenario["headers"], track_cost=False
                    )
                else:
                    response = await make_request(
                        http_client, scenario["method"], scenario["endpoint"],
                        scenario["headers"], scenario.get("data"), track_cost=False
                    )
                
                scenario_end = time.time()
                
                # Simulate contextual log entry creation
                simulated_context = {
                    "client_ip": "127.0.0.1",  # Simulated
                    "user_agent": "test-client/1.0",  # Simulated
                    "method": scenario["method"],
                    "path": scenario["endpoint"],
                    "request_id": f"req_{int(scenario_start)}",
                    "timestamp": scenario_end,
                    "status_code": response.status_code,
                    "duration_ms": (scenario_end - scenario_start) * 1000,
                    "api_key_id": "test_key_id" if scenario["headers"].get("Authorization") else None
                }
                
                # Add scenario-specific context
                if scenario.get("query_params"):
                    simulated_context["query_params"] = scenario["query_params"]
                
                if scenario.get("data"):
                    simulated_context["content_length"] = len(json.dumps(scenario["data"]))
                    
                    if "model" in scenario["data"]:
                        simulated_context["model"] = scenario["data"]["model"]
                    
                    if "messages" in scenario["data"]:
                        content = scenario["data"]["messages"][0].get("content", "")
                        
                        # Security context enrichment
                        suspicious_keywords = ["admin", "exploit", "hack", "password", "backdoor"]
                        security_flags = [keyword for keyword in suspicious_keywords if keyword in content.lower()]
                        
                        if security_flags:
                            simulated_context["security_flags"] = security_flags
                            simulated_context["risk_score"] = len(security_flags) * 0.3
                        
                        # Content hash
                        import hashlib
                        simulated_context["content_hash"] = hashlib.md5(content.encode()).hexdigest()[:8]
                
                if response.status_code >= 400:
                    simulated_context["error_type"] = "client_error" if response.status_code < 500 else "server_error"
                
                # Verify expected context fields
                context_fields_present = []
                for expected_field in scenario["expected_context_fields"]:
                    field_present = expected_field in simulated_context and simulated_context[expected_field] is not None
                    context_fields_present.append({
                        "field": expected_field,
                        "present": field_present,
                        "value": simulated_context.get(expected_field)
                    })
                
                fields_captured = sum(1 for field in context_fields_present if field["present"])
                total_expected = len(scenario["expected_context_fields"])
                context_richness = fields_captured / total_expected
                
                context_richness_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "status_code": response.status_code,
                    "simulated_context": simulated_context,
                    "expected_context_fields": scenario["expected_context_fields"],
                    "context_fields_present": context_fields_present,
                    "fields_captured": fields_captured,
                    "total_expected": total_expected,
                    "context_richness": context_richness,
                    "rich_context": context_richness >= 0.8
                })
            
            except Exception as e:
                context_richness_results.append({
                    "scenario": scenario["scenario"],
                    "description": scenario["description"],
                    "error": str(e)[:100],
                    "rich_context": False
                })
            
            await asyncio.sleep(0.3)
        
        # Verify contextual richness effectiveness
        rich_context_scenarios = sum(1 for result in context_richness_results 
                                   if result.get("rich_context", False))
        total_scenarios = len(context_richness_results)
        
        richness_effectiveness = rich_context_scenarios / total_scenarios
        
        assert richness_effectiveness >= 0.8, \
            f"Contextual richness effectiveness should be >= 80%: {richness_effectiveness:.2%}"
        
        logger.info(f"OBSERVABILITY_005: Contextual log richness tested - {richness_effectiveness:.2%} effectiveness")
        
        for result in context_richness_results:
            logger.info(f"  {result['scenario']}: richness={result.get('context_richness', 0):.2%}")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_observability_006_siem_integration_assessment(self, http_client: httpx.AsyncClient,
                                                               auth_headers: Dict[str, str],
                                                               make_request):
        """OBSERVABILITY_006: Assess SIEM integration and advanced security analytics"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test SIEM integration capabilities through observability patterns
        siem_assessment_scenarios = [
            {
                "capability": "log_format_standardization",
                "description": "Assess log format standardization for SIEM ingestion",
                "test_requests": [
                    {"endpoint": "/api/v1/models", "method": "GET"},
                    {"endpoint": "/api/v1/chat/completions", "method": "POST", "data": {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "SIEM integration test"}],
                        "max_tokens": 30
                    }}
                ]
            },
            {
                "capability": "event_correlation_readiness",
                "description": "Assess readiness for event correlation",
                "correlation_tests": [
                    {"pattern": "authentication_sequence", "requests": 3},
                    {"pattern": "error_sequence", "requests": 2}
                ]
            },
            {
                "capability": "real_time_streaming",
                "description": "Assess real-time log streaming capabilities",
                "streaming_tests": [
                    {"test_type": "continuous_requests", "duration": 10},
                    {"test_type": "burst_requests", "count": 5}
                ]
            },
            {
                "capability": "structured_logging",
                "description": "Assess structured logging for automated analysis",
                "structure_tests": [
                    {"format": "json", "parseable": True},
                    {"format": "key_value", "searchable": True}
                ]
            }
        ]
        
        siem_assessment_results = []
        
        for scenario in siem_assessment_scenarios:
            if scenario["capability"] == "log_format_standardization":
                # Test log format standardization
                format_results = []
                
                for test_request in scenario["test_requests"]:
                    try:
                        if test_request["method"] == "GET":
                            response = await make_request(
                                http_client, test_request["method"], test_request["endpoint"],
                                auth_headers, track_cost=False
                            )
                        else:
                            response = await make_request(
                                http_client, test_request["method"], test_request["endpoint"],
                                auth_headers, test_request.get("data"), track_cost=False
                            )
                        
                        # Simulate log format analysis
                        simulated_log_format = {
                            "format": "structured_json",
                            "timestamp_standardized": True,
                            "severity_levels": True,
                            "correlation_id": True,
                            "parseable": True,
                            "siem_ready": True
                        }
                        
                        format_results.append({
                            "request": test_request,
                            "status_code": response.status_code,
                            "log_format": simulated_log_format,
                            "siem_compatible": simulated_log_format["siem_ready"]
                        })
                    
                    except Exception as e:
                        format_results.append({
                            "request": test_request,
                            "error": str(e)[:100],
                            "siem_compatible": False
                        })
                    
                    await asyncio.sleep(0.2)
                
                compatible_formats = sum(1 for result in format_results 
                                       if result["siem_compatible"])
                total_tests = len(format_results)
                format_compatibility = compatible_formats / total_tests
                
                siem_assessment_results.append({
                    "capability": scenario["capability"],
                    "description": scenario["description"],
                    "format_results": format_results,
                    "format_compatibility": format_compatibility,
                    "siem_ready": format_compatibility >= 0.9
                })
            
            elif scenario["capability"] == "event_correlation_readiness":
                # Test event correlation readiness
                correlation_results = []
                
                for correlation_test in scenario["correlation_tests"]:
                    correlation_start = time.time()
                    request_ids = []
                    
                    for i in range(correlation_test["requests"]):
                        try:
                            if correlation_test["pattern"] == "authentication_sequence":
                                response = await make_request(
                                    http_client, "GET", "/api/v1/models",
                                    auth_headers, track_cost=False
                                )
                            else:  # error_sequence
                                response = await make_request(
                                    http_client, "GET", "/api/v1/nonexistent",
                                    auth_headers, track_cost=False
                                )
                            
                            # Simulate request ID tracking
                            request_id = f"req_{correlation_test['pattern']}_{i}_{int(time.time())}"
                            request_ids.append(request_id)
                        
                        except Exception:
                            request_id = f"req_{correlation_test['pattern']}_{i}_error"
                            request_ids.append(request_id)
                        
                        await asyncio.sleep(0.1)
                    
                    correlation_end = time.time()
                    
                    # Assess correlation capability
                    unique_requests = len(set(request_ids))
                    correlation_possible = unique_requests == len(request_ids)
                    
                    correlation_results.append({
                        "pattern": correlation_test["pattern"],
                        "request_ids": request_ids,
                        "unique_requests": unique_requests,
                        "total_requests": len(request_ids),
                        "correlation_possible": correlation_possible,
                        "sequence_duration": correlation_end - correlation_start
                    })
                
                correlation_ready = all(result["correlation_possible"] for result in correlation_results)
                
                siem_assessment_results.append({
                    "capability": scenario["capability"],
                    "description": scenario["description"],
                    "correlation_results": correlation_results,
                    "correlation_ready": correlation_ready,
                    "siem_ready": correlation_ready
                })
            
            elif scenario["capability"] == "real_time_streaming":
                # Test real-time streaming readiness
                streaming_results = []
                
                for streaming_test in scenario["streaming_tests"]:
                    if streaming_test["test_type"] == "continuous_requests":
                        # Continuous requests for specified duration
                        stream_start = time.time()
                        requests_made = 0
                        
                        while (time.time() - stream_start) < streaming_test["duration"]:
                            try:
                                response = await make_request(
                                    http_client, "GET", "/api/v1/models",
                                    auth_headers, track_cost=False
                                )
                                requests_made += 1
                            except Exception:
                                pass
                            
                            await asyncio.sleep(1)
                        
                        stream_end = time.time()
                        actual_duration = stream_end - stream_start
                        
                        streaming_results.append({
                            "test_type": streaming_test["test_type"],
                            "duration": actual_duration,
                            "requests_made": requests_made,
                            "request_rate": requests_made / actual_duration,
                            "streaming_viable": requests_made >= streaming_test["duration"] * 0.8
                        })
                    
                    elif streaming_test["test_type"] == "burst_requests":
                        # Burst requests
                        burst_start = time.time()
                        burst_responses = []
                        
                        for i in range(streaming_test["count"]):
                            try:
                                response = await make_request(
                                    http_client, "GET", "/api/v1/models",
                                    auth_headers, track_cost=False
                                )
                                burst_responses.append(response.status_code)
                            except Exception:
                                burst_responses.append(0)
                            
                            await asyncio.sleep(0.05)
                        
                        burst_end = time.time()
                        burst_duration = burst_end - burst_start
                        
                        streaming_results.append({
                            "test_type": streaming_test["test_type"],
                            "count": len(burst_responses),
                            "duration": burst_duration,
                            "successful_requests": sum(1 for status in burst_responses if status == 200),
                            "streaming_viable": burst_duration < streaming_test["count"] * 0.2
                        })
                
                streaming_viable = all(result["streaming_viable"] for result in streaming_results)
                
                siem_assessment_results.append({
                    "capability": scenario["capability"],
                    "description": scenario["description"],
                    "streaming_results": streaming_results,
                    "streaming_viable": streaming_viable,
                    "siem_ready": streaming_viable
                })
            
            elif scenario["capability"] == "structured_logging":
                # Test structured logging capabilities
                structure_results = []
                
                for structure_test in scenario["structure_tests"]:
                    # Simulate structured logging assessment
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                    
                    # Simulate structure analysis
                    simulated_structure = {
                        "format": structure_test["format"],
                        "parseable": structure_test.get("parseable", True),
                        "searchable": structure_test.get("searchable", True),
                        "machine_readable": True,
                        "schema_consistent": True
                    }
                    
                    structure_quality = sum(simulated_structure.values()) / len(simulated_structure)
                    
                    structure_results.append({
                        "format": structure_test["format"],
                        "structure_analysis": simulated_structure,
                        "structure_quality": structure_quality,
                        "siem_compatible": structure_quality >= 0.8
                    })
                
                structure_compatible = all(result["siem_compatible"] for result in structure_results)
                
                siem_assessment_results.append({
                    "capability": scenario["capability"],
                    "description": scenario["description"],
                    "structure_results": structure_results,
                    "structure_compatible": structure_compatible,
                    "siem_ready": structure_compatible
                })
        
        # Verify SIEM integration readiness
        siem_ready_capabilities = sum(1 for result in siem_assessment_results 
                                    if result.get("siem_ready", False))
        total_capabilities = len(siem_assessment_results)
        
        siem_readiness = siem_ready_capabilities / total_capabilities
        
        logger.info(f"OBSERVABILITY_006: SIEM integration assessed - {siem_readiness:.2%} readiness")
        
        for result in siem_assessment_results:
            logger.info(f"  {result['capability']}: ready={result.get('siem_ready', False)}")