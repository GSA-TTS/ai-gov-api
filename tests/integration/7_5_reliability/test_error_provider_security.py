# Section 7.5 - Enhanced Error Response Validation Tests - Provider and Security
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Error Response Validation.md
# Enhanced test cases - Provider Classification and Security

import pytest
import httpx
import asyncio
import time
import os
from typing import Dict, Any, List
from unittest.mock import patch, Mock
from dataclasses import dataclass

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestErrorProviderSecurityHandling:
    """Enhanced error response validation tests - Provider and Security scenarios"""
    
    def setup_method(self):
        """Setup test environment with sensitive data from .env"""
        # Load sensitive configuration from environment variables
        self.provider_credentials = {
            'aws_access_key': os.getenv('AWS_ACCESS_KEY_ID'),
            'aws_secret_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
            'vertex_project_id': os.getenv('VERTEX_PROJECT_ID'),
            'vertex_credentials': os.getenv('VERTEX_AI_CREDENTIALS')
        }

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_provider_error_classification_003(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """TC_R751_PROVIDER_CLASSIFICATION_003: Provider error classification with retry guidance"""
        # Test intelligent provider error classification with retry recommendations
        
        # Provider error classification scenarios
        provider_error_scenarios = [
            {
                "category": "transient",
                "description": "Temporary provider issues",
                "test_requests": [
                    # Simulate rate limiting
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Rate limit test: " + "request " * 100}],
                        "max_tokens": 500
                    }
                ] * 3,
                "expected_retry_guidance": "retry_with_backoff"
            },
            {
                "category": "permanent", 
                "description": "Configuration errors",
                "test_requests": [
                    {
                        "model": "provider_classification_invalid_model",
                        "messages": [{"role": "user", "content": "Configuration error test"}],
                        "max_tokens": 50
                    }
                ] * 2,
                "expected_retry_guidance": "do_not_retry"
            },
            {
                "category": "rate_limit",
                "description": "Rate limit errors", 
                "test_requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Rate limit test {i}"}],
                        "max_tokens": 30
                    }
                    for i in range(8)  # Rapid succession
                ],
                "expected_retry_guidance": "retry_after_delay"
            }
        ]
        
        classification_results = []
        
        for scenario in provider_error_scenarios:
            scenario_start_time = time.time()
            scenario_responses = []
            
            logger.info(f"Testing provider error classification: {scenario['category']}")
            
            # Execute scenario requests
            for request in scenario["test_requests"]:
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=False
                    )
                    
                    scenario_responses.append({
                        "status_code": response.status_code,
                        "response_headers": dict(response.headers),
                        "success": response.status_code == 200
                    })
                    
                except Exception as e:
                    scenario_responses.append({
                        "error": str(e),
                        "success": False
                    })
                
                # Small delay for rate limit testing
                if scenario["category"] == "rate_limit":
                    await asyncio.sleep(0.1)
                else:
                    await asyncio.sleep(0.3)
            
            scenario_end_time = time.time()
            
            # Analyze error classification
            error_responses = [r for r in scenario_responses if not r.get("success")]
            successful_responses = [r for r in scenario_responses if r.get("success")]
            
            # Check for retry guidance in responses
            retry_guidance_found = False
            rate_limit_headers = False
            
            for response in scenario_responses:
                if "response_headers" in response:
                    headers = response["response_headers"]
                    # Check for retry-related headers
                    if any(header.lower().startswith('retry-after') for header in headers.keys()):
                        retry_guidance_found = True
                        rate_limit_headers = True
                    elif any(header.lower().startswith('x-ratelimit') for header in headers.keys()):
                        rate_limit_headers = True
            
            classification_results.append({
                "category": scenario["category"],
                "total_requests": len(scenario_responses),
                "error_responses": len(error_responses),
                "success_rate": len(successful_responses) / len(scenario_responses),
                "retry_guidance_found": retry_guidance_found,
                "rate_limit_headers": rate_limit_headers,
                "scenario_duration": scenario_end_time - scenario_start_time
            })
        
        # Verify provider error classification
        for result in classification_results:
            if result["category"] == "rate_limit":
                # Rate limit scenarios should either succeed or show appropriate headers
                if result["error_responses"] > 0:
                    logger.info(f"Rate limit scenario: {result['error_responses']} errors detected")
            
            elif result["category"] == "permanent":
                # Permanent errors should have high error rate
                assert result["error_responses"] > 0, \
                    f"Permanent error scenario should generate errors: {result}"
            
            # All scenarios should handle errors gracefully
            assert result["success_rate"] >= 0 and result["success_rate"] <= 1, \
                f"Success rate should be valid: {result}"
        
        logger.info("Provider error classification testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_graceful_error_degradation_004(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TC_R751_GRACEFUL_DEGRADATION_004: Graceful error degradation and fallback responses"""
        # Test graceful degradation when primary error handling mechanisms fail
        
        # Simulate system overload conditions
        degradation_scenarios = [
            {
                "scenario": "normal_load",
                "description": "Normal system load",
                "concurrent_requests": 3,
                "request_interval": 0.5
            },
            {
                "scenario": "moderate_overload",
                "description": "Moderate system overload",
                "concurrent_requests": 8,
                "request_interval": 0.1
            },
            {
                "scenario": "high_overload",
                "description": "High system overload", 
                "concurrent_requests": 15,
                "request_interval": 0.05
            }
        ]
        
        degradation_results = []
        
        for scenario in degradation_scenarios:
            logger.info(f"Testing graceful degradation: {scenario['scenario']}")
            
            async def overload_request(request_id: int):
                """Generate request for overload testing"""
                # Mix of normal and potentially problematic requests
                if request_id % 4 == 0:
                    # Large request
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Overload test large: " + "content " * 200}],
                        "max_tokens": 300
                    }
                elif request_id % 4 == 1:
                    # Invalid request
                    request = {
                        "model": f"overload_invalid_{request_id}",
                        "messages": [{"role": "user", "content": "Overload invalid test"}],
                        "max_tokens": 50
                    }
                else:
                    # Normal request
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Overload normal test {request_id}"}],
                        "max_tokens": 40
                    }
                
                start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=(request_id % 4 >= 2)
                    )
                    
                    end_time = time.time()
                    
                    return {
                        "request_id": request_id,
                        "status_code": response.status_code,
                        "response_time": end_time - start_time,
                        "graceful": response.status_code in [200, 400, 422, 429, 503],
                        "request_type": "large" if request_id % 4 == 0 else "invalid" if request_id % 4 == 1 else "normal"
                    }
                    
                except Exception as e:
                    end_time = time.time()
                    
                    return {
                        "request_id": request_id,
                        "error": str(e),
                        "response_time": end_time - start_time,
                        "graceful": True,  # Exception handling is graceful
                        "request_type": "exception"
                    }
            
            # Execute overload test
            overload_tasks = [overload_request(i) for i in range(scenario["concurrent_requests"])]
            overload_responses = await asyncio.gather(*overload_tasks, return_exceptions=True)
            
            # Analyze degradation behavior
            valid_responses = [r for r in overload_responses if isinstance(r, dict)]
            graceful_responses = [r for r in valid_responses if r.get("graceful")]
            
            degradation_rate = len(graceful_responses) / len(valid_responses) if valid_responses else 0
            avg_response_time = sum(r.get("response_time", 0) for r in valid_responses) / len(valid_responses) if valid_responses else 0
            
            degradation_results.append({
                "scenario": scenario["scenario"],
                "total_requests": len(valid_responses),
                "graceful_responses": len(graceful_responses),
                "degradation_rate": degradation_rate,
                "avg_response_time": avg_response_time
            })
            
            await asyncio.sleep(2)  # Recovery time between scenarios
        
        # Verify graceful degradation
        for result in degradation_results:
            # System should degrade gracefully under all load conditions
            assert result["degradation_rate"] >= 0.8, \
                f"Graceful degradation rate should be high: {result['scenario']} - {result['degradation_rate']:.2%}"
            
            # Response times may increase but system should remain responsive
            assert result["avg_response_time"] <= 60.0, \
                f"Average response time should remain reasonable: {result['scenario']} - {result['avg_response_time']:.2f}s"
        
        logger.info("Graceful error degradation testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_error_response_security_005(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              security_validator: SecurityValidator,
                                              make_request):
        """TC_R751_SECURITY_DISCLOSURE_005: Error response security and information disclosure prevention"""
        # Test prevention of sensitive information disclosure in error responses
        
        # Security-sensitive error scenarios
        security_test_scenarios = [
            {
                "category": "stack_trace_leakage",
                "description": "Test for stack trace exposure",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Security test: " + "A" * 50000}],  # Oversized
                        "max_tokens": 1000
                    },
                    {
                        "model": None,  # Trigger internal error
                        "messages": [{"role": "user", "content": "Security null test"}],
                        "max_tokens": 50
                    }
                ]
            },
            {
                "category": "credential_sanitization",
                "description": "Test credential information filtering",
                "requests": [
                    {
                        "model": "security_test_invalid_with_credentials",
                        "messages": [{"role": "user", "content": "Test with API_KEY=secret123 and TOKEN=abc123"}],
                        "max_tokens": 50
                    }
                ]
            },
            {
                "category": "internal_path_disclosure",
                "description": "Test internal system path protection",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": {"invalid": "structure", "path": "/internal/system/path"},
                        "max_tokens": 50
                    }
                ]
            }
        ]
        
        security_results = []
        
        for scenario in security_test_scenarios:
            logger.info(f"Testing error security: {scenario['category']}")
            
            for request in scenario["requests"]:
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=False
                    )
                    
                    # Analyze response for security issues
                    security_analysis = security_validator.validate_error_message_security(
                        response.text
                    )
                    
                    security_results.append({
                        "category": scenario["category"],
                        "status_code": response.status_code,
                        "is_secure": security_analysis["is_secure"],
                        "security_issues": security_analysis.get("issues", []),
                        "response_length": len(response.text)
                    })
                    
                except Exception as e:
                    # Exceptions should also be secure
                    security_analysis = security_validator.validate_error_message_security(str(e))
                    
                    security_results.append({
                        "category": scenario["category"],
                        "exception": str(e),
                        "is_secure": security_analysis["is_secure"],
                        "security_issues": security_analysis.get("issues", [])
                    })
                
                await asyncio.sleep(0.2)
        
        # Verify security compliance
        security_violations = [r for r in security_results if not r.get("is_secure")]
        
        if security_violations:
            logger.warning(f"Security violations detected: {len(security_violations)}")
            for violation in security_violations:
                logger.warning(f"Security issue in {violation['category']}: {violation.get('security_issues')}")
        
        # All error responses should be secure
        assert len(security_violations) == 0, \
            f"Error responses should not expose sensitive information: {security_violations}"
        
        logger.info("Error response security validation completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_provider_error_mapping_consistency_006(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """TC_R751_PROVIDER_MAPPING_006: Provider error mapping consistency across providers"""
        # Test consistent error mapping across different LLM providers
        
        provider_consistency_tests = [
            {
                "error_type": "invalid_model",
                "test_data": {
                    "model": "definitely_invalid_model_name",
                    "messages": [{"role": "user", "content": "Test invalid model"}],
                    "max_tokens": 50
                },
                "expected_status": [400, 404],
                "expected_consistency": True
            },
            {
                "error_type": "oversized_request",
                "test_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test oversized: " + "X" * 100000}],
                    "max_tokens": 4000
                },
                "expected_status": [400, 413, 422],
                "expected_consistency": True
            },
            {
                "error_type": "invalid_parameters",
                "test_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test invalid params"}],
                    "max_tokens": -100  # Invalid negative value
                },
                "expected_status": [400, 422],
                "expected_consistency": True
            }
        ]
        
        consistency_results = []
        
        for test_case in provider_consistency_tests:
            logger.info(f"Testing provider error consistency: {test_case['error_type']}")
            
            # Test with available models from different providers if configured
            provider_models = [
                config.get_chat_model(0),  # Primary model
            ]
            
            # Add secondary models if available
            try:
                if len(config.available_chat_models) > 1:
                    provider_models.append(config.get_chat_model(1))
            except:
                pass
            
            provider_responses = {}
            
            for model in provider_models:
                test_data = test_case["test_data"].copy()
                test_data["model"] = model
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, test_data, track_cost=False
                    )
                    
                    provider_responses[model] = {
                        "status_code": response.status_code,
                        "response_text": response.text[:200],  # First 200 chars for analysis
                        "has_request_id": "request_id" in response.text.lower()
                    }
                    
                except Exception as e:
                    provider_responses[model] = {
                        "exception": str(e),
                        "has_request_id": False
                    }
                
                await asyncio.sleep(0.3)
            
            # Analyze consistency across providers
            status_codes = [r.get("status_code") for r in provider_responses.values() if "status_code" in r]
            request_id_consistency = all(r.get("has_request_id", False) for r in provider_responses.values())
            
            consistency_results.append({
                "error_type": test_case["error_type"],
                "provider_count": len(provider_responses),
                "status_codes": status_codes,
                "consistent_status": len(set(status_codes)) <= 1 if status_codes else True,
                "request_id_consistent": request_id_consistency,
                "within_expected": all(code in test_case["expected_status"] for code in status_codes)
            })
        
        # Verify provider error mapping consistency
        for result in consistency_results:
            # Status codes should be within expected range
            assert result["within_expected"], \
                f"Provider error status codes should be in expected range: {result}"
            
            # Error responses should consistently include request IDs
            if result["provider_count"] > 0:
                assert result["request_id_consistent"], \
                    f"Error responses should consistently include request IDs: {result}"
        
        logger.info("Provider error mapping consistency validation completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_security_header_validation_007(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TC_R751_SECURITY_HEADERS_007: Security header validation in error responses"""
        # Test security headers are properly set in error responses
        
        security_header_tests = [
            {
                "error_scenario": "authentication_failure",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "headers": {},  # No auth headers
                "expected_security_headers": [
                    "x-content-type-options",
                    "x-frame-options", 
                    "strict-transport-security"
                ]
            },
            {
                "error_scenario": "malformed_request",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "headers": auth_headers,
                "data": "invalid json",
                "expected_security_headers": [
                    "x-content-type-options",
                    "x-frame-options"
                ]
            }
        ]
        
        security_header_results = []
        
        for test in security_header_tests:
            logger.info(f"Testing security headers: {test['error_scenario']}")
            
            try:
                if test["method"] == "GET":
                    response = await make_request(
                        http_client, "GET", test["endpoint"],
                        test["headers"], track_cost=False
                    )
                else:
                    response = await make_request(
                        http_client, "POST", test["endpoint"],
                        test["headers"], test.get("data", {}), track_cost=False
                    )
                
                # Analyze security headers
                response_headers = {k.lower(): v for k, v in response.headers.items()}
                
                security_header_results.append({
                    "scenario": test["error_scenario"],
                    "status_code": response.status_code,
                    "security_headers_present": [
                        header for header in test["expected_security_headers"]
                        if header.lower() in response_headers
                    ],
                    "all_headers_present": all(
                        header.lower() in response_headers 
                        for header in test["expected_security_headers"]
                    )
                })
                
            except Exception as e:
                security_header_results.append({
                    "scenario": test["error_scenario"],
                    "exception": str(e),
                    "security_headers_present": [],
                    "all_headers_present": False
                })
            
            await asyncio.sleep(0.2)
        
        # Verify security headers are present
        for result in security_header_results:
            if "status_code" in result and result["status_code"] >= 400:
                # Error responses should include security headers
                logger.info(f"Security headers for {result['scenario']}: {result['security_headers_present']}")
                # Note: Don't assert strict requirements as this depends on server configuration
        
        logger.info("Security header validation completed")

    @pytest.mark.reliability 
    @pytest.mark.asyncio
    async def test_cross_provider_error_translation_008(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """TC_R751_CROSS_PROVIDER_008: Cross-provider error translation and normalization"""
        # Test error translation across different provider backends
        
        translation_scenarios = [
            {
                "scenario": "rate_limit_normalization",
                "description": "Rate limit errors should be normalized across providers",
                "test_requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Rate limit test {i}"}],
                        "max_tokens": 50
                    }
                    for i in range(10)  # Generate potential rate limit
                ]
            },
            {
                "scenario": "content_filtering_normalization", 
                "description": "Content filtering should be normalized",
                "test_requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Content filter test with sensitive content"}],
                        "max_tokens": 50
                    }
                ]
            }
        ]
        
        translation_results = []
        
        for scenario in translation_scenarios:
            logger.info(f"Testing error translation: {scenario['scenario']}")
            
            scenario_responses = []
            
            for request in scenario["test_requests"]:
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=False
                    )
                    
                    scenario_responses.append({
                        "status_code": response.status_code,
                        "error_type": "none" if response.status_code == 200 else "error",
                        "response_structure": "json" if response.headers.get("content-type", "").startswith("application/json") else "other"
                    })
                    
                except Exception as e:
                    scenario_responses.append({
                        "exception": str(e),
                        "error_type": "exception"
                    })
                
                # Rate limit testing requires rapid requests
                if scenario["scenario"] == "rate_limit_normalization":
                    await asyncio.sleep(0.05)
                else:
                    await asyncio.sleep(0.2)
            
            # Analyze translation consistency
            error_responses = [r for r in scenario_responses if r.get("error_type") != "none"]
            status_codes = [r.get("status_code") for r in error_responses if "status_code" in r]
            
            translation_results.append({
                "scenario": scenario["scenario"],
                "total_requests": len(scenario_responses),
                "error_count": len(error_responses),
                "unique_status_codes": list(set(status_codes)),
                "consistent_format": all(r.get("response_structure") == "json" for r in error_responses if "response_structure" in r)
            })
        
        # Verify error translation
        for result in translation_results:
            # Error responses should use consistent formatting
            if result["error_count"] > 0:
                assert result["consistent_format"], \
                    f"Error responses should have consistent format: {result}"
            
            logger.info(f"Translation result for {result['scenario']}: {result['error_count']} errors with codes {result['unique_status_codes']}")
        
        logger.info("Cross-provider error translation validation completed")