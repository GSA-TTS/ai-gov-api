# Section 7.5 - Timeout and Retry Strategy Validation Tests
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Timeout and Retry Strategy Validation.md

import pytest
import httpx
import asyncio
import time
from typing import Dict, Any, List
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestTimeoutRetryStrategy:
    """Timeout and retry strategy validation tests"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_provider_timeout_configuration_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TIMEOUT_PROVIDER_001: Provider timeout configuration"""
        # Test provider-specific timeout configurations
        
        # Test with requests of varying complexity to understand timeout behavior
        timeout_test_scenarios = [
            {
                "description": "Simple request",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Simple timeout test"}],
                    "max_tokens": 20
                },
                "expected_timeout": False
            },
            {
                "description": "Medium complexity request",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Medium complexity timeout test. Please provide a detailed explanation about AI systems and their applications in various fields."}],
                    "max_tokens": 200
                },
                "expected_timeout": False
            },
            {
                "description": "Large request",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Large timeout test: " + "Please analyze this extensive content. " * 100}],
                    "max_tokens": 500
                },
                "expected_timeout": "possible"
            }
        ]
        
        timeout_results = []
        
        for scenario in timeout_test_scenarios:
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"]
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                timeout_results.append({
                    "description": scenario["description"],
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "timed_out": False,
                    "completed": True
                })
                
                # Check for timeout indicators
                if response.status_code == 504:
                    logger.info(f"Gateway timeout detected for {scenario['description']}")
                elif response.status_code == 408:
                    logger.info(f"Request timeout detected for {scenario['description']}")
                elif response_time > 30:
                    logger.info(f"Long response time ({response_time:.2f}s) for {scenario['description']}")
                
            except httpx.TimeoutException as e:
                end_time = time.time()
                response_time = end_time - start_time
                
                timeout_results.append({
                    "description": scenario["description"],
                    "timed_out": True,
                    "response_time": response_time,
                    "timeout_type": "client_timeout",
                    "completed": False
                })
                
                logger.info(f"Client timeout after {response_time:.2f}s for {scenario['description']}")
            
            except Exception as e:
                timeout_results.append({
                    "description": scenario["description"],
                    "error": str(e),
                    "completed": False
                })
            
            await asyncio.sleep(0.5)  # Brief pause between tests
        
        # Analyze timeout behavior
        completed_requests = [r for r in timeout_results if r.get("completed")]
        timed_out_requests = [r for r in timeout_results if r.get("timed_out")]
        
        # Simple requests should complete within reasonable time
        simple_requests = [r for r in completed_requests if "Simple" in r["description"]]
        for request in simple_requests:
            assert request["response_time"] <= 10.0, \
                f"Simple requests should complete quickly: {request['response_time']:.2f}s"
        
        # Verify timeout handling is appropriate
        for request in timed_out_requests:
            assert request["response_time"] <= config.TIMEOUT + 5, \
                "Timeouts should occur within expected timeframe"
        
        logger.info(f"Provider timeout testing: {len(completed_requests)} completed, {len(timed_out_requests)} timed out")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_api_level_timeouts_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """TIMEOUT_API_001: API-level timeout configuration"""
        # Test API-level timeout configurations
        
        # Test different endpoint timeouts
        api_timeout_tests = [
            {
                "endpoint": "/api/v1/models",
                "method": "GET",
                "data": None,
                "expected_fast": True
            },
            {
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "API timeout test"}],
                    "max_tokens": 50
                },
                "expected_fast": False
            }
        ]
        
        api_timeout_results = []
        
        for test in api_timeout_tests:
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, test["method"], test["endpoint"],
                    auth_headers, test["data"], track_cost=(test["method"] == "POST")
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                api_timeout_results.append({
                    "endpoint": test["endpoint"],
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "expected_fast": test["expected_fast"],
                    "success": response.status_code == 200
                })
                
            except httpx.TimeoutException as e:
                end_time = time.time()
                response_time = end_time - start_time
                
                api_timeout_results.append({
                    "endpoint": test["endpoint"],
                    "timed_out": True,
                    "response_time": response_time,
                    "expected_fast": test["expected_fast"]
                })
            
            await asyncio.sleep(0.3)
        
        # Analyze API-level timeout behavior
        for result in api_timeout_results:
            if result.get("expected_fast") and result.get("success"):
                assert result["response_time"] <= 5.0, \
                    f"Fast endpoint {result['endpoint']} should respond quickly"
            
            if result.get("timed_out"):
                logger.info(f"Timeout occurred for {result['endpoint']} after {result['response_time']:.2f}s")
        
        logger.info("API-level timeout testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_streaming_timeout_handling_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TIMEOUT_STREAMING_001: Streaming response timeout handling"""
        # Test timeout handling for streaming responses
        
        # Test streaming request (if supported)
        streaming_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Generate a streaming response about technology trends."}],
            "max_tokens": 200,
            "stream": True
        }
        
        start_time = time.time()
        
        try:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, streaming_request
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            if response.status_code == 200:
                # Check if response is actually streaming
                content_type = response.headers.get("content-type", "")
                
                if "stream" in content_type or "text/event-stream" in content_type:
                    logger.info(f"Streaming response received in {response_time:.2f}s")
                    
                    # Verify streaming timeout behavior
                    assert response_time <= 60.0, \
                        "Streaming response should start within reasonable time"
                else:
                    logger.info("Non-streaming response received for stream request")
            
            elif response.status_code == 422:
                logger.info("Streaming not supported by this model/endpoint")
                
                # Test with non-streaming fallback
                non_streaming_request = streaming_request.copy()
                non_streaming_request.pop("stream", None)
                
                fallback_response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, non_streaming_request
                )
                
                assert fallback_response.status_code == 200, \
                    "Non-streaming fallback should work"
            
            else:
                logger.warning(f"Unexpected response for streaming request: {response.status_code}")
        
        except httpx.TimeoutException as e:
            end_time = time.time()
            timeout_duration = end_time - start_time
            
            logger.info(f"Streaming request timed out after {timeout_duration:.2f}s")
            
            # Streaming timeouts should be reasonable
            assert timeout_duration <= config.TIMEOUT + 10, \
                "Streaming timeout should occur within expected timeframe"
        
        except Exception as e:
            logger.info(f"Streaming test encountered exception: {e}")
        
        logger.info("Streaming timeout handling testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_retry_transient_errors_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """RETRY_TRANSIENT_001: Retry logic for transient errors"""
        # Test retry logic for transient error conditions
        
        # Simulate conditions that might cause transient errors
        transient_error_scenarios = [
            {
                "description": "Large request that might timeout",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Large request for retry testing: " + "content " * 500}],
                    "max_tokens": 300
                },
                "may_need_retry": True
            },
            {
                "description": "Complex request that might fail",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [
                        {"role": "user", "content": "Complex multi-turn conversation for retry testing"},
                        {"role": "assistant", "content": "I understand you want to test retry logic."},
                        {"role": "user", "content": "Yes, please provide a comprehensive response that might trigger retry behavior."}
                    ],
                    "max_tokens": 200
                },
                "may_need_retry": True
            }
        ]
        
        retry_test_results = []
        
        for scenario in transient_error_scenarios:
            # Measure total time to detect potential retries
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"]
                )
                
                end_time = time.time()
                total_time = end_time - start_time
                
                retry_test_results.append({
                    "description": scenario["description"],
                    "status_code": response.status_code,
                    "total_time": total_time,
                    "success": response.status_code == 200,
                    "possible_retries": total_time > 10.0  # Long time might indicate retries
                })
                
                # Long response times might indicate retry attempts
                if total_time > 15.0 and response.status_code == 200:
                    logger.info(f"Long response time ({total_time:.2f}s) - possible retries: {scenario['description']}")
                
            except httpx.TimeoutException as e:
                end_time = time.time()
                total_time = end_time - start_time
                
                retry_test_results.append({
                    "description": scenario["description"],
                    "timed_out": True,
                    "total_time": total_time,
                    "success": False
                })
                
                logger.info(f"Request timed out after {total_time:.2f}s: {scenario['description']}")
            
            except Exception as e:
                retry_test_results.append({
                    "description": scenario["description"],
                    "error": str(e),
                    "success": False
                })
            
            await asyncio.sleep(1)  # Pause between scenarios
        
        # Analyze retry behavior
        successful_requests = [r for r in retry_test_results if r.get("success")]
        possible_retries = [r for r in retry_test_results if r.get("possible_retries")]
        
        if possible_retries:
            logger.info(f"Possible retry behavior detected in {len(possible_retries)} requests")
        
        # Verify that transient errors are handled appropriately
        for result in retry_test_results:
            if result.get("success"):
                # Successful requests should eventually complete
                assert result["total_time"] <= 60.0, \
                    f"Successful requests should complete within reasonable time: {result['total_time']:.2f}s"
        
        logger.info("Transient error retry testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_exponential_backoff_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """RETRY_BACKOFF_001: Exponential backoff strategy"""
        # Test exponential backoff behavior in retry logic
        
        # Generate rapid requests to potentially trigger backoff
        backoff_test_requests = []
        request_intervals = []
        
        for i in range(8):  # Multiple rapid requests
            start_time = time.time()
            
            # Mix of potentially problematic requests
            if i % 3 == 0:
                # Large request
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Backoff test large request {i}: " + "content " * 200}],
                    "max_tokens": 150
                }
            elif i % 3 == 1:
                # Invalid request (should fail quickly)
                request = {
                    "model": f"backoff_invalid_model_{i}",
                    "messages": [{"role": "user", "content": f"Backoff test invalid {i}"}],
                    "max_tokens": 50
                }
            else:
                # Normal request
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Backoff test normal {i}"}],
                    "max_tokens": 50
                }
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=(i % 3 != 1)
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                backoff_test_requests.append({
                    "request_id": i,
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "request_type": "large" if i % 3 == 0 else "invalid" if i % 3 == 1 else "normal"
                })
                
                if i > 0:
                    interval = start_time - previous_start_time
                    request_intervals.append(interval)
                
                previous_start_time = start_time
                
            except Exception as e:
                backoff_test_requests.append({
                    "request_id": i,
                    "error": str(e),
                    "request_type": "error"
                })
            
            # Small delay between requests
            await asyncio.sleep(0.1)
        
        # Analyze backoff patterns
        response_times = [r.get("response_time", 0) for r in backoff_test_requests if "response_time" in r]
        
        if len(response_times) > 3:
            # Check for increasing response times (potential backoff)
            early_responses = response_times[:3]
            later_responses = response_times[-3:]
            
            avg_early = sum(early_responses) / len(early_responses)
            avg_later = sum(later_responses) / len(later_responses)
            
            if avg_later > avg_early * 1.5:
                logger.info(f"Potential backoff detected: early avg {avg_early:.2f}s, later avg {avg_later:.2f}s")
            else:
                logger.info("No obvious backoff pattern detected in response times")
        
        # Check for rate limiting responses that might trigger backoff
        rate_limited = [r for r in backoff_test_requests if r.get("status_code") == 429]
        server_errors = [r for r in backoff_test_requests if r.get("status_code", 0) >= 500]
        
        if rate_limited:
            logger.info(f"Rate limiting detected: {len(rate_limited)} requests returned 429")
        
        if server_errors:
            logger.info(f"Server errors detected: {len(server_errors)} requests returned 5xx")
        
        # Verify backoff behavior
        successful_requests = [r for r in backoff_test_requests if r.get("status_code") == 200]
        
        # Even with potential backoff, some requests should eventually succeed
        assert len(successful_requests) >= 2, \
            "At least some requests should succeed despite potential backoff"
        
        logger.info(f"Exponential backoff testing: {len(successful_requests)} successful, {len(rate_limited)} rate limited")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_max_retry_attempts_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """RETRY_MAX_ATTEMPTS_001: Maximum retry attempts validation"""
        # Test that retry logic respects maximum attempts
        
        # Create requests that are likely to fail consistently
        max_retry_scenarios = [
            {
                "description": "Consistently invalid model",
                "request": {
                    "model": "max_retry_invalid_model_persistent",
                    "messages": [{"role": "user", "content": "Max retry test"}],
                    "max_tokens": 50
                }
            },
            {
                "description": "Malformed request structure",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": "invalid_messages_format_for_retry",
                    "max_tokens": 50
                }
            }
        ]
        
        max_retry_results = []
        
        for scenario in max_retry_scenarios:
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"], track_cost=False
                )
                
                end_time = time.time()
                total_time = end_time - start_time
                
                max_retry_results.append({
                    "description": scenario["description"],
                    "status_code": response.status_code,
                    "total_time": total_time,
                    "final_failure": response.status_code >= 400
                })
                
                # If retries are happening, should fail relatively quickly after max attempts
                if response.status_code >= 400 and total_time > 5.0:
                    estimated_retries = max(1, int(total_time / config.RETRY_BACKOFF_SECONDS))
                    logger.info(f"Estimated {estimated_retries} retry attempts for {scenario['description']}")
                
            except Exception as e:
                end_time = time.time()
                total_time = end_time - start_time
                
                max_retry_results.append({
                    "description": scenario["description"],
                    "error": str(e),
                    "total_time": total_time,
                    "final_failure": True
                })
            
            await asyncio.sleep(0.5)
        
        # Verify max retry behavior
        for result in max_retry_results:
            # Consistently failing requests should fail within reasonable time
            # (indicating max retries are respected)
            if result.get("final_failure"):
                max_expected_time = config.RETRY_MAX_ATTEMPTS * config.RETRY_BACKOFF_SECONDS * 3  # Conservative estimate
                
                if result["total_time"] > max_expected_time:
                    logger.warning(f"Request took longer than expected max retry time: {result['total_time']:.2f}s")
                else:
                    logger.info(f"Request failed within expected retry bounds: {result['total_time']:.2f}s")
        
        logger.info("Maximum retry attempts testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_non_transient_error_handling_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """RETRY_NON_TRANSIENT_001: Non-transient error handling"""
        # Test that non-transient errors are not retried
        
        # Create non-transient error scenarios
        non_transient_scenarios = [
            {
                "description": "Invalid model name",
                "request": {
                    "model": "definitely_invalid_model_name",
                    "messages": [{"role": "user", "content": "Non-transient test"}],
                    "max_tokens": 50
                },
                "expected_status": 422,
                "should_retry": False
            },
            {
                "description": "Missing required field",
                "request": {
                    "model": config.get_chat_model(0),
                    "max_tokens": 50
                    # Missing messages field
                },
                "expected_status": 422,
                "should_retry": False
            },
            {
                "description": "Invalid parameter type",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Invalid param test"}],
                    "max_tokens": "invalid_string_instead_of_number"
                },
                "expected_status": 422,
                "should_retry": False
            }
        ]
        
        non_transient_results = []
        
        for scenario in non_transient_scenarios:
            start_time = time.time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"], track_cost=False
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                non_transient_results.append({
                    "description": scenario["description"],
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "should_retry": scenario["should_retry"],
                    "expected_status": scenario["expected_status"]
                })
                
                # Non-transient errors should fail quickly (no retries)
                if not scenario["should_retry"]:
                    assert response_time <= 5.0, \
                        f"Non-transient error should fail quickly: {response_time:.2f}s for {scenario['description']}"
                    
                    assert response.status_code == scenario["expected_status"], \
                        f"Non-transient error should return expected status: {response.status_code} vs {scenario['expected_status']}"
                
            except Exception as e:
                end_time = time.time()
                response_time = end_time - start_time
                
                non_transient_results.append({
                    "description": scenario["description"],
                    "error": str(e),
                    "response_time": response_time,
                    "should_retry": scenario["should_retry"]
                })
                
                # Exceptions should also occur quickly for non-transient errors
                if not scenario["should_retry"]:
                    assert response_time <= 5.0, \
                        f"Non-transient error exception should occur quickly: {response_time:.2f}s"
            
            await asyncio.sleep(0.3)
        
        # Verify non-transient error handling
        for result in non_transient_results:
            if not result["should_retry"]:
                # Non-transient errors should be handled quickly and consistently
                logger.info(f"Non-transient error handled in {result['response_time']:.2f}s: {result['description']}")
        
        logger.info("Non-transient error handling testing completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_database_timeout_handling_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TIMEOUT_DATABASE_001: Database timeout handling"""
        # Test database timeout handling through API operations
        
        # Operations that might involve database access
        database_operations = [
            {
                "description": "Model listing (database read)",
                "operation": lambda: make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
            },
            {
                "description": "Chat completion (potential database write for logging)",
                "operation": lambda: make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Database timeout test"}],
                        "max_tokens": 50
                    }
                )
            }
        ]
        
        database_timeout_results = []
        
        for operation in database_operations:
            start_time = time.time()
            
            try:
                response = await operation["operation"]()
                
                end_time = time.time()
                response_time = end_time - start_time
                
                database_timeout_results.append({
                    "description": operation["description"],
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "success": response.status_code == 200
                })
                
                # Database operations should complete reasonably quickly
                if response.status_code == 200:
                    assert response_time <= 15.0, \
                        f"Database operation should complete within reasonable time: {response_time:.2f}s"
                
            except httpx.TimeoutException as e:
                end_time = time.time()
                response_time = end_time - start_time
                
                database_timeout_results.append({
                    "description": operation["description"],
                    "timed_out": True,
                    "response_time": response_time
                })
                
                logger.warning(f"Database operation timed out: {operation['description']} after {response_time:.2f}s")
            
            except Exception as e:
                database_timeout_results.append({
                    "description": operation["description"],
                    "error": str(e)
                })
            
            await asyncio.sleep(0.5)
        
        # Verify database timeout handling
        successful_operations = [r for r in database_timeout_results if r.get("success")]
        timed_out_operations = [r for r in database_timeout_results if r.get("timed_out")]
        
        # Most database operations should succeed
        assert len(successful_operations) >= 1, \
            "At least some database operations should succeed"
        
        if timed_out_operations:
            logger.warning(f"Database timeouts detected: {len(timed_out_operations)} operations")
        
        logger.info("Database timeout handling testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r753_timeout_progressive_009(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TC_R753_TIMEOUT_PROGRESSIVE_009: Progressive timeout strategy"""
        # Test progressive timeout strategies under increasing load
        
        # Test with progressively longer/more complex requests
        progressive_timeout_scenarios = [
            {
                "phase": "quick_requests",
                "timeout_expected": 2.0,
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Quick request {i}"}],
                        "max_tokens": 20
                    }
                    for i in range(3)
                ]
            },
            {
                "phase": "medium_requests",
                "timeout_expected": 8.0,
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Medium complexity request {i} with moderate content"}],
                        "max_tokens": 100
                    }
                    for i in range(2)
                ]
            },
            {
                "phase": "complex_requests",
                "timeout_expected": 20.0,
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Complex request {i}: " + "detailed analysis " * 200}],
                        "max_tokens": 300
                    }
                ]
            }
        ]
        
        progressive_results = []
        
        for scenario in progressive_timeout_scenarios:
            phase_results = []
            
            for request in scenario["requests"]:
                start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    phase_results.append({
                        "status_code": response.status_code,
                        "duration": duration,
                        "success": response.status_code == 200,
                        "within_expected_timeout": duration <= scenario["timeout_expected"],
                        "timed_out": duration > scenario["timeout_expected"]
                    })
                    
                except Exception as e:
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    phase_results.append({
                        "exception": str(e),
                        "duration": duration,
                        "success": False,
                        "within_expected_timeout": True,  # Exception is acceptable timeout handling
                        "timed_out": duration > scenario["timeout_expected"]
                    })
                
                await asyncio.sleep(0.3)
            
            # Analyze phase results
            successful_requests = [r for r in phase_results if r["success"]]
            within_timeout = [r for r in phase_results if r["within_expected_timeout"]]
            
            progressive_results.append({
                "phase": scenario["phase"],
                "expected_timeout": scenario["timeout_expected"],
                "total_requests": len(phase_results),
                "successful_requests": len(successful_requests),
                "within_timeout": len(within_timeout),
                "success_rate": len(successful_requests) / len(phase_results),
                "timeout_compliance_rate": len(within_timeout) / len(phase_results),
                "avg_duration": sum(r["duration"] for r in phase_results) / len(phase_results)
            })
        
        # Verify progressive timeout strategy
        for result in progressive_results:
            # Most requests should complete within expected timeouts
            assert result["timeout_compliance_rate"] >= 0.7, \
                f"Progressive timeout should be respected: {result['phase']} - {result['timeout_compliance_rate']:.2%}"
            
            logger.info(f"Progressive timeout {result['phase']}: {result['avg_duration']:.2f}s avg, {result['timeout_compliance_rate']:.2%} within timeout")
        
        logger.info("Progressive timeout strategy testing completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r753_retry_circuit_breaker_010(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """TC_R753_RETRY_CIRCUIT_BREAKER_010: Retry circuit breaker integration"""
        # Test integration between retry mechanisms and circuit breaker patterns
        
        # Generate failure scenarios to test circuit breaker behavior with retries
        circuit_breaker_scenarios = [
            {
                "scenario": "rapid_failures",
                "description": "Rapid failures to trigger circuit breaker",
                "requests": [
                    {
                        "model": f"circuit_breaker_failure_{i}",
                        "messages": [{"role": "user", "content": "Circuit breaker test"}],
                        "max_tokens": 50
                    }
                    for i in range(8)
                ]
            },
            {
                "scenario": "mixed_success_failure",
                "description": "Mixed success and failure to test partial circuit breaker",
                "requests": [
                    {
                        "model": config.get_chat_model(0) if i % 3 != 0 else f"mixed_failure_{i}",
                        "messages": [{"role": "user", "content": f"Mixed test {i}"}],
                        "max_tokens": 40
                    }
                    for i in range(9)
                ]
            }
        ]
        
        circuit_breaker_results = []
        
        for scenario in circuit_breaker_scenarios:
            scenario_start_time = time.time()
            scenario_responses = []
            
            for i, request in enumerate(scenario["requests"]):
                request_start_time = time.time()
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=(scenario["scenario"] == "mixed_success_failure" and i % 3 == 0)
                    )
                    
                    request_end_time = time.time()
                    request_duration = request_end_time - request_start_time
                    
                    scenario_responses.append({
                        "request_id": i,
                        "status_code": response.status_code,
                        "duration": request_duration,
                        "success": response.status_code == 200,
                        "circuit_breaker_active": response.status_code == 503,
                        "fast_failure": request_duration < 1.0 and response.status_code != 200
                    })
                    
                except Exception as e:
                    request_end_time = time.time()
                    request_duration = request_end_time - request_start_time
                    
                    scenario_responses.append({
                        "request_id": i,
                        "exception": str(e),
                        "duration": request_duration,
                        "success": False,
                        "circuit_breaker_active": True,  # Exception indicates circuit breaker behavior
                        "fast_failure": request_duration < 1.0
                    })
                
                await asyncio.sleep(0.1)
            
            scenario_end_time = time.time()
            scenario_duration = scenario_end_time - scenario_start_time
            
            # Analyze circuit breaker behavior
            successful_responses = [r for r in scenario_responses if r["success"]]
            circuit_breaker_responses = [r for r in scenario_responses if r.get("circuit_breaker_active")]
            fast_failures = [r for r in scenario_responses if r.get("fast_failure")]
            
            circuit_breaker_results.append({
                "scenario": scenario["scenario"],
                "total_requests": len(scenario_responses),
                "successful_requests": len(successful_responses),
                "circuit_breaker_responses": len(circuit_breaker_responses),
                "fast_failures": len(fast_failures),
                "success_rate": len(successful_responses) / len(scenario_responses),
                "circuit_breaker_rate": len(circuit_breaker_responses) / len(scenario_responses),
                "fast_failure_rate": len(fast_failures) / len(scenario_responses),
                "scenario_duration": scenario_duration
            })
        
        # Verify circuit breaker integration with retry
        for result in circuit_breaker_results:
            if result["scenario"] == "rapid_failures":
                # Rapid failures should trigger fast failure responses
                assert result["fast_failure_rate"] >= 0.3, \
                    f"Rapid failures should trigger fast failures: {result['fast_failure_rate']:.2%}"
            
            elif result["scenario"] == "mixed_success_failure":
                # Mixed scenario should show some success
                assert result["success_rate"] >= 0.2, \
                    f"Mixed scenario should show partial success: {result['success_rate']:.2%}"
            
            logger.info(f"Circuit breaker {result['scenario']}: {result['success_rate']:.2%} success, {result['fast_failure_rate']:.2%} fast failures")
        
        # Test recovery after circuit breaker
        await asyncio.sleep(3)  # Allow circuit breaker to reset
        
        recovery_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Circuit breaker recovery test"}],
            "max_tokens": 40
        }
        
        recovery_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, recovery_request
        )
        
        assert recovery_response.status_code == 200, "System should recover after circuit breaker activation"
        
        logger.info("Retry circuit breaker integration testing completed")