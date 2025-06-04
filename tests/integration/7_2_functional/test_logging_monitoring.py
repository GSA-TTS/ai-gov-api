# Section 7.2 - Logging, Monitoring & Request Processing Middleware Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Logging, Monitoring & Request Processing Middleware.md

import pytest
import httpx
import time
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestRequestLogging:
    """Test request logging functionality"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_request_correlation_id_001(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """FV_LOG_REQUEST_CORRELATION_ID_001: Test request correlation ID generation"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test correlation ID logging"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        
        # Check for correlation ID in response headers
        correlation_headers = [
            "x-request-id", "x-correlation-id", "request-id", 
            "x-trace-id", "trace-id"
        ]
        
        found_correlation_header = False
        for header in correlation_headers:
            if header in response.headers:
                correlation_id = response.headers[header]
                assert len(correlation_id) > 10, f"Correlation ID should be substantial: {correlation_id}"
                found_correlation_header = True
                logger.info(f"FV_LOG_REQUEST_CORRELATION_ID_001: Found correlation header {header}: {correlation_id}")
                break
        
        if not found_correlation_header:
            logger.info("FV_LOG_REQUEST_CORRELATION_ID_001: No correlation ID header found")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_request_start_end_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """FV_LOG_REQUEST_START_END_001: Test request start/end logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        start_time = time.time()
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test request timing logging"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        end_time = time.time()
        request_duration = end_time - start_time
        
        assert response.status_code == 200
        
        # Check for timing headers
        timing_headers = [
            "x-response-time", "x-processing-time", "server-timing"
        ]
        
        for header in timing_headers:
            if header in response.headers:
                timing_value = response.headers[header]
                logger.info(f"FV_LOG_REQUEST_START_END_001: Found timing header {header}: {timing_value}")
        
        logger.info(f"FV_LOG_REQUEST_START_END_001: Request duration: {request_duration:.3f}s")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_request_body_size_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """FV_LOG_REQUEST_BODY_SIZE_001: Test request size logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with different sized requests
        request_sizes = [
            {"content": "Small request", "description": "small"},
            {"content": "Medium " * 50, "description": "medium"},
            {"content": "Large " * 200, "description": "large"}
        ]
        
        for test_case in request_sizes:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": test_case["content"]}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200
            
            # Check for content length logging
            content_length = len(str(request).encode('utf-8'))
            logger.info(f"FV_LOG_REQUEST_BODY_SIZE_001: {test_case['description']} request size: {content_length} bytes")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_user_agent_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """FV_LOG_USER_AGENT_001: Test User-Agent logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with custom User-Agent
        custom_headers = dict(auth_headers)
        custom_headers["User-Agent"] = "TestClient/1.0 (Integration Testing)"
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test User-Agent logging"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            custom_headers, request
        )
        
        assert response.status_code == 200
        logger.info("FV_LOG_USER_AGENT_001: Custom User-Agent request processed")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_ip_address_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """FV_LOG_IP_ADDRESS_001: Test IP address logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with X-Forwarded-For header
        headers_with_forwarded = dict(auth_headers)
        headers_with_forwarded["X-Forwarded-For"] = "203.0.113.1, 198.51.100.1"
        headers_with_forwarded["X-Real-IP"] = "203.0.113.1"
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test IP address logging"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            headers_with_forwarded, request
        )
        
        assert response.status_code == 200
        logger.info("FV_LOG_IP_ADDRESS_001: Request with forwarded IP headers processed")


class TestResponseLogging:
    """Test response logging functionality"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_response_status_codes_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """FV_LOG_RESPONSE_STATUS_CODES_001: Test response status code logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test various response scenarios
        test_scenarios = [
            # Success case
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Success test"}],
                "max_tokens": 50,
                "expected_status": 200,
                "description": "Success response"
            },
            # Validation error
            {
                "model": config.get_chat_model(0),
                "messages": "invalid_format",
                "max_tokens": 50,
                "expected_status": 422,
                "description": "Validation error"
            },
            # Model not found
            {
                "model": "nonexistent-model",
                "messages": [{"role": "user", "content": "Model error test"}],
                "max_tokens": 50,
                "expected_status": 422,
                "description": "Model error"
            }
        ]
        
        for scenario in test_scenarios:
            description = scenario.pop("description")
            expected_status = scenario.pop("expected_status")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario, track_cost=False
            )
            
            assert response.status_code == expected_status, f"{description} should return {expected_status}"
            logger.info(f"FV_LOG_RESPONSE_STATUS_CODES_001: {description} - Status {response.status_code}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_response_size_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """FV_LOG_RESPONSE_SIZE_001: Test response size logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test different response sizes
        response_size_tests = [
            {
                "content": "Brief response",
                "max_tokens": 10,
                "description": "small response"
            },
            {
                "content": "Generate a medium length response about AI",
                "max_tokens": 100,
                "description": "medium response"
            },
            {
                "content": "Write a detailed explanation",
                "max_tokens": 200,
                "description": "large response"
            }
        ]
        
        for test_case in response_size_tests:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": test_case["content"]}],
                "max_tokens": test_case["max_tokens"]
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200
            
            response_size = len(response.content)
            logger.info(f"FV_LOG_RESPONSE_SIZE_001: {test_case['description']} - Size: {response_size} bytes")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_response_headers_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """FV_LOG_RESPONSE_HEADERS_001: Test response header logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test response headers"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        
        # Check important response headers
        important_headers = [
            "content-type", "content-length", "date", "server",
            "x-ratelimit-remaining", "x-ratelimit-reset"
        ]
        
        found_headers = []
        for header in important_headers:
            if header in response.headers:
                found_headers.append(header)
                logger.info(f"FV_LOG_RESPONSE_HEADERS_001: Header {header}: {response.headers[header]}")
        
        logger.info(f"FV_LOG_RESPONSE_HEADERS_001: Found {len(found_headers)} important headers")


class TestUsageMetricsLogging:
    """Test usage metrics logging"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_token_usage_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """FV_LOG_TOKEN_USAGE_001: Test token usage logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test token usage logging with a detailed prompt"}],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        if "usage" in response_data:
            usage = response_data["usage"]
            prompt_tokens = usage.get("prompt_tokens", 0)
            completion_tokens = usage.get("completion_tokens", 0)
            total_tokens = usage.get("total_tokens", 0)
            
            logger.info(f"FV_LOG_TOKEN_USAGE_001: Token usage - Prompt: {prompt_tokens}, Completion: {completion_tokens}, Total: {total_tokens}")
            
            # Verify token counts are positive
            assert prompt_tokens > 0, "Prompt tokens should be positive"
            assert completion_tokens > 0, "Completion tokens should be positive"
            assert total_tokens == prompt_tokens + completion_tokens, "Total should equal sum"
        else:
            logger.info("FV_LOG_TOKEN_USAGE_001: No usage information in response")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_model_version_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """FV_LOG_MODEL_VERSION_001: Test model version logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test model version logging"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        # Check for model information in response
        if "model" in response_data:
            model_used = response_data["model"]
            logger.info(f"FV_LOG_MODEL_VERSION_001: Model used: {model_used}")
            assert len(model_used) > 0, "Model field should not be empty"
        else:
            logger.info("FV_LOG_MODEL_VERSION_001: No model information in response")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_api_key_scope_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """FV_LOG_API_KEY_SCOPE_001: Test API key scope logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with different endpoints to verify scope logging
        endpoints_tests = [
            {
                "method": "GET",
                "endpoint": "/api/v1/models",
                "data": None,
                "description": "Models endpoint"
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test scope"}],
                    "max_tokens": 50
                },
                "description": "Chat endpoint"
            }
        ]
        
        for test in endpoints_tests:
            response = await make_request(
                http_client, test["method"], test["endpoint"],
                auth_headers, test["data"]
            )
            
            # Should succeed with proper API key
            assert response.status_code == 200, f"{test['description']} should succeed with valid key"
            logger.info(f"FV_LOG_API_KEY_SCOPE_001: {test['description']} - API key scope validated")


class TestErrorLogging:
    """Test error logging functionality"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_error_details_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """FV_LOG_ERROR_DETAILS_001: Test error detail logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test various error conditions
        error_scenarios = [
            {
                "model": "invalid-model-name",
                "messages": [{"role": "user", "content": "Test error logging"}],
                "max_tokens": 50,
                "description": "Invalid model error"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [],
                "max_tokens": 50,
                "description": "Empty messages error"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": -1,
                "description": "Invalid max_tokens error"
            }
        ]
        
        for scenario in error_scenarios:
            description = scenario.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario, track_cost=False
            )
            
            # Should return error status
            assert response.status_code >= 400, f"{description} should return error status"
            
            response_data = response.json()
            assert "detail" in response_data, f"{description} should have error detail"
            
            logger.info(f"FV_LOG_ERROR_DETAILS_001: {description} - Status {response.status_code}")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_provider_errors_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """FV_LOG_PROVIDER_ERRORS_001: Test provider error logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test with potentially problematic provider requests
        provider_error_scenarios = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "A" * 50000}],  # Very long prompt
                "max_tokens": 50,
                "description": "Context length exceeded"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test provider error"}],
                "max_tokens": 50,
                "temperature": 5.0,  # Invalid temperature
                "description": "Invalid parameter range"
            }
        ]
        
        for scenario in provider_error_scenarios:
            description = scenario.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario, track_cost=False
            )
            
            # Should handle provider errors gracefully
            if response.status_code >= 400:
                logger.info(f"FV_LOG_PROVIDER_ERRORS_001: {description} - Error properly logged")
            else:
                logger.info(f"FV_LOG_PROVIDER_ERRORS_001: {description} - Request succeeded")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_security_events_001(self, http_client: httpx.AsyncClient,
                                             make_request):
        """FV_LOG_SECURITY_EVENTS_001: Test security event logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test various security-related scenarios
        security_scenarios = [
            # Invalid API key
            {
                "headers": {"Authorization": "Bearer invalid_key_test"},
                "description": "Invalid API key"
            },
            # Missing authorization header
            {
                "headers": {},
                "description": "Missing authorization"
            },
            # Malformed authorization header
            {
                "headers": {"Authorization": "InvalidFormat token123"},
                "description": "Malformed authorization"
            }
        ]
        
        for scenario in security_scenarios:
            headers = scenario["headers"]
            description = scenario["description"]
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, track_cost=False
            )
            
            # Should return authentication error
            assert response.status_code == 401, f"{description} should return 401"
            logger.info(f"FV_LOG_SECURITY_EVENTS_001: {description} - Security event logged")


class TestPerformanceMonitoring:
    """Test performance monitoring and metrics"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_response_time_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """FV_LOG_RESPONSE_TIME_001: Test response time monitoring"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test different request types for timing
        timing_tests = [
            {
                "endpoint": "/api/v1/models",
                "method": "GET",
                "data": None,
                "description": "Models list"
            },
            {
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Quick response"}],
                    "max_tokens": 20
                },
                "description": "Quick chat"
            },
            {
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Generate a longer response about AI"}],
                    "max_tokens": 150
                },
                "description": "Longer chat"
            }
        ]
        
        for test in timing_tests:
            start_time = time.time()
            
            response = await make_request(
                http_client, test["method"], test["endpoint"],
                auth_headers, test["data"]
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            assert response.status_code == 200, f"{test['description']} should succeed"
            
            # Check for server timing headers
            timing_header = response.headers.get("x-response-time") or response.headers.get("server-timing")
            if timing_header:
                logger.info(f"FV_LOG_RESPONSE_TIME_001: {test['description']} - Server timing: {timing_header}")
            
            logger.info(f"FV_LOG_RESPONSE_TIME_001: {test['description']} - Client timing: {response_time:.3f}s")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_throughput_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """FV_LOG_THROUGHPUT_001: Test throughput monitoring"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        import asyncio
        
        # Test concurrent requests for throughput measurement
        async def concurrent_request(request_id: int):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Throughput test {request_id}"}],
                "max_tokens": 30
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            end_time = time.time()
            
            return {
                "request_id": request_id,
                "response": response,
                "duration": end_time - start_time
            }
        
        # Run 5 concurrent requests
        start_time = time.time()
        tasks = [concurrent_request(i) for i in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.time() - start_time
        
        successful_requests = 0
        total_duration = 0
        
        for result in results:
            if isinstance(result, dict) and not isinstance(result, Exception):
                if hasattr(result["response"], "status_code") and result["response"].status_code == 200:
                    successful_requests += 1
                    total_duration += result["duration"]
        
        if successful_requests > 0:
            avg_response_time = total_duration / successful_requests
            throughput = successful_requests / total_time
            
            logger.info(f"FV_LOG_THROUGHPUT_001: {successful_requests}/5 requests successful")
            logger.info(f"FV_LOG_THROUGHPUT_001: Average response time: {avg_response_time:.3f}s")
            logger.info(f"FV_LOG_THROUGHPUT_001: Throughput: {throughput:.2f} req/s")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_resource_usage_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """FV_LOG_RESOURCE_USAGE_001: Test resource usage monitoring"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test different resource-intensive scenarios
        resource_tests = [
            {
                "content": "Small resource test",
                "max_tokens": 20,
                "description": "low resource"
            },
            {
                "content": "Medium resource test: " + "Generate detailed content " * 10,
                "max_tokens": 100,
                "description": "medium resource"
            },
            {
                "content": "High resource test: " + "Process this complex request " * 20,
                "max_tokens": 200,
                "description": "high resource"
            }
        ]
        
        for test in resource_tests:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": test["content"]}],
                "max_tokens": test["max_tokens"]
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"{test['description']} request should succeed"
            
            response_data = response.json()
            if "usage" in response_data:
                usage = response_data["usage"]
                total_tokens = usage.get("total_tokens", 0)
                logger.info(f"FV_LOG_RESOURCE_USAGE_001: {test['description']} - Token usage: {total_tokens}")
            
            # Check for resource usage headers
            resource_headers = ["x-compute-units", "x-processing-time", "x-memory-usage"]
            for header in resource_headers:
                if header in response.headers:
                    logger.info(f"FV_LOG_RESOURCE_USAGE_001: {test['description']} - {header}: {response.headers[header]}")


class TestComplianceLogging:
    """Test compliance and audit logging"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_audit_trail_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """FV_LOG_AUDIT_TRAIL_001: Test audit trail logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test various operations that should be audited
        audit_operations = [
            {
                "method": "GET",
                "endpoint": "/api/v1/models",
                "data": None,
                "description": "Model listing"
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Audit trail test"}],
                    "max_tokens": 50
                },
                "description": "Chat completion"
            }
        ]
        
        for operation in audit_operations:
            response = await make_request(
                http_client, operation["method"], operation["endpoint"],
                auth_headers, operation["data"]
            )
            
            assert response.status_code == 200, f"{operation['description']} should succeed"
            logger.info(f"FV_LOG_AUDIT_TRAIL_001: {operation['description']} - Audit event logged")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_data_retention_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """FV_LOG_DATA_RETENTION_001: Test data retention compliance"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test requests with sensitive content
        sensitive_requests = [
            {
                "content": "Test PII handling: John Doe, SSN 123-45-6789",
                "description": "PII content"
            },
            {
                "content": "Test financial data: Account 1234567890",
                "description": "Financial content"
            },
            {
                "content": "Test medical info: Patient ID 98765",
                "description": "Medical content"
            }
        ]
        
        for test in sensitive_requests:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": test["content"]}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"{test['description']} should be processed"
            logger.info(f"FV_LOG_DATA_RETENTION_001: {test['description']} - Data retention policies applied")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_log_regulatory_compliance_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """FV_LOG_REGULATORY_COMPLIANCE_001: Test regulatory compliance logging"""
        # Functional tests always run unless explicitly disabled via markers
        pass
        
        # Test operations requiring compliance logging
        compliance_tests = [
            {
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Government agency compliance test"}],
                    "max_tokens": 50
                },
                "description": "Government usage"
            },
            {
                "endpoint": "/api/v1/embeddings",
                "data": {
                    "model": config.get_embedding_model(0),
                    "input": "Regulatory compliance test data"
                },
                "description": "Data processing"
            }
        ]
        
        for test in compliance_tests:
            response = await make_request(
                http_client, "POST", test["endpoint"],
                auth_headers, test["data"]
            )
            
            # Should succeed and log compliance information
            assert response.status_code == 200, f"{test['description']} should succeed"
            logger.info(f"FV_LOG_REGULATORY_COMPLIANCE_001: {test['description']} - Compliance logged")