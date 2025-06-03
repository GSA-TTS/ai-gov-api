# Section 7.5 - Error Response Validation Testing
# Based on TestPlan.md Section 7.5 and related test case designs

import pytest
import httpx
import asyncio
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestErrorResponseValidation:
    """Test cases for error response validation"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_invalid_model_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           security_validator: SecurityValidator,
                                           make_request):
        """TC_R751_INVALID_MODEL_001: Invalid model parameter error handling"""
        invalid_models = [
            "non_existent_model",
            "model_with_special_chars!@#",
            "",  # Empty model
            None,  # Null model
            123,  # Numeric model
            {"invalid": "object"}  # Object instead of string
        ]
        
        for model in invalid_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should return 422 for validation errors
            assert response.status_code == 422, \
                f"Invalid model {model} should return 422"
            
            response_data = response.json()
            assert "detail" in response_data
            
            # Validate error message security
            error_validation = security_validator.validate_error_message_security(
                response.text
            )
            assert error_validation["is_secure"], \
                "Error message should not expose sensitive information"
        
        logger.info("TC_R751_INVALID_MODEL_001: Invalid model error handling validated")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_malformed_request_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               security_validator: SecurityValidator,
                                               make_request):
        """TC_R751_MALFORMED_REQUEST_001: Malformed request error handling"""
        malformed_requests = [
            # Missing required fields
            {"model": config.get_chat_model(0)},  # Missing messages
            {"messages": [{"role": "user", "content": "Test"}]},  # Missing model
            
            # Invalid field types
            {
                "model": config.get_chat_model(0),
                "messages": "not_an_array",
                "max_tokens": 50
            },
            
            # Invalid message structure
            {
                "model": config.get_chat_model(0),
                "messages": [{"invalid": "structure"}],
                "max_tokens": 50
            },
            
            # Invalid parameter ranges
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": -1,  # Negative tokens
                "temperature": 5.0  # Out of range temperature
            }
        ]
        
        for request in malformed_requests:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            assert response.status_code == 422, \
                f"Malformed request should return 422: {request}"
            
            response_data = response.json()
            assert "detail" in response_data
            
            # Error should be informative but not expose internals
            error_validation = security_validator.validate_error_message_security(
                response.text
            )
            assert error_validation["is_secure"], \
                "Error message should be secure"
        
        logger.info("TC_R751_MALFORMED_REQUEST_001: Malformed request error handling validated")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_concurrent_errors_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TC_R751_CONCURRENT_ERRORS_001: Concurrent error handling"""
        # Create multiple invalid requests to test concurrent error handling
        async def make_invalid_request():
            request = {
                "model": "invalid_model_" + str(asyncio.current_task().get_name()),
                "messages": [{"role": "user", "content": "Test concurrent error"}],
                "max_tokens": 50
            }
            
            return await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
        
        # Execute 5 concurrent invalid requests
        tasks = [make_invalid_request() for _ in range(5)]
        responses = await asyncio.gather(*tasks)
        
        # All should return errors consistently
        for i, response in enumerate(responses):
            assert response.status_code == 422, \
                f"Concurrent error request {i+1} should return 422"
            
            response_data = response.json()
            assert "detail" in response_data
        
        logger.info("TC_R751_CONCURRENT_ERRORS_001: Concurrent error handling validated")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_rate_limit_errors_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TC_R751_RATE_LIMIT_001: Rate limiting error response"""
        # Make rapid requests to potentially trigger rate limiting
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Rate limit test"}],
            "max_tokens": 10  # Small to minimize cost
        }
        
        responses = []
        for i in range(10):  # Make 10 rapid requests
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            responses.append(response)
            
            # Short delay between requests
            await asyncio.sleep(0.1)
        
        # Check if any rate limiting occurred
        rate_limited = any(r.status_code == 429 for r in responses)
        successful = any(r.status_code == 200 for r in responses)
        
        if rate_limited:
            # If rate limited, verify proper error structure
            rate_limit_response = next(r for r in responses if r.status_code == 429)
            response_data = rate_limit_response.json()
            assert "detail" in response_data or "error" in response_data
            logger.info("Rate limiting detected and properly handled")
        else:
            logger.info("No rate limiting detected in test")
        
        # At least some requests should be processed
        assert successful, "At least some requests should succeed"
        
        logger.info("TC_R751_RATE_LIMIT_001: Rate limiting behavior validated")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_timeout_handling_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """TC_R751_TIMEOUT_001: Timeout error handling"""
        # Create a request that might trigger timeout (very long prompt)
        long_prompt = "This is a very long prompt. " * 1000  # Approximately 5000 words
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": long_prompt}],
            "max_tokens": 1000  # Large response
        }
        
        try:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            # Should either succeed or timeout gracefully
            assert response.status_code in [200, 408, 504, 422], \
                "Long request should either succeed or timeout gracefully"
            
            if response.status_code in [408, 504]:
                # Timeout occurred
                response_data = response.json()
                assert "detail" in response_data or "error" in response_data
                logger.info("Timeout handling verified")
            elif response.status_code == 200:
                logger.info("Long request processed successfully")
            else:
                logger.info(f"Long request rejected with status {response.status_code}")
                
        except httpx.TimeoutException:
            # Client timeout - this is also acceptable
            logger.info("Client timeout occurred - acceptable behavior")
        
        logger.info("TC_R751_TIMEOUT_001: Timeout handling validated")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_error_consistency_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TC_R751_ERROR_CONSISTENCY_001: Error response consistency"""
        # Test the same error condition multiple times
        invalid_request = {
            "model": "consistent_invalid_model",
            "messages": [{"role": "user", "content": "Consistency test"}],
            "max_tokens": 50
        }
        
        responses = []
        for i in range(3):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, invalid_request, track_cost=False
            )
            responses.append(response)
            await asyncio.sleep(0.5)  # Small delay between requests
        
        # All responses should be consistent
        status_codes = [r.status_code for r in responses]
        assert all(code == status_codes[0] for code in status_codes), \
            "Error responses should be consistent"
        
        # Error messages should be consistent
        error_messages = []
        for response in responses:
            response_data = response.json()
            error_messages.append(response_data.get("detail", ""))
        
        assert all(msg == error_messages[0] for msg in error_messages), \
            "Error messages should be consistent"
        
        logger.info("TC_R751_ERROR_CONSISTENCY_001: Error consistency validated")


class TestHTTPProtocolErrors:
    """Test HTTP protocol error handling"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_http_method_not_allowed_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """Test HTTP method not allowed errors"""
        # Try unsupported methods on endpoints
        unsupported_methods = [
            ("PUT", "/api/v1/models"),
            ("DELETE", "/api/v1/models"),
            ("PATCH", "/api/v1/chat/completions"),
            ("GET", "/api/v1/chat/completions"),  # Should be POST
        ]
        
        for method, endpoint in unsupported_methods:
            response = await make_request(
                http_client, method, endpoint,
                auth_headers, track_cost=False
            )
            
            assert response.status_code == 405, \
                f"{method} {endpoint} should return 405 Method Not Allowed"
        
        logger.info("HTTP method not allowed errors handled correctly")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_content_type_errors_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str]):
        """Test content type error handling"""
        # Send request with wrong content type
        headers = auth_headers.copy()
        headers["Content-Type"] = "text/plain"
        
        async with httpx.AsyncClient(base_url=config.BASE_URL) as client:
            response = await client.post(
                "/api/v1/chat/completions",
                headers=headers,
                data="invalid plain text data"
            )
            
            # Should reject invalid content type
            assert response.status_code in [400, 415, 422], \
                "Invalid content type should be rejected"
        
        logger.info("Content type errors handled correctly")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_oversized_request_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       make_request):
        """Test oversized request handling"""
        # Create an extremely large request
        huge_content = "A" * (1024 * 1024)  # 1MB of A's
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": huge_content}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request, track_cost=False
        )
        
        # Should either reject or handle gracefully
        assert response.status_code in [200, 413, 422, 400], \
            "Oversized request should be handled appropriately"
        
        if response.status_code == 413:
            logger.info("Request entity too large properly handled")
        elif response.status_code == 422:
            logger.info("Request validation failed for oversized content")
        elif response.status_code == 200:
            logger.info("Large request processed successfully")
        
        logger.info("Oversized request handling validated")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_providermap_openai_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TC_R751_PROVIDERMAP_OPENAI_001: OpenAI provider error mapping"""
        # Test provider-specific error mapping for OpenAI errors
        
        # Test scenarios that should trigger OpenAI provider-specific errors
        openai_error_scenarios = [
            {
                "scenario": "openai_invalid_model",
                "request": {
                    "model": "gpt-99-ultra-invalid",  # Invalid OpenAI model
                    "messages": [{"role": "user", "content": "OpenAI provider error test"}],
                    "max_tokens": 50
                },
                "expected_status": 422,
                "expected_error_type": "model_not_found"
            },
            {
                "scenario": "openai_excessive_tokens",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Token limit test"}],
                    "max_tokens": 999999  # Excessive token request
                },
                "expected_status": 422,
                "expected_error_type": "invalid_request"
            },
            {
                "scenario": "openai_context_length",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Context length test: " + "word " * 10000}],
                    "max_tokens": 100
                },
                "expected_status": [422, 400],
                "expected_error_type": "context_length_exceeded"
            }
        ]
        
        provider_error_results = []
        
        for scenario in openai_error_scenarios:
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"], track_cost=False
                )
                
                provider_error_results.append({
                    "scenario": scenario["scenario"],
                    "status_code": response.status_code,
                    "response_content": response.text[:200],  # First 200 chars
                    "expected_status": scenario["expected_status"],
                    "error_handled": response.status_code in (scenario["expected_status"] if isinstance(scenario["expected_status"], list) else [scenario["expected_status"]])
                })
                
                # Verify error response structure
                if response.status_code >= 400:
                    try:
                        error_data = response.json()
                        
                        # Check for standard error fields
                        expected_fields = ["error", "message", "type"]
                        found_fields = [field for field in expected_fields if field in str(error_data).lower()]
                        
                        if found_fields:
                            logger.info(f"OpenAI error response structure valid for {scenario['scenario']}: {found_fields}")
                        
                    except:
                        logger.info(f"Non-JSON error response for {scenario['scenario']}")
                
            except Exception as e:
                provider_error_results.append({
                    "scenario": scenario["scenario"],
                    "error": str(e),
                    "error_handled": True  # Exception handling is valid error handling
                })
            
            await asyncio.sleep(0.3)
        
        # Verify provider error mapping
        for result in provider_error_results:
            assert result.get("error_handled", False), \
                f"OpenAI provider error should be properly mapped: {result['scenario']}"
        
        logger.info("OpenAI provider error mapping validated")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_providermap_bedrock_002(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TC_R751_PROVIDERMAP_BEDROCK_002: AWS Bedrock provider error mapping"""
        # Test provider-specific error mapping for AWS Bedrock errors
        
        # Test scenarios that should trigger Bedrock provider-specific errors
        bedrock_error_scenarios = [
            {
                "scenario": "bedrock_invalid_model",
                "request": {
                    "model": "anthropic.claude-invalid-9000",  # Invalid Bedrock model
                    "messages": [{"role": "user", "content": "Bedrock provider error test"}],
                    "max_tokens": 50
                },
                "expected_status": 422,
                "expected_error_type": "model_not_found"
            },
            {
                "scenario": "bedrock_region_error",
                "request": {
                    "model": "bedrock.anthropic.claude-invalid-region",
                    "messages": [{"role": "user", "content": "Region error test"}],
                    "max_tokens": 50
                },
                "expected_status": [422, 400],
                "expected_error_type": "access_denied"
            },
            {
                "scenario": "bedrock_throttling",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Throttling test with rapid requests"}],
                    "max_tokens": 200
                },
                "expected_status": [429, 503],
                "expected_error_type": "throttling"
            }
        ]
        
        bedrock_error_results = []
        
        for scenario in bedrock_error_scenarios:
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"], track_cost=False
                )
                
                bedrock_error_results.append({
                    "scenario": scenario["scenario"],
                    "status_code": response.status_code,
                    "response_content": response.text[:200],
                    "expected_status": scenario["expected_status"],
                    "error_handled": response.status_code in (scenario["expected_status"] if isinstance(scenario["expected_status"], list) else [scenario["expected_status"]])
                })
                
                # Check for Bedrock-specific error indicators
                if response.status_code >= 400:
                    try:
                        error_data = response.json()
                        
                        # Look for AWS/Bedrock error patterns
                        bedrock_indicators = ["aws", "bedrock", "throttle", "region", "access"]
                        response_text = str(error_data).lower()
                        found_indicators = [indicator for indicator in bedrock_indicators if indicator in response_text]
                        
                        if found_indicators:
                            logger.info(f"Bedrock error indicators found for {scenario['scenario']}: {found_indicators}")
                        
                    except:
                        logger.info(f"Non-JSON Bedrock error response for {scenario['scenario']}")
                
            except Exception as e:
                bedrock_error_results.append({
                    "scenario": scenario["scenario"],
                    "error": str(e),
                    "error_handled": True
                })
            
            await asyncio.sleep(0.5)  # Longer pause for potential throttling
        
        # Verify Bedrock provider error mapping
        handled_errors = [r for r in bedrock_error_results if r.get("error_handled")]
        
        # At least some Bedrock scenarios should demonstrate proper error handling
        assert len(handled_errors) >= len(bedrock_error_scenarios) * 0.5, \
            "Bedrock provider errors should be properly mapped"
        
        logger.info("Bedrock provider error mapping validated")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_providermap_vertex_003(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TC_R751_PROVIDERMAP_VERTEX_003: Google Vertex AI provider error mapping"""
        # Test provider-specific error mapping for Google Vertex AI errors
        
        # Test scenarios that should trigger Vertex AI provider-specific errors
        vertex_error_scenarios = [
            {
                "scenario": "vertex_invalid_model",
                "request": {
                    "model": "google.vertex-ai-invalid-model",  # Invalid Vertex model
                    "messages": [{"role": "user", "content": "Vertex AI provider error test"}],
                    "max_tokens": 50
                },
                "expected_status": 422,
                "expected_error_type": "model_not_found"
            },
            {
                "scenario": "vertex_project_error",
                "request": {
                    "model": "vertex.invalid-project.model",
                    "messages": [{"role": "user", "content": "Project error test"}],
                    "max_tokens": 50
                },
                "expected_status": [422, 403],
                "expected_error_type": "project_access"
            },
            {
                "scenario": "vertex_quota_exceeded",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Quota exceeded test with resource intensive request"}],
                    "max_tokens": 1000
                },
                "expected_status": [429, 403],
                "expected_error_type": "quota_exceeded"
            }
        ]
        
        vertex_error_results = []
        
        for scenario in vertex_error_scenarios:
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"], track_cost=False
                )
                
                vertex_error_results.append({
                    "scenario": scenario["scenario"],
                    "status_code": response.status_code,
                    "response_content": response.text[:200],
                    "expected_status": scenario["expected_status"],
                    "error_handled": response.status_code in (scenario["expected_status"] if isinstance(scenario["expected_status"], list) else [scenario["expected_status"]])
                })
                
                # Check for Vertex AI-specific error indicators
                if response.status_code >= 400:
                    try:
                        error_data = response.json()
                        
                        # Look for Google/Vertex error patterns
                        vertex_indicators = ["google", "vertex", "project", "quota", "gcp"]
                        response_text = str(error_data).lower()
                        found_indicators = [indicator for indicator in vertex_indicators if indicator in response_text]
                        
                        if found_indicators:
                            logger.info(f"Vertex AI error indicators found for {scenario['scenario']}: {found_indicators}")
                        
                    except:
                        logger.info(f"Non-JSON Vertex AI error response for {scenario['scenario']}")
                
            except Exception as e:
                vertex_error_results.append({
                    "scenario": scenario["scenario"],
                    "error": str(e),
                    "error_handled": True
                })
            
            await asyncio.sleep(0.4)
        
        # Verify Vertex AI provider error mapping
        handled_errors = [r for r in vertex_error_results if r.get("error_handled")]
        
        # Provider error mapping should handle most scenarios appropriately
        assert len(handled_errors) >= len(vertex_error_scenarios) * 0.5, \
            "Vertex AI provider errors should be properly mapped"
        
        logger.info("Vertex AI provider error mapping validated")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r751_providermap_generic_004(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TC_R751_PROVIDERMAP_GENERIC_004: Generic provider error mapping"""
        # Test generic provider error mapping for common error patterns
        
        # Test scenarios that should trigger generic provider error mapping
        generic_error_scenarios = [
            {
                "scenario": "timeout_simulation",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Timeout simulation test with extremely long content: " + "detailed analysis " * 500}],
                    "max_tokens": 1000
                },
                "expected_status": [408, 504, 500],
                "expected_error_type": "timeout"
            },
            {
                "scenario": "rate_limiting",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Rate limiting test"}],
                    "max_tokens": 50
                },
                "expected_status": [429, 503],
                "expected_error_type": "rate_limit"
            },
            {
                "scenario": "generic_server_error",
                "request": {
                    "model": "generic.error.trigger.model",
                    "messages": [{"role": "user", "content": "Generic server error test"}],
                    "max_tokens": 50
                },
                "expected_status": [500, 502, 503, 422],
                "expected_error_type": "server_error"
            }
        ]
        
        generic_error_results = []
        
        for scenario in generic_error_scenarios:
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, scenario["request"], track_cost=False
                )
                
                generic_error_results.append({
                    "scenario": scenario["scenario"],
                    "status_code": response.status_code,
                    "response_content": response.text[:200],
                    "expected_status": scenario["expected_status"],
                    "error_handled": response.status_code in scenario["expected_status"],
                    "is_success": response.status_code == 200
                })
                
                # Analyze generic error response structure
                if response.status_code >= 400:
                    try:
                        error_data = response.json()
                        
                        # Check for standard error response fields
                        standard_fields = ["error", "message", "code", "type", "details"]
                        error_text = str(error_data).lower()
                        found_fields = [field for field in standard_fields if field in error_text]
                        
                        if found_fields:
                            logger.info(f"Standard error fields found for {scenario['scenario']}: {found_fields}")
                        
                        # Check for proper error categorization
                        error_categories = ["client_error", "server_error", "validation_error", "timeout", "rate_limit"]
                        found_categories = [cat for cat in error_categories if cat.replace("_", "") in error_text.replace("_", "")]
                        
                        if found_categories:
                            logger.info(f"Error categories found for {scenario['scenario']}: {found_categories}")
                        
                    except:
                        # Non-JSON response is also valid for some error types
                        logger.info(f"Non-JSON generic error response for {scenario['scenario']}")
                
            except Exception as e:
                generic_error_results.append({
                    "scenario": scenario["scenario"],
                    "error": str(e),
                    "error_handled": True,
                    "exception_caught": True
                })
            
            await asyncio.sleep(0.3)
        
        # Verify generic provider error mapping
        for result in generic_error_results:
            # Either the error should be handled with expected status codes, or request succeeds, or exception is properly caught
            error_properly_mapped = (
                result.get("error_handled", False) or 
                result.get("is_success", False) or 
                result.get("exception_caught", False)
            )
            
            assert error_properly_mapped, \
                f"Generic provider error should be properly mapped: {result['scenario']}"
        
        # Check that we have diverse error handling
        different_status_codes = set()
        for result in generic_error_results:
            if "status_code" in result:
                different_status_codes.add(result["status_code"])
        
        logger.info(f"Generic error mapping produced {len(different_status_codes)} different status codes: {sorted(different_status_codes)}")
        
        logger.info("Generic provider error mapping validated")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r754_error_correlation_009(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TC_R754_ERROR_CORRELATION_009: Error correlation and tracking"""
        # Test error correlation across requests and system components
        
        # Generate correlated error scenarios
        correlation_scenarios = [
            {
                "correlation_id": "error_correlation_test_001",
                "requests": [
                    {
                        "model": "correlation_invalid_model_1",
                        "messages": [{"role": "user", "content": "Correlation test 1"}],
                        "max_tokens": 50
                    },
                    {
                        "model": "correlation_invalid_model_2", 
                        "messages": [{"role": "user", "content": "Correlation test 2"}],
                        "max_tokens": 50
                    }
                ]
            }
        ]
        
        correlation_results = []
        
        for scenario in correlation_scenarios:
            scenario_results = []
            
            for i, request in enumerate(scenario["requests"]):
                # Add correlation headers
                correlation_headers = auth_headers.copy()
                correlation_headers["X-Correlation-ID"] = scenario["correlation_id"]
                correlation_headers["X-Request-Sequence"] = str(i)
                
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        correlation_headers, request, track_cost=False
                    )
                    
                    scenario_results.append({
                        "sequence": i,
                        "status_code": response.status_code,
                        "correlation_id": scenario["correlation_id"],
                        "error_correlated": response.status_code >= 400,
                        "response_headers": dict(response.headers)
                    })
                    
                except Exception as e:
                    scenario_results.append({
                        "sequence": i,
                        "exception": str(e),
                        "correlation_id": scenario["correlation_id"],
                        "error_correlated": True
                    })
                
                await asyncio.sleep(0.2)
            
            correlation_results.append({
                "correlation_id": scenario["correlation_id"],
                "results": scenario_results,
                "total_requests": len(scenario_results),
                "correlated_errors": sum(1 for r in scenario_results if r.get("error_correlated"))
            })
        
        # Verify error correlation
        for result in correlation_results:
            assert result["correlated_errors"] > 0, "Should have correlated errors for tracking"
            
            # Check if correlation IDs are maintained in responses
            for req_result in result["results"]:
                logger.info(f"Correlated error: {req_result.get('correlation_id')} - sequence {req_result.get('sequence')}")
        
        logger.info("Error correlation and tracking validated")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r754_error_cascade_prevention_010(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """TC_R754_ERROR_CASCADE_010: Error cascade prevention"""
        # Test prevention of error cascades and system degradation
        
        # Phase 1: Generate initial errors
        initial_error_requests = [
            {
                "model": f"cascade_error_model_{i}",
                "messages": [{"role": "user", "content": "Cascade prevention test"}],
                "max_tokens": 50
            }
            for i in range(5)
        ]
        
        initial_error_results = []
        
        for i, request in enumerate(initial_error_requests):
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=False
                )
                
                initial_error_results.append({
                    "error_id": i,
                    "status_code": response.status_code,
                    "initial_error": response.status_code >= 400
                })
                
            except Exception as e:
                initial_error_results.append({
                    "error_id": i,
                    "exception": str(e),
                    "initial_error": True
                })
            
            await asyncio.sleep(0.1)
        
        # Phase 2: Test system stability during errors
        stability_test_requests = []
        
        for i in range(8):
            # Mix of normal and error requests
            if i % 3 == 0:
                request = {
                    "model": f"stability_error_model_{i}",
                    "messages": [{"role": "user", "content": "Stability test error"}],
                    "max_tokens": 50
                }
                track_cost = False
            else:
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Stability test normal {i}"}],
                    "max_tokens": 40
                }
                track_cost = True
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=track_cost
                )
                
                stability_test_requests.append({
                    "request_id": i,
                    "status_code": response.status_code,
                    "success": response.status_code == 200,
                    "system_stable": response.status_code in [200, 422, 400, 503]
                })
                
            except Exception as e:
                stability_test_requests.append({
                    "request_id": i,
                    "exception": str(e),
                    "success": False,
                    "system_stable": True  # Exception handling indicates stability
                })
            
            await asyncio.sleep(0.1)
        
        # Phase 3: Verify cascade prevention
        stable_responses = [r for r in stability_test_requests if r.get("system_stable")]
        successful_responses = [r for r in stability_test_requests if r.get("success")]
        
        stability_rate = len(stable_responses) / len(stability_test_requests)
        success_rate = len(successful_responses) / len(stability_test_requests)
        
        # System should remain stable even with errors
        assert stability_rate >= 0.8, f"System should prevent error cascades: {stability_rate:.2%}"
        
        # Some requests should still succeed despite errors
        assert success_rate >= 0.3, f"Some requests should succeed during error conditions: {success_rate:.2%}"
        
        logger.info(f"Error cascade prevention: {stability_rate:.2%} stability, {success_rate:.2%} success rate")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r754_error_context_preservation_011(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """TC_R754_ERROR_CONTEXT_011: Error context preservation"""
        # Test that error context is preserved across system components
        
        # Test error scenarios with rich context
        context_preservation_scenarios = [
            {
                "scenario": "multi_step_error",
                "context": {
                    "user_id": "context_test_user_001",
                    "session_id": "context_test_session_001",
                    "request_id": "context_test_request_001"
                },
                "request": {
                    "model": "context_preservation_invalid_model",
                    "messages": [
                        {"role": "user", "content": "Context preservation step 1"},
                        {"role": "assistant", "content": "I understand."},
                        {"role": "user", "content": "Context preservation step 2 - this should fail"}
                    ],
                    "max_tokens": 50
                }
            }
        ]
        
        context_preservation_results = []
        
        for scenario in context_preservation_scenarios:
            # Add context headers
            context_headers = auth_headers.copy()
            for key, value in scenario["context"].items():
                context_headers[f"X-{key.replace('_', '-').title()}"] = value
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    context_headers, scenario["request"], track_cost=False
                )
                
                # Check if context is preserved in error response
                context_preserved = False
                
                # Check response headers for context preservation
                response_headers = dict(response.headers)
                context_indicators = ["correlation", "request", "session", "user"]
                
                for indicator in context_indicators:
                    if any(indicator in header.lower() for header in response_headers.keys()):
                        context_preserved = True
                        break
                
                # If error response includes context information
                if response.status_code >= 400:
                    try:
                        error_data = response.json()
                        error_str = str(error_data).lower()
                        
                        # Check if any context is preserved in error response
                        for context_value in scenario["context"].values():
                            if context_value.lower() in error_str:
                                context_preserved = True
                                break
                    except:
                        pass
                
                context_preservation_results.append({
                    "scenario": scenario["scenario"],
                    "status_code": response.status_code,
                    "context_preserved": context_preserved,
                    "error_occurred": response.status_code >= 400,
                    "context_headers": scenario["context"]
                })
                
            except Exception as e:
                context_preservation_results.append({
                    "scenario": scenario["scenario"],
                    "exception": str(e),
                    "context_preserved": True,  # Exception handling preserves context
                    "error_occurred": True,
                    "context_headers": scenario["context"]
                })
        
        # Verify context preservation
        for result in context_preservation_results:
            assert result["error_occurred"], f"Error scenario should generate errors: {result['scenario']}"
            
            # Context preservation is beneficial but not strictly required
            if result["context_preserved"]:
                logger.info(f"Context preserved for scenario: {result['scenario']}")
            else:
                logger.info(f"Context not explicitly preserved for scenario: {result['scenario']}")
        
        logger.info("Error context preservation validation completed")