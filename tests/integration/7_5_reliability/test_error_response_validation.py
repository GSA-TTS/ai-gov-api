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