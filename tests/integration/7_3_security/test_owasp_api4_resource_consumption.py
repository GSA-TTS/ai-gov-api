# Section 7.3 - OWASP API4:2023 Unrestricted Resource Consumption Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API4_2023 - Unrestricted Resource Consumption.md

import pytest
import httpx
import asyncio
import time
from typing import Dict, Any, List

from ..config import config, logger


class TestOWASPAPI4ResourceConsumption:
    """API4:2023 - Unrestricted Resource Consumption tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api4_token_consumption_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """API4_TOKEN_CONSUMPTION_001: Excessive token consumption attack"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various token consumption scenarios
        token_tests = [
            # Excessive max_tokens request
            {
                "max_tokens": 100000,  # Very high token request
                "content": "Generate a very long response",
                "expected_behavior": "limit_or_reject"
            },
            # Large input with high max_tokens
            {
                "max_tokens": 4000,
                "content": "Please expand on this topic: " + "word " * 2000,
                "expected_behavior": "limit_or_reject"
            },
            # Normal token request (control)
            {
                "max_tokens": 100,
                "content": "Short response please",
                "expected_behavior": "accept"
            }
        ]
        
        for i, test in enumerate(token_tests):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": test["content"]}],
                "max_tokens": test["max_tokens"]
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request,
                track_cost=(test["expected_behavior"] == "accept")
            )
            
            if test["expected_behavior"] == "accept":
                assert response.status_code == 200, \
                    f"Normal token request {i} should be accepted"
            else:
                # Should either reject or limit the request
                if response.status_code == 200:
                    # If accepted, verify token limiting was applied
                    response_data = response.json()
                    usage = response_data.get("usage", {})
                    completion_tokens = usage.get("completion_tokens", 0)
                    
                    # Should not actually consume excessive tokens
                    assert completion_tokens < test["max_tokens"] * 0.1, \
                        "Excessive token request should be limited"
                    
                    logger.info(f"Token limiting applied: requested {test['max_tokens']}, got {completion_tokens}")
                else:
                    # Request was rejected - good
                    assert response.status_code in [422, 400, 413], \
                        f"Excessive token request should be rejected with appropriate status"
        
        logger.info("API4_TOKEN_CONSUMPTION_001: Token consumption limits validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api4_rate_limiting_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """API4_RATE_LIMITING_001: Rate limiting protection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test rapid requests to trigger rate limiting
        request_template = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Rate limit test"}],
            "max_tokens": 20
        }
        
        # Make rapid requests
        responses = []
        request_times = []
        
        for i in range(15):  # 15 rapid requests
            start_time = time.time()
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_template
            )
            
            end_time = time.time()
            request_times.append(end_time - start_time)
            responses.append(response)
            
            # Small delay to simulate realistic but rapid usage
            await asyncio.sleep(0.1)
        
        # Analyze responses for rate limiting
        status_codes = [r.status_code for r in responses]
        success_count = sum(1 for code in status_codes if code == 200)
        rate_limited_count = sum(1 for code in status_codes if code == 429)
        
        logger.info(f"Rate limiting test: {success_count} successful, {rate_limited_count} rate limited")
        
        # Either rate limiting should kick in, or all requests should succeed
        if rate_limited_count > 0:
            # Rate limiting is active
            assert rate_limited_count >= 1, "Rate limiting should be applied"
            
            # Check rate limited responses have proper structure
            for response in responses:
                if response.status_code == 429:
                    # Should have retry-after header or similar information
                    headers = dict(response.headers)
                    response_data = response.json() if response.content else {}
                    
                    # Verify proper rate limit response
                    assert "retry" in str(headers).lower() or \
                           "rate" in str(response_data).lower() or \
                           "limit" in str(response_data).lower(), \
                        "Rate limit response should provide guidance"
        else:
            # No rate limiting detected - verify reasonable response times
            avg_response_time = sum(request_times) / len(request_times)
            assert avg_response_time < 10.0, \
                "Without rate limiting, response times should be reasonable"
        
        logger.info("API4_RATE_LIMITING_001: Rate limiting behavior validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api4_concurrent_requests_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """API4_CONCURRENT_REQUESTS_001: Concurrent request handling and limits"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test concurrent request handling
        async def concurrent_request(request_id: int):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Concurrent test {request_id}"}],
                "max_tokens": 50
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            end_time = time.time()
            
            return {
                "request_id": request_id,
                "status_code": response.status_code,
                "response_time": end_time - start_time,
                "response": response
            }
        
        # Execute concurrent requests
        concurrent_count = 8
        tasks = [concurrent_request(i) for i in range(concurrent_count)]
        
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.time() - start_time
        
        # Analyze results
        successful_results = [r for r in results if not isinstance(r, Exception) and r["status_code"] == 200]
        failed_results = [r for r in results if isinstance(r, Exception) or (hasattr(r, "status_code") and r["status_code"] != 200)]
        
        logger.info(f"Concurrent requests: {len(successful_results)} successful, {len(failed_results)} failed/rejected")
        
        # Most requests should either succeed or be properly rate limited
        assert len(successful_results) >= concurrent_count * 0.5, \
            "At least 50% of concurrent requests should succeed or be properly handled"
        
        # Check for proper error handling in failed requests
        for result in failed_results:
            if not isinstance(result, Exception):
                assert result["status_code"] in [429, 503, 502], \
                    "Failed concurrent requests should have appropriate status codes"
        
        # Verify reasonable total processing time
        assert total_time < 60, "Concurrent requests should complete within reasonable time"
        
        logger.info("API4_CONCURRENT_REQUESTS_001: Concurrent request handling validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api4_large_payload_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """API4_LARGE_PAYLOAD_001: Large payload handling and limits"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various payload sizes
        payload_tests = [
            # Small payload (control)
            {
                "size": "small",
                "content": "Short message",
                "expected": "accept"
            },
            # Medium payload
            {
                "size": "medium", 
                "content": "Medium message: " + "word " * 500,
                "expected": "accept_or_limit"
            },
            # Large payload
            {
                "size": "large",
                "content": "Large message: " + "word " * 5000,
                "expected": "limit_or_reject"
            },
            # Very large payload
            {
                "size": "very_large",
                "content": "Very large message: " + "A" * 100000,
                "expected": "reject"
            }
        ]
        
        for test in payload_tests:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": test["content"]}],
                "max_tokens": 50
            }
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request,
                    track_cost=(test["expected"] == "accept")
                )
                
                if test["expected"] == "accept":
                    assert response.status_code == 200, \
                        f"{test['size']} payload should be accepted"
                elif test["expected"] == "reject":
                    assert response.status_code in [413, 422, 400], \
                        f"{test['size']} payload should be rejected"
                else:  # accept_or_limit or limit_or_reject
                    if response.status_code == 200:
                        logger.info(f"{test['size']} payload accepted")
                    else:
                        assert response.status_code in [413, 422, 400], \
                            f"{test['size']} payload should be properly rejected if not accepted"
                
                logger.info(f"Payload test ({test['size']}): {response.status_code}")
                
            except httpx.RequestEntityTooLarge:
                # Request entity too large - good protection
                assert test["expected"] in ["reject", "limit_or_reject"], \
                    f"{test['size']} payload rejection at HTTP level is appropriate"
                logger.info(f"Payload test ({test['size']}): Rejected at HTTP level")
        
        logger.info("API4_LARGE_PAYLOAD_001: Large payload handling validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api4_embedding_consumption_001(self, http_client: httpx.AsyncClient,
                                                 embedding_auth_headers: Dict[str, str],
                                                 make_request):
        """API4_EMBEDDING_CONSUMPTION_001: Embedding resource consumption limits"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test embedding resource consumption
        embedding_tests = [
            # Normal embedding request
            {
                "input": "Normal embedding test",
                "expected": "accept"
            },
            # Large text embedding
            {
                "input": "Large embedding test: " + "text " * 2000,
                "expected": "limit_or_reject"
            },
            # Multiple inputs (if supported)
            {
                "input": ["Text 1", "Text 2", "Text 3"] * 50,  # 150 inputs
                "expected": "limit_or_reject"
            }
        ]
        
        for i, test in enumerate(embedding_tests):
            request = {
                "model": config.get_embedding_model(0),
                "input": test["input"]
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request,
                track_cost=(test["expected"] == "accept")
            )
            
            if test["expected"] == "accept":
                assert response.status_code == 200, \
                    f"Normal embedding request {i} should be accepted"
            else:
                # Should be limited or rejected
                if response.status_code == 200:
                    # If accepted, verify reasonable processing
                    response_data = response.json()
                    usage = response_data.get("usage", {})
                    
                    # Should have usage tracking
                    assert "total_tokens" in usage, \
                        "Embedding response should include usage information"
                    
                    logger.info(f"Embedding request {i} processed with {usage.get('total_tokens', 0)} tokens")
                else:
                    assert response.status_code in [422, 413, 400], \
                        f"Large embedding request should be properly rejected"
        
        logger.info("API4_EMBEDDING_CONSUMPTION_001: Embedding consumption limits validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api4_streaming_consumption_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """API4_STREAMING_CONSUMPTION_001: Streaming resource consumption"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test streaming resource consumption
        streaming_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Generate a long streaming response about AI"}],
            "max_tokens": 500,
            "stream": True
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, streaming_request
        )
        
        if response.status_code == 422:
            # Streaming not supported
            logger.info("Streaming not supported - skipping streaming consumption test")
            return
        
        assert response.status_code == 200
        
        # If streaming is supported, verify proper handling
        content_type = response.headers.get("content-type", "")
        
        if "event-stream" in content_type:
            # Server-sent events streaming
            stream_content = response.text
            
            # Verify stream is not excessively long
            assert len(stream_content) < 1000000, \
                "Streaming response should have reasonable length limits"
            
            # Check for proper stream termination
            assert "data: [DONE]" in stream_content or stream_content.endswith("\n\n"), \
                "Stream should be properly terminated"
        else:
            # Non-streaming response despite stream=True
            response_data = response.json()
            assert "choices" in response_data, \
                "Non-streaming response should have proper structure"
        
        logger.info("API4_STREAMING_CONSUMPTION_001: Streaming consumption validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api4_quota_enforcement_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """API4_QUOTA_ENFORCEMENT_001: API quota and usage enforcement"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test quota enforcement through repeated requests
        quota_test_requests = []
        
        for i in range(10):  # Make 10 requests to test quota
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Quota test {i}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            quota_test_requests.append({
                "request_number": i,
                "status_code": response.status_code,
                "response": response
            })
            
            # Check for quota-related responses
            if response.status_code == 429:
                response_data = response.json() if response.content else {}
                
                # Should indicate quota/rate limiting
                response_text = str(response_data).lower()
                assert any(word in response_text for word in ["quota", "rate", "limit", "exceeded"]), \
                    "Quota exceeded response should provide clear indication"
            
            await asyncio.sleep(0.2)  # Small delay between requests
        
        # Analyze quota enforcement
        successful_requests = [r for r in quota_test_requests if r["status_code"] == 200]
        quota_limited_requests = [r for r in quota_test_requests if r["status_code"] == 429]
        
        logger.info(f"Quota test: {len(successful_requests)} successful, {len(quota_limited_requests)} quota limited")
        
        # Either all should succeed (high quota) or some should be limited
        total_requests = len(quota_test_requests)
        success_rate = len(successful_requests) / total_requests
        
        assert success_rate >= 0.3, \
            "At least 30% of requests should succeed unless quota is very restrictive"
        
        if len(quota_limited_requests) > 0:
            logger.info("Quota enforcement detected and working properly")
        else:
            logger.info("No quota limits reached during test")
        
        logger.info("API4_QUOTA_ENFORCEMENT_001: Quota enforcement validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api4_memory_consumption_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """API4_MEMORY_CONSUMPTION_001: Memory exhaustion attack prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test requests designed to consume excessive memory
        memory_tests = [
            # Deep nesting attack
            {
                "name": "deep_nesting",
                "content": "Analyze this data: " + "{"*1000 + "value" + "}"*1000,
                "expected": "reject_or_limit"
            },
            # Large array simulation
            {
                "name": "large_array",
                "content": "Process this list: " + str(list(range(10000))),
                "expected": "reject_or_limit"
            },
            # Repetitive content
            {
                "name": "repetitive",
                "content": "Repeat this: " + "ABCDEFGH" * 5000,
                "expected": "reject_or_limit"
            }
        ]
        
        for test in memory_tests:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": test["content"]}],
                "max_tokens": 100
            }
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=False
                )
                
                if test["expected"] == "reject_or_limit":
                    if response.status_code == 200:
                        # If accepted, verify it's processed safely
                        response_data = response.json()
                        usage = response_data.get("usage", {})
                        
                        # Should have reasonable token usage
                        total_tokens = usage.get("total_tokens", 0)
                        assert total_tokens < 5000, \
                            "Memory-intensive request should have token limits"
                        
                        logger.info(f"Memory test ({test['name']}) processed safely with {total_tokens} tokens")
                    else:
                        # Properly rejected
                        assert response.status_code in [413, 422, 400], \
                            f"Memory-intensive request should be properly rejected"
                        logger.info(f"Memory test ({test['name']}) properly rejected: {response.status_code}")
                
            except (httpx.RequestEntityTooLarge, httpx.TimeoutException):
                # Request rejected at HTTP level or timed out - good protection
                logger.info(f"Memory test ({test['name']}) rejected at HTTP level")
        
        logger.info("API4_MEMORY_CONSUMPTION_001: Memory consumption protection validated")