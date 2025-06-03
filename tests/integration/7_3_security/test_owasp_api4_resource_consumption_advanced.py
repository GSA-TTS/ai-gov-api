# Section 7.3 - Advanced OWASP API4:2023 Resource Consumption Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API4_2023 - Unrestricted Resource Consumption.md
# Implements missing test cases for advanced resource consumption security

import pytest
import httpx
import os
import asyncio
from typing import Dict, Any, List
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.security_fixtures import SecurityFixtures
from fixtures.multimodal_fixtures import MultiModalFixtures
from utils.security_validators import SecurityValidator


class TestOWASPAPI4ResourceConsumptionAdvanced:
    """Advanced tests for OWASP API4:2023 - Unrestricted Resource Consumption"""
    
    @pytest.mark.security
    @pytest.mark.owasp_api4
    @pytest.mark.asyncio
    async def test_api4_memory_consumption_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             security_validator: SecurityValidator,
                                             make_request):
        """API4_MEMORY_001: Memory Consumption Limits Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various memory consumption scenarios
        memory_consumption_tests = [
            {
                "description": "Extremely large single message",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "A" * 100000}],  # 100KB message
                    "max_tokens": 10
                },
                "expected_limit": "message_size"
            },
            {
                "description": "Large number of messages",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Message {i}"} for i in range(5000)],
                    "max_tokens": 10
                },
                "expected_limit": "message_count"
            },
            {
                "description": "Deeply nested message content",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "nested " * 10000}],
                    "max_tokens": 10
                },
                "expected_limit": "content_complexity"
            },
            {
                "description": "Large embedding input",
                "request_data": {
                    "model": config.get_embedding_models()[0] if config.get_embedding_models() else "test-embedding",
                    "input": ["Text chunk " * 1000 for _ in range(100)]  # Large batch
                },
                "endpoint": "/api/v1/embeddings",
                "expected_limit": "embedding_batch_size"
            }
        ]
        
        for test_case in memory_consumption_tests:
            endpoint = test_case.get("endpoint", "/api/v1/chat/completions")
            
            response = await make_request(
                http_client, "POST", endpoint,
                auth_headers, test_case["request_data"]
            )
            
            # Should handle large memory requests gracefully
            assert response.status_code in [200, 400, 413, 422], \
                f"Large memory request should be handled: {test_case['description']}"
            
            # Validate memory consumption protection
            validation_result = security_validator.validate_memory_consumption_protection(
                test_case, response.status_code,
                response.json() if response.status_code != 204 else {}
            )
            
            assert validation_result["is_protected"], \
                f"Memory consumption should be protected: {test_case['description']}"
            
            if response.status_code in [400, 413, 422]:
                # Memory limit exceeded - validate error handling
                error_data = response.json()
                memory_error_check = security_validator.validate_memory_limit_error(
                    test_case["expected_limit"], error_data
                )
                assert memory_error_check["is_secure"], \
                    f"Memory limit error should be secure: {test_case['description']}"
        
        logger.info("API4_MEMORY_001: Memory consumption limits tested")

    @pytest.mark.security
    @pytest.mark.owasp_api4
    @pytest.mark.asyncio
    async def test_api4_storage_consumption_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              security_validator: SecurityValidator,
                                              multimodal_fixtures: MultiModalFixtures,
                                              make_request):
        """API4_STORAGE_001: Storage Consumption Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test storage consumption with large files and images
        storage_consumption_tests = [
            {
                "description": "Large image file processing",
                "test_type": "large_image",
                "image_size": "10MB_equivalent",
                "expected_limit": "image_size"
            },
            {
                "description": "Multiple image files in single request",
                "test_type": "multiple_images",
                "image_count": 20,
                "expected_limit": "image_count"
            },
            {
                "description": "High resolution image simulation",
                "test_type": "high_resolution",
                "image_dimensions": "8000x8000_equivalent",
                "expected_limit": "image_resolution"
            }
        ]
        
        for test_case in storage_consumption_tests:
            if test_case["test_type"] == "large_image":
                # Create large image data simulation
                large_image_data = multimodal_fixtures.generate_large_image_data(test_case["image_size"])
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Analyze this large image"},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{large_image_data}"
                                }
                            }
                        ]
                    }],
                    "max_tokens": 50
                }
            
            elif test_case["test_type"] == "multiple_images":
                # Create multiple images in one request
                images_content = []
                for i in range(test_case["image_count"]):
                    image_data = multimodal_fixtures.get_base64_image(f"test_image_{i}.jpg")
                    images_content.append({
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{image_data}"}
                    })
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{
                        "role": "user",
                        "content": [{"type": "text", "text": "Analyze these images"}] + images_content
                    }],
                    "max_tokens": 100
                }
            
            elif test_case["test_type"] == "high_resolution":
                # Simulate high resolution image
                high_res_image_data = multimodal_fixtures.generate_high_resolution_image_data(
                    test_case["image_dimensions"]
                )
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Process this high resolution image"},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{high_res_image_data}"
                                }
                            }
                        ]
                    }],
                    "max_tokens": 50
                }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            # Should handle storage-intensive requests appropriately
            assert response.status_code in [200, 400, 413, 422], \
                f"Storage-intensive request should be handled: {test_case['description']}"
            
            # Validate storage consumption protection
            validation_result = security_validator.validate_storage_consumption_protection(
                test_case, response.status_code,
                response.json() if response.status_code != 204 else {}
            )
            
            assert validation_result["is_protected"], \
                f"Storage consumption should be protected: {test_case['description']}"
        
        logger.info("API4_STORAGE_001: Storage consumption testing completed")

    @pytest.mark.security
    @pytest.mark.owasp_api4
    @pytest.mark.asyncio
    async def test_api4_network_bandwidth_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            security_validator: SecurityValidator,
                                            make_request):
        """API4_NETWORK_001: Network Bandwidth Consumption Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test network bandwidth consumption scenarios
        bandwidth_tests = [
            {
                "description": "Large request payload",
                "payload_size": "large",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "X" * 50000}],
                    "max_tokens": 1000
                }
            },
            {
                "description": "High token count request",
                "payload_size": "high_tokens",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Generate a very long response"}],
                    "max_tokens": 4000
                }
            },
            {
                "description": "Streaming request with large response",
                "payload_size": "streaming",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Tell me a very long story"}],
                    "max_tokens": 2000,
                    "stream": True
                }
            }
        ]
        
        for test_case in bandwidth_tests:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_case["request_data"]
            )
            
            # Should handle bandwidth-intensive requests
            assert response.status_code in [200, 400, 413, 429], \
                f"Bandwidth-intensive request should be handled: {test_case['description']}"
            
            # Validate network bandwidth protection
            validation_result = security_validator.validate_network_bandwidth_protection(
                test_case, response.status_code,
                response.json() if response.status_code != 204 else {}
            )
            
            assert validation_result["is_protected"], \
                f"Network bandwidth should be protected: {test_case['description']}"
            
            # For streaming requests, validate stream handling
            if test_case["request_data"].get("stream") and response.status_code == 200:
                # Note: Streaming response handling would require special processing
                logger.info(f"Streaming response received for: {test_case['description']}")
        
        logger.info("API4_NETWORK_001: Network bandwidth consumption tested")

    @pytest.mark.security
    @pytest.mark.owasp_api4
    @pytest.mark.asyncio
    async def test_api4_provider_resource_limits_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   security_validator: SecurityValidator,
                                                   make_request):
        """API4_PROVIDER_001: Provider-Specific Resource Limits Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test provider-specific resource consumption patterns
        provider_tests = []
        
        # Test different models with varying resource requirements
        chat_models = config.get_chat_models() if config.get_chat_models() else ["test-model"]
        
        for model in chat_models[:3]:  # Test first 3 models
            provider_tests.extend([
                {
                    "description": f"Large context window test for {model}",
                    "model": model,
                    "resource_type": "context_window",
                    "request_data": {
                        "model": model,
                        "messages": [{"role": "user", "content": "Context " * 2000}],
                        "max_tokens": 100
                    }
                },
                {
                    "description": f"High token generation for {model}",
                    "model": model,
                    "resource_type": "token_generation",
                    "request_data": {
                        "model": model,
                        "messages": [{"role": "user", "content": "Generate maximum tokens"}],
                        "max_tokens": 4000
                    }
                },
                {
                    "description": f"Complex reasoning task for {model}",
                    "model": model,
                    "resource_type": "computational_complexity",
                    "request_data": {
                        "model": model,
                        "messages": [{"role": "user", "content": "Solve this complex multi-step reasoning problem with detailed explanation: " + "reasoning step " * 100}],
                        "max_tokens": 500
                    }
                }
            ])
        
        for test_case in provider_tests:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_case["request_data"]
            )
            
            # Should handle provider-specific resource limits
            assert response.status_code in [200, 400, 413, 429], \
                f"Provider resource request should be handled: {test_case['description']}"
            
            # Validate provider resource limit handling
            validation_result = security_validator.validate_provider_resource_limits(
                test_case, response.status_code,
                response.json() if response.status_code != 204 else {}
            )
            
            assert validation_result["is_protected"], \
                f"Provider resource limits should be enforced: {test_case['description']}"
            
            if response.status_code == 200:
                # Successful response - validate resource usage is reasonable
                response_data = response.json()
                usage_validation = security_validator.validate_resource_usage_metrics(
                    test_case, response_data
                )
                assert usage_validation["is_reasonable"], \
                    f"Resource usage should be reasonable: {test_case['description']}"
        
        logger.info("API4_PROVIDER_001: Provider-specific resource limits tested")

    @pytest.mark.security
    @pytest.mark.owasp_api4
    @pytest.mark.asyncio
    async def test_api4_concurrent_resource_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              security_validator: SecurityValidator,
                                              make_request):
        """API4_CONCURRENT_001: Concurrent Resource Usage Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test concurrent resource consumption scenarios
        concurrent_requests = 10
        request_template = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Concurrent resource test"}],
            "max_tokens": 100
        }
        
        # Execute concurrent requests
        async def make_concurrent_request(request_id):
            request_data = request_template.copy()
            request_data["messages"][0]["content"] += f" - Request {request_id}"
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            return {
                "request_id": request_id,
                "status_code": response.status_code,
                "response_data": response.json() if response.status_code == 200 else None,
                "error_data": response.json() if response.status_code != 200 else None
            }
        
        # Launch concurrent requests
        tasks = [make_concurrent_request(i) for i in range(concurrent_requests)]
        concurrent_responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and analyze responses
        valid_responses = [r for r in concurrent_responses if not isinstance(r, Exception)]
        
        # Validate concurrent resource handling
        validation_result = security_validator.validate_concurrent_resource_handling(
            concurrent_requests, valid_responses
        )
        
        assert validation_result["is_protected"], \
            "Concurrent resource consumption should be protected"
        
        # Analyze response patterns
        successful_requests = sum(1 for r in valid_responses if r["status_code"] == 200)
        rate_limited_requests = sum(1 for r in valid_responses if r["status_code"] == 429)
        error_requests = sum(1 for r in valid_responses if r["status_code"] >= 400 and r["status_code"] != 429)
        
        logger.info(f"Concurrent resource test results: {successful_requests} successful, {rate_limited_requests} rate limited, {error_requests} errors")
        
        # System should handle concurrent load gracefully
        assert (successful_requests + rate_limited_requests) > 0, \
            "System should handle some concurrent requests successfully or with rate limiting"
        
        # Validate that rate limiting is properly implemented if triggered
        if rate_limited_requests > 0:
            rate_limited_response = next(r for r in valid_responses if r["status_code"] == 429)
            rate_limit_validation = security_validator.validate_rate_limit_implementation(
                rate_limited_response["error_data"]
            )
            assert rate_limit_validation["is_proper"], \
                "Rate limiting should be properly implemented"
        
        logger.info("API4_CONCURRENT_001: Concurrent resource usage tested")

    @pytest.mark.security
    @pytest.mark.owasp_api4
    @pytest.mark.asyncio
    async def test_api4_resource_exhaustion_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              security_validator: SecurityValidator,
                                              make_request):
        """API4_EXHAUSTION_001: Resource Exhaustion Attack Testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various resource exhaustion attack vectors
        exhaustion_attacks = [
            {
                "description": "Memory exhaustion through large payloads",
                "attack_type": "memory",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "A" * (10000 * (i + 1))}],
                        "max_tokens": 10
                    } for i in range(5)
                ]
            },
            {
                "description": "CPU exhaustion through complex requests",
                "attack_type": "cpu",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Calculate complex mathematical sequence: {' + '.join([str(j) for j in range(100)])} * {i}"}],
                        "max_tokens": 200
                    } for i in range(5)
                ]
            },
            {
                "description": "Token exhaustion through max token requests",
                "attack_type": "tokens",
                "requests": [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Generate very long response {i}"}],
                        "max_tokens": 3000
                    } for i in range(3)
                ]
            }
        ]
        
        for attack_scenario in exhaustion_attacks:
            attack_responses = []
            
            # Execute attack requests sequentially to build up resource pressure
            for request_data in attack_scenario["requests"]:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                attack_responses.append({
                    "status_code": response.status_code,
                    "response_data": response.json() if response.status_code == 200 else None,
                    "error_data": response.json() if response.status_code != 200 else None
                })
                
                # If we get rate limited or errors, that's a good sign of protection
                if response.status_code in [429, 413, 500]:
                    break
            
            # Validate resource exhaustion protection
            validation_result = security_validator.validate_resource_exhaustion_protection(
                attack_scenario, attack_responses
            )
            
            assert validation_result["is_protected"], \
                f"Resource exhaustion should be prevented: {attack_scenario['description']}"
            
            # Check that system degrades gracefully under attack
            protection_indicators = sum(1 for r in attack_responses if r["status_code"] in [413, 429, 503])
            
            if protection_indicators > 0:
                logger.info(f"Resource protection triggered for {attack_scenario['attack_type']} attack: {protection_indicators} protected responses")
            
            # System should not crash or return 500 errors due to resource exhaustion
            server_errors = sum(1 for r in attack_responses if r["status_code"] == 500)
            assert server_errors == 0, \
                f"Resource exhaustion should not cause server errors: {attack_scenario['description']}"
        
        logger.info("API4_EXHAUSTION_001: Resource exhaustion attack protection tested")

    @pytest.mark.security
    @pytest.mark.owasp_api4
    @pytest.mark.asyncio
    async def test_api4_resource_cleanup_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           security_validator: SecurityValidator,
                                           make_request):
        """API4_CLEANUP_001: Resource Cleanup After Request Completion"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test resource cleanup scenarios
        cleanup_tests = [
            {
                "description": "Large request followed by small request",
                "sequence": [
                    {
                        "type": "large",
                        "request_data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Large content " * 1000}],
                            "max_tokens": 500
                        }
                    },
                    {
                        "type": "small",
                        "request_data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "Small test"}],
                            "max_tokens": 10
                        }
                    }
                ]
            },
            {
                "description": "Failed request followed by successful request",
                "sequence": [
                    {
                        "type": "failing",
                        "request_data": {
                            "model": "invalid-model-name",
                            "messages": [{"role": "user", "content": "This should fail"}],
                            "max_tokens": 10
                        }
                    },
                    {
                        "type": "successful",
                        "request_data": {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "This should work"}],
                            "max_tokens": 10
                        }
                    }
                ]
            }
        ]
        
        for test_case in cleanup_tests:
            sequence_responses = []
            
            for step in test_case["sequence"]:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, step["request_data"]
                )
                
                sequence_responses.append({
                    "step_type": step["type"],
                    "status_code": response.status_code,
                    "response_data": response.json() if response.status_code == 200 else None,
                    "error_data": response.json() if response.status_code != 200 else None
                })
            
            # Validate resource cleanup behavior
            validation_result = security_validator.validate_resource_cleanup(
                test_case, sequence_responses
            )
            
            assert validation_result["is_cleaned_up"], \
                f"Resources should be cleaned up: {test_case['description']}"
            
            # Check that subsequent requests are not affected by previous resource usage
            final_response = sequence_responses[-1]
            if test_case["sequence"][-1]["type"] in ["small", "successful"]:
                assert final_response["status_code"] == 200, \
                    f"Final request should succeed after cleanup: {test_case['description']}"
        
        logger.info("API4_CLEANUP_001: Resource cleanup after request completion tested")

    @pytest.mark.security
    @pytest.mark.owasp_api4
    @pytest.mark.asyncio
    async def test_api4_cost_based_limits_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            security_validator: SecurityValidator,
                                            make_request):
        """API4_COST_001: Cost-Based Resource Limits Enforcement"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test cost-based resource limiting
        cost_limit_tests = [
            {
                "description": "High-cost model usage",
                "cost_type": "model_expensive",
                "request_data": {
                    "model": config.get_chat_model(0),  # Assume this is expensive
                    "messages": [{"role": "user", "content": "Expensive model test"}],
                    "max_tokens": 1000
                }
            },
            {
                "description": "High token count leading to high cost",
                "cost_type": "token_expensive",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Generate maximum possible tokens"}],
                    "max_tokens": 4000
                }
            },
            {
                "description": "Multiple expensive requests",
                "cost_type": "volume_expensive",
                "multiple_requests": True,
                "request_count": 10,
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Moderate cost request"}],
                    "max_tokens": 200
                }
            }
        ]
        
        for test_case in cost_limit_tests:
            if test_case.get("multiple_requests"):
                # Execute multiple requests to test volume-based cost limiting
                cost_responses = []
                for i in range(test_case["request_count"]):
                    request_data = test_case["request_data"].copy()
                    request_data["messages"][0]["content"] += f" - Request {i}"
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    cost_responses.append({
                        "request_number": i,
                        "status_code": response.status_code,
                        "response_data": response.json() if response.status_code == 200 else None
                    })
                    
                    # If we hit cost limits, break
                    if response.status_code in [429, 402]:  # 402 = Payment Required
                        break
                
                # Validate cost-based limiting for multiple requests
                validation_result = security_validator.validate_cost_based_limiting(
                    test_case, cost_responses
                )
                
                assert validation_result["is_protected"], \
                    f"Cost-based limits should be enforced: {test_case['description']}"
            
            else:
                # Single expensive request
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, test_case["request_data"]
                )
                
                # Should handle expensive requests appropriately
                assert response.status_code in [200, 400, 402, 429], \
                    f"Expensive request should be handled: {test_case['description']}"
                
                # Validate cost limit enforcement
                validation_result = security_validator.validate_single_request_cost_limiting(
                    test_case, response.status_code,
                    response.json() if response.status_code != 204 else {}
                )
                
                assert validation_result["is_protected"], \
                    f"Cost limits should be enforced: {test_case['description']}"
                
                if response.status_code == 200:
                    # If allowed, validate usage tracking
                    response_data = response.json()
                    if "usage" in response_data:
                        usage_data = response_data["usage"]
                        cost_tracking_validation = security_validator.validate_cost_tracking(
                            test_case, usage_data
                        )
                        assert cost_tracking_validation["is_tracked"], \
                            f"Cost should be tracked: {test_case['description']}"
        
        logger.info("API4_COST_001: Cost-based resource limits enforcement tested")