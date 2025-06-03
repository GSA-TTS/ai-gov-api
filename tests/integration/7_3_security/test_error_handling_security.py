# Section 7.3 - Enhanced Error Handling Security Testing
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Enhanced Error Handling Security.md

import pytest
import httpx
import json
import time
import asyncio
from typing import Dict, Any, List
import re

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestValidationErrorInformationDisclosure:
    """Test ValidationError response for internal information disclosure"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_val_001_internal_path_disclosure(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """SEC_ERROR_VAL_001: Test ValidationError response for internal path disclosure"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test scenarios that trigger Pydantic ValidationError
        invalid_requests = [
            {
                "model": 123,  # Invalid type - should be string
                "messages": [{"role": "user", "content": "test"}],
                "description": "Invalid model type (integer)"
            },
            {
                "model": config.get_chat_model(0),
                "messages": "not_an_array",  # Invalid type - should be array
                "description": "Invalid messages type (string)"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test"}],
                "temperature": "invalid",  # Invalid type - should be number
                "description": "Invalid temperature type (string)"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "test"},
                            {"type": "image_url", "image_url": {"url": "invalid_data_uri"}}
                        ]
                    }
                ],
                "description": "Invalid multimodal content structure"
            }
        ]
        
        for invalid_request in invalid_requests:
            description = invalid_request.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, invalid_request, track_cost=False
            )
            
            assert response.status_code == 422, f"{description} should return 422"
            response_data = response.json()
            
            assert "detail" in response_data, f"{description} should contain error detail"
            
            response_text = json.dumps(response_data).lower()
            
            # Check for internal path disclosure
            sensitive_paths = ["/app/", "/usr/", "/home/", "/opt/", "/var/", "c:\\", "\\app\\"]
            for path in sensitive_paths:
                assert path not in response_text, f"{description} should not expose path: {path}"
            
            # Check for Pydantic model class exposure
            pydantic_internals = ["pydantic", "basemodel", "__root__", "field_info", "model_config"]
            for internal in pydantic_internals:
                assert internal not in response_text, f"{description} should not expose Pydantic internal: {internal}"
            
            # Check for stack trace indicators
            stack_indicators = ["traceback", "stack trace", "line ", "file \"", "in <module>"]
            for indicator in stack_indicators:
                assert indicator not in response_text, f"{description} should not contain stack trace: {indicator}"
            
            logger.info(f"SEC_ERROR_VAL_001: {description} - No internal path disclosure detected")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_val_002_configuration_detail_exposure(self, http_client: httpx.AsyncClient,
                                                                  auth_headers: Dict[str, str],
                                                                  make_request):
        """SEC_ERROR_VAL_002: Test ValidationError response for configuration detail exposure"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test constraint violations that might expose configuration
        constraint_violations = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test"}],
                "temperature": -5.0,  # Out of range
                "max_tokens": 50,
                "description": "Negative temperature constraint violation"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test"}],
                "top_p": 2.0,  # Out of range
                "max_tokens": 50,
                "description": "top_p constraint violation"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "invalid_role", "content": "test"}],  # Invalid enum
                "max_tokens": 50,
                "description": "Invalid role enum violation"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": ""}],  # Empty content
                "max_tokens": 50,
                "description": "Empty content constraint violation"
            }
        ]
        
        for violation in constraint_violations:
            description = violation.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, violation, track_cost=False
            )
            
            assert response.status_code == 422, f"{description} should return 422"
            response_data = response.json()
            
            response_text = json.dumps(response_data).lower()
            
            # Check for configuration exposure
            config_internals = ["backend_map", "provider_config", "model_mapping", "constraint_config"]
            for config_detail in config_internals:
                assert config_detail not in response_text, f"{description} should not expose config: {config_detail}"
            
            # Check for internal validation logic exposure
            validation_internals = ["validator", "constraint_func", "field_validator", "root_validator"]
            for validation_detail in validation_internals:
                assert validation_detail not in response_text, f"{description} should not expose validation logic: {validation_detail}"
            
            logger.info(f"SEC_ERROR_VAL_002: {description} - No configuration details exposed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_val_003_model_information_leakage(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """SEC_ERROR_VAL_003: Test ValidationError response for model information leakage"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test invalid model scenarios
        invalid_models = [
            "completely-nonexistent-model",
            "model-with-special-chars!@#$",
            "",  # Empty model
            None,  # Null model
            "gpt-4-secret-internal-model",  # Potential internal model probe
        ]
        
        for model in invalid_models:
            request_data = {
                "model": model,
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data, track_cost=False
            )
            
            # Should return error (422 or 400)
            assert response.status_code in [400, 422], f"Invalid model {model} should return error"
            response_data = response.json()
            
            response_text = json.dumps(response_data).lower()
            
            # Check that available models aren't listed
            model_listing_indicators = ["available models", "valid models", "supported models", "model list"]
            for indicator in model_listing_indicators:
                assert indicator not in response_text, f"Error for model {model} should not list available models"
            
            # Check for backend configuration exposure
            backend_internals = ["backend_map", "bedrock", "vertex", "openai", "provider_config"]
            for backend_detail in backend_internals:
                assert backend_detail not in response_text, f"Error for model {model} should not expose backend: {backend_detail}"
            
            # Verify error format is generic (no specific model suggestions)
            model_suggestions = ["did you mean", "similar to", "try using"]
            for suggestion in model_suggestions:
                assert suggestion not in response_text, f"Error for model {model} should not provide specific suggestions"
            
            logger.info(f"SEC_ERROR_VAL_003: Invalid model {model} - No model information leaked")


class TestProviderSpecificErrorPropagation:
    """Test provider error message sanitization"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_prov_001_bedrock_error_sanitization(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """SEC_ERROR_PROV_001: Test provider error message sanitization for Bedrock"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test scenarios that might trigger Bedrock-specific errors
        bedrock_error_scenarios = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "A" * 100000}],  # Exceed token limits
                "max_tokens": 50,
                "description": "Token limit exceeded"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test"}],
                "temperature": 999,  # Invalid configuration
                "max_tokens": 50,
                "description": "Invalid model configuration"
            }
        ]
        
        for scenario in bedrock_error_scenarios:
            description = scenario.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario, track_cost=False
            )
            
            # Should return some error
            assert response.status_code >= 400, f"{description} should return error status"
            
            if response.status_code in [400, 422, 500]:
                response_data = response.json()
                response_text = json.dumps(response_data).lower()
                
                # Check for AWS-specific details
                aws_specifics = ["aws", "amazon", "bedrock", "arn:", "account-id", "us-east-1", "us-west-2"]
                for aws_detail in aws_specifics:
                    if aws_detail in response_text and aws_detail not in ["amazon"]:  # "amazon" might be in model names
                        logger.warning(f"SEC_ERROR_PROV_001: {description} - AWS detail exposed: {aws_detail}")
                
                # Check for service URLs
                service_urls = ["amazonaws.com", "bedrock.us-", ".aws.amazon.com"]
                for url in service_urls:
                    assert url not in response_text, f"{description} should not expose service URL: {url}"
                
                # Check for SDK internals
                sdk_internals = ["boto3", "botocore", "awssdkpandas", "session.client"]
                for sdk_detail in sdk_internals:
                    assert sdk_detail not in response_text, f"{description} should not expose SDK detail: {sdk_detail}"
                
                logger.info(f"SEC_ERROR_PROV_001: Bedrock {description} - Error sanitization verified")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_prov_002_vertex_error_sanitization(self, http_client: httpx.AsyncClient,
                                                               auth_headers: Dict[str, str],
                                                               make_request):
        """SEC_ERROR_PROV_002: Test provider error message sanitization for Vertex AI"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test scenarios that might trigger Vertex AI-specific errors
        vertex_error_scenarios = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test" * 10000}],  # Large request
                "max_tokens": 50,
                "description": "Large request handling"
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "test"}],
                "top_p": 5.0,  # Invalid parameter
                "max_tokens": 50,
                "description": "Invalid parameter value"
            }
        ]
        
        for scenario in vertex_error_scenarios:
            description = scenario.pop("description")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, scenario, track_cost=False
            )
            
            # Should return some error
            assert response.status_code >= 400, f"{description} should return error status"
            
            if response.status_code in [400, 422, 500]:
                response_data = response.json()
                response_text = json.dumps(response_data).lower()
                
                # Check for GCP-specific details
                gcp_specifics = ["gcp", "google cloud", "vertex", "project-id", "service-account", "googleapis.com"]
                for gcp_detail in gcp_specifics:
                    if gcp_detail in response_text and gcp_detail not in ["google"]:  # "google" might be in model names
                        logger.warning(f"SEC_ERROR_PROV_002: {description} - GCP detail exposed: {gcp_detail}")
                
                # Check for service URLs
                service_urls = ["googleapis.com", "vertex-ai", ".googlecloud.com"]
                for url in service_urls:
                    assert url not in response_text, f"{description} should not expose service URL: {url}"
                
                # Check for SDK internals
                sdk_internals = ["google-cloud", "vertexai", "aiplatform", "credentials.json"]
                for sdk_detail in sdk_internals:
                    assert sdk_detail not in response_text, f"{description} should not expose SDK detail: {sdk_detail}"
                
                logger.info(f"SEC_ERROR_PROV_002: Vertex AI {description} - Error sanitization verified")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_prov_003_provider_consistency(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """SEC_ERROR_PROV_003: Test error response consistency across different providers"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test same invalid request across different models (potentially different providers)
        models = config.CHAT_MODELS[:3]  # Test first 3 models
        
        invalid_request = {
            "messages": [{"role": "user", "content": "test"}],
            "temperature": -1.0,  # Invalid temperature
            "max_tokens": 50
        }
        
        error_responses = []
        
        for model in models:
            test_request = invalid_request.copy()
            test_request["model"] = model
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_request, track_cost=False
            )
            
            if response.status_code in [400, 422]:
                error_responses.append({
                    "model": model,
                    "status_code": response.status_code,
                    "response": response.json()
                })
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        if len(error_responses) >= 2:
            # Compare error response structures
            first_response = error_responses[0]["response"]
            
            for i, error_resp in enumerate(error_responses[1:], 1):
                current_response = error_resp["response"]
                
                # Check that basic structure is consistent
                assert "detail" in current_response, f"Model {error_resp['model']} should have detail field"
                
                # Check that error format doesn't reveal provider differences
                first_keys = set(first_response.keys())
                current_keys = set(current_response.keys())
                
                # Allow some variation but major structure should be similar
                key_difference = len(first_keys.symmetric_difference(current_keys))
                assert key_difference <= 2, f"Error format difference too large between providers"
                
                # Check for provider-specific identifiers in errors
                response_text = json.dumps(current_response).lower()
                provider_identifiers = ["bedrock", "vertex", "openai", "claude", "gemini"]
                
                for identifier in provider_identifiers:
                    if identifier in response_text:
                        logger.warning(f"SEC_ERROR_PROV_003: Provider identifier {identifier} found in error for {error_resp['model']}")
                
                logger.info(f"SEC_ERROR_PROV_003: Error consistency verified between {error_responses[0]['model']} and {error_resp['model']}")


class TestFileHandlingErrorSecurity:
    """Test file validation error message content"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_file_001_validation_error_content(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """SEC_ERROR_FILE_001: Test file validation error message content for information disclosure"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test various invalid file scenarios
        invalid_file_scenarios = [
            {
                "content": [
                    {"type": "text", "text": "Describe this"},
                    {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,invalid_base64!@#"}}
                ],
                "description": "Invalid Base64 encoding"
            },
            {
                "content": [
                    {"type": "text", "text": "Describe this"},
                    {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + "A" * 10000000}}  # Very large file
                ],
                "description": "Oversized file content"
            },
            {
                "content": [
                    {"type": "text", "text": "Describe this"},
                    {"type": "image_url", "image_url": {"url": "data:text/plain;base64,SGVsbG8gV29ybGQ="}}  # Wrong MIME type
                ],
                "description": "Mismatched MIME type"
            },
            {
                "content": [
                    {"type": "text", "text": "Describe this"},
                    {"type": "image_url", "image_url": {"url": "not_a_data_uri"}}
                ],
                "description": "Malformed data URI"
            }
        ]
        
        for scenario in invalid_file_scenarios:
            description = scenario.pop("description")
            
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["content"]}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data, track_cost=False
            )
            
            # Should return validation error
            assert response.status_code in [400, 422], f"{description} should return validation error"
            response_data = response.json()
            
            response_text = json.dumps(response_data).lower()
            
            # Check for temporary file path exposure
            temp_paths = ["/tmp/", "/temp/", "c:\\temp", "\\tmp\\", "tmpfile", "temp_", "_tmp"]
            for temp_path in temp_paths:
                assert temp_path not in response_text, f"{description} should not expose temp path: {temp_path}"
            
            # Check for file processing library details
            file_lib_details = ["pillow", "pil", "imageio", "opencv", "magic", "mimetypes"]
            for lib_detail in file_lib_details:
                assert lib_detail not in response_text, f"{description} should not expose library: {lib_detail}"
            
            # Check for file system structure
            fs_details = ["filesystem", "inode", "mount", "directory", "folder"]
            for fs_detail in fs_details:
                assert fs_detail not in response_text, f"{description} should not expose filesystem detail: {fs_detail}"
            
            logger.info(f"SEC_ERROR_FILE_001: {description} - No file processing internals exposed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_file_002_malicious_filename_handling(self, http_client: httpx.AsyncClient,
                                                                 auth_headers: Dict[str, str],
                                                                 make_request):
        """SEC_ERROR_FILE_002: Test file name validation error handling for injection attempt detection"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test potentially malicious file names (if the API accepts file names)
        malicious_filenames = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "file_with_\x00_null_byte.jpg",
            "file_with_very_long_name_" + "A" * 1000 + ".jpg",
            "<script>alert('xss')</script>.jpg",
            "'; DROP TABLE files; --.jpg"
        ]
        
        for filename in malicious_filenames:
            # Test with multimodal content that might include filename
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Analyze this file: {filename}"},
                            {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,invalid"}}
                        ]
                    }
                ],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data, track_cost=False
            )
            
            # Should return some kind of error
            if response.status_code in [400, 422]:
                response_data = response.json()
                response_text = json.dumps(response_data).lower()
                
                # Check that error doesn't reveal security filtering
                security_indicators = ["filtered", "blocked", "security", "malicious", "injection"]
                for indicator in security_indicators:
                    assert indicator not in response_text, f"Error for {filename} should not indicate security filtering: {indicator}"
                
                # Check that error doesn't help refine attacks
                bypass_hints = ["try", "instead", "allowed", "permitted", "valid format"]
                for hint in bypass_hints:
                    assert hint not in response_text, f"Error for {filename} should not provide bypass hints: {hint}"
                
                logger.info(f"SEC_ERROR_FILE_002: Malicious filename {filename[:50]}... - No security filtering exposed")


class TestErrorResponseTimingAndLeakage:
    """Test error response timing and information leakage"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_timing_001_response_timing_consistency(self, http_client: httpx.AsyncClient,
                                                                   make_request):
        """SEC_ERROR_TIMING_001: Test error response timing for information disclosure"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test timing for different error conditions
        timing_scenarios = [
            {
                "headers": {"Authorization": "Bearer valid_but_nonexistent_key"},
                "description": "Invalid API key"
            },
            {
                "headers": {"Authorization": "Bearer sk-completely-invalid-format"},
                "description": "Malformed API key"
            },
            {
                "headers": {},
                "description": "Missing API key"
            }
        ]
        
        timing_results = []
        
        for scenario in timing_scenarios:
            description = scenario["description"]
            headers = scenario["headers"]
            
            # Measure response time
            start_time = time.time()
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                headers, track_cost=False
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            assert response.status_code == 401, f"{description} should return 401"
            
            timing_results.append({
                "description": description,
                "response_time": response_time
            })
            
            await asyncio.sleep(0.1)  # Small delay between requests
        
        # Analyze timing consistency
        if len(timing_results) >= 2:
            times = [result["response_time"] for result in timing_results]
            avg_time = sum(times) / len(times)
            max_deviation = max(abs(t - avg_time) for t in times)
            
            # Allow some variance but not too much (500ms threshold)
            assert max_deviation < 0.5, f"Error response timing variance too high: {max_deviation}s"
            
            logger.info(f"SEC_ERROR_TIMING_001: Timing consistency verified - max deviation: {max_deviation:.3f}s")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_timing_002_reconnaissance_value(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """SEC_ERROR_TIMING_002: Test error response content for reconnaissance value"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test systematic error conditions for reconnaissance
        recon_tests = [
            {
                "method": "GET",
                "endpoint": "/api/v1/models",
                "data": None,
                "description": "Valid endpoint"
            },
            {
                "method": "GET",
                "endpoint": "/api/v1/nonexistent",
                "data": None,
                "description": "Nonexistent endpoint"
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/models",  # Wrong method
                "data": {},
                "description": "Wrong HTTP method"
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {"malformed": "json"},
                "description": "Malformed request"
            }
        ]
        
        error_responses = []
        
        for test in recon_tests:
            response = await make_request(
                http_client, test["method"], test["endpoint"],
                auth_headers, test["data"], track_cost=False
            )
            
            if response.status_code >= 400:
                error_responses.append({
                    "test": test["description"],
                    "status_code": response.status_code,
                    "response": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
                })
                
                await asyncio.sleep(0.1)
        
        # Analyze error responses for reconnaissance value
        for error_resp in error_responses:
            if isinstance(error_resp["response"], dict):
                response_text = json.dumps(error_resp["response"]).lower()
            else:
                response_text = str(error_resp["response"]).lower()
            
            # Check for technology stack disclosure
            tech_stack = ["fastapi", "uvicorn", "pydantic", "starlette", "python", "nginx", "gunicorn"]
            for tech in tech_stack:
                if tech in response_text:
                    logger.warning(f"SEC_ERROR_TIMING_002: Technology {tech} disclosed in {error_resp['test']}")
            
            # Check for version information
            version_patterns = [r'\d+\.\d+\.\d+', r'version \d+', r'v\d+\.\d+']
            for pattern in version_patterns:
                if re.search(pattern, response_text):
                    logger.warning(f"SEC_ERROR_TIMING_002: Version pattern found in {error_resp['test']}")
            
            # Check for internal application structure
            internal_structure = ["router", "middleware", "handler", "endpoint", "route"]
            for structure in internal_structure:
                assert structure not in response_text, f"{error_resp['test']} should not reveal internal structure: {structure}"
            
            logger.info(f"SEC_ERROR_TIMING_002: {error_resp['test']} - Minimal reconnaissance value verified")


class TestExceptionHandlerSecurity:
    """Test unhandled exception exposure prevention"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_error_except_001_unhandled_exception_prevention(self, http_client: httpx.AsyncClient,
                                                                      auth_headers: Dict[str, str],
                                                                      make_request):
        """SEC_ERROR_EXCEPT_001: Test unhandled exception exposure prevention"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Test scenarios that might trigger unhandled exceptions
        exception_scenarios = [
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": '{"malformed": json}',  # Malformed JSON
                "description": "Malformed JSON",
                "raw": True
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions",
                "data": {"model": config.get_chat_model(0), "messages": [None]},  # Null in array
                "description": "Null values in array"
            },
            {
                "method": "POST",
                "endpoint": "/api/v1/chat/completions", 
                "data": {"model": config.get_chat_model(0), "messages": []},  # Empty required array
                "description": "Empty required array"
            }
        ]
        
        for scenario in exception_scenarios:
            description = scenario["description"]
            
            try:
                if scenario.get("raw"):
                    # Send raw malformed data
                    response = await http_client.post(
                        f"{config.BASE_URL}{scenario['endpoint']}",
                        headers={**auth_headers, "Content-Type": "application/json"},
                        content=scenario["data"]
                    )
                else:
                    response = await make_request(
                        http_client, scenario["method"], scenario["endpoint"],
                        auth_headers, scenario["data"], track_cost=False
                    )
                
                # Should return error, not unhandled exception
                assert response.status_code >= 400, f"{description} should return error status"
                
                if response.headers.get("content-type", "").startswith("application/json"):
                    response_data = response.json()
                    response_text = json.dumps(response_data).lower()
                else:
                    response_text = response.text.lower()
                
                # Check for stack trace indicators
                stack_indicators = [
                    "traceback", "stack trace", "file \"", "line ", "in <module>",
                    "exception", "error:", "at line", "caused by", "^", "~~~"
                ]
                for indicator in stack_indicators:
                    assert indicator not in response_text, f"{description} should not contain stack trace: {indicator}"
                
                # Check for internal application details
                internal_details = [
                    "app/", "/usr/", "/home/", "main.py", "__file__", "__name__",
                    "traceback.print_exc", "sys.exc_info", "import "
                ]
                for detail in internal_details:
                    assert detail not in response_text, f"{description} should not expose internal detail: {detail}"
                
                # Verify consistent error format
                if response.status_code in [400, 422, 500]:
                    assert ("detail" in response_text or "error" in response_text), \
                        f"{description} should have consistent error format"
                
                logger.info(f"SEC_ERROR_EXCEPT_001: {description} - Unhandled exception properly caught")
                
            except Exception as e:
                pytest.fail(f"SEC_ERROR_EXCEPT_001: {description} - Test itself failed: {str(e)}")
            
            await asyncio.sleep(0.1)