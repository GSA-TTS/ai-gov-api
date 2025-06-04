# Section 7.3 - Advanced OWASP API3:2023 Data Exposure Tests
# Based on design files for API3 (Data Exposure)
# Implements remaining missing test cases for data exposure protection

import pytest
import httpx
import os
from typing import Dict, Any, List
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.security_fixtures import SecurityFixtures
from utils.security_validators import SecurityValidator

class TestOWASPAPI3DataExposureAdvanced:
    """Advanced tests for OWASP API3:2023 - Data Exposure"""
    
    @pytest.mark.security
    @pytest.mark.owasp_api3
    @pytest.mark.asyncio
    async def test_api3_mass_assignment_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          security_validator: SecurityValidator,
                                          make_request):
        """API3_MASS_001: Mass Assignment Protection in LLM Configurations"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test mass assignment attacks on LLM request parameters
        mass_assignment_tests = [
            {
                "description": "Model configuration mass assignment",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10,
                    # Mass assignment attempts
                    "internal_model_id": "admin_model",
                    "provider_config": {"admin": True},
                    "billing_account": "premium_account",
                    "priority": "high",
                    "bypass_limits": True
                }
            },
            {
                "description": "Provider parameter mass assignment",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10,
                    # Provider-specific mass assignment
                    "aws_region": "us-west-2",
                    "aws_account_id": "123456789012",
                    "bedrock_model_arn": "malicious_arn",
                    "vertex_project": "admin_project"
                }
            },
            {
                "description": "Security context mass assignment",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10,
                    # Security context manipulation
                    "user_id": "admin",
                    "organization": "system",
                    "permissions": ["admin", "all"],
                    "auth_bypass": True,
                    "debug_mode": True
                }
            }
        ]
        
        for test_case in mass_assignment_tests:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_case["request_data"]
            )
            
            # Should handle mass assignment gracefully
            assert response.status_code in [200, 400, 422], \
                f"Mass assignment should be handled: {test_case['description']}"
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Validate mass assignment protection
                mass_assignment_validation = security_validator.validate_mass_assignment_protection(
                    test_case["request_data"], response_data
                )
                
                assert mass_assignment_validation["is_protected"], \
                    f"Mass assignment should be protected: {test_case['description']}"
                
                # Check that unauthorized parameters don't affect response
                unauthorized_params = ["internal_model_id", "billing_account", "aws_account_id", "auth_bypass"]
                response_str = str(response_data)
                
                for param in unauthorized_params:
                    if param in test_case["request_data"]:
                        assert test_case["request_data"][param] not in str(response_str), \
                            f"Unauthorized parameter should not affect response: {param}"
        
        logger.info("API3_MASS_001: Mass assignment protection tested")

    @pytest.mark.security
    @pytest.mark.owasp_api3
    @pytest.mark.asyncio
    async def test_api3_internal_metadata_exposure_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      security_validator: SecurityValidator,
                                                      make_request):
        """API3_METADATA_001: Internal Metadata Exposure Prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for internal metadata exposure in responses
        metadata_exposure_tests = [
            {
                "description": "Model list metadata exposure",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "check_fields": ["internal_id", "provider_arn", "billing_id", "server_location"]
            },
            {
                "description": "Chat response metadata exposure",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test metadata"}],
                    "max_tokens": 50
                },
                "check_fields": ["internal_request_id", "provider_metadata", "processing_metrics", "cost_details"]
            },
            {
                "description": "Error response metadata exposure",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "request_data": {
                    "model": "invalid_model_name",
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10
                },
                "check_fields": ["stack_trace", "internal_error_id", "database_query", "file_path"]
            }
        ]
        
        for test_case in metadata_exposure_tests:
            if test_case["method"] == "GET":
                response = await http_client.get(test_case["endpoint"], headers=auth_headers)
            else:
                response = await make_request(
                    http_client, test_case["method"], test_case["endpoint"],
                    auth_headers, test_case["request_data"]
                )
            
            # Should get some response
            assert response.status_code in [200, 400, 404, 422], \
                f"Request should be processed: {test_case['description']}"
            
            if response.headers.get("content-type", "").startswith("application/json"):
                response_data = response.json()
                
                # Validate no internal metadata exposure
                metadata_validation = security_validator.validate_metadata_exposure_prevention(
                    test_case["check_fields"], response_data
                )
                
                assert metadata_validation["is_secure"], \
                    f"Internal metadata should not be exposed: {test_case['description']}"
                
                # Check specific sensitive fields
                response_str = str(response_data).lower()
                sensitive_patterns = [
                    "arn:", "internal_", "debug_", "stack_trace", "file_path",
                    "/var/", "/home/", "localhost", "127.0.0.1", "database"
                ]
                
                exposed_patterns = [pattern for pattern in sensitive_patterns if pattern in response_str]
                
                if exposed_patterns:
                    logger.warning(f"Potential metadata exposure: {exposed_patterns} in {test_case['description']}")
        
        logger.info("API3_METADATA_001: Internal metadata exposure prevention tested")

    @pytest.mark.security
    @pytest.mark.owasp_api3
    @pytest.mark.asyncio
    async def test_api3_raw_provider_response_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 security_validator: SecurityValidator,
                                                 make_request):
        """API3_RAW_RESPONSE_001: Raw Provider Response Exposure Prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test that raw provider responses aren't exposed
        provider_response_tests = [
            {
                "description": "Chat completion response filtering",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test provider response filtering"}],
                    "max_tokens": 100
                }
            },
            {
                "description": "Embedding response filtering",
                "endpoint": "/api/v1/embeddings",
                "request_data": {
                    "model": config.get_embedding_models()[0] if config.get_embedding_models() else "test",
                    "input": "test embedding response filtering"
                }
            }
        ]
        
        for test_case in provider_response_tests:
            endpoint = test_case.get("endpoint", "/api/v1/chat/completions")
            
            response = await make_request(
                http_client, "POST", endpoint,
                auth_headers, test_case["request_data"]
            )
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Validate provider response filtering
                provider_validation = security_validator.validate_provider_response_filtering(
                    response_data
                )
                
                assert provider_validation["is_filtered"], \
                    f"Provider response should be filtered: {test_case['description']}"
                
                # Check for provider-specific fields that shouldn't be exposed
                provider_fields = [
                    "bedrock_response_metadata", "vertex_response_headers", "openai_raw_response",
                    "provider_request_id", "provider_billing_info", "provider_debug_info",
                    "aws_request_id", "gcp_trace_id", "anthropic_request_id"
                ]
                
                response_str = str(response_data)
                exposed_provider_fields = [field for field in provider_fields if field in response_str]
                
                assert len(exposed_provider_fields) == 0, \
                    f"Provider fields should not be exposed: {exposed_provider_fields}"
        
        logger.info("API3_RAW_RESPONSE_001: Raw provider response exposure prevention tested")

    @pytest.mark.security
    @pytest.mark.owasp_api3
    @pytest.mark.asyncio
    async def test_api3_debug_information_exposure_001(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      security_validator: SecurityValidator,
                                                      make_request):
        """API3_DEBUG_001: Debug Information Exposure Prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test debug information exposure scenarios
        debug_exposure_tests = [
            {
                "description": "Debug headers injection",
                "headers": {
                    "X-Debug": "true",
                    "X-Verbose": "1",
                    "X-Development": "true"
                },
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "debug test"}],
                    "max_tokens": 50
                }
            },
            {
                "description": "Debug parameters in request",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "debug test"}],
                    "max_tokens": 50,
                    "debug": True,
                    "verbose": True,
                    "trace": True,
                    "log_level": "DEBUG"
                }
            },
            {
                "description": "Error response debug exposure",
                "request_data": {
                    "model": "invalid_debug_model",
                    "messages": [{"role": "user", "content": "debug error test"}],
                    "max_tokens": 10,
                    "debug": True
                }
            }
        ]
        
        for test_case in debug_exposure_tests:
            # Prepare headers
            test_headers = auth_headers.copy()
            if "headers" in test_case:
                test_headers.update(test_case["headers"])
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                test_headers, test_case["request_data"]
            )
            
            # Should handle debug requests without exposing debug info
            assert response.status_code in [200, 400, 404], \
                f"Debug request should be handled: {test_case['description']}"
            
            response_data = response.json()
            
            # Validate debug information protection
            debug_validation = security_validator.validate_debug_information_protection(
                test_case, response_data
            )
            
            assert debug_validation["is_protected"], \
                f"Debug information should be protected: {test_case['description']}"
            
            # Check for debug-specific information leakage
            debug_indicators = [
                "debug", "trace", "stack_trace", "internal_error", "file_path",
                "line_number", "function_name", "variable_dump", "sql_query"
            ]
            
            response_str = str(response_data).lower()
            leaked_debug_info = [indicator for indicator in debug_indicators if indicator in response_str]
            
            assert len(leaked_debug_info) == 0, \
                f"Debug information should not leak: {leaked_debug_info} in {test_case['description']}"
        
        logger.info("API3_DEBUG_001: Debug information exposure prevention tested")

    @pytest.mark.security
    @pytest.mark.owasp_api3
    @pytest.mark.asyncio
    async def test_api3_configuration_data_exposure_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       security_validator: SecurityValidator,
                                                       make_request):
        """API3_CONFIG_001: Configuration Data Exposure Through Error Responses"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test configuration data exposure through various error scenarios
        config_exposure_tests = [
            {
                "description": "Invalid model configuration exposure",
                "request_data": {
                    "model": "config_test_invalid_model_name_123",
                    "messages": [{"role": "user", "content": "config test"}],
                    "max_tokens": 10
                },
                "expected_status": [400, 404]
            },
            {
                "description": "Malformed request configuration exposure",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": "invalid_messages_format",
                    "max_tokens": 10
                },
                "expected_status": [400, 422]
            },
            {
                "description": "Oversized request configuration exposure",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "X" * 100000}],
                    "max_tokens": 10
                },
                "expected_status": [400, 413, 422]
            }
        ]
        
        for test_case in config_exposure_tests:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_case["request_data"]
            )
            
            # Should return expected error status
            assert response.status_code in test_case["expected_status"], \
                f"Error request should return expected status: {test_case['description']}"
            
            error_data = response.json()
            
            # Validate configuration exposure prevention
            config_validation = security_validator.validate_configuration_exposure_prevention(
                test_case, error_data
            )
            
            assert config_validation["is_protected"], \
                f"Configuration should not be exposed: {test_case['description']}"
            
            # Check for configuration-specific leakage
            config_indicators = [
                "config", "settings", "environment", "database_url", "api_key",
                "secret", "token", "credential", "host", "port", "username", "password"
            ]
            
            error_str = str(error_data).lower()
            leaked_config = [indicator for indicator in config_indicators if indicator in error_str]
            
            # Some generic terms might be okay, but specific sensitive config should not leak
            sensitive_config = ["database_url", "api_key", "secret", "token", "credential", "password"]
            leaked_sensitive = [indicator for indicator in sensitive_config if indicator in error_str]
            
            assert len(leaked_sensitive) == 0, \
                f"Sensitive configuration should not leak: {leaked_sensitive} in {test_case['description']}"
        
        logger.info("API3_CONFIG_001: Configuration data exposure prevention tested")

    @pytest.mark.security
    @pytest.mark.owasp_api3
    @pytest.mark.asyncio
    async def test_api3_internal_processing_details_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       security_validator: SecurityValidator,
                                                       make_request):
        """API3_PROCESSING_001: Internal Processing Detail Exposure Prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test internal processing detail exposure
        processing_detail_tests = [
            {
                "description": "Request processing pipeline exposure",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test processing details"}],
                    "max_tokens": 100
                }
            },
            {
                "description": "Model loading process exposure",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test model loading"}],
                    "max_tokens": 50
                }
            },
            {
                "description": "Provider communication details",
                "request_data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "test provider communication"}],
                    "max_tokens": 50
                }
            }
        ]
        
        for test_case in processing_detail_tests:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_case["request_data"]
            )
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Validate processing detail protection
                processing_validation = security_validator.validate_processing_detail_protection(
                    response_data
                )
                
                assert processing_validation["is_protected"], \
                    f"Processing details should be protected: {test_case['description']}"
                
                # Check for internal processing information
                processing_indicators = [
                    "processing_time", "queue_time", "model_load_time", "provider_latency",
                    "memory_usage", "cpu_usage", "thread_id", "worker_id", "pipeline_stage",
                    "cache_hit", "cache_miss", "preprocessing_time", "postprocessing_time"
                ]
                
                response_str = str(response_data).lower()
                exposed_processing = [indicator for indicator in processing_indicators if indicator in response_str]
                
                # Some timing information might be acceptable in usage stats, but detailed processing should not be exposed
                sensitive_processing = [
                    "queue_time", "model_load_time", "memory_usage", "cpu_usage",
                    "thread_id", "worker_id", "pipeline_stage", "cache_hit", "cache_miss"
                ]
                
                leaked_sensitive_processing = [indicator for indicator in sensitive_processing if indicator in response_str]
                
                assert len(leaked_sensitive_processing) == 0, \
                    f"Sensitive processing details should not leak: {leaked_sensitive_processing}"
        
        logger.info("API3_PROCESSING_001: Internal processing detail exposure prevention tested")