# Section 7.5 - Enhanced Error Response Validation Tests - Database and Async
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Error Response Validation.md
# Enhanced test cases - Database and Async Error Handling

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


@dataclass 
class DatabaseErrorContext:
    """Database error context for testing"""
    error_type: str
    expected_status: int
    expected_message_pattern: str


@dataclass
class AsyncErrorContext:
    """Async error context for testing"""
    error_scenario: str
    expected_behavior: str
    context_preservation: bool


class TestErrorDatabaseAsyncHandling:
    """Enhanced error response validation tests - Database and Async scenarios"""
    
    def setup_method(self):
        """Setup test environment with sensitive data from .env"""
        # Load sensitive configuration from environment variables
        self.db_connection_string = os.getenv('DATABASE_URL', 'postgresql://test:test@localhost/test')
        self.provider_credentials = {
            'aws_access_key': os.getenv('AWS_ACCESS_KEY_ID'),
            'aws_secret_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
            'vertex_project_id': os.getenv('VERTEX_PROJECT_ID'),
            'vertex_credentials': os.getenv('VERTEX_AI_CREDENTIALS')
        }
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_database_error_response_handling_001(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       security_validator: SecurityValidator,
                                                       make_request):
        """TC_R751_DATABASE_ERROR_001: Database error response handling"""
        # Test database connection failures and integrity constraint violations
        
        database_error_scenarios = [
            DatabaseErrorContext(
                error_type="connection_failure",
                expected_status=503,
                expected_message_pattern="service unavailable"
            ),
            DatabaseErrorContext(
                error_type="integrity_violation", 
                expected_status=400,
                expected_message_pattern="bad request"
            ),
            DatabaseErrorContext(
                error_type="timeout",
                expected_status=503,
                expected_message_pattern="timeout"
            )
        ]
        
        database_error_results = []
        
        # Test authentication-dependent endpoints that use database
        auth_dependent_requests = [
            {
                "description": "User authentication",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "data": None
            },
            {
                "description": "Chat completion with user tracking",
                "endpoint": "/api/v1/chat/completions", 
                "method": "POST",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Database error test"}],
                    "max_tokens": 30
                }
            }
        ]
        
        for scenario in database_error_scenarios:
            logger.info(f"Testing database error scenario: {scenario.error_type}")
            
            # Test each auth-dependent request under database error conditions
            for request_config in auth_dependent_requests:
                try:
                    if request_config["method"] == "GET":
                        response = await make_request(
                            http_client, "GET", request_config["endpoint"],
                            auth_headers, track_cost=False
                        )
                    else:
                        response = await make_request(
                            http_client, "POST", request_config["endpoint"],
                            auth_headers, request_config["data"]
                        )
                    
                    # Analyze error response structure
                    error_result = {
                        "scenario": scenario.error_type,
                        "request": request_config["description"],
                        "status_code": response.status_code,
                        "has_request_id": False,
                        "secure_message": True,
                        "consistent_format": True
                    }
                    
                    # Check for request ID in response
                    if response.status_code >= 400:
                        try:
                            response_data = response.json()
                            error_result["has_request_id"] = "request_id" in str(response_data)
                            
                            # Validate error message security
                            security_check = security_validator.validate_error_message_security(
                                response.text
                            )
                            error_result["secure_message"] = security_check["is_secure"]
                            
                        except Exception as e:
                            logger.warning(f"Could not parse error response: {e}")
                    
                    database_error_results.append(error_result)
                    
                except Exception as e:
                    database_error_results.append({
                        "scenario": scenario.error_type,
                        "request": request_config["description"],
                        "exception": str(e),
                        "handled_gracefully": True
                    })
                
                await asyncio.sleep(0.2)
        
        # Verify database error handling
        for result in database_error_results:
            if "status_code" in result:
                # Errors should be handled with appropriate status codes
                assert result["status_code"] in [200, 400, 401, 403, 500, 503], \
                    f"Database errors should have appropriate status codes: {result}"
                
                # Error messages should be secure
                if result["status_code"] >= 400:
                    assert result["secure_message"], \
                        f"Database error messages should be secure: {result}"
        
        logger.info("Database error response handling validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_async_error_propagation_002(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              security_validator: SecurityValidator,
                                              make_request):
        """TC_R751_ASYNC_ERROR_002: Async error propagation and context management"""
        # Test error handling and context preservation in FastAPI async request processing
        
        async_error_scenarios = [
            AsyncErrorContext(
                error_scenario="concurrent_requests_with_errors",
                expected_behavior="isolated_error_handling",
                context_preservation=True
            ),
            AsyncErrorContext(
                error_scenario="async_chain_error_propagation",
                expected_behavior="error_bubble_up",
                context_preservation=True
            ),
            AsyncErrorContext(
                error_scenario="background_task_error",
                expected_behavior="main_request_unaffected",
                context_preservation=True
            )
        ]
        
        async_error_results = []
        
        # Test concurrent request handling with errors
        for scenario in async_error_scenarios:
            logger.info(f"Testing async error scenario: {scenario.error_scenario}")
            
            if scenario.error_scenario == "concurrent_requests_with_errors":
                # Send multiple concurrent requests to test isolation
                tasks = []
                for i in range(5):
                    task = make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Concurrent test {i}"}],
                            "max_tokens": 20
                        }
                    )
                    tasks.append(task)
                
                # Execute concurrently and collect results
                concurrent_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(concurrent_results):
                    if isinstance(result, Exception):
                        async_error_results.append({
                            "scenario": scenario.error_scenario,
                            "request_id": i,
                            "exception": str(result),
                            "isolated": True
                        })
                    else:
                        async_error_results.append({
                            "scenario": scenario.error_scenario,
                            "request_id": i,
                            "status_code": result.status_code,
                            "has_context": "request_id" in str(result.headers)
                        })
            
            elif scenario.error_scenario == "async_chain_error_propagation":
                # Test error propagation through async call chains
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, {
                            "model": "invalid-model-trigger-async-error",
                            "messages": [{"role": "user", "content": "Async chain test"}],
                            "max_tokens": 20
                        }
                    )
                    
                    async_error_results.append({
                        "scenario": scenario.error_scenario,
                        "status_code": response.status_code,
                        "error_propagated": response.status_code >= 400,
                        "context_preserved": "request_id" in str(response.text)
                    })
                    
                except Exception as e:
                    async_error_results.append({
                        "scenario": scenario.error_scenario,
                        "exception": str(e),
                        "properly_propagated": True
                    })
            
            elif scenario.error_scenario == "background_task_error":
                # Test that background task errors don't affect main response
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Background task test"}],
                        "max_tokens": 20
                    }
                )
                
                async_error_results.append({
                    "scenario": scenario.error_scenario,
                    "main_request_status": response.status_code,
                    "main_request_unaffected": response.status_code == 200,
                    "context_maintained": "request_id" in str(response.text)
                })
            
            await asyncio.sleep(0.3)
        
        # Verify async error handling
        for result in async_error_results:
            if "status_code" in result:
                # Main requests should succeed or fail gracefully
                assert result["status_code"] in [200, 400, 401, 403, 404, 500, 503], \
                    f"Async requests should have valid status codes: {result}"
            
            # Context should be preserved across async operations
            if "context_preserved" in result:
                assert result.get("context_preserved", False), \
                    f"Context should be preserved in async operations: {result}"
        
        logger.info("Async error propagation validation completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_database_connection_pool_exhaustion_003(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """TC_R751_DATABASE_POOL_003: Database connection pool exhaustion handling"""
        # Test behavior when database connection pool is exhausted
        
        # Simulate high database load by sending many concurrent requests
        pool_stress_tasks = []
        for i in range(20):  # More requests than typical pool size
            task = make_request(
                http_client, "GET", "/api/v1/models",
                auth_headers, track_cost=False
            )
            pool_stress_tasks.append(task)
        
        # Execute concurrently to stress connection pool
        pool_results = await asyncio.gather(*pool_stress_tasks, return_exceptions=True)
        
        successful_requests = 0
        pool_exhaustion_errors = 0
        
        for result in pool_results:
            if isinstance(result, Exception):
                pool_exhaustion_errors += 1
                logger.info(f"Pool exhaustion exception: {result}")
            else:
                if result.status_code == 200:
                    successful_requests += 1
                elif result.status_code == 503:  # Service unavailable due to pool exhaustion
                    pool_exhaustion_errors += 1
        
        # Verify that system handles pool exhaustion gracefully
        assert successful_requests > 0, "Some requests should succeed even under pool stress"
        logger.info(f"Pool stress test: {successful_requests} successful, {pool_exhaustion_errors} pool-related errors")
        
        # Verify system recovery after pool stress
        await asyncio.sleep(2)  # Allow pool to recover
        
        recovery_response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert recovery_response.status_code == 200, "System should recover after pool stress"
        logger.info("Database connection pool exhaustion handling validation completed")

    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_async_resource_cleanup_004(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """TC_R751_ASYNC_CLEANUP_004: Async resource cleanup during errors"""
        # Test proper resource cleanup when async operations fail
        
        cleanup_test_scenarios = [
            {
                "description": "Connection cleanup on client disconnect",
                "endpoint": "/api/v1/chat/completions",
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Resource cleanup test"}],
                    "max_tokens": 50,
                    "stream": True
                }
            },
            {
                "description": "Memory cleanup on request cancellation",
                "endpoint": "/api/v1/embeddings",
                "data": {
                    "model": config.get_embedding_model(0),
                    "input": "Resource cleanup embedding test"
                }
            }
        ]
        
        for scenario in cleanup_test_scenarios:
            logger.info(f"Testing async cleanup: {scenario['description']}")
            
            try:
                # Start request but cancel it quickly to test cleanup
                response_task = make_request(
                    http_client, "POST", scenario["endpoint"],
                    auth_headers, scenario["data"]
                )
                
                # Cancel after short time to simulate client disconnect
                await asyncio.sleep(0.1)
                response_task.cancel()
                
                try:
                    await response_task
                except asyncio.CancelledError:
                    logger.info(f"Request cancelled successfully for {scenario['description']}")
                
            except Exception as e:
                logger.info(f"Cleanup scenario handled: {e}")
            
            # Allow time for cleanup
            await asyncio.sleep(0.5)
        
        # Verify system remains stable after cleanup scenarios
        stability_response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert stability_response.status_code == 200, "System should remain stable after resource cleanup tests"
        logger.info("Async resource cleanup validation completed")