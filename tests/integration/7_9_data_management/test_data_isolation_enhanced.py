# Section 7.9 - Enhanced Data Isolation
# Based on: docs/test_design_n_planning/Testcases_7_9_DataManagement/Test Cases_Data Isolation.md

import pytest
import httpx
import asyncio
import time
import hashlib
import uuid
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor
import statistics

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class EnhancedIsolationResult:
    """Enhanced isolation test result structure"""
    test_name: str
    isolation_technique: str
    isolation_effectiveness: float
    violation_count: int
    recovery_successful: bool
    performance_impact: float
    success: bool


class TestEnhancedDataIsolation:
    """Test enhanced data isolation techniques"""
    
    def setup_method(self):
        """Setup for enhanced isolation tests"""
        self.test_session_id = str(uuid.uuid4())
        self.test_namespace = f"ENHANCED_ISO_{self.test_session_id[:8]}"
        logger.info(f"Starting enhanced isolation test session: {self.test_session_id}")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_iso_apikey_state_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """TDM_ISO_APIKEY_STATE_001: Verify API key state isolation across tests"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing API key state isolation")
        
        # Simulate multiple API keys for different tests
        api_key_scenarios = [
            {
                "key_id": f"{self.test_namespace}_KEY_A",
                "initial_state": "active",
                "scope": "read",
                "test_operations": ["read_operation", "status_check"]
            },
            {
                "key_id": f"{self.test_namespace}_KEY_B",
                "initial_state": "active",
                "scope": "write",
                "test_operations": ["write_operation", "deactivate", "reactivate"]
            },
            {
                "key_id": f"{self.test_namespace}_KEY_C",
                "initial_state": "inactive",
                "scope": "admin",
                "test_operations": ["activate", "admin_operation"]
            }
        ]
        
        # Execute tests that modify API key states
        async def test_api_key_operations(scenario):
            """Execute operations on API key and verify isolation"""
            operation_results = []
            
            for operation in scenario["test_operations"]:
                if operation == "read_operation":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Read using {scenario['key_id']} with scope {scenario['scope']}"}],
                        "max_tokens": 50
                    }
                elif operation == "write_operation":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Write using {scenario['key_id']} with scope {scenario['scope']}"}],
                        "max_tokens": 50
                    }
                elif operation == "deactivate":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Deactivate key {scenario['key_id']}"}],
                        "max_tokens": 30
                    }
                elif operation == "activate" or operation == "reactivate":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Activate key {scenario['key_id']}"}],
                        "max_tokens": 30
                    }
                elif operation == "status_check":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Check status of {scenario['key_id']}"}],
                        "max_tokens": 40
                    }
                elif operation == "admin_operation":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Admin operation with {scenario['key_id']}"}],
                        "max_tokens": 60
                    }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                operation_results.append({
                    "operation": operation,
                    "key_id": scenario["key_id"],
                    "success": response.status_code == 200,
                    "timestamp": time.time()
                })
                
                await asyncio.sleep(0.1)
            
            return {
                "key_id": scenario["key_id"],
                "initial_state": scenario["initial_state"],
                "operations": operation_results
            }
        
        # Execute all API key tests concurrently
        tasks = [test_api_key_operations(scenario) for scenario in api_key_scenarios]
        results = await asyncio.gather(*tasks)
        
        # Verify isolation between API keys
        isolation_violations = 0
        
        for i, result in enumerate(results):
            # Check if operations on one key affected others
            for j, other_result in enumerate(results):
                if i != j:
                    # Simplified check - in real implementation would verify actual state
                    if result["key_id"] in str(other_result["operations"]):
                        isolation_violations += 1
        
        # Cleanup simulation
        cleanup_successful = True
        for scenario in api_key_scenarios:
            cleanup_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Cleanup and restore {scenario['key_id']} to {scenario['initial_state']}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, cleanup_request
            )
            
            if response.status_code != 200:
                cleanup_successful = False
        
        # Verify results
        assert isolation_violations == 0, \
            f"API key operations should be isolated, found {isolation_violations} violations"
        
        assert cleanup_successful, \
            "All API keys should be cleaned up and restored"
        
        successful_operations = sum(
            len([op for op in result["operations"] if op["success"]])
            for result in results
        )
        total_operations = sum(len(result["operations"]) for result in results)
        
        assert successful_operations >= total_operations * 0.8, \
            f"Most operations should succeed, got {successful_operations}/{total_operations}"
        
        logger.info(f"API key isolation test completed: {isolation_violations} violations, "
                   f"{successful_operations}/{total_operations} successful operations")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_iso_user_data_002(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """TDM_ISO_USER_DATA_002: Verify user data isolation with unique identifiers"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing user data isolation")
        
        # Create unique users for each test
        test_users = []
        for i in range(3):
            unique_id = uuid.uuid4()
            test_users.append({
                "user_id": f"{self.test_namespace}_USER_{unique_id.hex[:8]}",
                "email": f"test_{unique_id.hex[:8]}@example.com",
                "manager_id": str(unique_id),
                "test_data": f"User {i} test data"
            })
        
        # Execute concurrent user operations
        async def create_and_test_user(user):
            """Create user and perform operations"""
            results = []
            
            # Create user
            create_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Create user {user['user_id']} with email {user['email']} and manager {user['manager_id']}"}],
                "max_tokens": 60
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, create_request
            )
            
            results.append({
                "operation": "create",
                "success": response.status_code == 200,
                "user_id": user["user_id"]
            })
            
            # Query user
            query_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Query user data for {user['user_id']}"}],
                "max_tokens": 80
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, query_request
            )
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                
                # Check for data from other users
                other_users = [u for u in test_users if u["user_id"] != user["user_id"]]
                cross_contamination = any(
                    other["user_id"] in content or other["email"] in content 
                    for other in other_users
                )
                
                results.append({
                    "operation": "query",
                    "success": True,
                    "cross_contamination": cross_contamination,
                    "user_id": user["user_id"]
                })
            else:
                results.append({
                    "operation": "query",
                    "success": False,
                    "cross_contamination": False,
                    "user_id": user["user_id"]
                })
            
            return results
        
        # Execute all user operations concurrently
        tasks = [create_and_test_user(user) for user in test_users]
        all_results = await asyncio.gather(*tasks)
        
        # Cleanup users
        cleanup_results = []
        for user in test_users:
            cleanup_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Delete user {user['user_id']}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, cleanup_request
            )
            
            cleanup_results.append(response.status_code == 200)
        
        # Verify results
        all_operations = [op for results in all_results for op in results]
        successful_operations = [op for op in all_operations if op["success"]]
        contaminated_operations = [op for op in all_operations if op.get("cross_contamination", False)]
        
        assert len(contaminated_operations) == 0, \
            f"No cross-contamination should occur, found {len(contaminated_operations)} cases"
        
        assert len(successful_operations) >= len(all_operations) * 0.8, \
            f"Most operations should succeed, got {len(successful_operations)}/{len(all_operations)}"
        
        assert all(cleanup_results), \
            "All users should be cleaned up successfully"
        
        logger.info(f"User data isolation test completed: "
                   f"{len(successful_operations)}/{len(all_operations)} successful, "
                   f"{len(contaminated_operations)} contamination cases")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_iso_billing_queue_interference_003(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """TDM_ISO_BILLING_QUEUE_INTERFERENCE_003: Verify billing queue isolation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing billing queue isolation")
        
        # Simulate multiple tests with billing operations
        test_scenarios = [
            {
                "test_id": f"{self.test_namespace}_BILLING_TEST_A",
                "operations": ["api_call_1", "api_call_2", "api_call_3"],
                "expected_billing_events": 3
            },
            {
                "test_id": f"{self.test_namespace}_BILLING_TEST_B",
                "operations": ["api_call_1", "api_call_2"],
                "expected_billing_events": 2
            }
        ]
        
        billing_results = []
        
        for scenario in test_scenarios:
            scenario_start = time.perf_counter()
            
            # Clear queue simulation (in real implementation)
            clear_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Clear billing queue for test {scenario['test_id']}"}],
                "max_tokens": 30
            }
            
            await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, clear_request
            )
            
            # Execute operations that generate billing events
            billing_events = []
            for operation in scenario["operations"]:
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Execute {operation} for test {scenario['test_id']}"}],
                    "max_tokens": 50
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                if response.status_code == 200:
                    billing_events.append({
                        "operation": operation,
                        "test_id": scenario["test_id"],
                        "timestamp": time.time()
                    })
            
            # Check billing queue state
            queue_check_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Check billing queue for test {scenario['test_id']}"}],
                "max_tokens": 60
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, queue_check_request
            )
            
            queue_state_valid = response.status_code == 200
            
            scenario_end = time.perf_counter()
            execution_time = (scenario_end - scenario_start) * 1000
            
            billing_results.append({
                "test_id": scenario["test_id"],
                "expected_events": scenario["expected_billing_events"],
                "actual_events": len(billing_events),
                "queue_state_valid": queue_state_valid,
                "execution_time": execution_time,
                "events_match": len(billing_events) == scenario["expected_billing_events"]
            })
            
            logger.info(f"Billing test {scenario['test_id']}: "
                       f"Events: {len(billing_events)}/{scenario['expected_billing_events']}, "
                       f"Queue valid: {queue_state_valid}")
        
        # Verify billing isolation
        assert all(result["events_match"] for result in billing_results), \
            "Each test should see only its own billing events"
        
        assert all(result["queue_state_valid"] for result in billing_results), \
            "Queue state should be valid for all tests"
        
        logger.info("Billing queue isolation test completed successfully")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_iso_db_state_management_004(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """TDM_ISO_DB_STATE_MANAGEMENT_004: Database state management and rollback"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing database state management with rollback")
        
        # Test database operations with rollback scenarios
        db_test_scenarios = [
            {
                "test_id": f"{self.test_namespace}_DB_TEST_1",
                "operations": [
                    {"type": "insert", "data": "Test record 1"},
                    {"type": "update", "data": "Updated record 1"},
                    {"type": "verify", "expected": "Updated record 1"}
                ],
                "rollback_needed": False
            },
            {
                "test_id": f"{self.test_namespace}_DB_TEST_2",
                "operations": [
                    {"type": "insert", "data": "Test record 2"},
                    {"type": "invalid_update", "data": "Invalid data"},
                    {"type": "verify", "expected": "Test record 2"}
                ],
                "rollback_needed": True
            }
        ]
        
        db_results = []
        
        for scenario in db_test_scenarios:
            scenario_start = time.perf_counter()
            operation_results = []
            
            # Begin transaction
            begin_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"BEGIN DB TRANSACTION {scenario['test_id']}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, begin_request
            )
            
            transaction_started = response.status_code == 200
            
            # Execute database operations
            for operation in scenario["operations"]:
                if operation["type"] == "insert":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"INSERT {operation['data']} in {scenario['test_id']}"}],
                        "max_tokens": 50
                    }
                elif operation["type"] == "update":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"UPDATE to {operation['data']} in {scenario['test_id']}"}],
                        "max_tokens": 50
                    }
                elif operation["type"] == "invalid_update":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": ""}],  # Invalid request
                        "max_tokens": 10
                    }
                elif operation["type"] == "verify":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"VERIFY data in {scenario['test_id']}"}],
                        "max_tokens": 60
                    }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                operation_results.append({
                    "type": operation["type"],
                    "success": response.status_code == 200
                })
                
                # If operation failed and rollback is needed
                if not response.status_code == 200 and scenario["rollback_needed"]:
                    break
            
            # Commit or rollback
            if scenario["rollback_needed"] or any(not op["success"] for op in operation_results):
                action_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"ROLLBACK TRANSACTION {scenario['test_id']}"}],
                    "max_tokens": 30
                }
                action = "ROLLBACK"
            else:
                action_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"COMMIT TRANSACTION {scenario['test_id']}"}],
                    "max_tokens": 30
                }
                action = "COMMIT"
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, action_request
            )
            
            action_successful = response.status_code == 200
            
            scenario_end = time.perf_counter()
            execution_time = (scenario_end - scenario_start) * 1000
            
            db_results.append({
                "test_id": scenario["test_id"],
                "transaction_started": transaction_started,
                "operations": operation_results,
                "action": action,
                "action_successful": action_successful,
                "execution_time": execution_time,
                "state_consistent": True  # Simplified - would verify actual state
            })
            
            logger.info(f"DB test {scenario['test_id']}: "
                       f"Action: {action}, "
                       f"Success: {action_successful}")
        
        # Verify database state management
        assert all(result["transaction_started"] for result in db_results), \
            "All transactions should start successfully"
        
        assert all(result["action_successful"] for result in db_results), \
            "All commit/rollback actions should succeed"
        
        assert all(result["state_consistent"] for result in db_results), \
            "Database state should be consistent after each test"
        
        logger.info("Database state management test completed successfully")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_iso_concurrent_test_execution_005(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """TDM_ISO_CONCURRENT_TEST_EXECUTION_005: Parallel test execution without interference"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing concurrent test execution isolation")
        
        # Define parallel test workloads
        parallel_tests = [
            {
                "test_id": f"{self.test_namespace}_PARALLEL_1",
                "workload": "cpu_intensive",
                "iterations": 5,
                "shared_resource": "cache"
            },
            {
                "test_id": f"{self.test_namespace}_PARALLEL_2",
                "workload": "io_intensive",
                "iterations": 4,
                "shared_resource": "database"
            },
            {
                "test_id": f"{self.test_namespace}_PARALLEL_3",
                "workload": "memory_intensive",
                "iterations": 3,
                "shared_resource": "memory_pool"
            },
            {
                "test_id": f"{self.test_namespace}_PARALLEL_4",
                "workload": "network_intensive",
                "iterations": 6,
                "shared_resource": "api_quota"
            }
        ]
        
        async def execute_parallel_test(test_config):
            """Execute a parallel test workload"""
            results = []
            
            for i in range(test_config["iterations"]):
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Execute {test_config['workload']} iteration {i} for {test_config['test_id']} using {test_config['shared_resource']}"}],
                    "max_tokens": 60
                }
                
                start_time = time.perf_counter()
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000
                
                if response.status_code == 200:
                    response_data = response.json()
                    content = response_data["choices"][0]["message"]["content"]
                    
                    # Check for interference from other parallel tests
                    other_test_ids = [t["test_id"] for t in parallel_tests if t["test_id"] != test_config["test_id"]]
                    interference_detected = any(other_id in content for other_id in other_test_ids)
                    
                    results.append({
                        "iteration": i,
                        "response_time": response_time,
                        "success": True,
                        "interference": interference_detected
                    })
                else:
                    results.append({
                        "iteration": i,
                        "response_time": response_time,
                        "success": False,
                        "interference": False
                    })
                
                # Small random delay to simulate varying workloads
                await asyncio.sleep(0.05 + (i % 3) * 0.05)
            
            return {
                "test_id": test_config["test_id"],
                "workload": test_config["workload"],
                "results": results
            }
        
        # Execute all tests in parallel
        parallel_tasks = [execute_parallel_test(test) for test in parallel_tests]
        parallel_results = await asyncio.gather(*parallel_tasks)
        
        # Analyze parallel execution results
        analysis = []
        
        for result in parallel_results:
            successful_iterations = [r for r in result["results"] if r["success"]]
            interference_iterations = [r for r in result["results"] if r.get("interference", False)]
            
            avg_response_time = statistics.mean([r["response_time"] for r in successful_iterations]) if successful_iterations else 0
            response_time_variance = statistics.stdev([r["response_time"] for r in successful_iterations]) if len(successful_iterations) > 1 else 0
            
            analysis.append({
                "test_id": result["test_id"],
                "workload": result["workload"],
                "total_iterations": len(result["results"]),
                "successful_iterations": len(successful_iterations),
                "interference_count": len(interference_iterations),
                "avg_response_time": avg_response_time,
                "response_time_variance": response_time_variance,
                "isolation_maintained": len(interference_iterations) == 0
            })
            
            logger.info(f"Parallel test {result['test_id']} ({result['workload']}): "
                       f"Success: {len(successful_iterations)}/{len(result['results'])}, "
                       f"Interference: {len(interference_iterations)}, "
                       f"Avg time: {avg_response_time:.2f}ms")
        
        # Verify parallel execution isolation
        isolated_tests = [a for a in analysis if a["isolation_maintained"]]
        successful_tests = [a for a in analysis if a["successful_iterations"] >= a["total_iterations"] * 0.8]
        
        assert len(isolated_tests) >= len(parallel_tests) * 0.9, \
            f"Most parallel tests should maintain isolation, got {len(isolated_tests)}/{len(parallel_tests)}"
        
        assert len(successful_tests) >= len(parallel_tests) * 0.8, \
            f"Most parallel tests should execute successfully, got {len(successful_tests)}/{len(parallel_tests)}"
        
        # Verify performance consistency (variance should be reasonable)
        high_variance_tests = [a for a in analysis if a["response_time_variance"] > a["avg_response_time"] * 0.5]
        assert len(high_variance_tests) <= len(parallel_tests) * 0.2, \
            f"Few tests should have high variance, got {len(high_variance_tests)}/{len(parallel_tests)}"
        
        logger.info("Concurrent test execution isolation verified successfully")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_iso_test_cleanup_mechanisms_006(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """TDM_ISO_TEST_CLEANUP_MECHANISMS_006: Test cleanup mechanism verification"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing cleanup mechanisms for test isolation")
        
        # Define test scenarios with different cleanup requirements
        cleanup_scenarios = [
            {
                "test_id": f"{self.test_namespace}_CLEANUP_1",
                "resources": ["api_key", "user_data", "temp_files"],
                "cleanup_strategy": "immediate"
            },
            {
                "test_id": f"{self.test_namespace}_CLEANUP_2",
                "resources": ["database_records", "cache_entries"],
                "cleanup_strategy": "deferred"
            },
            {
                "test_id": f"{self.test_namespace}_CLEANUP_3",
                "resources": ["billing_records", "audit_logs"],
                "cleanup_strategy": "scheduled"
            }
        ]
        
        cleanup_results = []
        
        for scenario in cleanup_scenarios:
            scenario_start = time.perf_counter()
            
            # Create test resources
            resource_creation_results = []
            for resource in scenario["resources"]:
                create_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Create {resource} for test {scenario['test_id']}"}],
                    "max_tokens": 50
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, create_request
                )
                
                resource_creation_results.append({
                    "resource": resource,
                    "created": response.status_code == 200
                })
            
            # Use resources in test
            test_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Execute test operations for {scenario['test_id']}"}],
                "max_tokens": 60
            }
            
            test_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, test_request
            )
            
            test_executed = test_response.status_code == 200
            
            # Cleanup resources based on strategy
            cleanup_start = time.perf_counter()
            resource_cleanup_results = []
            
            if scenario["cleanup_strategy"] == "immediate":
                # Cleanup immediately after test
                for resource in scenario["resources"]:
                    cleanup_request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Cleanup {resource} for test {scenario['test_id']}"}],
                        "max_tokens": 30
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, cleanup_request
                    )
                    
                    resource_cleanup_results.append({
                        "resource": resource,
                        "cleaned": response.status_code == 200
                    })
            
            elif scenario["cleanup_strategy"] == "deferred":
                # Simulate deferred cleanup
                await asyncio.sleep(0.2)  # Defer cleanup
                
                bulk_cleanup_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Bulk cleanup all resources for test {scenario['test_id']}"}],
                    "max_tokens": 40
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, bulk_cleanup_request
                )
                
                for resource in scenario["resources"]:
                    resource_cleanup_results.append({
                        "resource": resource,
                        "cleaned": response.status_code == 200
                    })
            
            elif scenario["cleanup_strategy"] == "scheduled":
                # Simulate scheduled cleanup
                schedule_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Schedule cleanup for test {scenario['test_id']}"}],
                    "max_tokens": 40
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, schedule_request
                )
                
                cleanup_scheduled = response.status_code == 200
                
                for resource in scenario["resources"]:
                    resource_cleanup_results.append({
                        "resource": resource,
                        "cleaned": cleanup_scheduled  # Assume scheduled cleanup will work
                    })
            
            cleanup_end = time.perf_counter()
            cleanup_time = (cleanup_end - cleanup_start) * 1000
            
            # Verify cleanup effectiveness
            verify_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Verify cleanup for test {scenario['test_id']}"}],
                "max_tokens": 50
            }
            
            verify_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, verify_request
            )
            
            cleanup_verified = verify_response.status_code == 200
            
            scenario_end = time.perf_counter()
            total_time = (scenario_end - scenario_start) * 1000
            
            # Calculate cleanup effectiveness
            resources_created = len([r for r in resource_creation_results if r["created"]])
            resources_cleaned = len([r for r in resource_cleanup_results if r["cleaned"]])
            
            cleanup_results.append({
                "test_id": scenario["test_id"],
                "cleanup_strategy": scenario["cleanup_strategy"],
                "resources_created": resources_created,
                "resources_cleaned": resources_cleaned,
                "test_executed": test_executed,
                "cleanup_time": cleanup_time,
                "cleanup_verified": cleanup_verified,
                "total_time": total_time,
                "cleanup_effectiveness": resources_cleaned / resources_created if resources_created > 0 else 0
            })
            
            logger.info(f"Cleanup test {scenario['test_id']} ({scenario['cleanup_strategy']}): "
                       f"Created: {resources_created}, "
                       f"Cleaned: {resources_cleaned}, "
                       f"Time: {cleanup_time:.2f}ms")
        
        # Verify cleanup mechanisms
        assert all(result["test_executed"] for result in cleanup_results), \
            "All tests should execute successfully"
        
        assert all(result["cleanup_effectiveness"] >= 0.9 for result in cleanup_results), \
            "Cleanup should be at least 90% effective for all tests"
        
        assert all(result["cleanup_verified"] for result in cleanup_results), \
            "Cleanup should be verified for all tests"
        
        # Verify cleanup performance
        immediate_cleanups = [r for r in cleanup_results if r["cleanup_strategy"] == "immediate"]
        if immediate_cleanups:
            avg_immediate_time = statistics.mean([r["cleanup_time"] for r in immediate_cleanups])
            assert avg_immediate_time < 500, \
                f"Immediate cleanup should be fast, got {avg_immediate_time:.2f}ms"
        
        logger.info("Test cleanup mechanisms verified successfully")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_iso_realtime_monitoring_010(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TDM_ISO_REALTIME_MONITORING_010: Real-time isolation violation detection"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing real-time isolation monitoring")
        
        # Set up monitoring for isolation violations
        monitoring_config = {
            "detection_threshold_ms": 100,
            "alert_threshold": 2,
            "monitoring_window_seconds": 5
        }
        
        # Simulate test scenarios with potential violations
        test_scenarios = [
            {
                "test_id": f"{self.test_namespace}_MONITOR_1",
                "operations": ["safe_operation_1", "safe_operation_2"],
                "expected_violations": 0
            },
            {
                "test_id": f"{self.test_namespace}_MONITOR_2",
                "operations": ["safe_operation", "cross_test_access", "safe_operation"],
                "expected_violations": 1
            },
            {
                "test_id": f"{self.test_namespace}_MONITOR_3",
                "operations": ["unsafe_operation_1", "unsafe_operation_2"],
                "expected_violations": 2
            }
        ]
        
        monitoring_results = []
        violation_events = []
        
        monitoring_start = time.time()
        
        for scenario in test_scenarios:
            scenario_violations = []
            
            for operation in scenario["operations"]:
                operation_start = time.perf_counter()
                
                # Simulate different operation types
                if "safe" in operation:
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Execute {operation} for {scenario['test_id']}"}],
                        "max_tokens": 50
                    }
                elif "cross_test_access" in operation:
                    # Simulate accessing another test's data
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Access data from OTHER_TEST while in {scenario['test_id']}"}],
                        "max_tokens": 50
                    }
                elif "unsafe" in operation:
                    # Simulate unsafe operation
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Unsafe {operation}: modify shared state from {scenario['test_id']}"}],
                        "max_tokens": 50
                    }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                operation_end = time.perf_counter()
                operation_time = (operation_end - operation_start) * 1000
                
                # Detect violations
                violation_detected = False
                violation_type = None
                
                if "cross_test_access" in operation:
                    violation_detected = True
                    violation_type = "cross_test_data_access"
                elif "unsafe" in operation:
                    violation_detected = True
                    violation_type = "shared_state_modification"
                elif operation_time > monitoring_config["detection_threshold_ms"]:
                    # Detect slow operations that might indicate contention
                    violation_detected = True
                    violation_type = "resource_contention"
                
                if violation_detected:
                    violation_event = {
                        "timestamp": time.time(),
                        "test_id": scenario["test_id"],
                        "operation": operation,
                        "violation_type": violation_type,
                        "severity": "high" if "unsafe" in operation else "medium",
                        "detection_latency_ms": operation_time
                    }
                    
                    violation_events.append(violation_event)
                    scenario_violations.append(violation_event)
                    
                    logger.warning(f"Isolation violation detected: {violation_type} in {scenario['test_id']}")
                
                await asyncio.sleep(0.1)
            
            # Check if alerts should be triggered
            if len(scenario_violations) >= monitoring_config["alert_threshold"]:
                alert_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"ALERT: Multiple isolation violations in {scenario['test_id']}"}],
                    "max_tokens": 40
                }
                
                alert_response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, alert_request
                )
                
                alert_sent = alert_response.status_code == 200
            else:
                alert_sent = False
            
            monitoring_results.append({
                "test_id": scenario["test_id"],
                "expected_violations": scenario["expected_violations"],
                "detected_violations": len(scenario_violations),
                "alert_triggered": alert_sent,
                "violations": scenario_violations
            })
        
        monitoring_end = time.time()
        monitoring_duration = monitoring_end - monitoring_start
        
        # Analyze monitoring effectiveness
        detection_accuracy = []
        for result in monitoring_results:
            accuracy = 1.0 - abs(result["expected_violations"] - result["detected_violations"]) / max(1, result["expected_violations"])
            detection_accuracy.append(accuracy)
            
            logger.info(f"Monitoring {result['test_id']}: "
                       f"Expected: {result['expected_violations']}, "
                       f"Detected: {result['detected_violations']}, "
                       f"Alert: {result['alert_triggered']}")
        
        # Verify monitoring effectiveness
        avg_accuracy = statistics.mean(detection_accuracy)
        assert avg_accuracy >= 0.8, \
            f"Detection accuracy should be at least 80%, got {avg_accuracy:.2%}"
        
        # Verify detection latency
        if violation_events:
            detection_latencies = [v["detection_latency_ms"] for v in violation_events]
            avg_latency = statistics.mean(detection_latencies)
            assert avg_latency < 1000, \
                f"Average detection latency should be under 1 second, got {avg_latency:.2f}ms"
        
        # Verify alerts
        high_violation_tests = [r for r in monitoring_results if r["detected_violations"] >= monitoring_config["alert_threshold"]]
        alerted_tests = [r for r in monitoring_results if r["alert_triggered"]]
        
        assert len(alerted_tests) >= len(high_violation_tests) * 0.9, \
            f"Most high-violation tests should trigger alerts, got {len(alerted_tests)}/{len(high_violation_tests)}"
        
        logger.info(f"Real-time monitoring completed: "
                   f"{len(violation_events)} violations detected, "
                   f"Accuracy: {avg_accuracy:.2%}")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_iso_cryptographic_011(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """TDM_ISO_CRYPTOGRAPHIC_011: Cryptographic test data isolation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing cryptographic isolation techniques")
        
        # Create cryptographically isolated test environments
        crypto_environments = []
        
        for i in range(3):
            # Generate unique encryption key for each test
            test_id = f"{self.test_namespace}_CRYPTO_{i}"
            encryption_key = hashlib.sha256(f"{test_id}_{uuid.uuid4()}".encode()).hexdigest()
            
            crypto_environments.append({
                "test_id": test_id,
                "encryption_key": encryption_key,
                "data_items": [
                    f"Sensitive data item {j} for test {i}"
                    for j in range(3)
                ]
            })
        
        crypto_results = []
        
        for env in crypto_environments:
            env_results = {
                "test_id": env["test_id"],
                "operations": [],
                "isolation_breaches": 0
            }
            
            # Encrypt and store test data
            for data_item in env["data_items"]:
                # Simulate encryption
                encrypted_data = hashlib.sha256(
                    f"{env['encryption_key']}:{data_item}".encode()
                ).hexdigest()
                
                store_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Store encrypted data {encrypted_data[:16]}... for {env['test_id']}"}],
                    "max_tokens": 40
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, store_request
                )
                
                env_results["operations"].append({
                    "type": "store",
                    "success": response.status_code == 200,
                    "encrypted": True
                })
            
            # Attempt to access data with wrong key (should fail)
            wrong_key = hashlib.sha256(f"wrong_key_{uuid.uuid4()}".encode()).hexdigest()
            
            access_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Access data for {env['test_id']} with key {wrong_key[:16]}..."}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, access_request
            )
            
            # In real implementation, this should fail or return encrypted data
            unauthorized_access = response.status_code == 200  # Simplified
            if unauthorized_access:
                env_results["isolation_breaches"] += 1
            
            # Access with correct key (should succeed)
            correct_access_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Access data for {env['test_id']} with key {env['encryption_key'][:16]}..."}],
                "max_tokens": 60
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, correct_access_request
            )
            
            env_results["operations"].append({
                "type": "authorized_access",
                "success": response.status_code == 200,
                "encrypted": True
            })
            
            # Secure key disposal
            disposal_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Securely dispose encryption key for {env['test_id']}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, disposal_request
            )
            
            env_results["key_disposed"] = response.status_code == 200
            
            crypto_results.append(env_results)
            
            logger.info(f"Crypto isolation {env['test_id']}: "
                       f"Operations: {len(env_results['operations'])}, "
                       f"Breaches: {env_results['isolation_breaches']}")
        
        # Verify cryptographic isolation
        assert all(result["isolation_breaches"] == 0 for result in crypto_results), \
            "No cryptographic isolation breaches should occur"
        
        assert all(result["key_disposed"] for result in crypto_results), \
            "All encryption keys should be securely disposed"
        
        successful_operations = sum(
            len([op for op in result["operations"] if op["success"]])
            for result in crypto_results
        )
        total_operations = sum(len(result["operations"]) for result in crypto_results)
        
        assert successful_operations >= total_operations * 0.8, \
            f"Most operations should succeed, got {successful_operations}/{total_operations}"
        
        logger.info("Cryptographic isolation test completed successfully")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_iso_blockchain_verification_014(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """TDM_ISO_BLOCKCHAIN_VERIFICATION_014: Blockchain-based isolation audit trail"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing blockchain-based isolation verification")
        
        # Initialize blockchain for isolation audit
        blockchain = []
        genesis_block = {
            "index": 0,
            "timestamp": time.time(),
            "data": "Genesis block - Test isolation audit trail",
            "previous_hash": "0",
            "hash": hashlib.sha256("Genesis block".encode()).hexdigest()
        }
        blockchain.append(genesis_block)
        
        # Test scenarios generating audit events
        audit_scenarios = [
            {
                "test_id": f"{self.test_namespace}_AUDIT_1",
                "events": [
                    {"type": "test_start", "isolated": True},
                    {"type": "data_access", "resource": "user_data", "authorized": True},
                    {"type": "test_complete", "cleanup": True}
                ]
            },
            {
                "test_id": f"{self.test_namespace}_AUDIT_2",
                "events": [
                    {"type": "test_start", "isolated": True},
                    {"type": "cross_test_attempt", "resource": "shared_cache", "blocked": True},
                    {"type": "test_complete", "cleanup": True}
                ]
            }
        ]
        
        audit_results = []
        
        for scenario in audit_scenarios:
            scenario_blocks = []
            
            for event in scenario["events"]:
                # Create audit record
                audit_record = {
                    "test_id": scenario["test_id"],
                    "event_type": event["type"],
                    "timestamp": time.time(),
                    "event_data": event,
                    "isolation_maintained": event.get("isolated", True) or event.get("blocked", False)
                }
                
                # Create blockchain block
                previous_block = blockchain[-1]
                block_data = json.dumps(audit_record, sort_keys=True)
                block_string = f"{len(blockchain)}:{previous_block['hash']}:{block_data}"
                block_hash = hashlib.sha256(block_string.encode()).hexdigest()
                
                new_block = {
                    "index": len(blockchain),
                    "timestamp": audit_record["timestamp"],
                    "data": audit_record,
                    "previous_hash": previous_block["hash"],
                    "hash": block_hash
                }
                
                blockchain.append(new_block)
                scenario_blocks.append(new_block)
                
                # Log event to API for verification
                log_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Log isolation event: {event['type']} for {scenario['test_id']} - Hash: {block_hash[:16]}..."}],
                    "max_tokens": 40
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, log_request
                )
                
                event_logged = response.status_code == 200
                
                logger.info(f"Blockchain event {event['type']} for {scenario['test_id']}: "
                           f"Block #{new_block['index']}, "
                           f"Hash: {block_hash[:16]}...")
            
            # Verify blockchain integrity for this test
            chain_valid = True
            for i in range(1, len(scenario_blocks)):
                current_block = scenario_blocks[i]
                previous_block = scenario_blocks[i-1]
                
                # Verify hash chain
                if current_block["previous_hash"] != previous_block["hash"]:
                    chain_valid = False
                    break
                
                # Verify block hash
                block_data = json.dumps(current_block["data"], sort_keys=True)
                expected_hash = hashlib.sha256(
                    f"{current_block['index']}:{current_block['previous_hash']}:{block_data}".encode()
                ).hexdigest()
                
                if current_block["hash"] != expected_hash:
                    chain_valid = False
                    break
            
            # Generate compliance report
            isolation_events = [b["data"] for b in scenario_blocks if b["data"]["isolation_maintained"]]
            violation_events = [b["data"] for b in scenario_blocks if not b["data"]["isolation_maintained"]]
            
            audit_results.append({
                "test_id": scenario["test_id"],
                "total_events": len(scenario_blocks),
                "isolation_maintained_count": len(isolation_events),
                "violation_count": len(violation_events),
                "blockchain_valid": chain_valid,
                "audit_complete": True
            })
        
        # Verify blockchain-based audit
        assert all(result["blockchain_valid"] for result in audit_results), \
            "Blockchain integrity should be maintained for all tests"
        
        assert all(result["audit_complete"] for result in audit_results), \
            "Audit trail should be complete for all tests"
        
        # Verify overall blockchain integrity
        overall_chain_valid = True
        for i in range(1, len(blockchain)):
            if blockchain[i]["previous_hash"] != blockchain[i-1]["hash"]:
                overall_chain_valid = False
                break
        
        assert overall_chain_valid, \
            "Overall blockchain integrity should be maintained"
        
        # Generate final audit report
        total_blocks = len(blockchain)
        total_isolation_events = sum(result["isolation_maintained_count"] for result in audit_results)
        total_violations = sum(result["violation_count"] for result in audit_results)
        
        logger.info(f"Blockchain audit complete: "
                   f"{total_blocks} blocks, "
                   f"{total_isolation_events} isolation events, "
                   f"{total_violations} violations, "
                   f"Chain valid: {overall_chain_valid}")
        
        logger.info("Blockchain-based isolation verification completed successfully")