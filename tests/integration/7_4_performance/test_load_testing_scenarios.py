# Section 7.4 - Load Testing Scenarios
# Based on: docs/test_design_n_planning/Testcases_7_4_Performance Testing/Test Cases_Load Testing Scenarios.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List
from dataclasses import dataclass

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class LoadTestResult:
    """Load test result data structure"""
    test_name: str
    concurrent_users: int
    total_requests: int
    successful_requests: int
    failed_requests: int
    total_duration: float
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    p95_response_time: float
    requests_per_second: float
    error_rate: float


class TestLoadTestingScenarios:
    """Load testing scenarios for API performance validation"""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_baseline_load_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """PERF_BASELINE_001: Baseline load testing"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Baseline load test: 10 concurrent users, 50 requests total
        test_config = {
            "name": "baseline_load",
            "concurrent_users": 10,
            "requests_per_user": 5,
            "duration_seconds": 30
        }
        
        result = await self._execute_load_test(
            http_client, auth_headers, make_request, test_config
        )
        
        # Baseline performance assertions
        assert result.error_rate <= 0.05, f"Error rate should be <= 5%, got {result.error_rate:.2%}"
        assert result.avg_response_time <= 5.0, f"Average response time should be <= 5s, got {result.avg_response_time:.2f}s"
        assert result.requests_per_second >= 1.0, f"RPS should be >= 1, got {result.requests_per_second:.2f}"
        
        logger.info(f"Baseline Load Test Results: {result}")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_peak_load_001(self, http_client: httpx.AsyncClient,
                                    auth_headers: Dict[str, str],
                                    make_request):
        """PERF_PEAK_001: Peak load testing"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Peak load test: 50 concurrent users
        test_config = {
            "name": "peak_load",
            "concurrent_users": 50,
            "requests_per_user": 3,
            "duration_seconds": 60
        }
        
        result = await self._execute_load_test(
            http_client, auth_headers, make_request, test_config
        )
        
        # Peak load performance assertions
        assert result.error_rate <= 0.10, f"Error rate should be <= 10%, got {result.error_rate:.2%}"
        assert result.avg_response_time <= 10.0, f"Average response time should be <= 10s, got {result.avg_response_time:.2f}s"
        assert result.p95_response_time <= 20.0, f"P95 response time should be <= 20s, got {result.p95_response_time:.2f}s"
        
        logger.info(f"Peak Load Test Results: {result}")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_stress_load_001(self, http_client: httpx.AsyncClient,
                                      auth_headers: Dict[str, str],
                                      make_request):
        """PERF_STRESS_001: Stress testing beyond normal capacity"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Stress test: 100 concurrent users
        test_config = {
            "name": "stress_load",
            "concurrent_users": 100,
            "requests_per_user": 2,
            "duration_seconds": 90
        }
        
        result = await self._execute_load_test(
            http_client, auth_headers, make_request, test_config
        )
        
        # Stress test assertions (more lenient)
        assert result.error_rate <= 0.20, f"Error rate should be <= 20%, got {result.error_rate:.2%}"
        assert result.avg_response_time <= 30.0, f"Average response time should be <= 30s, got {result.avg_response_time:.2f}s"
        
        # System should not crash under stress
        assert result.successful_requests > 0, "Some requests should succeed even under stress"
        
        logger.info(f"Stress Load Test Results: {result}")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_spike_load_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     make_request):
        """PERF_SPIKE_001: Spike load testing (sudden traffic increase)"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Spike test: Gradual increase then sudden spike
        spike_phases = [
            {"users": 5, "duration": 10},   # Warm up
            {"users": 10, "duration": 10},  # Normal load
            {"users": 50, "duration": 15},  # Spike
            {"users": 10, "duration": 10}   # Cool down
        ]
        
        all_results = []
        
        for i, phase in enumerate(spike_phases):
            test_config = {
                "name": f"spike_phase_{i+1}",
                "concurrent_users": phase["users"],
                "requests_per_user": 2,
                "duration_seconds": phase["duration"]
            }
            
            result = await self._execute_load_test(
                http_client, auth_headers, make_request, test_config
            )
            all_results.append(result)
            
            logger.info(f"Spike Phase {i+1} Results: {result}")
            
            # Brief pause between phases
            await asyncio.sleep(2)
        
        # Verify system handles spike gracefully
        spike_result = all_results[2]  # The spike phase
        assert spike_result.error_rate <= 0.25, "Spike should not cause excessive errors"
        
        # System should recover after spike
        cooldown_result = all_results[3]
        assert cooldown_result.error_rate <= 0.10, "System should recover after spike"
        
        logger.info("Spike Load Test completed successfully")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_endurance_001(self, http_client: httpx.AsyncClient,
                                    auth_headers: Dict[str, str],
                                    make_request):
        """PERF_ENDURANCE_001: Endurance testing (sustained load)"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Endurance test: Moderate load for extended period
        test_config = {
            "name": "endurance",
            "concurrent_users": 20,
            "requests_per_user": 10,
            "duration_seconds": 300  # 5 minutes
        }
        
        result = await self._execute_load_test(
            http_client, auth_headers, make_request, test_config
        )
        
        # Endurance test assertions
        assert result.error_rate <= 0.08, f"Error rate should be <= 8% for endurance, got {result.error_rate:.2%}"
        assert result.avg_response_time <= 8.0, f"Average response time should be <= 8s, got {result.avg_response_time:.2f}s"
        
        # Performance should not degrade significantly over time
        # (This would require time-series analysis in a full implementation)
        
        logger.info(f"Endurance Test Results: {result}")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_mixed_workload_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         embedding_auth_headers: Dict[str, str],
                                         make_request):
        """PERF_MIXED_WORKLOAD_001: Mixed workload testing (chat + embeddings)"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Mixed workload: 70% chat, 30% embeddings
        async def mixed_workload_user(user_id: int, duration: int):
            """Simulate a user with mixed workload"""
            end_time = time.time() + duration
            requests = []
            
            while time.time() < end_time:
                # 70% chance of chat request
                if user_id % 10 < 7:
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Mixed workload test {user_id}"}],
                        "max_tokens": 50
                    }
                    headers = auth_headers
                    endpoint = "/api/v1/chat/completions"
                else:
                    # 30% chance of embedding request
                    request = {
                        "model": config.get_embedding_model(0),
                        "input": f"Mixed workload embedding {user_id}"
                    }
                    headers = embedding_auth_headers
                    endpoint = "/api/v1/embeddings"
                
                start_time = time.time()
                response = await make_request(
                    http_client, "POST", endpoint, headers, request
                )
                end_time_req = time.time()
                
                requests.append({
                    "status_code": response.status_code,
                    "response_time": end_time_req - start_time,
                    "endpoint": endpoint
                })
                
                await asyncio.sleep(0.5)  # Delay between requests
            
            return requests
        
        # Execute mixed workload test
        concurrent_users = 15
        duration = 30
        
        start_time = time.time()
        tasks = [mixed_workload_user(i, duration) for i in range(concurrent_users)]
        results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        # Analyze mixed workload results
        all_requests = [req for user_requests in results for req in user_requests]
        successful_requests = [req for req in all_requests if req["status_code"] == 200]
        failed_requests = [req for req in all_requests if req["status_code"] != 200]
        
        if all_requests:
            error_rate = len(failed_requests) / len(all_requests)
            avg_response_time = statistics.mean([req["response_time"] for req in all_requests])
            rps = len(all_requests) / total_duration
            
            # Mixed workload assertions
            assert error_rate <= 0.10, f"Mixed workload error rate should be <= 10%, got {error_rate:.2%}"
            assert avg_response_time <= 6.0, f"Mixed workload avg response time should be <= 6s, got {avg_response_time:.2f}s"
            
            logger.info(f"Mixed Workload Test: {len(all_requests)} requests, {error_rate:.2%} error rate, {avg_response_time:.2f}s avg response time, {rps:.2f} RPS")
        else:
            pytest.fail("No requests completed in mixed workload test")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_ramp_up_001(self, http_client: httpx.AsyncClient,
                                  auth_headers: Dict[str, str],
                                  make_request):
        """PERF_RAMP_UP_001: Gradual ramp-up testing"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Gradual ramp-up: 5 -> 10 -> 20 -> 30 users
        ramp_phases = [5, 10, 20, 30]
        phase_duration = 15  # seconds per phase
        
        results = []
        
        for phase_users in ramp_phases:
            test_config = {
                "name": f"ramp_up_{phase_users}_users",
                "concurrent_users": phase_users,
                "requests_per_user": 2,
                "duration_seconds": phase_duration
            }
            
            result = await self._execute_load_test(
                http_client, auth_headers, make_request, test_config
            )
            results.append(result)
            
            logger.info(f"Ramp-up Phase ({phase_users} users): {result}")
            
            # Brief pause between phases
            await asyncio.sleep(1)
        
        # Analyze ramp-up performance
        for i, result in enumerate(results):
            assert result.error_rate <= 0.12, f"Ramp-up phase {i+1} error rate too high: {result.error_rate:.2%}"
            
            # Performance shouldn't degrade too much as load increases
            if i > 0:
                prev_result = results[i-1]
                response_time_increase = result.avg_response_time / prev_result.avg_response_time
                assert response_time_increase <= 3.0, f"Response time increase too high: {response_time_increase:.2f}x"
        
        logger.info("Ramp-up test completed successfully")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_chaos_provider_failure_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """PERF_CHAOS_001: Chaos testing with provider failures"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Chaos test: Normal load with simulated provider failures
        test_config = {
            "name": "chaos_provider_failure",
            "concurrent_users": 25,
            "requests_per_user": 4,
            "duration_seconds": 60
        }
        
        # Include some invalid models to simulate provider failures
        chaos_models = [
            config.get_chat_model(0),
            config.get_chat_model(0),
            "invalid_model_chaos_test",  # Simulated failure
            config.get_chat_model(0)
        ]
        
        result = await self._execute_chaos_load_test(
            http_client, auth_headers, make_request, test_config, chaos_models
        )
        
        # Chaos test should handle failures gracefully
        assert result.error_rate <= 0.30, f"Chaos test error rate should be <= 30%, got {result.error_rate:.2%}"
        assert result.successful_requests > 0, "Some requests should succeed despite chaos"
        
        logger.info(f"Chaos Test Results: {result}")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_volume_extreme_data_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """PERF_VOLUME_001: Volume testing with extreme data sizes"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Volume test: Large payloads
        large_content = "X" * 10000  # 10KB content
        
        test_config = {
            "name": "volume_extreme_data",
            "concurrent_users": 15,
            "requests_per_user": 3,
            "duration_seconds": 45
        }
        
        result = await self._execute_volume_load_test(
            http_client, auth_headers, make_request, test_config, large_content
        )
        
        # Volume test assertions
        assert result.error_rate <= 0.15, f"Volume test error rate should be <= 15%, got {result.error_rate:.2%}"
        assert result.avg_response_time <= 30.0, f"Large payload response time should be <= 30s, got {result.avg_response_time:.2f}s"
        
        logger.info(f"Volume Test Results: {result}")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_scalability_horizontal_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """PERF_SCALABILITY_001: Horizontal scaling performance validation"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Test scalability by increasing concurrent users progressively
        scalability_phases = [
            {"users": 20, "expected_rps": 2.0},
            {"users": 40, "expected_rps": 3.5},
            {"users": 60, "expected_rps": 4.8}
        ]
        
        results = []
        
        for phase in scalability_phases:
            test_config = {
                "name": f"scalability_{phase['users']}_users",
                "concurrent_users": phase["users"],
                "requests_per_user": 3,
                "duration_seconds": 30
            }
            
            result = await self._execute_load_test(
                http_client, auth_headers, make_request, test_config
            )
            results.append((result, phase["expected_rps"]))
            
            logger.info(f"Scalability Phase ({phase['users']} users): {result}")
        
        # Validate scalability
        for result, expected_rps in results:
            assert result.error_rate <= 0.12, f"Scalability error rate too high: {result.error_rate:.2%}"
            # RPS should scale reasonably with user count
            rps_ratio = result.requests_per_second / expected_rps
            assert 0.7 <= rps_ratio <= 1.5, f"RPS scaling not optimal: {result.requests_per_second:.2f} vs expected {expected_rps:.2f}"
        
        logger.info("Scalability test completed successfully")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_capacity_planning_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """PERF_CAPACITY_001: Capacity planning stress tests"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Capacity planning: Find breaking point
        capacity_phases = [
            {"users": 30, "duration": 20},
            {"users": 60, "duration": 20},
            {"users": 90, "duration": 20},
            {"users": 120, "duration": 15}
        ]
        
        breaking_point_found = False
        
        for phase in capacity_phases:
            test_config = {
                "name": f"capacity_{phase['users']}_users",
                "concurrent_users": phase["users"],
                "requests_per_user": 2,
                "duration_seconds": phase["duration"]
            }
            
            result = await self._execute_load_test(
                http_client, auth_headers, make_request, test_config
            )
            
            logger.info(f"Capacity Phase ({phase['users']} users): {result}")
            
            # Check if we've reached breaking point
            if result.error_rate > 0.5 or result.avg_response_time > 60.0:
                breaking_point_found = True
                logger.info(f"Breaking point identified at {phase['users']} concurrent users")
                break
            
            # Brief pause between phases
            await asyncio.sleep(5)
        
        # At least some phases should work well
        # (Breaking point is expected at higher loads)
        
        logger.info("Capacity planning test completed")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_failover_performance_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """PERF_FAILOVER_001: Failover performance testing"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Simulate failover scenario with model switching
        chat_models = config.get_chat_models() or ["test_model"]
        if len(chat_models) < 2:
            pytest.skip("Multiple models required for failover testing")
        
        test_config = {
            "name": "failover_performance",
            "concurrent_users": 20,
            "requests_per_user": 5,
            "duration_seconds": 40
        }
        
        result = await self._execute_failover_load_test(
            http_client, auth_headers, make_request, test_config, chat_models
        )
        
        # Failover should not cause excessive degradation
        assert result.error_rate <= 0.20, f"Failover error rate should be <= 20%, got {result.error_rate:.2%}"
        assert result.avg_response_time <= 15.0, f"Failover response time should be <= 15s, got {result.avg_response_time:.2f}s"
        
        logger.info(f"Failover Performance Test Results: {result}")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_perf_config_change_impact_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """PERF_CONFIG_001: Configuration change impact testing"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Test performance with different configuration parameters
        config_variations = [
            {"max_tokens": 50, "expected_performance": "baseline"},
            {"max_tokens": 200, "expected_performance": "slower"},
            {"max_tokens": 10, "expected_performance": "faster"}
        ]
        
        results = []
        
        for variation in config_variations:
            test_config = {
                "name": f"config_max_tokens_{variation['max_tokens']}",
                "concurrent_users": 15,
                "requests_per_user": 3,
                "duration_seconds": 20,
                "max_tokens": variation["max_tokens"]
            }
            
            result = await self._execute_config_load_test(
                http_client, auth_headers, make_request, test_config
            )
            results.append((result, variation))
            
            logger.info(f"Config variation (max_tokens={variation['max_tokens']}): {result}")
        
        # Validate configuration impact
        for result, variation in results:
            assert result.error_rate <= 0.10, f"Config variation error rate too high: {result.error_rate:.2%}"
        
        logger.info("Configuration change impact test completed")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_perf_multi_region_distribution_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """PERF_REGION_001: Multi-region load distribution testing"""
        if not config.should_run_load_tests():
            pytest.skip("Load tests disabled")
        
        # Simulate multi-region load distribution
        # In a real scenario, this would involve multiple endpoints
        test_config = {
            "name": "multi_region_distribution",
            "concurrent_users": 30,
            "requests_per_user": 4,
            "duration_seconds": 50
        }
        
        result = await self._execute_distributed_load_test(
            http_client, auth_headers, make_request, test_config
        )
        
        # Multi-region should handle load efficiently
        assert result.error_rate <= 0.08, f"Multi-region error rate should be <= 8%, got {result.error_rate:.2%}"
        assert result.avg_response_time <= 8.0, f"Multi-region response time should be <= 8s, got {result.avg_response_time:.2f}s"
        
        logger.info(f"Multi-region Distribution Test Results: {result}")
    
    async def _execute_chaos_load_test(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     make_request, test_config: Dict[str, Any],
                                     chaos_models: List[str]) -> LoadTestResult:
        """Execute chaos load test with model failures"""
        
        async def chaos_user(user_id: int, requests_per_user: int, duration: int):
            end_time = time.time() + duration
            user_requests = []
            
            for i in range(requests_per_user):
                if time.time() >= end_time:
                    break
                
                # Use chaos model (some invalid)
                model = chaos_models[i % len(chaos_models)]
                request = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Chaos test user {user_id} request {i}"}],
                    "max_tokens": 50
                }
                
                start_time = time.time()
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    end_time_req = time.time()
                    
                    user_requests.append({
                        "status_code": response.status_code,
                        "response_time": end_time_req - start_time,
                        "success": response.status_code == 200,
                        "model": model
                    })
                    
                except Exception as e:
                    end_time_req = time.time()
                    user_requests.append({
                        "status_code": 0,
                        "response_time": end_time_req - start_time,
                        "success": False,
                        "error": str(e),
                        "model": model
                    })
                
                await asyncio.sleep(0.2)
            
            return user_requests
        
        # Execute chaos load test
        start_time = time.time()
        
        tasks = [
            chaos_user(i, test_config["requests_per_user"], test_config["duration_seconds"])
            for i in range(test_config["concurrent_users"])
        ]
        
        user_results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        return self._aggregate_results(user_results, test_config, total_duration)
    
    async def _execute_volume_load_test(self, http_client: httpx.AsyncClient,
                                      auth_headers: Dict[str, str],
                                      make_request, test_config: Dict[str, Any],
                                      large_content: str) -> LoadTestResult:
        """Execute volume load test with large payloads"""
        
        async def volume_user(user_id: int, requests_per_user: int, duration: int):
            end_time = time.time() + duration
            user_requests = []
            
            for i in range(requests_per_user):
                if time.time() >= end_time:
                    break
                
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"{large_content} - User {user_id} request {i}"}],
                    "max_tokens": 100
                }
                
                start_time = time.time()
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    end_time_req = time.time()
                    
                    user_requests.append({
                        "status_code": response.status_code,
                        "response_time": end_time_req - start_time,
                        "success": response.status_code == 200,
                        "payload_size": len(large_content)
                    })
                    
                except Exception as e:
                    end_time_req = time.time()
                    user_requests.append({
                        "status_code": 0,
                        "response_time": end_time_req - start_time,
                        "success": False,
                        "error": str(e),
                        "payload_size": len(large_content)
                    })
                
                await asyncio.sleep(0.3)
            
            return user_requests
        
        start_time = time.time()
        
        tasks = [
            volume_user(i, test_config["requests_per_user"], test_config["duration_seconds"])
            for i in range(test_config["concurrent_users"])
        ]
        
        user_results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        return self._aggregate_results(user_results, test_config, total_duration)
    
    async def _execute_failover_load_test(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request, test_config: Dict[str, Any],
                                        models: List[str]) -> LoadTestResult:
        """Execute failover load test with model switching"""
        
        async def failover_user(user_id: int, requests_per_user: int, duration: int):
            end_time = time.time() + duration
            user_requests = []
            
            for i in range(requests_per_user):
                if time.time() >= end_time:
                    break
                
                # Switch models to simulate failover
                model = models[i % len(models)]
                request = {
                    "model": model,
                    "messages": [{"role": "user", "content": f"Failover test user {user_id} request {i}"}],
                    "max_tokens": 50
                }
                
                start_time = time.time()
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    end_time_req = time.time()
                    
                    user_requests.append({
                        "status_code": response.status_code,
                        "response_time": end_time_req - start_time,
                        "success": response.status_code == 200,
                        "model": model
                    })
                    
                except Exception as e:
                    end_time_req = time.time()
                    user_requests.append({
                        "status_code": 0,
                        "response_time": end_time_req - start_time,
                        "success": False,
                        "error": str(e),
                        "model": model
                    })
                
                await asyncio.sleep(0.15)
            
            return user_requests
        
        start_time = time.time()
        
        tasks = [
            failover_user(i, test_config["requests_per_user"], test_config["duration_seconds"])
            for i in range(test_config["concurrent_users"])
        ]
        
        user_results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        return self._aggregate_results(user_results, test_config, total_duration)
    
    async def _execute_config_load_test(self, http_client: httpx.AsyncClient,
                                      auth_headers: Dict[str, str],
                                      make_request, test_config: Dict[str, Any]) -> LoadTestResult:
        """Execute load test with specific configuration parameters"""
        
        async def config_user(user_id: int, requests_per_user: int, duration: int, max_tokens: int):
            end_time = time.time() + duration
            user_requests = []
            
            for i in range(requests_per_user):
                if time.time() >= end_time:
                    break
                
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Config test user {user_id} request {i}"}],
                    "max_tokens": max_tokens
                }
                
                start_time = time.time()
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    end_time_req = time.time()
                    
                    user_requests.append({
                        "status_code": response.status_code,
                        "response_time": end_time_req - start_time,
                        "success": response.status_code == 200,
                        "max_tokens": max_tokens
                    })
                    
                except Exception as e:
                    end_time_req = time.time()
                    user_requests.append({
                        "status_code": 0,
                        "response_time": end_time_req - start_time,
                        "success": False,
                        "error": str(e),
                        "max_tokens": max_tokens
                    })
                
                await asyncio.sleep(0.1)
            
            return user_requests
        
        start_time = time.time()
        
        tasks = [
            config_user(i, test_config["requests_per_user"], test_config["duration_seconds"], test_config["max_tokens"])
            for i in range(test_config["concurrent_users"])
        ]
        
        user_results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        return self._aggregate_results(user_results, test_config, total_duration)
    
    async def _execute_distributed_load_test(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request, test_config: Dict[str, Any]) -> LoadTestResult:
        """Execute distributed load test simulating multi-region"""
        
        async def distributed_user(user_id: int, requests_per_user: int, duration: int):
            end_time = time.time() + duration
            user_requests = []
            
            for i in range(requests_per_user):
                if time.time() >= end_time:
                    break
                
                # Add region identifier to simulate distributed requests
                region = f"region_{user_id % 3}"  # Simulate 3 regions
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Multi-region test from {region} user {user_id} request {i}"}],
                    "max_tokens": 50
                }
                
                start_time = time.time()
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    end_time_req = time.time()
                    
                    user_requests.append({
                        "status_code": response.status_code,
                        "response_time": end_time_req - start_time,
                        "success": response.status_code == 200,
                        "region": region
                    })
                    
                except Exception as e:
                    end_time_req = time.time()
                    user_requests.append({
                        "status_code": 0,
                        "response_time": end_time_req - start_time,
                        "success": False,
                        "error": str(e),
                        "region": region
                    })
                
                await asyncio.sleep(0.1)
            
            return user_requests
        
        start_time = time.time()
        
        tasks = [
            distributed_user(i, test_config["requests_per_user"], test_config["duration_seconds"])
            for i in range(test_config["concurrent_users"])
        ]
        
        user_results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        return self._aggregate_results(user_results, test_config, total_duration)
    
    def _aggregate_results(self, user_results: List[List[Dict]], test_config: Dict[str, Any], total_duration: float) -> LoadTestResult:
        """Aggregate results from multiple users into a LoadTestResult"""
        all_requests = [req for user_reqs in user_results for req in user_reqs]
        
        if not all_requests:
            return LoadTestResult(
                test_name=test_config["name"],
                concurrent_users=test_config["concurrent_users"],
                total_requests=0,
                successful_requests=0,
                failed_requests=0,
                total_duration=total_duration,
                avg_response_time=0,
                min_response_time=0,
                max_response_time=0,
                p95_response_time=0,
                requests_per_second=0,
                error_rate=1.0
            )
        
        successful_requests = [req for req in all_requests if req["success"]]
        failed_requests = [req for req in all_requests if not req["success"]]
        response_times = [req["response_time"] for req in all_requests]
        
        # Calculate statistics
        total_requests = len(all_requests)
        success_count = len(successful_requests)
        failed_count = len(failed_requests)
        error_rate = failed_count / total_requests if total_requests > 0 else 1.0
        
        avg_response_time = statistics.mean(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max_response_time
        
        requests_per_second = total_requests / total_duration if total_duration > 0 else 0
        
        return LoadTestResult(
            test_name=test_config["name"],
            concurrent_users=test_config["concurrent_users"],
            total_requests=total_requests,
            successful_requests=success_count,
            failed_requests=failed_count,
            total_duration=total_duration,
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            p95_response_time=p95_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate
        )
    
    async def _execute_load_test(self, http_client: httpx.AsyncClient,
                               auth_headers: Dict[str, str],
                               make_request, test_config: Dict[str, Any]) -> LoadTestResult:
        """Execute a load test with given configuration"""
        
        async def simulate_user(user_id: int, requests_per_user: int, duration: int):
            """Simulate a single user making requests"""
            end_time = time.time() + duration
            user_requests = []
            
            for i in range(requests_per_user):
                if time.time() >= end_time:
                    break
                
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Load test user {user_id} request {i}"}],
                    "max_tokens": 50
                }
                
                start_time = time.time()
                try:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    end_time_req = time.time()
                    
                    user_requests.append({
                        "status_code": response.status_code,
                        "response_time": end_time_req - start_time,
                        "success": response.status_code == 200
                    })
                    
                except Exception as e:
                    end_time_req = time.time()
                    user_requests.append({
                        "status_code": 0,
                        "response_time": end_time_req - start_time,
                        "success": False,
                        "error": str(e)
                    })
                
                # Small delay between requests from same user
                await asyncio.sleep(0.1)
            
            return user_requests
        
        # Execute load test
        start_time = time.time()
        
        tasks = [
            simulate_user(i, test_config["requests_per_user"], test_config["duration_seconds"])
            for i in range(test_config["concurrent_users"])
        ]
        
        user_results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        # Aggregate results
        all_requests = [req for user_reqs in user_results for req in user_reqs]
        
        if not all_requests:
            return LoadTestResult(
                test_name=test_config["name"],
                concurrent_users=test_config["concurrent_users"],
                total_requests=0,
                successful_requests=0,
                failed_requests=0,
                total_duration=total_duration,
                avg_response_time=0,
                min_response_time=0,
                max_response_time=0,
                p95_response_time=0,
                requests_per_second=0,
                error_rate=1.0
            )
        
        successful_requests = [req for req in all_requests if req["success"]]
        failed_requests = [req for req in all_requests if not req["success"]]
        response_times = [req["response_time"] for req in all_requests]
        
        # Calculate statistics
        total_requests = len(all_requests)
        success_count = len(successful_requests)
        failed_count = len(failed_requests)
        error_rate = failed_count / total_requests if total_requests > 0 else 1.0
        
        avg_response_time = statistics.mean(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max_response_time
        
        requests_per_second = total_requests / total_duration if total_duration > 0 else 0
        
        return LoadTestResult(
            test_name=test_config["name"],
            concurrent_users=test_config["concurrent_users"],
            total_requests=total_requests,
            successful_requests=success_count,
            failed_requests=failed_count,
            total_duration=total_duration,
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            p95_response_time=p95_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate
        )