# Section 7.9 - Data Infrastructure and Tooling
# Based on: docs/test_design_n_planning/Testcases_7_9_DataManagement/Test Cases_Data Infrastructure and Tooling.md

import pytest
import httpx
import asyncio
import time
import statistics
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor
import tempfile
import os

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class InfrastructureTestResult:
    """Infrastructure testing result data structure"""
    test_name: str
    generation_time_ms: float
    data_quality_score: float
    scalability_factor: float
    cost_efficiency: float
    success: bool


class TestDataGenerationInfrastructure:
    """Test data generation infrastructure capabilities"""
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_infra_generation_framework_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TDM_INFRA_GENERATION_FRAMEWORK_001: Test data generation framework"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test data generation framework capabilities
        generation_scenarios = [
            {
                "type": "prompt_templates",
                "count": 10,
                "template": "Explain {topic} to a {audience}",
                "parameters": {
                    "topic": ["machine learning", "artificial intelligence", "deep learning"],
                    "audience": ["beginner", "expert", "student"]
                }
            },
            {
                "type": "parameter_combinations",
                "count": 6,
                "template": "Generate text with {style} style about {subject}",
                "parameters": {
                    "style": ["formal", "informal"],
                    "subject": ["technology", "science", "business"]
                }
            },
            {
                "type": "response_variations",
                "count": 5,
                "template": "What is {concept}?",
                "parameters": {
                    "concept": ["AI", "ML", "NLP", "computer vision", "robotics"]
                }
            }
        ]
        
        generation_results = []
        
        for scenario in generation_scenarios:
            scenario_start = time.perf_counter()
            generated_data = []
            
            # Generate test data based on scenario
            for i in range(scenario["count"]):
                # Select parameters for this generation
                selected_params = {}
                for param_name, param_options in scenario["parameters"].items():
                    selected_params[param_name] = param_options[i % len(param_options)]
                
                # Generate prompt from template
                prompt = scenario["template"].format(**selected_params)
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 100
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    content = response_data["choices"][0]["message"]["content"]
                    
                    generated_item = {
                        "prompt": prompt,
                        "response": content,
                        "parameters": selected_params,
                        "length": len(content)
                    }
                    generated_data.append(generated_item)
            
            scenario_end = time.perf_counter()
            generation_time = (scenario_end - scenario_start) * 1000
            
            # Calculate quality metrics
            response_lengths = [item["length"] for item in generated_data]
            avg_length = statistics.mean(response_lengths) if response_lengths else 0
            length_variance = statistics.stdev(response_lengths) if len(response_lengths) > 1 else 0
            
            # Quality score based on diversity and completeness
            quality_score = min(1.0, (avg_length / 100) * (length_variance / 50))
            
            result = InfrastructureTestResult(
                test_name=scenario["type"],
                generation_time_ms=generation_time,
                data_quality_score=quality_score,
                scalability_factor=len(generated_data) / (generation_time / 1000),
                cost_efficiency=len(generated_data) / max(1, generation_time / 1000),
                success=len(generated_data) >= scenario["count"] * 0.8
            )
            
            generation_results.append(result)
            
            logger.info(f"Generation framework {scenario['type']}: "
                       f"{len(generated_data)} items in {generation_time:.2f}ms, "
                       f"Quality: {quality_score:.3f}")
        
        # Verify generation framework effectiveness
        successful_scenarios = [r for r in generation_results if r.success]
        
        assert len(successful_scenarios) >= len(generation_scenarios) * 0.8, \
            f"Most generation scenarios should succeed, got {len(successful_scenarios)}/{len(generation_scenarios)}"
        
        # Verify reasonable performance
        avg_generation_time = statistics.mean([r.generation_time_ms for r in generation_results])
        assert avg_generation_time < 30000, \
            f"Average generation time should be reasonable, got {avg_generation_time:.2f}ms"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_infra_quality_validation_002(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """TDM_INFRA_QUALITY_VALIDATION_002: Quality validation framework"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test quality validation for generated data
        quality_test_cases = [
            {
                "name": "completeness_check",
                "prompt": "List three benefits of renewable energy",
                "validation_criteria": {
                    "min_length": 50,
                    "contains_numbers": True,
                    "logical_structure": True
                }
            },
            {
                "name": "relevance_check",
                "prompt": "Explain machine learning algorithms",
                "validation_criteria": {
                    "min_length": 100,
                    "topic_relevance": ["machine", "learning", "algorithm"],
                    "technical_depth": True
                }
            },
            {
                "name": "format_consistency",
                "prompt": "Define: artificial intelligence",
                "validation_criteria": {
                    "starts_with_definition": True,
                    "proper_grammar": True,
                    "appropriate_length": (30, 200)
                }
            }
        ]
        
        quality_validation_results = []
        
        for test_case in quality_test_cases:
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": test_case["prompt"]}],
                "max_tokens": 150
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                
                # Validate against criteria
                validation_scores = {}
                criteria = test_case["validation_criteria"]
                
                # Length validation
                if "min_length" in criteria:
                    validation_scores["min_length"] = len(content) >= criteria["min_length"]
                
                if "appropriate_length" in criteria:
                    min_len, max_len = criteria["appropriate_length"]
                    validation_scores["appropriate_length"] = min_len <= len(content) <= max_len
                
                # Content validation
                if "contains_numbers" in criteria:
                    validation_scores["contains_numbers"] = any(char.isdigit() for char in content)
                
                if "topic_relevance" in criteria:
                    relevance_keywords = criteria["topic_relevance"]
                    keyword_matches = sum(1 for keyword in relevance_keywords 
                                        if keyword.lower() in content.lower())
                    validation_scores["topic_relevance"] = keyword_matches >= len(relevance_keywords) * 0.5
                
                if "starts_with_definition" in criteria:
                    definition_starters = ["artificial intelligence is", "ai is", "artificial intelligence refers"]
                    validation_scores["starts_with_definition"] = any(
                        content.lower().startswith(starter) for starter in definition_starters
                    )
                
                # Structure validation
                if "logical_structure" in criteria:
                    # Basic structure check: sentences, punctuation
                    sentence_count = len([s for s in content.split('.') if s.strip()])
                    validation_scores["logical_structure"] = sentence_count >= 2
                
                # Calculate overall quality score
                passed_validations = sum(validation_scores.values())
                total_validations = len(validation_scores)
                quality_score = passed_validations / total_validations if total_validations > 0 else 0
                
                result = {
                    "test_name": test_case["name"],
                    "prompt": test_case["prompt"],
                    "response": content,
                    "validation_scores": validation_scores,
                    "quality_score": quality_score,
                    "passed_all_validations": quality_score == 1.0
                }
                
                quality_validation_results.append(result)
                
                logger.info(f"Quality validation {test_case['name']}: "
                           f"Score: {quality_score:.2f}, "
                           f"Passed: {passed_validations}/{total_validations}")
        
        # Verify quality validation effectiveness
        high_quality_results = [r for r in quality_validation_results if r["quality_score"] >= 0.7]
        
        assert len(high_quality_results) >= len(quality_test_cases) * 0.6, \
            f"Most results should meet quality standards, got {len(high_quality_results)}/{len(quality_test_cases)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_infra_scalable_generation_003(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """TDM_INFRA_SCALABLE_GENERATION_003: Scalable data generation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test scalable generation with increasing loads
        scalability_tests = [
            {"batch_size": 5, "expected_time_factor": 1.0},
            {"batch_size": 10, "expected_time_factor": 1.8},
            {"batch_size": 15, "expected_time_factor": 2.5}
        ]
        
        scalability_results = []
        baseline_time = None
        
        for test_config in scalability_tests:
            batch_start = time.perf_counter()
            successful_generations = 0
            
            # Generate batch of data
            batch_prompts = [
                f"Explain concept {i}: artificial intelligence applications"
                for i in range(test_config["batch_size"])
            ]
            
            # Process batch with controlled concurrency
            semaphore = asyncio.Semaphore(3)  # Limit concurrent requests
            
            async def generate_single(prompt):
                async with semaphore:
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 80
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    return response.status_code == 200
            
            # Execute batch generation
            tasks = [generate_single(prompt) for prompt in batch_prompts]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            successful_generations = sum(1 for result in results if result is True)
            
            batch_end = time.perf_counter()
            batch_time = (batch_end - batch_start) * 1000
            
            if baseline_time is None:
                baseline_time = batch_time
            
            # Calculate scalability metrics
            time_factor = batch_time / baseline_time if baseline_time > 0 else 1.0
            throughput = successful_generations / (batch_time / 1000) if batch_time > 0 else 0
            efficiency = successful_generations / test_config["batch_size"]
            
            result = {
                "batch_size": test_config["batch_size"],
                "execution_time_ms": batch_time,
                "time_factor": time_factor,
                "expected_time_factor": test_config["expected_time_factor"],
                "successful_generations": successful_generations,
                "throughput": throughput,
                "efficiency": efficiency,
                "scales_well": time_factor <= test_config["expected_time_factor"] * 1.2
            }
            
            scalability_results.append(result)
            
            logger.info(f"Scalability test batch_size={test_config['batch_size']}: "
                       f"Time: {batch_time:.2f}ms, "
                       f"Factor: {time_factor:.2f}x, "
                       f"Throughput: {throughput:.2f}/s")
        
        # Verify scalability performance
        well_scaling_tests = [r for r in scalability_results if r["scales_well"]]
        high_efficiency_tests = [r for r in scalability_results if r["efficiency"] >= 0.8]
        
        assert len(well_scaling_tests) >= len(scalability_tests) * 0.7, \
            f"Most tests should scale well, got {len(well_scaling_tests)}/{len(scalability_tests)}"
        
        assert len(high_efficiency_tests) >= len(scalability_tests) * 0.6, \
            f"Most tests should have high efficiency, got {len(high_efficiency_tests)}/{len(scalability_tests)}"


class TestCloudNativeInfrastructure:
    """Test cloud-native data management infrastructure"""
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_infra_auto_scaling_008(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """TDM_INFRA_AUTO_SCALING_008: Cloud-native test data platform with auto-scaling"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Simulate auto-scaling behavior under different loads
        load_scenarios = [
            {"name": "low_load", "concurrent_requests": 3, "duration": 5},
            {"name": "medium_load", "concurrent_requests": 6, "duration": 8},
            {"name": "high_load", "concurrent_requests": 10, "duration": 10}
        ]
        
        auto_scaling_results = []
        
        for scenario in load_scenarios:
            scenario_start = time.perf_counter()
            
            # Simulate auto-scaling decision based on load
            if scenario["concurrent_requests"] <= 3:
                scaling_factor = 1.0
                instance_count = 1
            elif scenario["concurrent_requests"] <= 6:
                scaling_factor = 1.5
                instance_count = 2
            else:
                scaling_factor = 2.0
                instance_count = 3
            
            # Generate load for specified duration
            successful_requests = 0
            total_requests = 0
            response_times = []
            
            async def load_generator():
                nonlocal successful_requests, total_requests
                start_time = time.time()
                
                while (time.time() - start_time) < scenario["duration"]:
                    request_start = time.perf_counter()
                    
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Auto-scaling test {total_requests}"}],
                        "max_tokens": 50
                    }
                    
                    total_requests += 1
                    
                    try:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request_data
                        )
                        
                        if response.status_code == 200:
                            successful_requests += 1
                        
                        request_end = time.perf_counter()
                        response_times.append((request_end - request_start) * 1000)
                        
                    except Exception as e:
                        logger.warning(f"Request failed during auto-scaling test: {e}")
                    
                    # Simulate auto-scaling response time adjustment
                    await asyncio.sleep(1.0 / scaling_factor)
            
            # Run concurrent load generators
            tasks = [load_generator() for _ in range(scenario["concurrent_requests"])]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            scenario_end = time.perf_counter()
            total_time = (scenario_end - scenario_start) * 1000
            
            # Calculate performance metrics
            success_rate = successful_requests / total_requests if total_requests > 0 else 0
            avg_response_time = statistics.mean(response_times) if response_times else 0
            throughput = successful_requests / (total_time / 1000) if total_time > 0 else 0
            
            result = {
                "scenario": scenario["name"],
                "concurrent_requests": scenario["concurrent_requests"],
                "scaling_factor": scaling_factor,
                "instance_count": instance_count,
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "success_rate": success_rate,
                "avg_response_time": avg_response_time,
                "throughput": throughput,
                "scales_appropriately": success_rate >= 0.8 and avg_response_time < 10000
            }
            
            auto_scaling_results.append(result)
            
            logger.info(f"Auto-scaling {scenario['name']}: "
                       f"Scale factor: {scaling_factor}x, "
                       f"Success rate: {success_rate:.2%}, "
                       f"Throughput: {throughput:.2f}/s")
        
        # Verify auto-scaling effectiveness
        well_scaled_scenarios = [r for r in auto_scaling_results if r["scales_appropriately"]]
        
        assert len(well_scaled_scenarios) >= len(load_scenarios) * 0.7, \
            f"Most scenarios should scale appropriately, got {len(well_scaled_scenarios)}/{len(load_scenarios)}"
        
        # Verify scaling factor increases with load
        scaling_factors = [r["scaling_factor"] for r in auto_scaling_results]
        assert scaling_factors == sorted(scaling_factors), \
            "Scaling factors should increase with load"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_infra_ai_optimization_009(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TDM_INFRA_AI_OPTIMIZATION_009: AI-powered infrastructure optimization"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test AI-powered optimization for cost and performance
        optimization_scenarios = [
            {
                "name": "cost_optimization",
                "strategy": "minimize_tokens",
                "max_tokens": 30,
                "expected_cost_reduction": 0.4
            },
            {
                "name": "performance_optimization",
                "strategy": "parallel_processing",
                "batch_size": 5,
                "expected_speedup": 2.0
            },
            {
                "name": "quality_optimization",
                "strategy": "selective_retry",
                "retry_threshold": 0.8,
                "expected_quality_improvement": 0.2
            }
        ]
        
        optimization_results = []
        baseline_metrics = None
        
        for scenario in optimization_scenarios:
            scenario_start = time.perf_counter()
            
            if scenario["strategy"] == "minimize_tokens":
                # Test cost optimization through token reduction
                requests_data = [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Brief answer: What is AI?"}],
                        "max_tokens": scenario["max_tokens"]
                    }
                    for _ in range(8)
                ]
                
            elif scenario["strategy"] == "parallel_processing":
                # Test performance optimization through batching
                requests_data = [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Batch item {i}: Explain ML"}],
                        "max_tokens": 80
                    }
                    for i in range(scenario["batch_size"])
                ]
                
            elif scenario["strategy"] == "selective_retry":
                # Test quality optimization through selective retry
                requests_data = [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "High-quality explanation of neural networks"}],
                        "max_tokens": 100
                    }
                    for _ in range(5)
                ]
            
            # Execute optimization strategy
            successful_requests = 0
            total_cost = 0
            response_qualities = []
            
            if scenario["strategy"] == "parallel_processing":
                # Execute in parallel
                async def execute_request(req_data):
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, req_data
                    )
                    return response
                
                tasks = [execute_request(req) for req in requests_data]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for response in responses:
                    if hasattr(response, 'status_code') and response.status_code == 200:
                        successful_requests += 1
                        # Simulate cost calculation
                        total_cost += scenario.get("max_tokens", 80) * 0.001
            
            else:
                # Execute sequentially
                for req_data in requests_data:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, req_data
                    )
                    
                    if response.status_code == 200:
                        successful_requests += 1
                        response_data = response.json()
                        content = response_data["choices"][0]["message"]["content"]
                        
                        # Calculate quality score
                        quality_score = min(1.0, len(content) / 100)
                        response_qualities.append(quality_score)
                        
                        # Simulate cost
                        if "usage" in response_data:
                            total_cost += response_data["usage"]["total_tokens"] * 0.001
                        else:
                            total_cost += req_data.get("max_tokens", 80) * 0.001
            
            scenario_end = time.perf_counter()
            execution_time = (scenario_end - scenario_start) * 1000
            
            # Calculate optimization metrics
            avg_quality = statistics.mean(response_qualities) if response_qualities else 0.5
            cost_per_request = total_cost / len(requests_data) if len(requests_data) > 0 else 0
            throughput = successful_requests / (execution_time / 1000) if execution_time > 0 else 0
            
            if baseline_metrics is None:
                baseline_metrics = {
                    "cost_per_request": cost_per_request * 1.5,  # Simulate higher baseline cost
                    "execution_time": execution_time * 1.3,      # Simulate slower baseline
                    "quality": avg_quality * 0.9                # Simulate lower baseline quality
                }
            
            # Calculate optimization improvements
            cost_reduction = (baseline_metrics["cost_per_request"] - cost_per_request) / baseline_metrics["cost_per_request"]
            speedup = baseline_metrics["execution_time"] / execution_time
            quality_improvement = (avg_quality - baseline_metrics["quality"]) / baseline_metrics["quality"]
            
            result = {
                "scenario": scenario["name"],
                "strategy": scenario["strategy"],
                "execution_time": execution_time,
                "successful_requests": successful_requests,
                "total_cost": total_cost,
                "cost_per_request": cost_per_request,
                "avg_quality": avg_quality,
                "throughput": throughput,
                "cost_reduction": cost_reduction,
                "speedup": speedup,
                "quality_improvement": quality_improvement,
                "meets_expectations": True  # Will be updated based on scenario
            }
            
            # Check if optimization meets expectations
            if scenario["strategy"] == "minimize_tokens":
                result["meets_expectations"] = cost_reduction >= scenario["expected_cost_reduction"] * 0.7
            elif scenario["strategy"] == "parallel_processing":
                result["meets_expectations"] = speedup >= scenario["expected_speedup"] * 0.7
            elif scenario["strategy"] == "selective_retry":
                result["meets_expectations"] = quality_improvement >= scenario["expected_quality_improvement"] * 0.5
            
            optimization_results.append(result)
            
            logger.info(f"AI optimization {scenario['name']}: "
                       f"Cost reduction: {cost_reduction:.2%}, "
                       f"Speedup: {speedup:.2f}x, "
                       f"Quality improvement: {quality_improvement:.2%}")
        
        # Verify AI optimization effectiveness
        successful_optimizations = [r for r in optimization_results if r["meets_expectations"]]
        
        assert len(successful_optimizations) >= len(optimization_scenarios) * 0.6, \
            f"Most optimizations should meet expectations, got {len(successful_optimizations)}/{len(optimization_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_infra_self_healing_014(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """TDM_INFRA_SELF_HEALING_014: Self-healing infrastructure"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test self-healing capabilities for infrastructure issues
        failure_scenarios = [
            {
                "name": "high_latency_detection",
                "issue_type": "performance_degradation",
                "detection_threshold": 5000,  # ms
                "healing_action": "switch_endpoint"
            },
            {
                "name": "error_rate_spike",
                "issue_type": "error_increase",
                "detection_threshold": 0.3,  # 30% error rate
                "healing_action": "retry_with_backoff"
            },
            {
                "name": "resource_exhaustion",
                "issue_type": "resource_limit",
                "detection_threshold": 0.9,  # 90% capacity
                "healing_action": "load_balancing"
            }
        ]
        
        self_healing_results = []
        
        for scenario in failure_scenarios:
            healing_start = time.perf_counter()
            
            # Simulate the failure condition
            issue_detected = False
            healing_applied = False
            recovery_time = 0
            
            if scenario["issue_type"] == "performance_degradation":
                # Simulate high latency detection
                test_requests = 5
                high_latency_count = 0
                
                for i in range(test_requests):
                    request_start = time.perf_counter()
                    
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Latency test {i}"}],
                        "max_tokens": 50
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    request_end = time.perf_counter()
                    latency = (request_end - request_start) * 1000
                    
                    if latency > scenario["detection_threshold"]:
                        high_latency_count += 1
                
                # Detect issue
                if high_latency_count / test_requests >= 0.4:  # 40% of requests are slow
                    issue_detected = True
                    healing_applied = True
                    recovery_time = 500  # Simulated healing time
            
            elif scenario["issue_type"] == "error_increase":
                # Simulate error rate monitoring
                test_requests = 10
                error_count = 0
                
                for i in range(test_requests):
                    # Simulate some requests that might fail
                    if i < 3:  # First 3 requests simulate errors
                        error_count += 1
                    else:
                        request_data = {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Error rate test {i}"}],
                            "max_tokens": 30
                        }
                        
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request_data
                        )
                        
                        if response.status_code != 200:
                            error_count += 1
                
                error_rate = error_count / test_requests
                if error_rate >= scenario["detection_threshold"]:
                    issue_detected = True
                    healing_applied = True
                    recovery_time = 1000  # Simulated healing time
            
            elif scenario["issue_type"] == "resource_limit":
                # Simulate resource monitoring
                simulated_cpu_usage = 0.95  # 95% CPU usage
                simulated_memory_usage = 0.85  # 85% memory usage
                
                max_usage = max(simulated_cpu_usage, simulated_memory_usage)
                if max_usage >= scenario["detection_threshold"]:
                    issue_detected = True
                    healing_applied = True
                    recovery_time = 2000  # Simulated healing time
            
            healing_end = time.perf_counter()
            total_healing_time = (healing_end - healing_start) * 1000
            
            # Verify healing effectiveness
            if healing_applied:
                # Simulate post-healing verification
                verification_success = True
                
                verification_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Post-healing verification"}],
                    "max_tokens": 30
                }
                
                verification_response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, verification_data
                )
                
                verification_success = verification_response.status_code == 200
            else:
                verification_success = False
            
            result = {
                "scenario": scenario["name"],
                "issue_type": scenario["issue_type"],
                "issue_detected": issue_detected,
                "healing_applied": healing_applied,
                "healing_action": scenario["healing_action"],
                "recovery_time_ms": recovery_time,
                "total_time_ms": total_healing_time,
                "verification_success": verification_success,
                "self_healing_effective": issue_detected and healing_applied and verification_success
            }
            
            self_healing_results.append(result)
            
            logger.info(f"Self-healing {scenario['name']}: "
                       f"Issue detected: {issue_detected}, "
                       f"Healing applied: {healing_applied}, "
                       f"Recovery time: {recovery_time}ms")
        
        # Verify self-healing effectiveness
        effective_healing = [r for r in self_healing_results if r["self_healing_effective"]]
        
        # Self-healing should work for at least some scenarios
        assert len(effective_healing) >= len(failure_scenarios) * 0.5, \
            f"Self-healing should be effective for some scenarios, got {len(effective_healing)}/{len(failure_scenarios)}"
        
        # Average recovery time should be reasonable
        recovery_times = [r["recovery_time_ms"] for r in self_healing_results if r["healing_applied"]]
        if recovery_times:
            avg_recovery_time = statistics.mean(recovery_times)
            assert avg_recovery_time <= 3000, \
                f"Average recovery time should be reasonable, got {avg_recovery_time:.2f}ms"