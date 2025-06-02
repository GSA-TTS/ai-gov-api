# Section 7.9 - Data Parameterization
# Based on: docs/test_design_n_planning/Testcases_7_9_DataManagement/Test Cases_Data Parameterization.md

import pytest
import httpx
import asyncio
import time
import statistics
import itertools
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import json
import yaml
import csv
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class ParameterizationTestResult:
    """Data parameterization test result structure"""
    test_name: str
    parameter_combinations: int
    successful_combinations: int
    coverage_percentage: float
    execution_time_ms: float
    optimization_factor: float
    success: bool


class TestBasicParameterization:
    """Test basic parameterization capabilities"""
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_modelid_coverage_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TDM_PARAM_MODELID_COVERAGE_001: Model ID coverage across all configured models"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test all available models from configuration
        available_models = []
        for i in range(10):  # Test first 10 model slots
            try:
                model = config.get_chat_model(i)
                if model and model not in available_models:
                    available_models.append(model)
            except (IndexError, KeyError):
                break
        
        model_coverage_results = []
        
        for model_id in available_models:
            model_start = time.perf_counter()
            
            # Test basic functionality with this model
            test_scenarios = [
                {"prompt": "Hello", "max_tokens": 20},
                {"prompt": "What is AI?", "max_tokens": 50},
                {"prompt": "Explain briefly", "max_tokens": 30}
            ]
            
            successful_tests = 0
            
            for scenario in test_scenarios:
                request_data = {
                    "model": model_id,
                    "messages": [{"role": "user", "content": scenario["prompt"]}],
                    "max_tokens": scenario["max_tokens"]
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                if response.status_code == 200:
                    successful_tests += 1
            
            model_end = time.perf_counter()
            model_time = (model_end - model_start) * 1000
            
            coverage_result = {
                "model_id": model_id,
                "test_scenarios": len(test_scenarios),
                "successful_tests": successful_tests,
                "success_rate": successful_tests / len(test_scenarios),
                "execution_time": model_time,
                "model_functional": successful_tests >= len(test_scenarios) * 0.8
            }
            
            model_coverage_results.append(coverage_result)
            
            logger.info(f"Model coverage {model_id}: "
                       f"{successful_tests}/{len(test_scenarios)} tests passed, "
                       f"Time: {model_time:.2f}ms")
        
        # Verify model coverage
        functional_models = [r for r in model_coverage_results if r["model_functional"]]
        
        assert len(available_models) >= 1, "At least one model should be available"
        assert len(functional_models) >= len(available_models) * 0.8, \
            f"Most models should be functional, got {len(functional_models)}/{len(available_models)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_llmparam_variation_chat_002(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """TDM_PARAM_LLMPARAM_VARIATION_CHAT_002: Chat completion parameter variations"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Define parameter variations for comprehensive testing
        parameter_variations = {
            "max_tokens": [10, 50, 100],
            "temperature": [0.0, 0.5, 1.0],
            "top_p": [0.1, 0.5, 1.0],
            "stream": [False, True]  # Note: streaming requires different handling
        }
        
        # Generate parameter combinations (limit to manageable size)
        param_combinations = []
        for max_tokens in parameter_variations["max_tokens"]:
            for temperature in parameter_variations["temperature"]:
                for top_p in parameter_variations["top_p"]:
                    for stream in parameter_variations["stream"]:
                        if stream:
                            continue  # Skip streaming for this test
                        param_combinations.append({
                            "max_tokens": max_tokens,
                            "temperature": temperature,
                            "top_p": top_p,
                            "stream": stream
                        })
        
        param_variation_results = []
        
        for params in param_combinations[:15]:  # Test first 15 combinations
            combo_start = time.perf_counter()
            
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test parameter variation"}],
                **params
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            combo_end = time.perf_counter()
            combo_time = (combo_end - combo_start) * 1000
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                
                # Validate parameter effects
                token_count = len(content.split())
                within_token_limit = token_count <= params["max_tokens"] * 1.2  # 20% tolerance
                
                result = {
                    "parameters": params,
                    "response_length": len(content),
                    "token_count": token_count,
                    "within_token_limit": within_token_limit,
                    "execution_time": combo_time,
                    "success": True
                }
            else:
                result = {
                    "parameters": params,
                    "success": False,
                    "execution_time": combo_time,
                    "error_code": response.status_code
                }
            
            param_variation_results.append(result)
        
        # Analyze parameter variation effectiveness
        successful_variations = [r for r in param_variation_results if r.get("success", False)]
        compliant_variations = [r for r in successful_variations if r.get("within_token_limit", False)]
        
        coverage_percentage = len(param_combinations[:15]) / len(param_combinations) * 100
        success_rate = len(successful_variations) / len(param_combinations[:15])
        
        logger.info(f"Parameter variation testing: "
                   f"{len(successful_variations)}/{len(param_combinations[:15])} successful, "
                   f"Coverage: {coverage_percentage:.1f}%")
        
        assert success_rate >= 0.8, \
            f"Most parameter variations should succeed, got {success_rate:.2%}"
        
        assert len(compliant_variations) >= len(successful_variations) * 0.8, \
            f"Most successful variations should be compliant, got {len(compliant_variations)}/{len(successful_variations)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_message_structure_chat_004(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """TDM_PARAM_MESSAGE_STRUCTURE_CHAT_004: Chat message structure variations"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Define various message structure patterns
        message_structures = [
            {
                "name": "single_user",
                "messages": [{"role": "user", "content": "Hello"}]
            },
            {
                "name": "system_plus_user",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant"},
                    {"role": "user", "content": "Hello"}
                ]
            },
            {
                "name": "short_conversation",
                "messages": [
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi there!"},
                    {"role": "user", "content": "How are you?"}
                ]
            },
            {
                "name": "long_conversation",
                "messages": [
                    {"role": "user", "content": "Start conversation"},
                    {"role": "assistant", "content": "Hello"},
                    {"role": "user", "content": "Question 1"},
                    {"role": "assistant", "content": "Answer 1"},
                    {"role": "user", "content": "Question 2"},
                    {"role": "assistant", "content": "Answer 2"},
                    {"role": "user", "content": "Final question"}
                ]
            },
            {
                "name": "system_heavy",
                "messages": [
                    {"role": "system", "content": "You are an expert in AI"},
                    {"role": "system", "content": "Answer concisely"},
                    {"role": "user", "content": "Explain AI"}
                ]
            }
        ]
        
        message_structure_results = []
        
        for structure in message_structures:
            structure_start = time.perf_counter()
            
            request_data = {
                "model": config.get_chat_model(0),
                "messages": structure["messages"],
                "max_tokens": 100
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            structure_end = time.perf_counter()
            structure_time = (structure_end - structure_start) * 1000
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                
                # Analyze response quality based on structure
                response_length = len(content)
                has_contextual_response = len(content) > 10
                
                result = {
                    "structure_name": structure["name"],
                    "message_count": len(structure["messages"]),
                    "response_length": response_length,
                    "has_contextual_response": has_contextual_response,
                    "execution_time": structure_time,
                    "success": True
                }
            else:
                result = {
                    "structure_name": structure["name"],
                    "message_count": len(structure["messages"]),
                    "success": False,
                    "execution_time": structure_time,
                    "error_code": response.status_code
                }
            
            message_structure_results.append(result)
            
            logger.info(f"Message structure {structure['name']}: "
                       f"Messages: {len(structure['messages'])}, "
                       f"Success: {result.get('success', False)}")
        
        # Verify message structure handling
        successful_structures = [r for r in message_structure_results if r.get("success", False)]
        contextual_responses = [r for r in successful_structures if r.get("has_contextual_response", False)]
        
        assert len(successful_structures) >= len(message_structures) * 0.8, \
            f"Most message structures should be handled, got {len(successful_structures)}/{len(message_structures)}"
        
        assert len(contextual_responses) >= len(successful_structures) * 0.7, \
            f"Most responses should be contextual, got {len(contextual_responses)}/{len(successful_structures)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_external_data_files_005(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """TDM_PARAM_EXTERNAL_DATA_FILES_005: External data file parameterization"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Create temporary external data files for testing
        test_data_files = {}
        
        # JSON parameter file
        json_data = {
            "test_scenarios": [
                {"prompt": "Explain AI", "max_tokens": 50, "temperature": 0.5},
                {"prompt": "What is ML?", "max_tokens": 60, "temperature": 0.7},
                {"prompt": "Define NLP", "max_tokens": 40, "temperature": 0.3}
            ]
        }
        
        # CSV parameter file
        csv_data = [
            ["prompt", "max_tokens", "temperature"],
            ["Test prompt 1", "30", "0.2"],
            ["Test prompt 2", "50", "0.8"],
            ["Test prompt 3", "40", "0.5"]
        ]
        
        # YAML parameter file
        yaml_data = {
            "parameters": {
                "models": ["model1", "model2"],
                "scenarios": [
                    {"name": "basic", "config": {"max_tokens": 30}},
                    {"name": "detailed", "config": {"max_tokens": 80}}
                ]
            }
        }
        
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(json_data, f)
            test_data_files['json'] = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            writer = csv.writer(f)
            writer.writerows(csv_data)
            test_data_files['csv'] = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(yaml_data, f)
            test_data_files['yaml'] = f.name
        
        external_data_results = []
        
        try:
            # Test JSON data file
            with open(test_data_files['json'], 'r') as f:
                json_params = json.load(f)
            
            for scenario in json_params["test_scenarios"]:
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": scenario["prompt"]}],
                    "max_tokens": scenario["max_tokens"],
                    "temperature": scenario["temperature"]
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                external_data_results.append({
                    "file_type": "json",
                    "scenario": scenario,
                    "success": response.status_code == 200
                })
            
            # Test CSV data file
            with open(test_data_files['csv'], 'r') as f:
                csv_reader = csv.DictReader(f)
                for row in csv_reader:
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": row["prompt"]}],
                        "max_tokens": int(row["max_tokens"]),
                        "temperature": float(row["temperature"])
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    external_data_results.append({
                        "file_type": "csv",
                        "scenario": row,
                        "success": response.status_code == 200
                    })
            
            # Test YAML data file
            with open(test_data_files['yaml'], 'r') as f:
                yaml_params = yaml.safe_load(f)
            
            for scenario in yaml_params["parameters"]["scenarios"]:
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Test {scenario['name']}"}],
                    **scenario["config"]
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                external_data_results.append({
                    "file_type": "yaml",
                    "scenario": scenario,
                    "success": response.status_code == 200
                })
            
        finally:
            # Cleanup temporary files
            for file_path in test_data_files.values():
                try:
                    os.unlink(file_path)
                except OSError:
                    pass
        
        # Analyze external data file effectiveness
        successful_tests = [r for r in external_data_results if r["success"]]
        file_types_tested = set(r["file_type"] for r in external_data_results)
        
        logger.info(f"External data file testing: "
                   f"{len(successful_tests)}/{len(external_data_results)} successful, "
                   f"File types: {file_types_tested}")
        
        assert len(successful_tests) >= len(external_data_results) * 0.8, \
            f"Most external data tests should succeed, got {len(successful_tests)}/{len(external_data_results)}"
        
        assert len(file_types_tested) == 3, \
            f"All file types should be tested, got {file_types_tested}"


class TestAdvancedParameterization:
    """Test advanced parameterization strategies"""
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_dynamic_matrix_007(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """TDM_PARAM_DYNAMIC_MATRIX_007: Dynamic parameter matrix generation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Define parameter space for dynamic matrix generation
        parameter_space = {
            "max_tokens": {"min": 10, "max": 100, "step": 20},
            "temperature": {"values": [0.0, 0.3, 0.7, 1.0]},
            "top_p": {"values": [0.1, 0.5, 1.0]},
            "frequency_penalty": {"values": [0.0, 0.5]}
        }
        
        # Generate dynamic parameter matrix
        def generate_parameter_matrix(space, max_combinations=20):
            """Generate optimized parameter combinations"""
            combinations = []
            
            # Generate all possible combinations
            max_tokens_values = list(range(
                space["max_tokens"]["min"],
                space["max_tokens"]["max"] + 1,
                space["max_tokens"]["step"]
            ))
            
            all_combinations = list(itertools.product(
                max_tokens_values,
                space["temperature"]["values"],
                space["top_p"]["values"],
                space["frequency_penalty"]["values"]
            ))
            
            # Select representative combinations (optimization)
            import random
            random.seed(42)  # Deterministic for testing
            selected_combinations = random.sample(
                all_combinations,
                min(max_combinations, len(all_combinations))
            )
            
            for combo in selected_combinations:
                combinations.append({
                    "max_tokens": combo[0],
                    "temperature": combo[1],
                    "top_p": combo[2],
                    "frequency_penalty": combo[3]
                })
            
            return combinations
        
        # Generate and test dynamic matrix
        matrix_start = time.perf_counter()
        parameter_matrix = generate_parameter_matrix(parameter_space)
        matrix_generation_time = (time.perf_counter() - matrix_start) * 1000
        
        matrix_results = []
        
        for params in parameter_matrix:
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Dynamic matrix test"}],
                **params
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            matrix_results.append({
                "parameters": params,
                "success": response.status_code == 200,
                "response_valid": response.status_code == 200 and len(response.json().get("choices", [])) > 0
            })
        
        # Analyze matrix effectiveness
        successful_tests = [r for r in matrix_results if r["success"]]
        valid_responses = [r for r in matrix_results if r.get("response_valid", False)]
        
        coverage_percentage = len(parameter_matrix) / len(list(itertools.product(
            list(range(parameter_space["max_tokens"]["min"], parameter_space["max_tokens"]["max"] + 1, parameter_space["max_tokens"]["step"])),
            parameter_space["temperature"]["values"],
            parameter_space["top_p"]["values"],
            parameter_space["frequency_penalty"]["values"]
        ))) * 100
        
        result = ParameterizationTestResult(
            test_name="dynamic_matrix_generation",
            parameter_combinations=len(parameter_matrix),
            successful_combinations=len(successful_tests),
            coverage_percentage=coverage_percentage,
            execution_time_ms=matrix_generation_time,
            optimization_factor=len(parameter_matrix) / max(1, len(parameter_matrix)) * 100,
            success=len(successful_tests) >= len(parameter_matrix) * 0.8
        )
        
        logger.info(f"Dynamic matrix generation: "
                   f"{len(parameter_matrix)} combinations, "
                   f"{len(successful_tests)} successful, "
                   f"{coverage_percentage:.1f}% coverage")
        
        assert result.success, \
            f"Dynamic matrix should achieve high success rate, got {len(successful_tests)}/{len(parameter_matrix)}"
        
        assert coverage_percentage >= 10, \
            f"Matrix should provide reasonable coverage, got {coverage_percentage:.1f}%"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_cross_provider_009(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """TDM_PARAM_CROSS_PROVIDER_009: Cross-provider parameter compatibility"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Define provider-specific parameter mappings
        provider_parameters = {
            "openai_compatible": {
                "max_tokens": 50,
                "temperature": 0.7,
                "top_p": 0.9,
                "frequency_penalty": 0.0
            },
            "anthropic_compatible": {
                "max_tokens": 50,
                "temperature": 0.7,
                # top_p might not be supported
            },
            "universal": {
                "max_tokens": 50,
                "temperature": 0.7
            }
        }
        
        cross_provider_results = []
        
        # Test each parameter set
        for provider_type, params in provider_parameters.items():
            provider_start = time.perf_counter()
            
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Cross-provider test for {provider_type}"}],
                **params
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            provider_end = time.perf_counter()
            provider_time = (provider_end - provider_start) * 1000
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                
                # Analyze response consistency
                response_length = len(content)
                reasonable_response = 10 <= response_length <= params["max_tokens"] * 10  # Generous bounds
                
                result = {
                    "provider_type": provider_type,
                    "parameters": params,
                    "response_length": response_length,
                    "reasonable_response": reasonable_response,
                    "execution_time": provider_time,
                    "success": True
                }
            else:
                result = {
                    "provider_type": provider_type,
                    "parameters": params,
                    "success": False,
                    "execution_time": provider_time,
                    "error_code": response.status_code
                }
            
            cross_provider_results.append(result)
            
            logger.info(f"Cross-provider {provider_type}: "
                       f"Success: {result.get('success', False)}, "
                       f"Time: {provider_time:.2f}ms")
        
        # Verify cross-provider compatibility
        successful_providers = [r for r in cross_provider_results if r.get("success", False)]
        reasonable_responses = [r for r in successful_providers if r.get("reasonable_response", False)]
        
        assert len(successful_providers) >= len(provider_parameters) * 0.7, \
            f"Most provider parameter sets should work, got {len(successful_providers)}/{len(provider_parameters)}"
        
        assert len(reasonable_responses) >= len(successful_providers) * 0.8, \
            f"Most responses should be reasonable, got {len(reasonable_responses)}/{len(successful_providers)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_performance_optimized_011(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """TDM_PARAM_PERFORMANCE_OPTIMIZED_011: Performance-optimized parameterization"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Define parameter batches for performance testing
        parameter_batches = [
            {
                "batch_name": "quick_tests",
                "parameters": [
                    {"max_tokens": 20, "temperature": 0.0},
                    {"max_tokens": 30, "temperature": 0.2},
                    {"max_tokens": 25, "temperature": 0.1}
                ]
            },
            {
                "batch_name": "medium_tests",
                "parameters": [
                    {"max_tokens": 50, "temperature": 0.5},
                    {"max_tokens": 60, "temperature": 0.6},
                    {"max_tokens": 55, "temperature": 0.4}
                ]
            },
            {
                "batch_name": "comprehensive_tests",
                "parameters": [
                    {"max_tokens": 80, "temperature": 0.8},
                    {"max_tokens": 90, "temperature": 0.9},
                    {"max_tokens": 85, "temperature": 0.7}
                ]
            }
        ]
        
        batch_results = []
        
        for batch in parameter_batches:
            batch_start = time.perf_counter()
            
            # Execute batch with controlled concurrency
            semaphore = asyncio.Semaphore(3)  # Limit concurrent requests
            
            async def execute_parameter_test(params):
                async with semaphore:
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Performance test"}],
                        **params
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    return {
                        "parameters": params,
                        "success": response.status_code == 200
                    }
            
            # Execute batch in parallel
            tasks = [execute_parameter_test(params) for params in batch["parameters"]]
            batch_test_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            batch_end = time.perf_counter()
            batch_time = (batch_end - batch_start) * 1000
            
            # Analyze batch performance
            successful_tests = [r for r in batch_test_results if isinstance(r, dict) and r.get("success", False)]
            
            # Calculate performance metrics
            throughput = len(successful_tests) / (batch_time / 1000) if batch_time > 0 else 0
            efficiency = len(successful_tests) / len(batch["parameters"])
            
            result = {
                "batch_name": batch["batch_name"],
                "total_parameters": len(batch["parameters"]),
                "successful_tests": len(successful_tests),
                "batch_time": batch_time,
                "throughput": throughput,
                "efficiency": efficiency,
                "performance_optimized": efficiency >= 0.8 and throughput >= 1.0
            }
            
            batch_results.append(result)
            
            logger.info(f"Performance batch {batch['batch_name']}: "
                       f"Efficiency: {efficiency:.2%}, "
                       f"Throughput: {throughput:.2f}/s, "
                       f"Time: {batch_time:.2f}ms")
        
        # Verify performance optimization
        optimized_batches = [r for r in batch_results if r["performance_optimized"]]
        total_throughput = sum(r["throughput"] for r in batch_results)
        
        assert len(optimized_batches) >= len(parameter_batches) * 0.7, \
            f"Most batches should be performance optimized, got {len(optimized_batches)}/{len(parameter_batches)}"
        
        assert total_throughput >= 2.0, \
            f"Total throughput should be reasonable, got {total_throughput:.2f}/s"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_compliance_validation_014(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """TDM_PARAM_COMPLIANCE_VALIDATION_014: Compliance-driven parameter validation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Define compliance rules for parameter validation
        compliance_rules = {
            "government_safe": {
                "max_tokens": {"max": 100, "reason": "Response length limits"},
                "temperature": {"max": 0.7, "reason": "Deterministic outputs required"},
                "top_p": {"max": 0.9, "reason": "Conservative sampling"},
                "frequency_penalty": {"max": 1.0, "reason": "Content control"}
            },
            "privacy_protected": {
                "max_tokens": {"max": 200, "reason": "Prevent information leakage"},
                "temperature": {"min": 0.1, "max": 0.8, "reason": "Balanced randomness"},
                "top_p": {"min": 0.1, "max": 1.0, "reason": "Sampling bounds"}
            },
            "security_hardened": {
                "max_tokens": {"max": 50, "reason": "Minimal output"},
                "temperature": {"max": 0.5, "reason": "Predictable behavior"},
                "top_p": {"max": 0.7, "reason": "Conservative generation"}
            }
        }
        
        def validate_compliance(params, rules):
            """Validate parameters against compliance rules"""
            violations = []
            
            for param, value in params.items():
                if param in rules:
                    rule = rules[param]
                    
                    if "max" in rule and value > rule["max"]:
                        violations.append(f"{param} exceeds max {rule['max']}: {rule['reason']}")
                    
                    if "min" in rule and value < rule["min"]:
                        violations.append(f"{param} below min {rule['min']}: {rule['reason']}")
            
            return violations
        
        compliance_results = []
        
        for compliance_type, rules in compliance_rules.items():
            # Generate compliant parameters
            compliant_params = {
                "max_tokens": min(rules.get("max_tokens", {}).get("max", 100), 50),
                "temperature": min(rules.get("temperature", {}).get("max", 1.0), 0.5),
                "top_p": min(rules.get("top_p", {}).get("max", 1.0), 0.8)
            }
            
            # Validate compliance
            violations = validate_compliance(compliant_params, rules)
            
            # Test with compliant parameters
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Compliance test for {compliance_type}"}],
                **compliant_params
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                
                # Verify compliance outcomes
                content_length = len(content)
                within_limits = content_length <= compliant_params["max_tokens"] * 10  # Generous bound
                
                result = {
                    "compliance_type": compliance_type,
                    "parameters": compliant_params,
                    "violations": violations,
                    "compliant": len(violations) == 0,
                    "content_length": content_length,
                    "within_limits": within_limits,
                    "success": True
                }
            else:
                result = {
                    "compliance_type": compliance_type,
                    "parameters": compliant_params,
                    "violations": violations,
                    "compliant": len(violations) == 0,
                    "success": False,
                    "error_code": response.status_code
                }
            
            compliance_results.append(result)
            
            logger.info(f"Compliance validation {compliance_type}: "
                       f"Compliant: {result['compliant']}, "
                       f"Success: {result.get('success', False)}, "
                       f"Violations: {len(violations)}")
        
        # Verify compliance validation effectiveness
        compliant_tests = [r for r in compliance_results if r["compliant"]]
        successful_tests = [r for r in compliance_results if r.get("success", False)]
        within_limit_tests = [r for r in successful_tests if r.get("within_limits", False)]
        
        assert len(compliant_tests) == len(compliance_rules), \
            f"All compliance tests should be compliant, got {len(compliant_tests)}/{len(compliance_rules)}"
        
        assert len(successful_tests) >= len(compliance_rules) * 0.8, \
            f"Most compliance tests should succeed, got {len(successful_tests)}/{len(compliance_rules)}"
        
        assert len(within_limit_tests) >= len(successful_tests) * 0.9, \
            f"Most successful tests should be within limits, got {len(within_limit_tests)}/{len(successful_tests)}"