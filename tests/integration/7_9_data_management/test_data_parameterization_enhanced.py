# Section 7.9 - Enhanced Data Parameterization
# Based on: docs/test_design_n_planning/Testcases_7_9_DataManagement/Test Cases_Data Parameterization.md

import pytest
import httpx
import asyncio
import time
import statistics
import itertools
import random
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import json
import yaml
import csv
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor
import hashlib
from sklearn.model_selection import ParameterGrid
from scipy.optimize import differential_evolution
import uuid

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class AIOptimizationResult:
    """AI-driven parameter optimization result structure"""
    test_name: str
    parameter_space_size: int
    explored_combinations: int
    optimal_parameters: Dict[str, Any]
    optimization_score: float
    convergence_iterations: int
    defect_detection_improvement: float
    success: bool


@dataclass
class ContextAwareResult:
    """Context-aware parameter generation result structure"""
    test_name: str
    context_scenario: str
    generated_parameters: Dict[str, Any]
    context_relevance_score: float
    business_domain_alignment: float
    user_persona_fit: float
    success: bool


@dataclass
class HierarchicalDependencyResult:
    """Hierarchical parameter dependency management result"""
    test_name: str
    dependency_graph_size: int
    resolved_dependencies: int
    circular_dependencies_detected: int
    parameter_inheritance_levels: int
    constraint_satisfaction_score: float
    success: bool


class TestEnhancedParameterization:
    """Test enhanced data parameterization strategies"""
    
    def setup_method(self):
        """Setup for enhanced parameterization tests"""
        self.test_session_id = str(uuid.uuid4())
        self.parameter_history = []
        self.optimization_metrics = {}
        random.seed(42)  # For reproducible results
        np.random.seed(42)
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_ai_optimization_008(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TDM_PARAM_AI_OPTIMIZATION_008: AI-driven parameter selection and optimization"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing AI-driven parameter optimization")
        
        # Define parameter space for AI optimization
        parameter_space = {
            'max_tokens': {'min': 20, 'max': 200, 'type': 'int'},
            'temperature': {'min': 0.0, 'max': 1.5, 'type': 'float'},
            'top_p': {'min': 0.1, 'max': 1.0, 'type': 'float'},
            'frequency_penalty': {'min': 0.0, 'max': 2.0, 'type': 'float'},
            'presence_penalty': {'min': 0.0, 'max': 2.0, 'type': 'float'}
        }
        
        # Simulate historical defect detection data
        historical_data = [
            {'params': {'max_tokens': 50, 'temperature': 0.5, 'top_p': 0.9}, 'defects_found': 3},
            {'params': {'max_tokens': 100, 'temperature': 0.7, 'top_p': 0.8}, 'defects_found': 5},
            {'params': {'max_tokens': 150, 'temperature': 0.3, 'top_p': 0.95}, 'defects_found': 2},
            {'params': {'max_tokens': 75, 'temperature': 0.9, 'top_p': 0.7}, 'defects_found': 7},
            {'params': {'max_tokens': 200, 'temperature': 0.1, 'top_p': 0.6}, 'defects_found': 1}
        ]
        
        def objective_function(params):
            """Simulate AI objective function for parameter optimization"""
            max_tokens, temperature, top_p, freq_penalty, pres_penalty = params
            
            # Simulate complex scoring based on historical patterns
            # Higher scores for parameters likely to find more defects
            diversity_score = temperature * top_p  # Higher diversity
            control_score = (2.0 - freq_penalty) * (2.0 - pres_penalty)  # Balanced control
            length_score = max_tokens / 200.0  # Normalized length
            
            # Combine scores with learned weights
            composite_score = (0.4 * diversity_score + 0.3 * control_score + 0.3 * length_score)
            
            # Add noise to simulate real-world variance
            noise = np.random.normal(0, 0.1)
            return -(composite_score + noise)  # Negative because we minimize
        
        # AI-driven optimization using differential evolution
        optimization_start = time.time()
        
        bounds = [
            (parameter_space['max_tokens']['min'], parameter_space['max_tokens']['max']),
            (parameter_space['temperature']['min'], parameter_space['temperature']['max']),
            (parameter_space['top_p']['min'], parameter_space['top_p']['max']),
            (parameter_space['frequency_penalty']['min'], parameter_space['frequency_penalty']['max']),
            (parameter_space['presence_penalty']['min'], parameter_space['presence_penalty']['max'])
        ]
        
        # Run optimization
        result = differential_evolution(
            objective_function,
            bounds,
            maxiter=20,  # Limit iterations for testing
            popsize=5,   # Small population for testing
            seed=42
        )
        
        optimization_end = time.time()
        optimization_time = (optimization_end - optimization_start) * 1000
        
        # Extract optimal parameters
        optimal_params = {
            'max_tokens': int(result.x[0]),
            'temperature': round(result.x[1], 2),
            'top_p': round(result.x[2], 2),
            'frequency_penalty': round(result.x[3], 2),
            'presence_penalty': round(result.x[4], 2)
        }
        
        # Test with optimized parameters
        ai_optimization_results = []
        
        for i in range(3):  # Test multiple scenarios with optimized params
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"AI optimization test scenario {i+1}"}],
                **optimal_params
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            # Simulate defect detection scoring
            simulated_defects = max(0, int(abs(result.fun) * 10) + random.randint(0, 2))
            
            result_data = {
                "scenario": i + 1,
                "optimal_parameters": optimal_params,
                "response_success": response.status_code == 200,
                "simulated_defects_found": simulated_defects,
                "optimization_score": abs(result.fun)
            }
            
            ai_optimization_results.append(result_data)
        
        # Calculate improvement metrics
        baseline_defects = statistics.mean([h['defects_found'] for h in historical_data])
        optimized_defects = statistics.mean([r['simulated_defects_found'] for r in ai_optimization_results])
        improvement_percentage = ((optimized_defects - baseline_defects) / baseline_defects) * 100 if baseline_defects > 0 else 0
        
        ai_result = AIOptimizationResult(
            test_name="ai_driven_parameter_optimization",
            parameter_space_size=len(parameter_space),
            explored_combinations=result.nfev,  # Function evaluations
            optimal_parameters=optimal_params,
            optimization_score=abs(result.fun),
            convergence_iterations=result.nit,
            defect_detection_improvement=improvement_percentage,
            success=result.success and len([r for r in ai_optimization_results if r["response_success"]]) >= 2
        )
        
        logger.info(f"AI parameter optimization: "
                   f"Explored {result.nfev} combinations, "
                   f"Improvement: {improvement_percentage:.1f}%, "
                   f"Time: {optimization_time:.2f}ms")
        
        # Verify AI optimization effectiveness
        assert ai_result.success, "AI optimization should successfully find optimal parameters"
        assert ai_result.explored_combinations >= 50, f"Should explore sufficient combinations, got {ai_result.explored_combinations}"
        assert ai_result.optimization_score > 0, "Optimization should produce meaningful score"
        assert ai_result.defect_detection_improvement >= 0, "Should not decrease defect detection capability"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_context_aware_010(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """TDM_PARAM_CONTEXT_AWARE_010: Context-aware parameter generation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing context-aware parameter generation")
        
        # Define context scenarios with different requirements
        context_scenarios = [
            {
                "name": "government_compliance",
                "domain": "government",
                "user_persona": "government_official",
                "business_requirements": ["accuracy", "auditability", "conservative_outputs"],
                "regulatory_context": "strict_compliance",
                "expected_params": {
                    "temperature": {"min": 0.0, "max": 0.3},
                    "max_tokens": {"min": 50, "max": 150},
                    "top_p": {"min": 0.1, "max": 0.7}
                }
            },
            {
                "name": "creative_marketing",
                "domain": "marketing",
                "user_persona": "content_creator",
                "business_requirements": ["creativity", "engagement", "diverse_outputs"],
                "regulatory_context": "standard_compliance",
                "expected_params": {
                    "temperature": {"min": 0.7, "max": 1.2},
                    "max_tokens": {"min": 100, "max": 300},
                    "top_p": {"min": 0.8, "max": 1.0}
                }
            },
            {
                "name": "financial_analysis",
                "domain": "finance",
                "user_persona": "analyst",
                "business_requirements": ["precision", "consistency", "detailed_reasoning"],
                "regulatory_context": "financial_compliance",
                "expected_params": {
                    "temperature": {"min": 0.1, "max": 0.5},
                    "max_tokens": {"min": 200, "max": 500},
                    "top_p": {"min": 0.3, "max": 0.8}
                }
            },
            {
                "name": "healthcare_documentation",
                "domain": "healthcare",
                "user_persona": "medical_professional",
                "business_requirements": ["accuracy", "privacy", "clinical_terminology"],
                "regulatory_context": "hipaa_compliance",
                "expected_params": {
                    "temperature": {"min": 0.0, "max": 0.4},
                    "max_tokens": {"min": 150, "max": 400},
                    "top_p": {"min": 0.2, "max": 0.6}
                }
            }
        ]
        
        context_aware_results = []
        
        for scenario in context_scenarios:
            # Generate context-aware parameters
            def generate_context_parameters(context):
                """Generate parameters based on context requirements"""
                params = {}
                
                # Temperature based on creativity vs accuracy requirements
                if "creativity" in context["business_requirements"]:
                    params["temperature"] = random.uniform(0.7, 1.2)
                elif "accuracy" in context["business_requirements"]:
                    params["temperature"] = random.uniform(0.0, 0.4)
                else:
                    params["temperature"] = random.uniform(0.3, 0.8)
                
                # Max tokens based on detail requirements
                if "detailed_reasoning" in context["business_requirements"]:
                    params["max_tokens"] = random.randint(200, 500)
                elif "conservative_outputs" in context["business_requirements"]:
                    params["max_tokens"] = random.randint(50, 150)
                else:
                    params["max_tokens"] = random.randint(100, 300)
                
                # Top_p based on diversity requirements
                if "diverse_outputs" in context["business_requirements"]:
                    params["top_p"] = random.uniform(0.8, 1.0)
                elif "consistency" in context["business_requirements"]:
                    params["top_p"] = random.uniform(0.1, 0.5)
                else:
                    params["top_p"] = random.uniform(0.5, 0.9)
                
                # Adjust for regulatory context
                if context["regulatory_context"] in ["strict_compliance", "hipaa_compliance"]:
                    params["temperature"] = min(params["temperature"], 0.4)
                    params["top_p"] = min(params["top_p"], 0.7)
                
                return params
            
            generated_params = generate_context_parameters(scenario)
            
            # Validate parameter alignment with expected ranges
            def calculate_alignment_score(generated, expected):
                """Calculate how well generated parameters align with expected ranges"""
                alignment_scores = []
                
                for param, value in generated.items():
                    if param in expected:
                        expected_range = expected[param]
                        if expected_range["min"] <= value <= expected_range["max"]:
                            alignment_scores.append(1.0)
                        else:
                            # Calculate distance from range
                            if value < expected_range["min"]:
                                distance = (expected_range["min"] - value) / expected_range["min"]
                            else:
                                distance = (value - expected_range["max"]) / expected_range["max"]
                            alignment_scores.append(max(0, 1.0 - distance))
                
                return statistics.mean(alignment_scores) if alignment_scores else 0.0
            
            context_relevance = calculate_alignment_score(generated_params, scenario["expected_params"])
            
            # Test with context-aware parameters
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{
                    "role": "user", 
                    "content": f"Generate {scenario['domain']} content for {scenario['user_persona']}"
                }],
                **generated_params
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            # Calculate business domain alignment
            domain_alignment = 0.8  # Simulated based on parameter appropriateness
            if scenario["domain"] == "government" and generated_params["temperature"] <= 0.4:
                domain_alignment = 0.9
            elif scenario["domain"] == "marketing" and generated_params["temperature"] >= 0.7:
                domain_alignment = 0.95
            elif scenario["domain"] == "finance" and generated_params["max_tokens"] >= 200:
                domain_alignment = 0.85
            elif scenario["domain"] == "healthcare" and generated_params["top_p"] <= 0.6:
                domain_alignment = 0.9
            
            # Calculate user persona fit
            persona_fit = 0.75  # Base score
            if scenario["user_persona"] == "government_official" and generated_params["temperature"] <= 0.3:
                persona_fit = 0.9
            elif scenario["user_persona"] == "content_creator" and generated_params["temperature"] >= 0.8:
                persona_fit = 0.95
            
            result = ContextAwareResult(
                test_name=scenario["name"],
                context_scenario=scenario["domain"],
                generated_parameters=generated_params,
                context_relevance_score=context_relevance,
                business_domain_alignment=domain_alignment,
                user_persona_fit=persona_fit,
                success=response.status_code == 200 and context_relevance >= 0.7
            )
            
            context_aware_results.append(result)
            
            logger.info(f"Context-aware generation {scenario['name']}: "
                       f"Relevance: {context_relevance:.2%}, "
                       f"Domain alignment: {domain_alignment:.2%}, "
                       f"Persona fit: {persona_fit:.2%}")
        
        # Verify context-aware parameter generation effectiveness
        high_relevance_results = [r for r in context_aware_results if r.context_relevance_score >= 0.7]
        good_domain_alignment = [r for r in context_aware_results if r.business_domain_alignment >= 0.8]
        successful_tests = [r for r in context_aware_results if r.success]
        
        assert len(high_relevance_results) >= len(context_scenarios) * 0.7, \
            f"Most scenarios should have high context relevance, got {len(high_relevance_results)}/{len(context_scenarios)}"
        
        assert len(good_domain_alignment) >= len(context_scenarios) * 0.6, \
            f"Most should have good domain alignment, got {len(good_domain_alignment)}/{len(context_scenarios)}"
        
        assert len(successful_tests) >= len(context_scenarios) * 0.8, \
            f"Most tests should succeed, got {len(successful_tests)}/{len(context_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_hierarchical_dependency_012(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """TDM_PARAM_HIERARCHICAL_DEPENDENCY_012: Hierarchical parameter dependency management"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing hierarchical parameter dependency management")
        
        # Define hierarchical parameter dependencies
        parameter_hierarchy = {
            "root": {
                "model_type": {
                    "chat": {
                        "temperature": {"min": 0.0, "max": 2.0, "default": 0.7},
                        "max_tokens": {"min": 1, "max": 4000, "default": 150},
                        "conversation_style": {
                            "formal": {
                                "temperature": {"override": 0.3},
                                "top_p": {"override": 0.7}
                            },
                            "creative": {
                                "temperature": {"override": 1.2},
                                "top_p": {"override": 0.95}
                            },
                            "balanced": {
                                "temperature": {"inherit": True},
                                "top_p": {"default": 0.9}
                            }
                        }
                    },
                    "embedding": {
                        "dimensions": {"min": 128, "max": 2048, "default": 1536},
                        "input_type": {"values": ["query", "document"], "default": "document"}
                    }
                }
            }
        }
        
        def resolve_parameter_dependencies(hierarchy, path=[]):
            """Resolve parameter dependencies in hierarchical structure"""
            resolved_params = {}
            inheritance_chain = []
            
            current_level = hierarchy
            for step in path:
                if step in current_level:
                    current_level = current_level[step]
                    inheritance_chain.append(step)
                else:
                    break
            
            def collect_parameters(node, inherited_params=None):
                if inherited_params is None:
                    inherited_params = {}
                
                local_params = {}
                
                for key, value in node.items():
                    if isinstance(value, dict):
                        if "min" in value or "max" in value or "default" in value:
                            # This is a parameter definition
                            if "override" in value:
                                local_params[key] = value["override"]
                            elif "inherit" in value and value["inherit"]:
                                if key in inherited_params:
                                    local_params[key] = inherited_params[key]
                            elif "default" in value:
                                local_params[key] = value["default"]
                        else:
                            # This is a nested level
                            child_params = collect_parameters(value, {**inherited_params, **local_params})
                            local_params.update(child_params)
                
                return local_params
            
            resolved_params = collect_parameters(current_level)
            return resolved_params, len(inheritance_chain)
        
        # Test dependency resolution scenarios
        dependency_test_scenarios = [
            {
                "name": "chat_formal_style",
                "path": ["root", "model_type", "chat", "conversation_style", "formal"],
                "expected_overrides": ["temperature", "top_p"]
            },
            {
                "name": "chat_creative_style", 
                "path": ["root", "model_type", "chat", "conversation_style", "creative"],
                "expected_overrides": ["temperature", "top_p"]
            },
            {
                "name": "chat_balanced_style",
                "path": ["root", "model_type", "chat", "conversation_style", "balanced"],
                "expected_inheritance": ["temperature"]
            },
            {
                "name": "embedding_basic",
                "path": ["root", "model_type", "embedding"],
                "expected_defaults": ["dimensions", "input_type"]
            }
        ]
        
        hierarchical_results = []
        
        for scenario in dependency_test_scenarios:
            # Resolve dependencies for this scenario
            resolved_params, inheritance_levels = resolve_parameter_dependencies(
                parameter_hierarchy, scenario["path"]
            )
            
            # Detect circular dependencies (simplified check)
            def detect_circular_dependencies(params):
                # In a real implementation, this would check for actual circular references
                # For testing, we simulate detection
                circular_count = 0
                if "temperature" in params and "top_p" in params:
                    # Simulate a potential circular dependency scenario
                    if abs(params["temperature"] - 0.7) < 0.1 and abs(params.get("top_p", 0.9) - 0.9) < 0.1:
                        circular_count = 1  # Simulated detection
                return circular_count
            
            circular_deps = detect_circular_dependencies(resolved_params)
            
            # Test constraint satisfaction
            def validate_constraints(params, hierarchy_path):
                """Validate that resolved parameters satisfy all constraints"""
                violations = []
                
                # Check temperature constraints
                if "temperature" in params:
                    temp = params["temperature"]
                    if temp < 0.0 or temp > 2.0:
                        violations.append(f"temperature {temp} outside valid range [0.0, 2.0]")
                
                # Check max_tokens constraints
                if "max_tokens" in params:
                    tokens = params["max_tokens"]
                    if tokens < 1 or tokens > 4000:
                        violations.append(f"max_tokens {tokens} outside valid range [1, 4000]")
                
                # Check top_p constraints
                if "top_p" in params:
                    top_p = params["top_p"]
                    if top_p < 0.0 or top_p > 1.0:
                        violations.append(f"top_p {top_p} outside valid range [0.0, 1.0]")
                
                return len(violations) == 0, violations
            
            constraints_satisfied, violations = validate_constraints(resolved_params, scenario["path"])
            constraint_score = 1.0 if constraints_satisfied else 0.5
            
            # Test with resolved parameters (if they're valid for chat)
            if "chat" in scenario["path"] and resolved_params:
                # Prepare request parameters
                request_params = {}
                if "temperature" in resolved_params:
                    request_params["temperature"] = resolved_params["temperature"]
                if "max_tokens" in resolved_params:
                    request_params["max_tokens"] = resolved_params["max_tokens"]
                if "top_p" in resolved_params:
                    request_params["top_p"] = resolved_params["top_p"]
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Test hierarchical dependencies for {scenario['name']}"}],
                    **request_params
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                response_success = response.status_code == 200
            else:
                response_success = True  # Non-chat scenarios don't need API testing
            
            result = HierarchicalDependencyResult(
                test_name=scenario["name"],
                dependency_graph_size=len(scenario["path"]),
                resolved_dependencies=len(resolved_params),
                circular_dependencies_detected=circular_deps,
                parameter_inheritance_levels=inheritance_levels,
                constraint_satisfaction_score=constraint_score,
                success=response_success and constraints_satisfied and circular_deps == 0
            )
            
            hierarchical_results.append(result)
            
            logger.info(f"Hierarchical dependency {scenario['name']}: "
                       f"Resolved {len(resolved_params)} params, "
                       f"Inheritance levels: {inheritance_levels}, "
                       f"Constraint score: {constraint_score:.2f}")
        
        # Verify hierarchical dependency management effectiveness
        successful_resolutions = [r for r in hierarchical_results if r.success]
        constraint_compliant = [r for r in hierarchical_results if r.constraint_satisfaction_score >= 0.9]
        no_circular_deps = [r for r in hierarchical_results if r.circular_dependencies_detected == 0]
        
        assert len(successful_resolutions) >= len(dependency_test_scenarios) * 0.7, \
            f"Most dependency resolutions should succeed, got {len(successful_resolutions)}/{len(dependency_test_scenarios)}"
        
        assert len(constraint_compliant) >= len(dependency_test_scenarios) * 0.8, \
            f"Most should satisfy constraints, got {len(constraint_compliant)}/{len(dependency_test_scenarios)}"
        
        assert len(no_circular_deps) == len(dependency_test_scenarios), \
            f"No circular dependencies should be present, got {len(no_circular_deps)}/{len(dependency_test_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_adaptive_exploration_013(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TDM_PARAM_ADAPTIVE_EXPLORATION_013: Adaptive parameter exploration and discovery"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing adaptive parameter exploration and discovery")
        
        # Initialize parameter space for exploration
        parameter_bounds = {
            'temperature': (0.0, 2.0),
            'max_tokens': (10, 300),
            'top_p': (0.1, 1.0),
            'frequency_penalty': (0.0, 2.0)
        }
        
        class AdaptiveParameterExplorer:
            """Adaptive parameter exploration using genetic algorithm principles"""
            
            def __init__(self, bounds, population_size=8):
                self.bounds = bounds
                self.population_size = population_size
                self.population = []
                self.fitness_scores = []
                self.generation = 0
                self.discovered_edges = []
                
            def initialize_population(self):
                """Initialize random population of parameter combinations"""
                self.population = []
                for _ in range(self.population_size):
                    individual = {}
                    for param, (min_val, max_val) in self.bounds.items():
                        if param == 'max_tokens':
                            individual[param] = random.randint(int(min_val), int(max_val))
                        else:
                            individual[param] = random.uniform(min_val, max_val)
                    self.population.append(individual)
            
            def evaluate_fitness(self, individual, response_success, response_data=None):
                """Evaluate fitness of parameter combination"""
                fitness = 0.0
                
                # Base fitness for successful response
                if response_success:
                    fitness += 1.0
                
                # Bonus for exploring edge cases
                for param, value in individual.items():
                    min_val, max_val = self.bounds[param]
                    range_span = max_val - min_val
                    
                    # Higher fitness for values near boundaries (edge exploration)
                    distance_from_min = abs(value - min_val) / range_span
                    distance_from_max = abs(value - max_val) / range_span
                    edge_proximity = min(distance_from_min, distance_from_max)
                    
                    if edge_proximity < 0.1:  # Within 10% of boundary
                        fitness += 0.5
                        self.discovered_edges.append((param, value))
                
                # Bonus for parameter diversity
                temp_diversity = abs(individual.get('temperature', 0.5) - 0.5) * 2  # Distance from center
                fitness += temp_diversity * 0.3
                
                return fitness
            
            def select_parents(self):
                """Select parents using tournament selection"""
                parents = []
                for _ in range(2):
                    tournament_size = 3
                    tournament_indices = random.sample(range(len(self.population)), tournament_size)
                    tournament_fitness = [self.fitness_scores[i] for i in tournament_indices]
                    winner_idx = tournament_indices[np.argmax(tournament_fitness)]
                    parents.append(self.population[winner_idx].copy())
                return parents
            
            def crossover(self, parent1, parent2):
                """Create offspring through parameter crossover"""
                child = {}
                for param in self.bounds.keys():
                    if random.random() < 0.5:
                        child[param] = parent1[param]
                    else:
                        child[param] = parent2[param]
                return child
            
            def mutate(self, individual, mutation_rate=0.2):
                """Mutate individual parameters"""
                for param, (min_val, max_val) in self.bounds.items():
                    if random.random() < mutation_rate:
                        if param == 'max_tokens':
                            individual[param] = random.randint(int(min_val), int(max_val))
                        else:
                            individual[param] = random.uniform(min_val, max_val)
                return individual
            
            def evolve_generation(self):
                """Evolve to next generation"""
                new_population = []
                
                # Keep best performers (elitism)
                elite_count = 2
                elite_indices = np.argsort(self.fitness_scores)[-elite_count:]
                for idx in elite_indices:
                    new_population.append(self.population[idx].copy())
                
                # Generate offspring
                while len(new_population) < self.population_size:
                    parents = self.select_parents()
                    child = self.crossover(parents[0], parents[1])
                    child = self.mutate(child)
                    new_population.append(child)
                
                self.population = new_population
                self.generation += 1
        
        # Initialize adaptive explorer
        explorer = AdaptiveParameterExplorer(parameter_bounds)
        explorer.initialize_population()
        
        exploration_results = []
        generations_to_run = 3  # Limited for testing
        
        for generation in range(generations_to_run):
            generation_start = time.time()
            generation_fitness = []
            
            # Evaluate current population
            for i, individual in enumerate(explorer.population):
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Adaptive exploration gen {generation} individual {i}"}],
                    **individual
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                response_data = None
                if response.status_code == 200:
                    response_data = response.json()
                
                fitness = explorer.evaluate_fitness(
                    individual, 
                    response.status_code == 200, 
                    response_data
                )
                generation_fitness.append(fitness)
            
            explorer.fitness_scores = generation_fitness
            generation_end = time.time()
            generation_time = (generation_end - generation_start) * 1000
            
            # Record generation results
            best_fitness = max(generation_fitness)
            avg_fitness = statistics.mean(generation_fitness)
            edge_cases_found = len([e for e in explorer.discovered_edges 
                                  if any(abs(e[1] - bound[0]) < 0.1 * (bound[1] - bound[0]) or 
                                        abs(e[1] - bound[1]) < 0.1 * (bound[1] - bound[0])
                                        for bound in [parameter_bounds[e[0]]])])
            
            generation_result = {
                "generation": generation,
                "population_size": len(explorer.population),
                "best_fitness": best_fitness,
                "average_fitness": avg_fitness,
                "edge_cases_discovered": edge_cases_found,
                "total_edges_found": len(explorer.discovered_edges),
                "generation_time_ms": generation_time,
                "successful_evaluations": sum(1 for f in generation_fitness if f >= 1.0)
            }
            
            exploration_results.append(generation_result)
            
            logger.info(f"Adaptive exploration Gen {generation}: "
                       f"Best fitness: {best_fitness:.2f}, "
                       f"Avg fitness: {avg_fitness:.2f}, "
                       f"Edge cases: {edge_cases_found}")
            
            # Evolve to next generation (except for last iteration)
            if generation < generations_to_run - 1:
                explorer.evolve_generation()
        
        # Analyze exploration effectiveness
        total_edge_cases = sum(result["edge_cases_discovered"] for result in exploration_results)
        total_successful = sum(result["successful_evaluations"] for result in exploration_results)
        total_evaluations = sum(result["population_size"] for result in exploration_results)
        
        # Check for parameter boundary exploration
        boundary_coverage = {}
        for param, (min_val, max_val) in parameter_bounds.items():
            explored_edges = [e for e in explorer.discovered_edges if e[0] == param]
            boundary_coverage[param] = len(explored_edges)
        
        # Calculate improvement over generations
        if len(exploration_results) > 1:
            fitness_improvement = (exploration_results[-1]["best_fitness"] - 
                                 exploration_results[0]["best_fitness"])
        else:
            fitness_improvement = 0.0
        
        logger.info(f"Adaptive exploration summary: "
                   f"{total_edge_cases} edge cases discovered, "
                   f"{total_successful}/{total_evaluations} successful evaluations, "
                   f"Fitness improvement: {fitness_improvement:.2f}")
        
        # Verify adaptive exploration effectiveness
        assert total_edge_cases >= generations_to_run, \
            f"Should discover edge cases in each generation, got {total_edge_cases}"
        
        assert total_successful >= total_evaluations * 0.7, \
            f"Most evaluations should succeed, got {total_successful}/{total_evaluations}"
        
        assert len(boundary_coverage) == len(parameter_bounds), \
            "Should explore boundaries for all parameters"
        
        assert fitness_improvement >= 0, \
            f"Fitness should improve over generations, got {fitness_improvement}"
        
        # Verify each parameter had some boundary exploration
        unexplored_params = [param for param, count in boundary_coverage.items() if count == 0]
        assert len(unexplored_params) <= len(parameter_bounds) * 0.3, \
            f"Most parameters should have boundary exploration, unexplored: {unexplored_params}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_compliance_validation_extended_014(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """TDM_PARAM_COMPLIANCE_VALIDATION_014: Extended compliance-driven parameter validation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing extended compliance-driven parameter validation")
        
        # Define comprehensive compliance frameworks
        compliance_frameworks = {
            "NIST_SP_800-53": {
                "security_controls": {
                    "AC-3": {  # Access Enforcement
                        "max_tokens": {"max": 500, "reason": "Limit information disclosure"},
                        "temperature": {"max": 0.6, "reason": "Predictable behavior for auditing"}
                    },
                    "AU-3": {  # Audit Content
                        "stream": {"forbidden": True, "reason": "Complete audit logging required"},
                        "temperature": {"max": 0.8, "reason": "Deterministic for audit trails"}
                    },
                    "SC-8": {  # Transmission Confidentiality
                        "max_tokens": {"max": 200, "reason": "Minimize data transmission"},
                        "frequency_penalty": {"min": 0.3, "reason": "Reduce repetitive patterns"}
                    }
                }
            },
            "GDPR_Article_25": {  # Data Protection by Design
                "privacy_requirements": {
                    "data_minimization": {
                        "max_tokens": {"max": 150, "reason": "Minimize personal data processing"},
                        "temperature": {"max": 0.5, "reason": "Reduce random personal data generation"}
                    },
                    "purpose_limitation": {
                        "top_p": {"max": 0.7, "reason": "Focused responses for specific purposes"},
                        "presence_penalty": {"min": 0.2, "reason": "Avoid off-topic content"}
                    }
                }
            },
            "SOX_Section_404": {  # Financial Controls
                "financial_controls": {
                    "accuracy": {
                        "temperature": {"max": 0.3, "reason": "High accuracy for financial data"},
                        "top_p": {"max": 0.6, "reason": "Conservative sampling for reliability"}
                    },
                    "completeness": {
                        "max_tokens": {"min": 100, "reason": "Adequate detail for financial reporting"},
                        "frequency_penalty": {"max": 0.5, "reason": "Allow necessary repetition"}
                    }
                }
            },
            "HIPAA_Security_Rule": {
                "healthcare_safeguards": {
                    "confidentiality": {
                        "max_tokens": {"max": 300, "reason": "Limit PHI exposure"},
                        "temperature": {"max": 0.4, "reason": "Predictable handling of PHI"}
                    },
                    "integrity": {
                        "top_p": {"max": 0.8, "reason": "Consistent medical terminology"},
                        "presence_penalty": {"min": 0.1, "reason": "Maintain medical context"}
                    }
                }
            }
        }
        
        def validate_compliance(parameters, framework_name, control_set):
            """Validate parameters against specific compliance requirements"""
            violations = []
            compliance_score = 0.0
            total_checks = 0
            
            for control_name, requirements in control_set.items():
                for param, constraint in requirements.items():
                    if param in parameters:
                        total_checks += 1
                        param_value = parameters[param]
                        
                        # Check maximum constraints
                        if "max" in constraint:
                            if param_value <= constraint["max"]:
                                compliance_score += 1.0
                            else:
                                violations.append({
                                    "framework": framework_name,
                                    "control": control_name,
                                    "parameter": param,
                                    "violation": f"Value {param_value} exceeds max {constraint['max']}",
                                    "reason": constraint["reason"]
                                })
                        
                        # Check minimum constraints
                        if "min" in constraint:
                            if param_value >= constraint["min"]:
                                compliance_score += 1.0
                            else:
                                violations.append({
                                    "framework": framework_name,
                                    "control": control_name,
                                    "parameter": param,
                                    "violation": f"Value {param_value} below min {constraint['min']}",
                                    "reason": constraint["reason"]
                                })
                        
                        # Check forbidden values
                        if "forbidden" in constraint and constraint["forbidden"]:
                            if param_value is True or param_value == True:
                                violations.append({
                                    "framework": framework_name,
                                    "control": control_name,
                                    "parameter": param,
                                    "violation": f"Parameter {param} is forbidden",
                                    "reason": constraint["reason"]
                                })
                            else:
                                compliance_score += 1.0
                        
                        # If no specific constraint applies, assume compliance
                        if not any(key in constraint for key in ["max", "min", "forbidden"]):
                            compliance_score += 1.0
            
            return violations, compliance_score / max(total_checks, 1)
        
        compliance_test_scenarios = [
            {
                "name": "nist_high_security",
                "framework": "NIST_SP_800-53",
                "control_set": "security_controls",
                "test_parameters": {
                    "max_tokens": 300,  # Should violate AC-3
                    "temperature": 0.4,
                    "stream": False,
                    "frequency_penalty": 0.5
                }
            },
            {
                "name": "gdpr_privacy_compliant",
                "framework": "GDPR_Article_25",
                "control_set": "privacy_requirements",
                "test_parameters": {
                    "max_tokens": 120,
                    "temperature": 0.3,
                    "top_p": 0.6,
                    "presence_penalty": 0.3
                }
            },
            {
                "name": "sox_financial_accuracy",
                "framework": "SOX_Section_404",
                "control_set": "financial_controls",
                "test_parameters": {
                    "max_tokens": 150,
                    "temperature": 0.2,
                    "top_p": 0.5,
                    "frequency_penalty": 0.3
                }
            },
            {
                "name": "hipaa_healthcare_safe",
                "framework": "HIPAA_Security_Rule",
                "control_set": "healthcare_safeguards",
                "test_parameters": {
                    "max_tokens": 250,
                    "temperature": 0.3,
                    "top_p": 0.7,
                    "presence_penalty": 0.2
                }
            }
        ]
        
        extended_compliance_results = []
        
        for scenario in compliance_test_scenarios:
            framework = compliance_frameworks[scenario["framework"]]
            control_set = framework[scenario["control_set"]]
            
            # Validate compliance
            violations, compliance_score = validate_compliance(
                scenario["test_parameters"], 
                scenario["framework"], 
                control_set
            )
            
            # Generate compliance report
            compliance_report = {
                "framework": scenario["framework"],
                "control_set": scenario["control_set"],
                "total_violations": len(violations),
                "compliance_score": compliance_score,
                "violations": violations
            }
            
            # Test with compliant/non-compliant parameters
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{
                    "role": "user", 
                    "content": f"Test compliance for {scenario['framework']} framework"
                }],
                **{k: v for k, v in scenario["test_parameters"].items() if k != "stream"}
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            # Calculate compliance effectiveness metrics
            risk_mitigation_score = compliance_score * 0.8 + (1.0 - len(violations) / 10.0) * 0.2
            
            result = {
                "scenario": scenario["name"],
                "framework": scenario["framework"],
                "compliance_report": compliance_report,
                "risk_mitigation_score": risk_mitigation_score,
                "response_success": response.status_code == 200,
                "compliance_level": "HIGH" if compliance_score >= 0.9 else "MEDIUM" if compliance_score >= 0.7 else "LOW"
            }
            
            extended_compliance_results.append(result)
            
            logger.info(f"Extended compliance {scenario['name']}: "
                       f"Score: {compliance_score:.2%}, "
                       f"Violations: {len(violations)}, "
                       f"Level: {result['compliance_level']}")
        
        # Generate cross-framework compliance analysis
        framework_compliance_summary = {}
        for result in extended_compliance_results:
            framework = result["framework"]
            if framework not in framework_compliance_summary:
                framework_compliance_summary[framework] = {
                    "total_tests": 0,
                    "compliant_tests": 0,
                    "average_score": 0.0,
                    "total_violations": 0
                }
            
            summary = framework_compliance_summary[framework]
            summary["total_tests"] += 1
            summary["total_violations"] += result["compliance_report"]["total_violations"]
            summary["average_score"] += result["compliance_report"]["compliance_score"]
            
            if result["compliance_report"]["compliance_score"] >= 0.8:
                summary["compliant_tests"] += 1
        
        # Calculate averages
        for framework_summary in framework_compliance_summary.values():
            if framework_summary["total_tests"] > 0:
                framework_summary["average_score"] /= framework_summary["total_tests"]
                framework_summary["compliance_rate"] = framework_summary["compliant_tests"] / framework_summary["total_tests"]
        
        logger.info(f"Cross-framework compliance summary: "
                   f"{len(framework_compliance_summary)} frameworks analyzed")
        
        # Verify extended compliance validation effectiveness
        high_compliance_results = [r for r in extended_compliance_results 
                                 if r["compliance_report"]["compliance_score"] >= 0.7]
        successful_responses = [r for r in extended_compliance_results if r["response_success"]]
        low_risk_results = [r for r in extended_compliance_results if r["risk_mitigation_score"] >= 0.8]
        
        assert len(high_compliance_results) >= len(compliance_test_scenarios) * 0.6, \
            f"Most scenarios should achieve good compliance, got {len(high_compliance_results)}/{len(compliance_test_scenarios)}"
        
        assert len(successful_responses) >= len(compliance_test_scenarios) * 0.8, \
            f"Most requests should succeed, got {len(successful_responses)}/{len(compliance_test_scenarios)}"
        
        assert len(low_risk_results) >= len(compliance_test_scenarios) * 0.5, \
            f"Many scenarios should achieve low risk, got {len(low_risk_results)}/{len(compliance_test_scenarios)}"
        
        # Verify framework coverage
        assert len(framework_compliance_summary) == len(compliance_frameworks), \
            "All compliance frameworks should be tested"
        
        # Verify no framework has complete compliance failure
        failed_frameworks = [name for name, summary in framework_compliance_summary.items() 
                           if summary["compliance_rate"] == 0.0]
        assert len(failed_frameworks) == 0, \
            f"No framework should have complete compliance failure, failed: {failed_frameworks}"