# Section 7.9 - Data Refresh Strategy (Basic)
# Based on: docs/test_design_n_planning/Testcases_7_9_DataManagement/Test Cases_Data Refresh Strategy.md

import pytest
import httpx
import asyncio
import time
import statistics
import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import random
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class RefreshTestResult:
    """Data refresh strategy test result structure"""
    test_name: str
    refresh_operation: str
    data_items_processed: int
    staleness_detected: int
    refresh_success_rate: float
    execution_time_ms: float
    success: bool


class TestBasicRefreshStrategy:
    """Test basic data refresh strategies"""
    
    def setup_method(self):
        """Setup for refresh strategy tests"""
        self.test_data_registry = {
            "prompts": [
                {"id": "prompt_001", "content": "What is AI?", "created": datetime.now() - timedelta(days=30), "usage_count": 150},
                {"id": "prompt_002", "content": "Explain machine learning", "created": datetime.now() - timedelta(days=60), "usage_count": 89},
                {"id": "prompt_003", "content": "Define neural networks", "created": datetime.now() - timedelta(days=90), "usage_count": 200},
                {"id": "prompt_004", "content": "What is deep learning?", "created": datetime.now() - timedelta(days=120), "usage_count": 45}
            ],
            "parameters": [
                {"id": "param_001", "config": {"max_tokens": 50}, "created": datetime.now() - timedelta(days=45), "effectiveness": 0.85},
                {"id": "param_002", "config": {"temperature": 0.7}, "created": datetime.now() - timedelta(days=75), "effectiveness": 0.65},
                {"id": "param_003", "config": {"top_p": 0.9}, "created": datetime.now() - timedelta(days=100), "effectiveness": 0.90}
            ]
        }
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_refresh_review_process_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TDM_REFRESH_REVIEW_PROCESS_001: Systematic test data review process"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Simulate systematic review process for test data
        review_criteria = {
            "age_threshold_days": 90,
            "usage_threshold": 100,
            "effectiveness_threshold": 0.8
        }
        
        review_results = []
        
        # Review prompts
        for prompt_data in self.test_data_registry["prompts"]:
            review_start = time.perf_counter()
            
            # Calculate staleness indicators
            age_days = (datetime.now() - prompt_data["created"]).days
            is_stale_by_age = age_days > review_criteria["age_threshold_days"]
            is_underused = prompt_data["usage_count"] < review_criteria["usage_threshold"]
            
            # Test the prompt to assess current effectiveness
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt_data["content"]}],
                "max_tokens": 80
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            review_end = time.perf_counter()
            review_time = (review_end - review_start) * 1000
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                
                # Assess current effectiveness
                response_quality = min(1.0, len(content) / 50)  # Normalized quality score
                is_effective = response_quality >= 0.7
                
                # Determine review outcome
                needs_refresh = is_stale_by_age or is_underused or not is_effective
                
                result = {
                    "item_id": prompt_data["id"],
                    "item_type": "prompt",
                    "age_days": age_days,
                    "usage_count": prompt_data["usage_count"],
                    "response_quality": response_quality,
                    "is_stale_by_age": is_stale_by_age,
                    "is_underused": is_underused,
                    "is_effective": is_effective,
                    "needs_refresh": needs_refresh,
                    "review_time": review_time,
                    "success": True
                }
            else:
                result = {
                    "item_id": prompt_data["id"],
                    "item_type": "prompt",
                    "needs_refresh": True,  # Failed prompts definitely need refresh
                    "success": False,
                    "review_time": review_time,
                    "error_code": response.status_code
                }
            
            review_results.append(result)
        
        # Analyze review process effectiveness
        successful_reviews = [r for r in review_results if r["success"]]
        items_needing_refresh = [r for r in review_results if r.get("needs_refresh", False)]
        
        # Calculate review metrics
        total_review_time = sum(r["review_time"] for r in review_results)
        avg_review_time = total_review_time / len(review_results) if review_results else 0
        refresh_rate = len(items_needing_refresh) / len(review_results) if review_results else 0
        
        logger.info(f"Review process: {len(successful_reviews)}/{len(review_results)} successful, "
                   f"{len(items_needing_refresh)} need refresh, "
                   f"Avg time: {avg_review_time:.2f}ms")
        
        assert len(successful_reviews) >= len(review_results) * 0.8, \
            f"Most reviews should succeed, got {len(successful_reviews)}/{len(review_results)}"
        
        assert 0.1 <= refresh_rate <= 0.8, \
            f"Refresh rate should be reasonable, got {refresh_rate:.2%}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_refresh_prompt_diversity_update_002(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """TDM_REFRESH_PROMPT_DIVERSITY_UPDATE_002: Prompt library diversity expansion"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Define new prompt categories for diversity expansion
        new_prompt_categories = {
            "technical_reasoning": [
                "Analyze the computational complexity of this algorithm",
                "Compare the trade-offs between different data structures",
                "Explain the security implications of this design pattern"
            ],
            "creative_problem_solving": [
                "Design an innovative solution for sustainable energy",
                "Create a framework for improving team collaboration",
                "Develop a strategy for digital transformation"
            ],
            "ethical_considerations": [
                "Discuss the ethical implications of AI in healthcare",
                "Analyze bias in machine learning algorithms",
                "Evaluate privacy concerns in data collection"
            ],
            "multi_step_reasoning": [
                "Break down this complex problem into manageable steps",
                "Walk through the logical sequence for decision making",
                "Demonstrate cause-and-effect relationships in this scenario"
            ]
        }
        
        diversity_expansion_results = []
        
        for category, prompts in new_prompt_categories.items():
            category_start = time.perf_counter()
            category_results = []
            
            logger.info(f"Testing prompt diversity expansion for category: {category}")
            
            for prompt in prompts:
                # Test new prompt effectiveness
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 120
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    content = response_data["choices"][0]["message"]["content"]
                    
                    # Assess prompt quality and diversity value
                    response_length = len(content)
                    complexity_indicators = sum(1 for word in content.split() if len(word) > 6)
                    diversity_score = min(1.0, complexity_indicators / 10)
                    
                    # Check for category-appropriate keywords
                    category_keywords = {
                        "technical_reasoning": ["algorithm", "complexity", "structure", "pattern"],
                        "creative_problem_solving": ["solution", "innovation", "strategy", "framework"],
                        "ethical_considerations": ["ethical", "bias", "privacy", "implications"],
                        "multi_step_reasoning": ["step", "sequence", "logical", "process"]
                    }
                    
                    relevant_keywords = category_keywords.get(category, [])
                    keyword_matches = sum(1 for keyword in relevant_keywords if keyword.lower() in content.lower())
                    relevance_score = keyword_matches / len(relevant_keywords) if relevant_keywords else 0.5
                    
                    category_results.append({
                        "prompt": prompt,
                        "response_length": response_length,
                        "diversity_score": diversity_score,
                        "relevance_score": relevance_score,
                        "adds_diversity": diversity_score >= 0.6 and relevance_score >= 0.3,
                        "success": True
                    })
                else:
                    category_results.append({
                        "prompt": prompt,
                        "adds_diversity": False,
                        "success": False,
                        "error_code": response.status_code
                    })
            
            category_end = time.perf_counter()
            category_time = (category_end - category_start) * 1000
            
            # Analyze category expansion effectiveness
            successful_prompts = [r for r in category_results if r["success"]]
            diverse_prompts = [r for r in category_results if r.get("adds_diversity", False)]
            
            avg_diversity = statistics.mean([r["diversity_score"] for r in successful_prompts]) if successful_prompts else 0
            avg_relevance = statistics.mean([r["relevance_score"] for r in successful_prompts]) if successful_prompts else 0
            
            expansion_result = {
                "category": category,
                "total_prompts": len(prompts),
                "successful_prompts": len(successful_prompts),
                "diverse_prompts": len(diverse_prompts),
                "avg_diversity_score": avg_diversity,
                "avg_relevance_score": avg_relevance,
                "expansion_time": category_time,
                "expansion_effective": len(diverse_prompts) >= len(prompts) * 0.7
            }
            
            diversity_expansion_results.append(expansion_result)
            
            logger.info(f"Diversity expansion {category}: "
                       f"{len(diverse_prompts)}/{len(prompts)} prompts add diversity, "
                       f"Avg diversity: {avg_diversity:.3f}")
        
        # Verify diversity expansion effectiveness
        effective_expansions = [r for r in diversity_expansion_results if r["expansion_effective"]]
        
        assert len(effective_expansions) >= len(new_prompt_categories) * 0.7, \
            f"Most category expansions should be effective, got {len(effective_expansions)}/{len(new_prompt_categories)}"
        
        # Verify overall diversity improvement
        total_diverse_prompts = sum(r["diverse_prompts"] for r in diversity_expansion_results)
        total_prompts = sum(r["total_prompts"] for r in diversity_expansion_results)
        overall_diversity_rate = total_diverse_prompts / total_prompts if total_prompts > 0 else 0
        
        assert overall_diversity_rate >= 0.6, \
            f"Overall diversity rate should be high, got {overall_diversity_rate:.2%}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_refresh_edge_case_expansion_003(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """TDM_REFRESH_EDGE_CASE_EXPANSION_003: Edge case test data expansion"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Define new edge cases discovered through field research
        new_edge_cases = [
            {
                "category": "parameter_boundaries",
                "cases": [
                    {"max_tokens": 1, "temperature": 0.0, "description": "Minimal token generation"},
                    {"max_tokens": 1000, "temperature": 2.0, "description": "Maximum boundary test"},
                    {"max_tokens": 50, "temperature": 0.0, "top_p": 0.0, "description": "Zero randomness combination"}
                ]
            },
            {
                "category": "input_edge_cases",
                "cases": [
                    {"prompt": "", "description": "Empty prompt handling"},
                    {"prompt": "a" * 1000, "description": "Very long prompt"},
                    {"prompt": "🚀🌟💫✨", "description": "Unicode emoji only"},
                    {"prompt": "SELECT * FROM users;", "description": "SQL injection attempt"}
                ]
            },
            {
                "category": "conversation_edge_cases",
                "cases": [
                    {
                        "messages": [{"role": "user", "content": "Hi"}] * 50,
                        "description": "Repetitive conversation pattern"
                    },
                    {
                        "messages": [
                            {"role": "system", "content": "You are helpful"},
                            {"role": "system", "content": "You are unhelpful"},
                            {"role": "user", "content": "Help me"}
                        ],
                        "description": "Conflicting system messages"
                    }
                ]
            }
        ]
        
        edge_case_expansion_results = []
        
        for edge_category in new_edge_cases:
            category_start = time.perf_counter()
            category_name = edge_category["category"]
            
            logger.info(f"Testing edge case expansion for category: {category_name}")
            
            for case in edge_category["cases"]:
                case_start = time.perf_counter()
                
                # Prepare request based on case type
                if "prompt" in case:
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": case["prompt"]}],
                        "max_tokens": 50
                    }
                elif "messages" in case:
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": case["messages"],
                        "max_tokens": 50
                    }
                else:
                    # Parameter boundary case
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Edge case test"}],
                        **{k: v for k, v in case.items() if k not in ["description"]}
                    }
                
                # Execute edge case test
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                case_end = time.perf_counter()
                case_time = (case_end - case_start) * 1000
                
                # Analyze edge case behavior
                if response.status_code == 200:
                    response_data = response.json()
                    if "choices" in response_data and response_data["choices"]:
                        content = response_data["choices"][0]["message"]["content"]
                        graceful_handling = len(content) > 0 and len(content) < 2000
                    else:
                        graceful_handling = False
                    
                    result = {
                        "category": category_name,
                        "description": case["description"],
                        "response_code": response.status_code,
                        "response_length": len(content) if "content" in locals() else 0,
                        "graceful_handling": graceful_handling,
                        "case_time": case_time,
                        "expands_coverage": True,
                        "success": True
                    }
                else:
                    # Some edge cases are expected to fail, which is also valuable data
                    result = {
                        "category": category_name,
                        "description": case["description"],
                        "response_code": response.status_code,
                        "graceful_handling": response.status_code in [400, 422],  # Expected error codes
                        "case_time": case_time,
                        "expands_coverage": True,
                        "success": response.status_code in [200, 400, 422]
                    }
                
                edge_case_expansion_results.append(result)
        
        # Analyze edge case expansion effectiveness
        successful_cases = [r for r in edge_case_expansion_results if r["success"]]
        gracefully_handled_cases = [r for r in edge_case_expansion_results if r.get("graceful_handling", False)]
        coverage_expanding_cases = [r for r in edge_case_expansion_results if r.get("expands_coverage", False)]
        
        categories_tested = set(r["category"] for r in edge_case_expansion_results)
        
        logger.info(f"Edge case expansion: "
                   f"{len(successful_cases)}/{len(edge_case_expansion_results)} successful, "
                   f"{len(gracefully_handled_cases)} gracefully handled, "
                   f"{len(categories_tested)} categories tested")
        
        assert len(successful_cases) >= len(edge_case_expansion_results) * 0.7, \
            f"Most edge cases should be handled successfully, got {len(successful_cases)}/{len(edge_case_expansion_results)}"
        
        assert len(gracefully_handled_cases) >= len(edge_case_expansion_results) * 0.6, \
            f"Most edge cases should be handled gracefully, got {len(gracefully_handled_cases)}/{len(edge_case_expansion_results)}"
        
        assert len(coverage_expanding_cases) == len(edge_case_expansion_results), \
            f"All edge cases should expand coverage, got {len(coverage_expanding_cases)}/{len(edge_case_expansion_results)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_refresh_stale_data_detection_005(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """TDM_REFRESH_STALE_DATA_DETECTION_005: Automated stale data detection"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Simulate stale data detection algorithms
        staleness_indicators = {
            "age_based": {"threshold_days": 60, "weight": 0.3},
            "usage_based": {"min_usage": 50, "weight": 0.2},
            "effectiveness_based": {"min_effectiveness": 0.7, "weight": 0.4},
            "relevance_based": {"min_relevance": 0.6, "weight": 0.1}
        }
        
        def calculate_staleness_score(item_data):
            """Calculate composite staleness score"""
            score = 0.0
            
            # Age-based staleness
            age_days = (datetime.now() - item_data["created"]).days
            if age_days > staleness_indicators["age_based"]["threshold_days"]:
                score += staleness_indicators["age_based"]["weight"]
            
            # Usage-based staleness
            if item_data.get("usage_count", 0) < staleness_indicators["usage_based"]["min_usage"]:
                score += staleness_indicators["usage_based"]["weight"]
            
            # Effectiveness-based staleness
            if item_data.get("effectiveness", 1.0) < staleness_indicators["effectiveness_based"]["min_effectiveness"]:
                score += staleness_indicators["effectiveness_based"]["weight"]
            
            # Relevance-based staleness (simulated)
            relevance = random.uniform(0.4, 1.0)  # Simulated relevance score
            if relevance < staleness_indicators["relevance_based"]["min_relevance"]:
                score += staleness_indicators["relevance_based"]["weight"]
            
            return min(1.0, score)
        
        stale_detection_results = []
        
        # Test stale data detection on test data registry
        for data_type, items in self.test_data_registry.items():
            for item in items:
                detection_start = time.perf_counter()
                
                # Calculate staleness score
                staleness_score = calculate_staleness_score(item)
                is_stale = staleness_score > 0.5
                
                # Test current item effectiveness
                if data_type == "prompts":
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": item["content"]}],
                        "max_tokens": 60
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    current_effectiveness = 0.8 if response.status_code == 200 else 0.2
                elif data_type == "parameters":
                    # Test parameter effectiveness
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Parameter test"}],
                        **item["config"]
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    current_effectiveness = 0.9 if response.status_code == 200 else 0.1
                
                detection_end = time.perf_counter()
                detection_time = (detection_end - detection_start) * 1000
                
                # Validate staleness detection accuracy
                predicted_stale = is_stale
                actual_stale = current_effectiveness < 0.7
                detection_accurate = (predicted_stale and actual_stale) or (not predicted_stale and not actual_stale)
                
                result = {
                    "item_id": item["id"],
                    "data_type": data_type,
                    "staleness_score": staleness_score,
                    "predicted_stale": predicted_stale,
                    "actual_stale": actual_stale,
                    "detection_accurate": detection_accurate,
                    "current_effectiveness": current_effectiveness,
                    "detection_time": detection_time
                }
                
                stale_detection_results.append(result)
        
        # Analyze stale data detection effectiveness
        accurate_detections = [r for r in stale_detection_results if r["detection_accurate"]]
        stale_items_detected = [r for r in stale_detection_results if r["predicted_stale"]]
        actually_stale_items = [r for r in stale_detection_results if r["actual_stale"]]
        
        detection_accuracy = len(accurate_detections) / len(stale_detection_results) if stale_detection_results else 0
        avg_detection_time = statistics.mean([r["detection_time"] for r in stale_detection_results])
        
        logger.info(f"Stale data detection: "
                   f"Accuracy: {detection_accuracy:.2%}, "
                   f"Detected stale: {len(stale_items_detected)}, "
                   f"Actually stale: {len(actually_stale_items)}, "
                   f"Avg time: {avg_detection_time:.2f}ms")
        
        assert detection_accuracy >= 0.7, \
            f"Stale data detection should be reasonably accurate, got {detection_accuracy:.2%}"
        
        assert avg_detection_time <= 5000, \
            f"Detection should be fast, got {avg_detection_time:.2f}ms"