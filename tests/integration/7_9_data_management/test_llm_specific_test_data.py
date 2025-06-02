# Section 7.9 - LLM-Specific Test Data
# Based on: docs/test_design_n_planning/Testcases_7_9_DataManagement/Test Cases_LLM-Specific Test Data.md

import pytest
import httpx
import asyncio
import time
import statistics
import json
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from faker import Faker

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class LLMTestDataResult:
    """LLM-specific test data result structure"""
    test_name: str
    prompt_category: str
    response_quality_score: float
    semantic_relevance_score: float
    token_efficiency: float
    success: bool


class TestPromptLibraryManagement:
    """Test LLM-specific prompt library and management"""
    
    def setup_method(self):
        """Setup prompt library for testing"""
        self.faker = Faker()
        self.prompt_library = {
            "conversational": [
                "Hello, how are you today?",
                "Can you help me understand this concept?",
                "I'm having trouble with this problem.",
                "Thank you for your assistance."
            ],
            "analytical": [
                "Analyze the following data and provide insights:",
                "Compare and contrast these two approaches:",
                "What are the pros and cons of this solution?",
                "Evaluate the effectiveness of this strategy."
            ],
            "creative": [
                "Write a short story about:",
                "Create a marketing slogan for:",
                "Design a solution for:",
                "Imagine a world where:"
            ],
            "technical": [
                "Explain the technical implementation of:",
                "Debug this code and suggest improvements:",
                "Optimize this algorithm for better performance:",
                "Design a system architecture for:"
            ],
            "educational": [
                "Teach me about this topic step by step:",
                "Provide examples to illustrate this concept:",
                "Create a lesson plan for:",
                "Explain this to a beginner:"
            ]
        }
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_llm_prompt_library_generation_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """TDM_LLM_PROMPT_LIBRARY_GENERATION_001: AI-powered prompt library generation and curation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test AI-powered prompt generation for different categories
        prompt_generation_results = []
        
        for category, base_prompts in self.prompt_library.items():
            category_results = []
            
            logger.info(f"Testing prompt generation for category: {category}")
            
            # Generate variations of existing prompts
            for base_prompt in base_prompts[:2]:  # Test first 2 prompts per category
                # Request prompt variations
                generation_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Generate 3 variations of this {category} prompt: '{base_prompt}'. Keep the same intent but vary the wording."}],
                    "max_tokens": 150
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, generation_request
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    generated_content = response_data["choices"][0]["message"]["content"]
                    
                    # Extract individual prompts from the response
                    generated_prompts = self._extract_prompts_from_response(generated_content)
                    
                    # Test each generated prompt
                    for i, generated_prompt in enumerate(generated_prompts[:3]):
                        test_request = {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": generated_prompt}],
                            "max_tokens": 100
                        }
                        
                        test_response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, test_request
                        )
                        
                        if test_response.status_code == 200:
                            test_data = test_response.json()
                            test_content = test_data["choices"][0]["message"]["content"]
                            
                            # Evaluate prompt quality
                            quality_score = self._evaluate_prompt_quality(generated_prompt, test_content, category)
                            relevance_score = self._evaluate_semantic_relevance(base_prompt, generated_prompt)
                            
                            category_results.append({
                                "base_prompt": base_prompt,
                                "generated_prompt": generated_prompt,
                                "response_content": test_content,
                                "quality_score": quality_score,
                                "relevance_score": relevance_score,
                                "response_length": len(test_content),
                                "prompt_length": len(generated_prompt),
                                "success": True
                            })
                        else:
                            category_results.append({
                                "base_prompt": base_prompt,
                                "generated_prompt": generated_prompt,
                                "quality_score": 0.0,
                                "relevance_score": 0.0,
                                "success": False
                            })
                        
                        await asyncio.sleep(0.1)
            
            # Analyze category results
            successful_generations = [r for r in category_results if r["success"]]
            avg_quality = statistics.mean([r["quality_score"] for r in successful_generations]) if successful_generations else 0
            avg_relevance = statistics.mean([r["relevance_score"] for r in successful_generations]) if successful_generations else 0
            
            prompt_generation_results.append({
                "category": category,
                "total_generations": len(category_results),
                "successful_generations": len(successful_generations),
                "avg_quality_score": avg_quality,
                "avg_relevance_score": avg_relevance,
                "generation_success_rate": len(successful_generations) / len(category_results) if category_results else 0,
                "category_results": category_results
            })
            
            logger.info(f"Category {category}: "
                       f"Success: {len(successful_generations)}/{len(category_results)}, "
                       f"Quality: {avg_quality:.3f}, "
                       f"Relevance: {avg_relevance:.3f}")
        
        # Verify prompt library generation effectiveness
        high_quality_categories = [r for r in prompt_generation_results if r["avg_quality_score"] >= 0.7]
        high_relevance_categories = [r for r in prompt_generation_results if r["avg_relevance_score"] >= 0.8]
        successful_categories = [r for r in prompt_generation_results if r["generation_success_rate"] >= 0.8]
        
        assert len(high_quality_categories) >= len(self.prompt_library) * 0.6, \
            f"Most categories should generate high-quality prompts, got {len(high_quality_categories)}/{len(self.prompt_library)}"
        
        assert len(high_relevance_categories) >= len(self.prompt_library) * 0.7, \
            f"Most categories should maintain semantic relevance, got {len(high_relevance_categories)}/{len(self.prompt_library)}"
        
        assert len(successful_categories) >= len(self.prompt_library) * 0.8, \
            f"Most categories should have high success rates, got {len(successful_categories)}/{len(self.prompt_library)}"
    
    def _extract_prompts_from_response(self, content: str) -> List[str]:
        """Extract individual prompts from AI-generated response"""
        # Simple extraction logic - look for numbered lists or bullet points
        lines = content.split('\n')
        prompts = []
        
        for line in lines:
            line = line.strip()
            # Look for numbered items (1., 2., etc.) or bullet points
            if re.match(r'^[\d\-\*\•]\s*[\.\)]*\s*', line):
                prompt = re.sub(r'^[\d\-\*\•\s\.\)]*', '', line).strip()
                if len(prompt) > 10:  # Ensure it's a substantial prompt
                    prompts.append(prompt)
        
        # If no structured list found, try to split by sentences
        if not prompts:
            sentences = [s.strip() for s in content.split('.') if len(s.strip()) > 10]
            prompts = sentences[:3]  # Take first 3 sentences
        
        return prompts[:3]  # Return max 3 prompts
    
    def _evaluate_prompt_quality(self, prompt: str, response: str, category: str) -> float:
        """Evaluate the quality of a generated prompt based on its response"""
        score = 0.0
        
        # Length appropriateness (0.2 weight)
        if 10 <= len(prompt) <= 200:
            score += 0.2
        
        # Response relevance (0.3 weight)
        if len(response) > 20:
            score += 0.3
        
        # Category alignment (0.3 weight)
        category_keywords = {
            "conversational": ["hello", "help", "thank", "please"],
            "analytical": ["analyze", "compare", "evaluate", "assess"],
            "creative": ["create", "write", "design", "imagine"],
            "technical": ["implement", "code", "system", "algorithm"],
            "educational": ["teach", "explain", "learn", "example"]
        }
        
        if category in category_keywords:
            keywords = category_keywords[category]
            keyword_matches = sum(1 for keyword in keywords if keyword.lower() in prompt.lower())
            if keyword_matches > 0:
                score += 0.3
        
        # Clarity and grammar (0.2 weight)
        if '?' in prompt or prompt.endswith('.') or prompt.endswith(':'):
            score += 0.2
        
        return min(1.0, score)
    
    def _evaluate_semantic_relevance(self, base_prompt: str, generated_prompt: str) -> float:
        """Evaluate semantic relevance between base and generated prompts"""
        # Simple word overlap analysis
        base_words = set(base_prompt.lower().split())
        generated_words = set(generated_prompt.lower().split())
        
        # Remove common stop words for better relevance detection
        stop_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by"}
        base_words = base_words - stop_words
        generated_words = generated_words - stop_words
        
        if not base_words or not generated_words:
            return 0.5  # Neutral score if no meaningful words
        
        # Calculate Jaccard similarity
        intersection = len(base_words.intersection(generated_words))
        union = len(base_words.union(generated_words))
        
        similarity = intersection / union if union > 0 else 0
        
        # Bonus for maintaining question structure
        base_is_question = '?' in base_prompt
        generated_is_question = '?' in generated_prompt
        if base_is_question == generated_is_question:
            similarity += 0.2
        
        return min(1.0, similarity)
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_llm_multimodal_integration_002(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TDM_LLM_MULTIMODAL_INTEGRATION_002: Multi-modal LLM test data integration"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test multi-modal prompts (text-only simulation since we don't have image support in this API)
        multimodal_scenarios = [
            {
                "modality": "text_with_description",
                "prompts": [
                    "Describe what you would see in an image of a bustling city street",
                    "Analyze the components that would be in a technical diagram",
                    "Explain what elements would be present in a data visualization chart"
                ]
            },
            {
                "modality": "text_with_context",
                "prompts": [
                    "Given a hypothetical image showing climate data, what insights would you derive?",
                    "If you were looking at a flowchart of a business process, what would you analyze?",
                    "Considering a map showing demographic information, what patterns would you identify?"
                ]
            },
            {
                "modality": "descriptive_analysis",
                "prompts": [
                    "Describe the layout and design principles you would apply to create an effective infographic",
                    "Explain how you would structure a visual presentation of financial data",
                    "Detail the components needed for an architectural blueprint"
                ]
            }
        ]
        
        multimodal_results = []
        
        for scenario in multimodal_scenarios:
            scenario_results = []
            
            logger.info(f"Testing multimodal scenario: {scenario['modality']}")
            
            for prompt in scenario["prompts"]:
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 150
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
                    
                    # Evaluate multimodal understanding
                    visual_keywords = ["image", "visual", "see", "look", "view", "display", "show", "chart", "graph", "diagram"]
                    visual_understanding = sum(1 for keyword in visual_keywords if keyword in content.lower())
                    
                    descriptive_quality = len([word for word in content.split() if len(word) > 6])  # Complex words
                    
                    multimodal_score = min(1.0, (visual_understanding / 5) + (descriptive_quality / 20))
                    
                    scenario_results.append({
                        "prompt": prompt,
                        "response": content,
                        "response_time": response_time,
                        "response_length": len(content),
                        "visual_understanding": visual_understanding,
                        "multimodal_score": multimodal_score,
                        "success": True
                    })
                else:
                    scenario_results.append({
                        "prompt": prompt,
                        "multimodal_score": 0.0,
                        "success": False
                    })
                
                await asyncio.sleep(0.1)
            
            # Analyze scenario results
            successful_responses = [r for r in scenario_results if r["success"]]
            avg_multimodal_score = statistics.mean([r["multimodal_score"] for r in successful_responses]) if successful_responses else 0
            avg_response_time = statistics.mean([r["response_time"] for r in successful_responses]) if successful_responses else 0
            
            multimodal_results.append({
                "modality": scenario["modality"],
                "total_prompts": len(scenario["prompts"]),
                "successful_responses": len(successful_responses),
                "avg_multimodal_score": avg_multimodal_score,
                "avg_response_time": avg_response_time,
                "success_rate": len(successful_responses) / len(scenario["prompts"]) if scenario["prompts"] else 0
            })
            
            logger.info(f"Multimodal {scenario['modality']}: "
                       f"Success: {len(successful_responses)}/{len(scenario['prompts'])}, "
                       f"Multimodal score: {avg_multimodal_score:.3f}, "
                       f"Avg time: {avg_response_time:.2f}ms")
        
        # Verify multimodal integration effectiveness
        high_scoring_scenarios = [r for r in multimodal_results if r["avg_multimodal_score"] >= 0.6]
        successful_scenarios = [r for r in multimodal_results if r["success_rate"] >= 0.8]
        
        assert len(high_scoring_scenarios) >= len(multimodal_scenarios) * 0.6, \
            f"Most scenarios should show good multimodal understanding, got {len(high_scoring_scenarios)}/{len(multimodal_scenarios)}"
        
        assert len(successful_scenarios) >= len(multimodal_scenarios) * 0.8, \
            f"Most scenarios should have high success rates, got {len(successful_scenarios)}/{len(multimodal_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_llm_semantic_response_validation_007(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """TDM_LLM_SEMANTIC_RESPONSE_VALIDATION_007: Advanced semantic response validation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test semantic validation of responses
        semantic_test_cases = [
            {
                "domain": "scientific",
                "prompts": [
                    "Explain the process of photosynthesis",
                    "Describe how DNA replication works",
                    "What causes the greenhouse effect?"
                ],
                "expected_concepts": ["process", "mechanism", "cause", "effect", "energy", "carbon", "reaction"],
                "coherence_threshold": 0.8
            },
            {
                "domain": "mathematical",
                "prompts": [
                    "Solve the equation 2x + 5 = 13",
                    "Explain the concept of derivatives",
                    "What is the Pythagorean theorem?"
                ],
                "expected_concepts": ["equation", "solve", "calculate", "theorem", "function", "formula", "proof"],
                "coherence_threshold": 0.9
            },
            {
                "domain": "literary",
                "prompts": [
                    "Analyze the theme of love in Romeo and Juliet",
                    "Describe the writing style of Ernest Hemingway",
                    "What is symbolism in literature?"
                ],
                "expected_concepts": ["theme", "character", "style", "meaning", "symbol", "narrative", "author"],
                "coherence_threshold": 0.7
            }
        ]
        
        semantic_validation_results = []
        
        for test_case in semantic_test_cases:
            domain_results = []
            
            logger.info(f"Testing semantic validation for domain: {test_case['domain']}")
            
            for prompt in test_case["prompts"]:
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
                    
                    # Semantic analysis
                    concept_coverage = self._calculate_concept_coverage(content, test_case["expected_concepts"])
                    coherence_score = self._calculate_coherence_score(content)
                    domain_relevance = self._calculate_domain_relevance(content, test_case["domain"])
                    
                    # Overall semantic quality
                    semantic_quality = (concept_coverage + coherence_score + domain_relevance) / 3
                    
                    domain_results.append({
                        "prompt": prompt,
                        "response": content,
                        "concept_coverage": concept_coverage,
                        "coherence_score": coherence_score,
                        "domain_relevance": domain_relevance,
                        "semantic_quality": semantic_quality,
                        "meets_threshold": coherence_score >= test_case["coherence_threshold"],
                        "success": True
                    })
                else:
                    domain_results.append({
                        "prompt": prompt,
                        "semantic_quality": 0.0,
                        "meets_threshold": False,
                        "success": False
                    })
                
                await asyncio.sleep(0.1)
            
            # Analyze domain results
            successful_responses = [r for r in domain_results if r["success"]]
            threshold_meeting_responses = [r for r in domain_results if r["meets_threshold"]]
            
            avg_semantic_quality = statistics.mean([r["semantic_quality"] for r in successful_responses]) if successful_responses else 0
            avg_concept_coverage = statistics.mean([r["concept_coverage"] for r in successful_responses]) if successful_responses else 0
            avg_coherence = statistics.mean([r["coherence_score"] for r in successful_responses]) if successful_responses else 0
            
            semantic_validation_results.append({
                "domain": test_case["domain"],
                "total_prompts": len(test_case["prompts"]),
                "successful_responses": len(successful_responses),
                "threshold_meeting_responses": len(threshold_meeting_responses),
                "avg_semantic_quality": avg_semantic_quality,
                "avg_concept_coverage": avg_concept_coverage,
                "avg_coherence": avg_coherence,
                "coherence_threshold": test_case["coherence_threshold"],
                "domain_validation_score": len(threshold_meeting_responses) / len(test_case["prompts"]) if test_case["prompts"] else 0
            })
            
            logger.info(f"Domain {test_case['domain']}: "
                       f"Success: {len(successful_responses)}/{len(test_case['prompts'])}, "
                       f"Semantic quality: {avg_semantic_quality:.3f}, "
                       f"Threshold met: {len(threshold_meeting_responses)}/{len(test_case['prompts'])}")
        
        # Verify semantic validation effectiveness
        high_quality_domains = [r for r in semantic_validation_results if r["avg_semantic_quality"] >= 0.7]
        threshold_meeting_domains = [r for r in semantic_validation_results if r["domain_validation_score"] >= 0.8]
        
        assert len(high_quality_domains) >= len(semantic_test_cases) * 0.6, \
            f"Most domains should show high semantic quality, got {len(high_quality_domains)}/{len(semantic_test_cases)}"
        
        assert len(threshold_meeting_domains) >= len(semantic_test_cases) * 0.6, \
            f"Most domains should meet coherence thresholds, got {len(threshold_meeting_domains)}/{len(semantic_test_cases)}"
    
    def _calculate_concept_coverage(self, content: str, expected_concepts: List[str]) -> float:
        """Calculate how well the response covers expected concepts"""
        content_lower = content.lower()
        covered_concepts = sum(1 for concept in expected_concepts if concept.lower() in content_lower)
        return covered_concepts / len(expected_concepts) if expected_concepts else 0
    
    def _calculate_coherence_score(self, content: str) -> float:
        """Calculate coherence score based on structure and flow"""
        sentences = [s.strip() for s in content.split('.') if s.strip()]
        
        if len(sentences) < 2:
            return 0.5  # Single sentence gets neutral score
        
        # Check for logical connectors
        connectors = ["because", "therefore", "however", "additionally", "furthermore", "moreover", "consequently"]
        connector_count = sum(1 for connector in connectors if connector in content.lower())
        
        # Check sentence length variation (good coherence has varied sentence lengths)
        sentence_lengths = [len(s.split()) for s in sentences]
        length_variation = statistics.stdev(sentence_lengths) if len(sentence_lengths) > 1 else 0
        
        # Base coherence score
        coherence = 0.6  # Base score
        
        # Add points for connectors
        coherence += min(0.2, connector_count * 0.05)
        
        # Add points for good sentence variation
        coherence += min(0.2, length_variation * 0.02)
        
        return min(1.0, coherence)
    
    def _calculate_domain_relevance(self, content: str, domain: str) -> float:
        """Calculate domain relevance score"""
        domain_keywords = {
            "scientific": ["research", "study", "experiment", "hypothesis", "data", "analysis", "theory", "evidence"],
            "mathematical": ["equation", "formula", "calculate", "solve", "proof", "theorem", "function", "variable"],
            "literary": ["author", "character", "theme", "plot", "narrative", "style", "meaning", "interpretation"]
        }
        
        if domain not in domain_keywords:
            return 0.5  # Neutral score for unknown domains
        
        keywords = domain_keywords[domain]
        content_lower = content.lower()
        
        keyword_matches = sum(1 for keyword in keywords if keyword in content_lower)
        relevance_score = keyword_matches / len(keywords)
        
        return min(1.0, relevance_score)
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_llm_token_aware_generation_016(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """TDM_LLM_TOKEN_AWARE_GENERATION_016: Dynamic token-aware test data generation with ±5 token accuracy"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test token-aware generation with precise token targeting
        token_targets = [
            {"target_tokens": 25, "tolerance": 5, "prompt_type": "brief_explanation"},
            {"target_tokens": 50, "tolerance": 5, "prompt_type": "medium_explanation"},
            {"target_tokens": 75, "tolerance": 5, "prompt_type": "detailed_explanation"},
            {"target_tokens": 100, "tolerance": 5, "prompt_type": "comprehensive_explanation"}
        ]
        
        token_accuracy_results = []
        
        for target_config in token_targets:
            target_results = []
            
            logger.info(f"Testing token-aware generation for {target_config['target_tokens']} tokens")
            
            # Generate test prompts for this token target
            test_prompts = [
                f"Provide a {target_config['prompt_type'].replace('_', ' ')} of artificial intelligence",
                f"Give a {target_config['prompt_type'].replace('_', ' ')} of machine learning",
                f"Explain quantum computing with a {target_config['prompt_type'].replace('_', ' ')}"
            ]
            
            for prompt in test_prompts:
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": target_config["target_tokens"]
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    content = response_data["choices"][0]["message"]["content"]
                    
                    # Calculate actual token count (approximate)
                    actual_tokens = len(content.split())  # Word-based approximation
                    if "usage" in response_data:
                        actual_tokens = response_data["usage"]["completion_tokens"]
                    
                    # Calculate token accuracy
                    token_difference = abs(actual_tokens - target_config["target_tokens"])
                    within_tolerance = token_difference <= target_config["tolerance"]
                    token_accuracy = max(0, 1 - (token_difference / target_config["target_tokens"]))
                    
                    # Calculate efficiency (content quality per token)
                    content_quality = len(set(content.lower().split())) / len(content.split()) if content.split() else 0  # Unique word ratio
                    token_efficiency = content_quality * (actual_tokens / target_config["target_tokens"]) if target_config["target_tokens"] > 0 else 0
                    
                    target_results.append({
                        "prompt": prompt,
                        "response": content,
                        "target_tokens": target_config["target_tokens"],
                        "actual_tokens": actual_tokens,
                        "token_difference": token_difference,
                        "within_tolerance": within_tolerance,
                        "token_accuracy": token_accuracy,
                        "token_efficiency": token_efficiency,
                        "content_quality": content_quality,
                        "success": True
                    })
                else:
                    target_results.append({
                        "prompt": prompt,
                        "target_tokens": target_config["target_tokens"],
                        "actual_tokens": 0,
                        "within_tolerance": False,
                        "token_accuracy": 0.0,
                        "token_efficiency": 0.0,
                        "success": False
                    })
                
                await asyncio.sleep(0.1)
            
            # Analyze target results
            successful_responses = [r for r in target_results if r["success"]]
            within_tolerance_responses = [r for r in target_results if r["within_tolerance"]]
            
            avg_token_accuracy = statistics.mean([r["token_accuracy"] for r in successful_responses]) if successful_responses else 0
            avg_token_efficiency = statistics.mean([r["token_efficiency"] for r in successful_responses]) if successful_responses else 0
            avg_token_difference = statistics.mean([r["token_difference"] for r in successful_responses]) if successful_responses else float('inf')
            
            token_accuracy_results.append({
                "target_tokens": target_config["target_tokens"],
                "tolerance": target_config["tolerance"],
                "prompt_type": target_config["prompt_type"],
                "total_prompts": len(test_prompts),
                "successful_responses": len(successful_responses),
                "within_tolerance_responses": len(within_tolerance_responses),
                "avg_token_accuracy": avg_token_accuracy,
                "avg_token_efficiency": avg_token_efficiency,
                "avg_token_difference": avg_token_difference,
                "tolerance_success_rate": len(within_tolerance_responses) / len(test_prompts) if test_prompts else 0,
                "meets_accuracy_target": avg_token_difference <= target_config["tolerance"]
            })
            
            logger.info(f"Token target {target_config['target_tokens']}: "
                       f"Success: {len(successful_responses)}/{len(test_prompts)}, "
                       f"Within tolerance: {len(within_tolerance_responses)}/{len(test_prompts)}, "
                       f"Avg difference: ±{avg_token_difference:.1f} tokens, "
                       f"Accuracy: {avg_token_accuracy:.3f}")
        
        # Verify token-aware generation accuracy
        accurate_targets = [r for r in token_accuracy_results if r["meets_accuracy_target"]]
        high_tolerance_targets = [r for r in token_accuracy_results if r["tolerance_success_rate"] >= 0.7]
        efficient_targets = [r for r in token_accuracy_results if r["avg_token_efficiency"] >= 0.6]
        
        assert len(accurate_targets) >= len(token_targets) * 0.7, \
            f"Most token targets should meet accuracy requirements, got {len(accurate_targets)}/{len(token_targets)}"
        
        assert len(high_tolerance_targets) >= len(token_targets) * 0.8, \
            f"Most targets should have high tolerance success rates, got {len(high_tolerance_targets)}/{len(token_targets)}"
        
        assert len(efficient_targets) >= len(token_targets) * 0.6, \
            f"Most targets should show good token efficiency, got {len(efficient_targets)}/{len(token_targets)}"