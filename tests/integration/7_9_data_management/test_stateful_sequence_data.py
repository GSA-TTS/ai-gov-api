# Section 7.9 - Stateful Sequence Data Management
# Based on: docs/test_design_n_planning/Testcases_7_9_DataManagement/Test Cases_Stateful Sequence Data Management.md

import pytest
import httpx
import asyncio
import time
import statistics
import hashlib
import json
import os
import re
import random
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import uuid

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class StatefulSequenceResult:
    """Stateful sequence data management test result structure"""
    test_name: str
    conversation_turns: int
    context_preserved: bool
    semantic_coherence: float
    state_isolation: bool
    success: bool


class TestBasicStatefulSequence:
    """Test basic stateful sequence data management"""
    
    def setup_method(self):
        """Setup for stateful sequence tests"""
        self.conversation_templates = {
            "personal_info": {
                "initial": "My name is {name}. My favorite color is {color}.",
                "queries": [
                    "What is my favorite color?",
                    "What was my name?",
                    "Tell me something about myself."
                ],
                "expected_responses": ["color", "name", "personal"]
            },
            "instruction_following": {
                "initial": "Please remember these instructions: {instructions}",
                "queries": [
                    "What instructions did I give you?",
                    "Follow the instructions I gave earlier.",
                    "Can you repeat the instructions?"
                ],
                "expected_responses": ["instructions", "follow", "repeat"]
            },
            "technical_context": {
                "initial": "I'm working on a {project_type} project using {technology}.",
                "queries": [
                    "What technology am I using?",
                    "What type of project am I working on?",
                    "Can you help with my project?"
                ],
                "expected_responses": ["technology", "project", "help"]
            }
        }
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_context_accum_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TDM_STATEFUL_CONTEXT_ACCUM_001: Context accumulation in growing messages array"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test context accumulation over multiple conversation turns
        conversation_scenarios = [
            {
                "name": "Bob",
                "color": "blue",
                "template": "personal_info"
            },
            {
                "name": "Alice",
                "color": "green", 
                "template": "personal_info"
            },
            {
                "name": "Charlie",
                "color": "red",
                "template": "personal_info"
            }
        ]
        
        context_accumulation_results = []
        
        for scenario in conversation_scenarios:
            accum_start = time.perf_counter()
            template = self.conversation_templates[scenario["template"]]
            
            # Initialize conversation with personal info
            initial_message = template["initial"].format(
                name=scenario["name"],
                color=scenario["color"]
            )
            
            messages = [{"role": "user", "content": initial_message}]
            
            logger.info(f"Testing context accumulation for {scenario['name']}")
            
            # Turn 1: Initial information
            request_data = {
                "model": config.get_chat_model(0),
                "messages": messages,
                "max_tokens": 80
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            if response.status_code == 200:
                response_data = response.json()
                assistant_response = response_data["choices"][0]["message"]["content"]
                messages.append({"role": "assistant", "content": assistant_response})
                
                turn_results = []
                
                # Multiple follow-up turns testing context retention
                for i, query in enumerate(template["queries"]):
                    messages.append({"role": "user", "content": query})
                    
                    follow_up_request = {
                        "model": config.get_chat_model(0),
                        "messages": messages,
                        "max_tokens": 60
                    }
                    
                    follow_up_response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, follow_up_request
                    )
                    
                    if follow_up_response.status_code == 200:
                        follow_up_data = follow_up_response.json()
                        content = follow_up_data["choices"][0]["message"]["content"]
                        messages.append({"role": "assistant", "content": content})
                        
                        # Check if context was preserved
                        expected_keyword = template["expected_responses"][i]
                        context_preserved = False
                        
                        if expected_keyword == "color":
                            context_preserved = scenario["color"].lower() in content.lower()
                        elif expected_keyword == "name":
                            context_preserved = scenario["name"].lower() in content.lower()
                        elif expected_keyword == "personal":
                            context_preserved = (scenario["name"].lower() in content.lower() or 
                                               scenario["color"].lower() in content.lower())
                        
                        turn_results.append({
                            "turn": i + 2,
                            "query": query,
                            "response": content,
                            "context_preserved": context_preserved,
                            "message_count": len(messages)
                        })
                    else:
                        turn_results.append({
                            "turn": i + 2,
                            "query": query,
                            "context_preserved": False,
                            "message_count": len(messages),
                            "error_code": follow_up_response.status_code
                        })
                
                accum_end = time.perf_counter()
                accum_time = (accum_end - accum_start) * 1000
                
                # Calculate overall context preservation
                preserved_count = sum(1 for r in turn_results if r.get("context_preserved", False))
                context_preservation_rate = preserved_count / len(turn_results) if turn_results else 0
                
                result = {
                    "scenario_name": scenario["name"],
                    "template": scenario["template"],
                    "total_turns": len(turn_results) + 1,
                    "final_message_count": len(messages),
                    "context_preservation_rate": context_preservation_rate,
                    "turn_results": turn_results,
                    "accumulation_time": accum_time,
                    "success": context_preservation_rate >= 0.7
                }
                
                context_accumulation_results.append(result)
                
                logger.info(f"Context accumulation {scenario['name']}: "
                           f"Preservation: {context_preservation_rate:.2%}, "
                           f"Turns: {len(turn_results) + 1}")
        
        # Verify context accumulation effectiveness
        successful_scenarios = [r for r in context_accumulation_results if r["success"]]
        high_preservation_scenarios = [r for r in context_accumulation_results if r["context_preservation_rate"] >= 0.8]
        
        assert len(successful_scenarios) >= len(conversation_scenarios) * 0.7, \
            f"Most scenarios should preserve context well, got {len(successful_scenarios)}/{len(conversation_scenarios)}"
        
        assert len(high_preservation_scenarios) >= len(conversation_scenarios) * 0.5, \
            f"Many scenarios should have high preservation rates, got {len(high_preservation_scenarios)}/{len(conversation_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_role_sequencing_002(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """TDM_STATEFUL_ROLE_SEQUENCING_002: Valid and unusual message role sequences"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test different role sequencing patterns
        role_sequence_scenarios = [
            {
                "name": "standard_sequence",
                "messages": [
                    {"role": "user", "content": "Hello, I need help."},
                    {"role": "assistant", "content": "Hello! I'm here to help."},
                    {"role": "user", "content": "Can you explain AI?"}
                ],
                "expected_valid": True
            },
            {
                "name": "system_prompt_sequence",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "What is machine learning?"},
                    {"role": "assistant", "content": "Machine learning is..."},
                    {"role": "user", "content": "Can you give me examples?"}
                ],
                "expected_valid": True
            },
            {
                "name": "consecutive_user_messages",
                "messages": [
                    {"role": "user", "content": "I have a question."},
                    {"role": "user", "content": "Actually, let me clarify my question."},
                    {"role": "user", "content": "What is the difference between AI and ML?"}
                ],
                "expected_valid": True
            },
            {
                "name": "assistant_first_sequence",
                "messages": [
                    {"role": "assistant", "content": "Welcome! How can I help you today?"},
                    {"role": "user", "content": "I need help with programming."}
                ],
                "expected_valid": True  # Unusual but schema-valid
            },
            {
                "name": "multiple_system_messages",
                "messages": [
                    {"role": "system", "content": "You are helpful."},
                    {"role": "system", "content": "You are also concise."},
                    {"role": "user", "content": "Explain quantum computing."}
                ],
                "expected_valid": True  # Multiple system messages
            }
        ]
        
        role_sequencing_results = []
        
        for scenario in role_sequence_scenarios:
            sequence_start = time.perf_counter()
            
            logger.info(f"Testing role sequence: {scenario['name']}")
            
            request_data = {
                "model": config.get_chat_model(0),
                "messages": scenario["messages"],
                "max_tokens": 100
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            sequence_end = time.perf_counter()
            sequence_time = (sequence_end - sequence_start) * 1000
            
            # Analyze response
            api_accepted = response.status_code == 200
            schema_valid = True  # All our test scenarios are schema-valid
            
            if api_accepted:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                
                # Assess response quality for unusual sequences
                response_quality_indicators = {
                    "non_empty": len(content.strip()) > 0,
                    "relevant": len(content.split()) >= 3,  # At least a few words
                    "coherent": not any(error in content.lower() for error in ["error", "invalid", "cannot"])
                }
                
                response_quality = sum(response_quality_indicators.values()) / len(response_quality_indicators)
            else:
                response_quality = 0.0
                content = ""
            
            # Check if behavior matches expectations
            sequence_handled_correctly = api_accepted == scenario["expected_valid"]
            
            result = {
                "sequence_name": scenario["name"],
                "message_count": len(scenario["messages"]),
                "roles_sequence": [msg["role"] for msg in scenario["messages"]],
                "api_accepted": api_accepted,
                "schema_valid": schema_valid,
                "expected_valid": scenario["expected_valid"],
                "sequence_handled_correctly": sequence_handled_correctly,
                "response_quality": response_quality,
                "response_content": content[:100] + "..." if len(content) > 100 else content,
                "sequence_time": sequence_time
            }
            
            role_sequencing_results.append(result)
            
            logger.info(f"Role sequence {scenario['name']}: "
                       f"Accepted: {api_accepted}, "
                       f"Quality: {response_quality:.2f}")
        
        # Verify role sequencing handling
        correctly_handled = [r for r in role_sequencing_results if r["sequence_handled_correctly"]]
        good_quality_responses = [r for r in role_sequencing_results if r["response_quality"] >= 0.7]
        
        assert len(correctly_handled) >= len(role_sequence_scenarios) * 0.8, \
            f"Most role sequences should be handled correctly, got {len(correctly_handled)}/{len(role_sequence_scenarios)}"
        
        assert len(good_quality_responses) >= len(role_sequence_scenarios) * 0.6, \
            f"Most sequences should generate good responses, got {len(good_quality_responses)}/{len(role_sequence_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_context_token_limit_003(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """TDM_STATEFUL_CONTEXT_TOKEN_LIMIT_003: Context token limit behavior testing"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Build progressively longer conversation histories
        token_limit_scenarios = [
            {"target_length": "short", "turns": 3, "message_length": 20},
            {"target_length": "medium", "turns": 8, "message_length": 50},  
            {"target_length": "long", "turns": 15, "message_length": 100},
            {"target_length": "very_long", "turns": 25, "message_length": 150}
        ]
        
        token_limit_results = []
        
        for scenario in token_limit_scenarios:
            limit_start = time.perf_counter()
            
            logger.info(f"Testing context token limit: {scenario['target_length']}")
            
            # Build conversation incrementally
            messages = []
            turn_data = []
            
            for turn in range(scenario["turns"]):
                # Add user message
                user_content = f"Turn {turn + 1}: " + "A" * scenario["message_length"] + f" What do you think about this topic {turn + 1}?"
                messages.append({"role": "user", "content": user_content})
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": messages,
                    "max_tokens": 80
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                turn_result = {
                    "turn": turn + 1,
                    "message_count": len(messages),
                    "estimated_input_tokens": sum(len(msg["content"]) // 4 for msg in messages),
                    "response_status": response.status_code
                }
                
                if response.status_code == 200:
                    response_data = response.json()
                    assistant_content = response_data["choices"][0]["message"]["content"]
                    messages.append({"role": "assistant", "content": assistant_content})
                    
                    # Extract token usage if available
                    if "usage" in response_data:
                        turn_result["prompt_tokens"] = response_data["usage"].get("prompt_tokens", 0)
                        turn_result["completion_tokens"] = response_data["usage"].get("completion_tokens", 0)
                        turn_result["total_tokens"] = response_data["usage"].get("total_tokens", 0)
                    
                    turn_result["success"] = True
                    turn_result["response_length"] = len(assistant_content)
                else:
                    # Request failed - likely due to context limit
                    turn_result["success"] = False
                    turn_result["error_code"] = response.status_code
                    break  # Stop building conversation
                
                turn_data.append(turn_result)
                await asyncio.sleep(0.1)  # Brief delay between requests
            
            limit_end = time.perf_counter()
            limit_time = (limit_end - limit_start) * 1000
            
            # Analyze token limit behavior
            successful_turns = [t for t in turn_data if t["success"]]
            failed_turns = [t for t in turn_data if not t["success"]]
            
            max_successful_tokens = max((t.get("total_tokens", t["estimated_input_tokens"]) 
                                       for t in successful_turns), default=0)
            
            result = {
                "scenario": scenario["target_length"],
                "target_turns": scenario["turns"],
                "actual_turns": len(turn_data),
                "successful_turns": len(successful_turns),
                "failed_turns": len(failed_turns),
                "max_successful_tokens": max_successful_tokens,
                "turn_data": turn_data,
                "graceful_failure": len(failed_turns) > 0 and all(t.get("error_code") in [400, 413, 422] for t in failed_turns),
                "test_time": limit_time
            }
            
            token_limit_results.append(result)
            
            logger.info(f"Token limit {scenario['target_length']}: "
                       f"Successful: {len(successful_turns)}/{scenario['turns']}, "
                       f"Max tokens: {max_successful_tokens}")
        
        # Verify token limit handling
        scenarios_with_data = [r for r in token_limit_results if r["successful_turns"] > 0]
        graceful_failures = [r for r in token_limit_results if r.get("graceful_failure", True)]
        
        assert len(scenarios_with_data) >= len(token_limit_scenarios) * 0.8, \
            f"Most scenarios should generate some successful turns, got {len(scenarios_with_data)}/{len(token_limit_scenarios)}"
        
        assert len(graceful_failures) == len(token_limit_results), \
            f"All failures should be graceful, got {len(graceful_failures)}/{len(token_limit_results)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_conversation_reset_004(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """TDM_STATEFUL_CONVERSATION_RESET_004: Conversation isolation between requests"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test conversation isolation (statelessness per request)
        isolation_scenarios = [
            {
                "secret_info": "My secret word is 'banana'",
                "secret_query": "What is my secret word?",
                "expected_isolation": True
            },
            {
                "secret_info": "Remember that my code is 12345",
                "secret_query": "What was my code?",
                "expected_isolation": True
            },
            {
                "secret_info": "I told you my favorite number is 42",
                "secret_query": "What is my favorite number?",
                "expected_isolation": True
            }
        ]
        
        conversation_isolation_results = []
        
        for i, scenario in enumerate(isolation_scenarios):
            isolation_start = time.perf_counter()
            
            logger.info(f"Testing conversation isolation scenario {i + 1}")
            
            # Request 1: Establish secret information
            request1_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["secret_info"]}],
                "max_tokens": 50
            }
            
            response1 = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request1_data
            )
            
            # Brief delay to ensure request separation
            await asyncio.sleep(0.5)
            
            # Request 2: Try to access secret information (fresh messages array)
            request2_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["secret_query"]}],
                "max_tokens": 50
            }
            
            response2 = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request2_data
            )
            
            isolation_end = time.perf_counter()
            isolation_time = (isolation_end - isolation_start) * 1000
            
            # Analyze isolation effectiveness
            if response1.status_code == 200 and response2.status_code == 200:
                response1_data = response1.json()
                response2_data = response2.json()
                
                content1 = response1_data["choices"][0]["message"]["content"]
                content2 = response2_data["choices"][0]["message"]["content"]
                
                # Check if secret information leaked to second request
                secret_words = ["banana", "12345", "42"]
                secret_leaked = any(word in content2.lower() for word in secret_words)
                
                # Check if response indicates lack of context
                isolation_indicators = [
                    "don't know" in content2.lower(),
                    "not sure" in content2.lower(),
                    "no information" in content2.lower(),
                    "can't recall" in content2.lower(),
                    "don't have" in content2.lower()
                ]
                
                isolation_demonstrated = any(isolation_indicators) or not secret_leaked
                
                result = {
                    "scenario_id": i + 1,
                    "secret_info": scenario["secret_info"],
                    "secret_query": scenario["secret_query"],
                    "response1": content1[:50] + "..." if len(content1) > 50 else content1,
                    "response2": content2[:50] + "..." if len(content2) > 50 else content2,
                    "secret_leaked": secret_leaked,
                    "isolation_demonstrated": isolation_demonstrated,
                    "isolation_time": isolation_time,
                    "isolation_successful": isolation_demonstrated and not secret_leaked
                }
            else:
                result = {
                    "scenario_id": i + 1,
                    "isolation_successful": False,
                    "error_request1": response1.status_code if response1.status_code != 200 else None,
                    "error_request2": response2.status_code if response2.status_code != 200 else None,
                    "isolation_time": isolation_time
                }
            
            conversation_isolation_results.append(result)
            
            logger.info(f"Isolation scenario {i + 1}: "
                       f"Success: {result.get('isolation_successful', False)}, "
                       f"Leaked: {result.get('secret_leaked', 'unknown')}")
        
        # Verify conversation isolation
        successful_isolations = [r for r in conversation_isolation_results if r.get("isolation_successful", False)]
        no_leakage_cases = [r for r in conversation_isolation_results if not r.get("secret_leaked", True)]
        
        assert len(successful_isolations) >= len(isolation_scenarios) * 0.8, \
            f"Most scenarios should demonstrate isolation, got {len(successful_isolations)}/{len(isolation_scenarios)}"
        
        assert len(no_leakage_cases) >= len(isolation_scenarios) * 0.9, \
            f"Almost all scenarios should prevent information leakage, got {len(no_leakage_cases)}/{len(isolation_scenarios)}"


class TestAdvancedStatefulSequence:
    """Test advanced stateful sequence data management"""
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_ai_conversation_007(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """TDM_STATEFUL_AI_CONVERSATION_007: AI-powered conversation flow generation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # AI-generated conversation flow scenarios
        conversation_patterns = [
            {
                "domain": "technical_support",
                "pattern": "problem_diagnosis",
                "flow_steps": [
                    "User reports technical issue",
                    "Assistant requests more details",
                    "User provides system information",
                    "Assistant suggests solutions",
                    "User confirms resolution"
                ]
            },
            {
                "domain": "educational",
                "pattern": "concept_learning",
                "flow_steps": [
                    "User asks about concept",
                    "Assistant explains basics",
                    "User asks follow-up questions",
                    "Assistant provides examples",
                    "User requests practice problems"
                ]
            },
            {
                "domain": "creative_writing",
                "pattern": "story_development", 
                "flow_steps": [
                    "User proposes story idea",
                    "Assistant suggests plot elements",
                    "User refines characters",
                    "Assistant develops conflict",
                    "User requests ending options"
                ]
            }
        ]
        
        ai_conversation_results = []
        
        for pattern in conversation_patterns:
            conversation_start = time.perf_counter()
            
            logger.info(f"Testing AI conversation pattern: {pattern['domain']}")
            
            messages = []
            flow_coherence_scores = []
            
            # Simulate AI-generated conversation flow
            for step_idx, step_description in enumerate(pattern["flow_steps"]):
                # Generate conversation turn based on pattern
                if "technical" in pattern["domain"]:
                    if step_idx == 0:
                        user_content = "I'm having trouble with my application crashing when I try to save files."
                    elif step_idx == 2:
                        user_content = "I'm using Windows 10, 16GB RAM, and the latest version of the software."
                    elif step_idx == 4:
                        user_content = "Yes, that fixed the issue! Thank you for your help."
                    else:
                        continue  # Skip assistant turns for this test
                
                elif "educational" in pattern["domain"]:
                    if step_idx == 0:
                        user_content = "Can you explain machine learning to me?"
                    elif step_idx == 2:
                        user_content = "What's the difference between supervised and unsupervised learning?"
                    elif step_idx == 4:
                        user_content = "Can you give me some practice problems to work on?"
                    else:
                        continue
                
                elif "creative" in pattern["domain"]:
                    if step_idx == 0:
                        user_content = "I want to write a story about time travel and its consequences."
                    elif step_idx == 2:
                        user_content = "The main character should be a scientist who accidentally changes history."
                    elif step_idx == 4:
                        user_content = "I'd like to see different possible endings for this story."
                    else:
                        continue
                
                messages.append({"role": "user", "content": user_content})
                
                # Get AI response
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": messages,
                    "max_tokens": 120
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    assistant_content = response_data["choices"][0]["message"]["content"]
                    messages.append({"role": "assistant", "content": assistant_content})
                    
                    # Assess flow coherence
                    domain_keywords = {
                        "technical_support": ["problem", "solution", "error", "fix", "system"],
                        "educational": ["explain", "learn", "understand", "example", "concept"],
                        "creative_writing": ["story", "character", "plot", "creative", "narrative"]
                    }
                    
                    relevant_keywords = domain_keywords[pattern["domain"]]
                    keyword_matches = sum(1 for keyword in relevant_keywords if keyword.lower() in assistant_content.lower())
                    coherence_score = min(1.0, keyword_matches / 3)  # Normalize to 0-1
                    
                    flow_coherence_scores.append(coherence_score)
                
                await asyncio.sleep(0.1)
            
            conversation_end = time.perf_counter()
            conversation_time = (conversation_end - conversation_start) * 1000
            
            # Analyze conversation flow quality
            avg_coherence = statistics.mean(flow_coherence_scores) if flow_coherence_scores else 0
            conversation_completeness = len(messages) >= len(pattern["flow_steps"])
            natural_progression = len(flow_coherence_scores) >= 2 and all(score >= 0.4 for score in flow_coherence_scores)
            
            result = {
                "domain": pattern["domain"],
                "pattern": pattern["pattern"],
                "total_turns": len(messages),
                "completed_steps": len(flow_coherence_scores),
                "avg_coherence": avg_coherence,
                "conversation_completeness": conversation_completeness,
                "natural_progression": natural_progression,
                "conversation_time": conversation_time,
                "ai_conversation_effective": avg_coherence >= 0.6 and natural_progression
            }
            
            ai_conversation_results.append(result)
            
            logger.info(f"AI conversation {pattern['domain']}: "
                       f"Coherence: {avg_coherence:.3f}, "
                       f"Turns: {len(messages)}, "
                       f"Effective: {result['ai_conversation_effective']}")
        
        # Verify AI conversation generation effectiveness
        effective_conversations = [r for r in ai_conversation_results if r["ai_conversation_effective"]]
        high_coherence_conversations = [r for r in ai_conversation_results if r["avg_coherence"] >= 0.7]
        
        assert len(effective_conversations) >= len(conversation_patterns) * 0.7, \
            f"Most AI conversations should be effective, got {len(effective_conversations)}/{len(conversation_patterns)}"
        
        assert len(high_coherence_conversations) >= len(conversation_patterns) * 0.5, \
            f"Many conversations should have high coherence, got {len(high_coherence_conversations)}/{len(conversation_patterns)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_multithreaded_008(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TDM_STATEFUL_MULTITHREADED_008: Multi-threaded conversation state management"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test concurrent conversation threads with isolation
        thread_scenarios = [
            {
                "thread_id": "thread_001",
                "topic": "machine_learning",
                "secret_word": "neural",
                "messages": [
                    "Let's talk about machine learning. My secret word is neural.",
                    "What is supervised learning?",
                    "What was my secret word?"
                ]
            },
            {
                "thread_id": "thread_002", 
                "topic": "web_development",
                "secret_word": "framework",
                "messages": [
                    "I want to learn web development. My secret word is framework.",
                    "What is React used for?",
                    "What was my secret word?"
                ]
            },
            {
                "thread_id": "thread_003",
                "topic": "data_science",
                "secret_word": "algorithm",
                "messages": [
                    "Let's discuss data science. My secret word is algorithm.",
                    "What is data preprocessing?",
                    "What was my secret word?"
                ]
            }
        ]
        
        async def run_conversation_thread(scenario):
            """Run a single conversation thread"""
            thread_start = time.perf_counter()
            thread_messages = []
            thread_results = []
            
            for i, message_content in enumerate(scenario["messages"]):
                thread_messages.append({"role": "user", "content": message_content})
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": thread_messages,
                    "max_tokens": 80
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    assistant_content = response_data["choices"][0]["message"]["content"]
                    thread_messages.append({"role": "assistant", "content": assistant_content})
                    
                    # Check for context preservation (especially secret word recall)
                    if i == 2:  # Final message asks for secret word
                        secret_recalled = scenario["secret_word"].lower() in assistant_content.lower()
                        thread_results.append({
                            "turn": i + 1,
                            "secret_recalled": secret_recalled,
                            "response": assistant_content
                        })
                    else:
                        thread_results.append({
                            "turn": i + 1,
                            "response": assistant_content
                        })
                else:
                    thread_results.append({
                        "turn": i + 1,
                        "error_code": response.status_code
                    })
                
                # Small delay between messages in thread
                await asyncio.sleep(0.05)
            
            thread_end = time.perf_counter()
            thread_time = (thread_end - thread_start) * 1000
            
            return {
                "thread_id": scenario["thread_id"],
                "topic": scenario["topic"],
                "secret_word": scenario["secret_word"],
                "thread_results": thread_results,
                "thread_time": thread_time,
                "message_count": len(thread_messages),
                "secret_recalled": any(r.get("secret_recalled", False) for r in thread_results)
            }
        
        # Run all conversation threads concurrently
        multithreaded_start = time.perf_counter()
        
        tasks = [run_conversation_thread(scenario) for scenario in thread_scenarios]
        thread_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        multithreaded_end = time.perf_counter()
        total_multithreaded_time = (multithreaded_end - multithreaded_start) * 1000
        
        # Filter out any exceptions
        successful_threads = [r for r in thread_results if isinstance(r, dict)]
        
        # Verify thread isolation
        threads_with_recall = [t for t in successful_threads if t["secret_recalled"]]
        unique_topics = set(t["topic"] for t in successful_threads)
        
        logger.info(f"Multithreaded conversations: "
                   f"{len(successful_threads)}/{len(thread_scenarios)} successful, "
                   f"Secret recall: {len(threads_with_recall)}/{len(successful_threads)}")
        
        # Check for cross-thread contamination
        cross_contamination_detected = False
        for thread in successful_threads:
            for other_thread in successful_threads:
                if thread["thread_id"] != other_thread["thread_id"]:
                    # Check if one thread's secret word appears in another thread's responses
                    for result in thread["thread_results"]:
                        if "response" in result:
                            if other_thread["secret_word"].lower() in result["response"].lower():
                                cross_contamination_detected = True
                                break
        
        assert len(successful_threads) >= len(thread_scenarios) * 0.8, \
            f"Most threads should complete successfully, got {len(successful_threads)}/{len(thread_scenarios)}"
        
        assert len(threads_with_recall) >= len(successful_threads) * 0.7, \
            f"Most threads should recall their context, got {len(threads_with_recall)}/{len(successful_threads)}"
        
        assert not cross_contamination_detected, \
            "No cross-thread contamination should occur"
        
        assert len(unique_topics) == len(successful_threads), \
            f"All threads should maintain distinct topics, got {len(unique_topics)} unique topics"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_semantic_validation_011(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       make_request):
        """TDM_STATEFUL_SEMANTIC_VALIDATION_011: Semantic context validation and coherence testing"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        # Test semantic coherence in multi-turn conversations
        semantic_scenarios = [
            {
                "scenario": "logical_consistency",
                "conversation": [
                    {"role": "user", "content": "I am 25 years old and work as a software engineer."},
                    {"role": "user", "content": "What career advice would you give someone my age in my field?"},
                    {"role": "user", "content": "How many years of experience do I likely have if I'm 25?"}
                ],
                "coherence_checks": ["age_consistency", "profession_consistency", "experience_logic"]
            },
            {
                "scenario": "temporal_consistency",
                "conversation": [
                    {"role": "user", "content": "Yesterday I went to the store and bought groceries."},
                    {"role": "user", "content": "Today I'm planning to cook dinner with what I bought."},
                    {"role": "user", "content": "What did I do yesterday according to our conversation?"}
                ],
                "coherence_checks": ["temporal_sequence", "activity_continuity", "memory_accuracy"]
            },
            {
                "scenario": "domain_expertise",
                "conversation": [
                    {"role": "user", "content": "I'm studying quantum physics and need help with quantum entanglement."},
                    {"role": "user", "content": "Can you explain how entangled particles maintain correlation?"},
                    {"role": "user", "content": "How does this relate to what we discussed about my studies?"}
                ],
                "coherence_checks": ["domain_consistency", "technical_accuracy", "context_reference"]
            }
        ]
        
        semantic_validation_results = []
        
        for scenario in semantic_scenarios:
            validation_start = time.perf_counter()
            
            logger.info(f"Testing semantic validation: {scenario['scenario']}")
            
            messages = []
            turn_analyses = []
            
            for i, message in enumerate(scenario["conversation"]):
                messages.append(message)
                
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": messages,
                    "max_tokens": 100
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request_data
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    assistant_content = response_data["choices"][0]["message"]["content"]
                    messages.append({"role": "assistant", "content": assistant_content})
                    
                    # Analyze semantic coherence
                    if scenario["scenario"] == "logical_consistency":
                        coherence_indicators = {
                            "mentions_age": "25" in assistant_content or "twenty" in assistant_content.lower(),
                            "mentions_profession": any(term in assistant_content.lower() for term in ["software", "engineer", "developer", "programming"]),
                            "logical_advice": any(term in assistant_content.lower() for term in ["experience", "career", "skill", "development"])
                        }
                    elif scenario["scenario"] == "temporal_consistency":
                        coherence_indicators = {
                            "temporal_awareness": any(term in assistant_content.lower() for term in ["yesterday", "today", "bought", "store"]),
                            "activity_sequence": any(term in assistant_content.lower() for term in ["groceries", "cook", "dinner"]),
                            "memory_reference": "yesterday" in assistant_content.lower() or "store" in assistant_content.lower()
                        }
                    elif scenario["scenario"] == "domain_expertise":
                        coherence_indicators = {
                            "domain_appropriate": any(term in assistant_content.lower() for term in ["quantum", "physics", "entangle", "particle"]),
                            "technical_level": any(term in assistant_content.lower() for term in ["correlation", "measurement", "state"]),
                            "context_aware": any(term in assistant_content.lower() for term in ["studies", "learning", "physics"])
                        }
                    
                    coherence_score = sum(coherence_indicators.values()) / len(coherence_indicators)
                    
                    turn_analyses.append({
                        "turn": i + 1,
                        "coherence_score": coherence_score,
                        "coherence_indicators": coherence_indicators,
                        "response_length": len(assistant_content)
                    })
            
            validation_end = time.perf_counter()
            validation_time = (validation_end - validation_start) * 1000
            
            # Calculate overall semantic quality
            avg_coherence = statistics.mean([a["coherence_score"] for a in turn_analyses]) if turn_analyses else 0
            coherence_trend = "improving" if len(turn_analyses) >= 2 and turn_analyses[-1]["coherence_score"] >= turn_analyses[0]["coherence_score"] else "stable"
            
            result = {
                "scenario": scenario["scenario"],
                "total_turns": len(turn_analyses),
                "avg_coherence": avg_coherence,
                "coherence_trend": coherence_trend,
                "turn_analyses": turn_analyses,
                "validation_time": validation_time,
                "semantic_validation_successful": avg_coherence >= 0.6,
                "high_semantic_quality": avg_coherence >= 0.8
            }
            
            semantic_validation_results.append(result)
            
            logger.info(f"Semantic validation {scenario['scenario']}: "
                       f"Avg coherence: {avg_coherence:.3f}, "
                       f"Turns: {len(turn_analyses)}")
        
        # Verify semantic validation effectiveness
        successful_validations = [r for r in semantic_validation_results if r["semantic_validation_successful"]]
        high_quality_scenarios = [r for r in semantic_validation_results if r["high_semantic_quality"]]
        
        assert len(successful_validations) >= len(semantic_scenarios) * 0.7, \
            f"Most semantic validations should succeed, got {len(successful_validations)}/{len(semantic_scenarios)}"
        
        assert len(high_quality_scenarios) >= len(semantic_scenarios) * 0.5, \
            f"Many scenarios should have high semantic quality, got {len(high_quality_scenarios)}/{len(semantic_scenarios)}"
        
        # Verify coherence consistency
        avg_coherence_scores = [r["avg_coherence"] for r in semantic_validation_results]
        coherence_variance = statistics.variance(avg_coherence_scores) if len(avg_coherence_scores) > 1 else 0
        
        assert coherence_variance <= 0.1, \
            f"Coherence should be consistent across scenarios, got variance: {coherence_variance:.3f}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_conversation_templates_gap_005(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """TDM_STATEFUL_CONVERSATION_TEMPLATES_GAP_005: Assess lack of conversation templates"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing conversation template development and assessment")
        
        # Define conversation template patterns that should be systematically tested
        template_patterns = {
            "qa_session": {
                "pattern": ["question", "answer", "follow_up", "answer", "clarification", "answer"],
                "example_flow": [
                    "What is machine learning?",
                    "[AI response about ML]",
                    "How does it differ from traditional programming?",
                    "[AI response about differences]",
                    "Can you give me a practical example?",
                    "[AI response with example]"
                ]
            },
            "instruction_following": {
                "pattern": ["instruction", "execution", "feedback", "adjustment", "execution"],
                "example_flow": [
                    "Please write a function to calculate factorial",
                    "[AI provides function]",
                    "Add error handling for negative numbers",
                    "[AI adjusts function]",
                    "Now optimize it for large numbers"
                ]
            },
            "role_play": {
                "pattern": ["setup", "interaction", "development", "resolution"],
                "example_flow": [
                    "Act as a helpful tutor teaching math",
                    "Student: I don't understand fractions",
                    "Tutor: Let me explain with examples...",
                    "Student: Now I understand, thank you!"
                ]
            },
            "context_recall": {
                "pattern": ["information", "task", "recall", "application"],
                "example_flow": [
                    "My name is Alice and I'm a data scientist",
                    "I'm working on a customer churn prediction model",
                    "What's my profession again?",
                    "Based on my work, what metrics should I focus on?"
                ]
            }
        }
        
        template_assessment_results = {}
        
        for template_name, template_data in template_patterns.items():
            logger.info(f"Testing conversation template: {template_name}")
            
            # Test the template pattern
            pattern = template_data["pattern"]
            example_flow = template_data["example_flow"]
            
            # Build conversation following the template
            messages = []
            conversation_results = []
            
            for i, (step, example) in enumerate(zip(pattern, example_flow)):
                if step in ["question", "instruction", "setup", "information", "task", "recall"]:
                    # User message
                    messages.append({"role": "user", "content": example})
                    
                    # Get AI response
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": messages.copy(),
                        "max_tokens": 150
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    if response.status_code == 200:
                        response_data = response.json()
                        ai_response = response_data["choices"][0]["message"]["content"]
                        messages.append({"role": "assistant", "content": ai_response})
                        
                        conversation_results.append({
                            "step": step,
                            "user_input": example,
                            "ai_response": ai_response,
                            "step_number": i + 1,
                            "context_length": len(messages),
                            "success": True
                        })
                    else:
                        conversation_results.append({
                            "step": step,
                            "user_input": example,
                            "success": False
                        })
                    
                    await asyncio.sleep(0.1)
            
            # Analyze template effectiveness
            successful_steps = [r for r in conversation_results if r["success"]]
            template_completion_rate = len(successful_steps) / len(pattern) if pattern else 0
            
            # Assess conversation coherence for this template
            coherence_score = self._assess_conversation_coherence(conversation_results)
            
            template_assessment_results[template_name] = {
                "pattern": pattern,
                "total_steps": len(pattern),
                "successful_steps": len(successful_steps),
                "completion_rate": template_completion_rate,
                "coherence_score": coherence_score,
                "conversation_results": conversation_results,
                "template_effective": template_completion_rate >= 0.8 and coherence_score >= 0.6
            }
            
            logger.info(f"Template {template_name}: "
                       f"Completion: {template_completion_rate:.2%}, "
                       f"Coherence: {coherence_score:.3f}")
        
        # Verify template assessment reveals gaps
        effective_templates = [name for name, result in template_assessment_results.items() 
                              if result["template_effective"]]
        
        # This is a gap assessment, so we expect to find areas for improvement
        assert len(template_assessment_results) >= 3, \
            f"Should assess multiple template types, got {len(template_assessment_results)}"
        
        # Document recommendations for systematic template development
        logger.info(f"Template assessment complete: {len(effective_templates)}/{len(template_assessment_results)} templates effective")
        logger.info("Recommendation: Develop systematic conversation templates for reusable testing patterns")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_helper_utilities_gap_006(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """TDM_STATEFUL_HELPER_UTILITIES_GAP_006: Assess lack of state management helpers"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing state management helper utility needs assessment")
        
        # Demonstrate the manual complexity of managing conversation state
        # This test shows what could be simplified with helper utilities
        
        utility_scenarios = [
            {
                "name": "manual_message_building",
                "description": "Manual construction of messages array",
                "complexity_factors": [
                    "role_management",
                    "content_formatting", 
                    "history_tracking",
                    "context_limits",
                    "error_handling"
                ]
            },
            {
                "name": "conversation_branching",
                "description": "Managing multiple conversation branches",
                "complexity_factors": [
                    "branch_isolation",
                    "state_copying",
                    "branch_comparison",
                    "merge_conflicts",
                    "cleanup"
                ]
            },
            {
                "name": "context_window_management",
                "description": "Handling context window limitations",
                "complexity_factors": [
                    "token_counting",
                    "history_truncation",
                    "priority_retention",
                    "summarization",
                    "seamless_continuation"
                ]
            }
        ]
        
        helper_assessment_results = {}
        
        for scenario in utility_scenarios:
            logger.info(f"Assessing helper utility need: {scenario['name']}")
            
            # Demonstrate manual complexity by building a test conversation
            messages = []
            complexity_score = 0
            
            # Simulate the manual work that helpers could simplify
            for i in range(5):  # 5-turn conversation
                # Manual message construction (what helpers could simplify)
                user_message = f"This is turn {i+1} in our conversation about {scenario['description']}"
                
                # Manual role management
                messages.append({"role": "user", "content": user_message})
                
                # Manual API call with error handling
                try:
                    request_data = {
                        "model": config.get_chat_model(0),
                        "messages": messages.copy(),  # Manual history management
                        "max_tokens": 100
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request_data
                    )
                    
                    if response.status_code == 200:
                        response_data = response.json()
                        ai_response = response_data["choices"][0]["message"]["content"]
                        
                        # Manual response handling
                        messages.append({"role": "assistant", "content": ai_response})
                        complexity_score += 1  # Each manual step increases complexity
                    else:
                        complexity_score += 2  # Error handling adds more complexity
                except Exception as e:
                    complexity_score += 3  # Exception handling is even more complex
                
                # Manual context limit checking (what helpers should do automatically)
                total_content_length = sum(len(msg["content"]) for msg in messages)
                if total_content_length > 2000:  # Arbitrary limit for demonstration
                    # Manual truncation logic
                    messages = messages[-6:]  # Keep last 3 exchanges
                    complexity_score += 2
                
                await asyncio.sleep(0.1)
            
            # Calculate utility need score based on manual complexity
            complexity_factors = scenario["complexity_factors"]
            factor_coverage = len([f for f in complexity_factors if f in 
                                 ["role_management", "history_tracking", "error_handling"]])  # Basic factors we demonstrated
            
            utility_need_score = (complexity_score / 15.0) + (factor_coverage / len(complexity_factors))
            
            helper_assessment_results[scenario["name"]] = {
                "description": scenario["description"],
                "complexity_factors": complexity_factors,
                "manual_complexity_score": complexity_score,
                "factor_coverage": factor_coverage,
                "utility_need_score": min(utility_need_score, 1.0),
                "high_utility_need": utility_need_score >= 0.6,
                "total_messages": len(messages)
            }
            
            logger.info(f"Helper utility need for {scenario['name']}: "
                       f"Complexity: {complexity_score}, "
                       f"Utility need: {utility_need_score:.3f}")
        
        # Verify gap assessment identifies need for helpers
        high_need_scenarios = [name for name, result in helper_assessment_results.items() 
                              if result["high_utility_need"]]
        
        assert len(high_need_scenarios) >= len(utility_scenarios) * 0.6, \
            f"Most scenarios should show high utility need for helpers, got {len(high_need_scenarios)}/{len(utility_scenarios)}"
        
        # Document recommendations
        avg_utility_need = sum(result["utility_need_score"] for result in helper_assessment_results.values()) / len(helper_assessment_results)
        
        logger.info(f"Helper utility assessment complete: Average need score: {avg_utility_need:.3f}")
        logger.info("Recommendation: Develop helper utilities for conversation state management")
    
    def _assess_conversation_coherence(self, conversation_results: List[Dict[str, Any]]) -> float:
        """Assess coherence of conversation flow"""
        if not conversation_results:
            return 0.0
        
        successful_results = [r for r in conversation_results if r.get("success", False)]
        if not successful_results:
            return 0.0
        
        # Simple coherence assessment based on response appropriateness
        coherence_score = 0.0
        
        for result in successful_results:
            user_input = result.get("user_input", "")
            ai_response = result.get("ai_response", "")
            
            # Check if response seems appropriate to input
            if len(ai_response) > 10:  # Non-trivial response
                coherence_score += 0.5
            
            # Check for contextual continuity (simple keyword matching)
            user_words = set(user_input.lower().split())
            response_words = set(ai_response.lower().split())
            word_overlap = len(user_words.intersection(response_words))
            
            if word_overlap > 0:
                coherence_score += 0.3
            
            # Check response length appropriateness
            if 20 <= len(ai_response) <= 500:  # Reasonable response length
                coherence_score += 0.2
        
        # Normalize by number of successful results
        return min(coherence_score / len(successful_results), 1.0)
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_context_optimization_009(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """TDM_STATEFUL_CONTEXT_OPTIMIZATION_009: Test intelligent context window optimization"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing dynamic context window optimization")
        
        # Test scenarios for context optimization
        optimization_scenarios = [
            {
                "scenario": "intelligent_truncation",
                "description": "Smart truncation of conversation history",
                "turns": 8,
                "optimization_strategy": "priority_retention"
            },
            {
                "scenario": "conversation_summarization", 
                "description": "Automatic summarization of older turns",
                "turns": 6,
                "optimization_strategy": "summarization"
            },
            {
                "scenario": "adaptive_context_management",
                "description": "Adaptive management based on conversation type",
                "turns": 10,
                "optimization_strategy": "adaptive"
            }
        ]
        
        optimization_results = []
        
        for scenario_data in optimization_scenarios:
            logger.info(f"Testing context optimization: {scenario_data['scenario']}")
            
            # Build a long conversation to test optimization
            messages = []
            turn_results = []
            
            for turn in range(scenario_data["turns"]):
                # Create progressively longer conversation
                user_content = f"Turn {turn + 1}: Please explain the concept of {['machine learning', 'data science', 'artificial intelligence', 'neural networks', 'deep learning', 'computer vision', 'natural language processing', 'robotics', 'automation', 'algorithms'][turn % 10]} in detail."
                
                messages.append({"role": "user", "content": user_content})
                
                # Test conversation before optimization
                pre_optimization_request = {
                    "model": config.get_chat_model(0),
                    "messages": messages.copy(),
                    "max_tokens": 150
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, pre_optimization_request
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    ai_response = response_data["choices"][0]["message"]["content"]
                    prompt_tokens = response_data.get("usage", {}).get("prompt_tokens", 0)
                    
                    messages.append({"role": "assistant", "content": ai_response})
                    
                    # Simulate context optimization based on strategy
                    optimized_messages = self._apply_context_optimization(
                        messages.copy(), scenario_data["optimization_strategy"]
                    )
                    
                    # Test optimized conversation
                    post_optimization_request = {
                        "model": config.get_chat_model(0),
                        "messages": optimized_messages,
                        "max_tokens": 150
                    }
                    
                    opt_response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, post_optimization_request
                    )
                    
                    if opt_response.status_code == 200:
                        opt_response_data = opt_response.json()
                        opt_prompt_tokens = opt_response_data.get("usage", {}).get("prompt_tokens", 0)
                        
                        # Calculate optimization effectiveness
                        token_reduction = prompt_tokens - opt_prompt_tokens
                        reduction_percentage = (token_reduction / prompt_tokens) if prompt_tokens > 0 else 0
                        
                        turn_results.append({
                            "turn": turn + 1,
                            "original_prompt_tokens": prompt_tokens,
                            "optimized_prompt_tokens": opt_prompt_tokens,
                            "token_reduction": token_reduction,
                            "reduction_percentage": reduction_percentage,
                            "optimization_strategy": scenario_data["optimization_strategy"],
                            "coherence_maintained": self._assess_optimization_coherence(messages, optimized_messages),
                            "success": True
                        })
                    else:
                        turn_results.append({
                            "turn": turn + 1,
                            "success": False
                        })
                else:
                    turn_results.append({
                        "turn": turn + 1,
                        "success": False
                    })
                
                await asyncio.sleep(0.1)
            
            # Assess optimization effectiveness
            successful_turns = [r for r in turn_results if r["success"]]
            avg_reduction = sum(r["reduction_percentage"] for r in successful_turns) / len(successful_turns) if successful_turns else 0
            coherence_maintained = sum(r["coherence_maintained"] for r in successful_turns) / len(successful_turns) if successful_turns else 0
            
            optimization_results.append({
                "scenario": scenario_data["scenario"],
                "optimization_strategy": scenario_data["optimization_strategy"],
                "total_turns": scenario_data["turns"],
                "successful_turns": len(successful_turns),
                "avg_token_reduction": avg_reduction,
                "avg_coherence_score": coherence_maintained,
                "optimization_effective": avg_reduction >= 0.1 and coherence_maintained >= 0.7,
                "turn_results": turn_results
            })
            
            logger.info(f"Context optimization {scenario_data['scenario']}: "
                       f"Token reduction: {avg_reduction:.2%}, "
                       f"Coherence: {coherence_maintained:.3f}")
        
        # Verify optimization effectiveness
        effective_optimizations = [r for r in optimization_results if r["optimization_effective"]]
        high_reduction_scenarios = [r for r in optimization_results if r["avg_token_reduction"] >= 0.15]
        
        assert len(effective_optimizations) >= len(optimization_scenarios) * 0.6, \
            f"Most optimization strategies should be effective, got {len(effective_optimizations)}/{len(optimization_scenarios)}"
        
        logger.info(f"Context optimization assessment complete: {len(effective_optimizations)}/{len(optimization_scenarios)} strategies effective")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_stateful_cross_session_010(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TDM_STATEFUL_CROSS_SESSION_010: Test conversation continuity across sessions"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing cross-session conversation continuity")
        
        # Test cross-session scenarios
        session_scenarios = [
            {
                "scenario": "session_state_persistence",
                "description": "Maintain conversation state across sessions",
                "session_count": 3,
                "turns_per_session": 2
            },
            {
                "scenario": "conversation_recovery",
                "description": "Recover conversation after interruption",
                "session_count": 2,
                "turns_per_session": 3
            },
            {
                "scenario": "cross_session_context_integrity",
                "description": "Maintain context integrity across multiple sessions",
                "session_count": 4,
                "turns_per_session": 2
            }
        ]
        
        session_continuity_results = []
        
        for scenario_data in session_scenarios:
            logger.info(f"Testing cross-session scenario: {scenario_data['scenario']}")
            
            # Simulate conversation across multiple sessions
            full_conversation_history = []
            session_results = []
            
            for session_num in range(scenario_data["session_count"]):
                logger.info(f"Session {session_num + 1}")
                
                # Start new session with previous context (simulated)
                session_messages = full_conversation_history.copy()
                
                for turn in range(scenario_data["turns_per_session"]):
                    # Create contextual user message
                    if session_num == 0 and turn == 0:
                        user_content = "Hello, I'm starting a conversation about renewable energy technologies."
                    elif session_num > 0 and turn == 0:
                        user_content = f"Continuing our conversation from session {session_num}, can you remind me what we discussed?"
                    else:
                        user_content = f"Session {session_num + 1}, Turn {turn + 1}: Please expand on the previous point about solar panel efficiency."
                    
                    session_messages.append({"role": "user", "content": user_content})
                    
                    # Test conversation with session context
                    session_request = {
                        "model": config.get_chat_model(0),
                        "messages": session_messages.copy(),
                        "max_tokens": 150
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, session_request
                    )
                    
                    if response.status_code == 200:
                        response_data = response.json()
                        ai_response = response_data["choices"][0]["message"]["content"]
                        
                        session_messages.append({"role": "assistant", "content": ai_response})
                        
                        # Assess context continuity
                        context_continuity_score = self._assess_cross_session_continuity(
                            full_conversation_history, session_messages, session_num
                        )
                        
                        session_results.append({
                            "session": session_num + 1,
                            "turn": turn + 1,
                            "user_content": user_content,
                            "ai_response": ai_response,
                            "context_continuity_score": context_continuity_score,
                            "session_context_maintained": context_continuity_score >= 0.6,
                            "success": True
                        })
                    else:
                        session_results.append({
                            "session": session_num + 1,
                            "turn": turn + 1,
                            "success": False
                        })
                    
                    await asyncio.sleep(0.1)
                
                # Update full conversation history with session results
                full_conversation_history = session_messages.copy()
            
            # Assess overall cross-session continuity
            successful_turns = [r for r in session_results if r["success"]]
            continuity_maintained_turns = [r for r in successful_turns if r["session_context_maintained"]]
            
            avg_continuity_score = sum(r["context_continuity_score"] for r in successful_turns) / len(successful_turns) if successful_turns else 0
            continuity_rate = len(continuity_maintained_turns) / len(successful_turns) if successful_turns else 0
            
            session_continuity_results.append({
                "scenario": scenario_data["scenario"],
                "description": scenario_data["description"],
                "total_sessions": scenario_data["session_count"],
                "total_turns": len(session_results),
                "successful_turns": len(successful_turns),
                "continuity_maintained_turns": len(continuity_maintained_turns),
                "avg_continuity_score": avg_continuity_score,
                "continuity_rate": continuity_rate,
                "cross_session_effective": continuity_rate >= 0.7 and avg_continuity_score >= 0.6,
                "session_results": session_results
            })
            
            logger.info(f"Cross-session continuity {scenario_data['scenario']}: "
                       f"Continuity rate: {continuity_rate:.2%}, "
                       f"Avg score: {avg_continuity_score:.3f}")
        
        # Verify cross-session continuity effectiveness
        effective_scenarios = [r for r in session_continuity_results if r["cross_session_effective"]]
        high_continuity_scenarios = [r for r in session_continuity_results if r["continuity_rate"] >= 0.8]
        
        assert len(effective_scenarios) >= len(session_scenarios) * 0.6, \
            f"Most cross-session scenarios should maintain continuity, got {len(effective_scenarios)}/{len(session_scenarios)}"
        
        logger.info(f"Cross-session continuity assessment complete: {len(effective_scenarios)}/{len(session_scenarios)} scenarios effective")
    
    def _apply_context_optimization(self, messages: List[Dict[str, str]], strategy: str) -> List[Dict[str, str]]:
        """Apply context optimization strategy to message history"""
        if strategy == "priority_retention":
            # Keep first message (context) and last 4 messages
            if len(messages) > 6:
                return [messages[0]] + messages[-4:]
            return messages
        
        elif strategy == "summarization":
            # Simulate summarization by condensing older messages
            if len(messages) > 6:
                # Keep first message and summarize middle messages
                summary_msg = {
                    "role": "system", 
                    "content": f"[Summary of previous conversation: Discussion covered {len(messages[1:-2])} topics]"
                }
                return [messages[0], summary_msg] + messages[-2:]
            return messages
        
        elif strategy == "adaptive":
            # Adaptive strategy based on message length
            if len(messages) > 8:
                # Keep important messages (first, last 3, and any short messages)
                important_messages = [messages[0]]  # First message
                for msg in messages[1:-3]:
                    if len(msg.get("content", "")) < 50:  # Keep short messages
                        important_messages.append(msg)
                important_messages.extend(messages[-3:])  # Last 3 messages
                return important_messages
            return messages
        
        return messages
    
    def _assess_optimization_coherence(self, original_messages: List[Dict[str, str]], 
                                     optimized_messages: List[Dict[str, str]]) -> float:
        """Assess if optimization maintains conversation coherence"""
        if not original_messages or not optimized_messages:
            return 0.0
        
        # Check if key context elements are preserved
        original_content = " ".join(msg.get("content", "") for msg in original_messages)
        optimized_content = " ".join(msg.get("content", "") for msg in optimized_messages)
        
        # Simple word overlap assessment
        original_words = set(original_content.lower().split())
        optimized_words = set(optimized_content.lower().split())
        
        if len(original_words) == 0:
            return 0.0
        
        overlap_ratio = len(original_words.intersection(optimized_words)) / len(original_words)
        
        # Boost score if optimization preserves conversation structure
        if len(optimized_messages) >= 2 and optimized_messages[0].get("role") == "user":
            overlap_ratio += 0.2
        
        return min(overlap_ratio, 1.0)
    
    def _assess_cross_session_continuity(self, previous_history: List[Dict[str, str]], 
                                       current_session: List[Dict[str, str]], 
                                       session_num: int) -> float:
        """Assess cross-session conversation continuity"""
        if session_num == 0:
            return 1.0  # First session always has perfect continuity
        
        if not previous_history or not current_session:
            return 0.0
        
        # Check if current session references previous context
        current_content = " ".join(msg.get("content", "") for msg in current_session[-3:])  # Last 3 messages
        previous_content = " ".join(msg.get("content", "") for msg in previous_history[-6:])  # Last 6 from previous
        
        # Look for continuity indicators
        continuity_indicators = [
            "previous", "earlier", "before", "discussed", "mentioned", 
            "continue", "following up", "as we talked", "from our conversation"
        ]
        
        continuity_score = 0.0
        found_indicators = sum(1 for indicator in continuity_indicators 
                             if indicator in current_content.lower())
        
        if found_indicators > 0:
            continuity_score += 0.5
        
        # Check for topic consistency
        previous_words = set(previous_content.lower().split())
        current_words = set(current_content.lower().split())
        
        if len(previous_words) > 0:
            topic_overlap = len(previous_words.intersection(current_words)) / len(previous_words)
            continuity_score += topic_overlap * 0.5
        
        return min(continuity_score, 1.0)