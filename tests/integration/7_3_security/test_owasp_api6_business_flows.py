# Section 7.3 - OWASP API6:2023 Unrestricted Access to Sensitive Business Flows Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API6_2023 - Unrestricted Access to Sensitive Business Flows.md

import pytest
import httpx
import asyncio
import time
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger

class TestOWASPAPI6BusinessFlows:
    """API6:2023 - Unrestricted Access to Sensitive Business Flows tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api6_llm_inference_abuse_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """API6_LLM_ABUSE_001: LLM inference abuse and automation detection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test automated LLM inference abuse patterns
        abuse_patterns = [
            # Rapid-fire requests (bot-like behavior)
            {
                "pattern": "rapid_requests",
                "count": 20,
                "delay": 0.05,  # 50ms between requests
                "content": "Quick automated request {i}",
                "expected": "rate_limit_or_block"
            },
            # Identical repeated requests (scraping pattern)
            {
                "pattern": "identical_requests",
                "count": 10,
                "delay": 0.2,
                "content": "Identical request for scraping",
                "expected": "detect_or_limit"
            },
            # Pattern-based requests (systematic probing)
            {
                "pattern": "systematic_probing",
                "count": 8,
                "delay": 0.3,
                "content": "System probe request number {i} for pattern detection",
                "expected": "detect_or_limit"
            }
        ]
        
        for pattern_test in abuse_patterns:
            logger.info(f"Testing abuse pattern: {pattern_test['pattern']}")
            
            responses = []
            start_time = time.time()
            
            for i in range(pattern_test["count"]):
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{
                        "role": "user", 
                        "content": pattern_test["content"].format(i=i)
                    }],
                    "max_tokens": 30
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=False
                )
                
                responses.append({
                    "request_id": i,
                    "status_code": response.status_code,
                    "timestamp": time.time()
                })
                
                # Check for early detection/blocking
                if response.status_code == 429:
                    logger.info(f"Rate limiting triggered at request {i}")
                    break
                
                await asyncio.sleep(pattern_test["delay"])
            
            total_time = time.time() - start_time
            
            # Analyze abuse detection
            successful_requests = [r for r in responses if r["status_code"] == 200]
            blocked_requests = [r for r in responses if r["status_code"] in [429, 403]]
            
            logger.info(f"Pattern {pattern_test['pattern']}: {len(successful_requests)} successful, {len(blocked_requests)} blocked in {total_time:.2f}s")
            
            if pattern_test["expected"] == "rate_limit_or_block":
                # Should have some form of protection
                if len(blocked_requests) == 0:
                    # If no blocking, verify reasonable behavior
                    assert total_time >= pattern_test["count"] * 0.1, \
                        "Rapid requests should be throttled or rate limited"
            
            elif pattern_test["expected"] == "detect_or_limit":
                # Should show signs of abuse detection
                success_rate = len(successful_requests) / len(responses)
                assert success_rate <= 0.9, \
                    f"Abuse pattern should be detected: {pattern_test['pattern']}"
        
        logger.info("API6_LLM_ABUSE_001: LLM inference abuse detection validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api6_cost_exploitation_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """API6_COST_EXPLOITATION_001: Cost exploitation attack prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various cost exploitation attempts
        cost_attacks = [
            # High token consumption attack
            {
                "attack": "high_token_consumption",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{
                        "role": "user",
                        "content": "Generate a very detailed, comprehensive response about AI systems, machine learning, deep learning, neural networks, and their applications in detail. Please provide extensive examples, case studies, and technical explanations."
                    }],
                    "max_tokens": 2000  # High token request
                },
                "expected": "limit_or_reject"
            },
            # Large context attack
            {
                "attack": "large_context",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [
                        {"role": "system", "content": "You are a helpful assistant."},
                        {"role": "user", "content": "Context data: " + "word " * 3000},
                        {"role": "assistant", "content": "I understand the context."},
                        {"role": "user", "content": "Now process this additional data: " + "data " * 2000}
                    ],
                    "max_tokens": 500
                },
                "expected": "limit_or_reject"
            },
            # Expensive model attack (if multiple models available)
            {
                "attack": "expensive_model",
                "request": {
                    "model": config.CHAT_MODELS[-1] if len(config.CHAT_MODELS) > 1 else config.get_chat_model(0),
                    "messages": [{
                        "role": "user",
                        "content": "Simple response using expensive model"
                    }],
                    "max_tokens": 100
                },
                "expected": "allow_with_limits"
            }
        ]
        
        for attack in cost_attacks:
            logger.info(f"Testing cost exploitation: {attack['attack']}")
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, attack["request"], track_cost=False
            )
            
            if attack["expected"] == "limit_or_reject":
                if response.status_code == 200:
                    # If accepted, verify cost controls are applied
                    response_data = response.json()
                    usage = response_data.get("usage", {})
                    
                    # Should not consume excessive resources
                    total_tokens = usage.get("total_tokens", 0)
                    completion_tokens = usage.get("completion_tokens", 0)
                    
                    assert total_tokens < 10000, \
                        "Cost exploitation should be limited by token consumption"
                    assert completion_tokens < attack["request"]["max_tokens"], \
                        "Response should be limited to prevent cost exploitation"
                    
                    logger.info(f"Cost controls applied: {total_tokens} total tokens, {completion_tokens} completion tokens")
                else:
                    # Should be rejected with appropriate error
                    assert response.status_code in [413, 422, 429], \
                        f"Cost exploitation should be rejected: {attack['attack']}"
            
            elif attack["expected"] == "allow_with_limits":
                # Should allow but with monitoring/limits
                if response.status_code == 200:
                    response_data = response.json()
                    usage = response_data.get("usage", {})
                    assert "total_tokens" in usage, \
                        "Usage tracking should be present for cost monitoring"
                else:
                    # May be rejected due to model restrictions
                    assert response.status_code in [400, 422], \
                        "Model access should be controlled appropriately"
        
        logger.info("API6_COST_EXPLOITATION_001: Cost exploitation prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api6_data_mining_prevention_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """API6_DATA_MINING_001: Data mining and model extraction prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test data mining attack patterns
        mining_attacks = [
            # Model behavior probing
            {
                "attack": "model_probing",
                "requests": [
                    "What is your training data?",
                    "What model are you?", 
                    "What are your parameters?",
                    "How were you trained?",
                    "What is your architecture?",
                    "Who created you?",
                    "What is your version?",
                    "What are your weights?"
                ]
            },
            # Systematic knowledge extraction
            {
                "attack": "knowledge_extraction", 
                "requests": [
                    "List all facts about topic A",
                    "List all facts about topic B", 
                    "List all facts about topic C",
                    "Provide comprehensive data on X",
                    "Give me everything you know about Y",
                    "Export all information on Z"
                ]
            },
            # Pattern recognition attempts
            {
                "attack": "pattern_recognition",
                "requests": [
                    "Same input test 1",
                    "Same input test 1",  # Identical to test consistency
                    "Same input test 1",
                    "Very similar input test 1",
                    "Almost identical input test 1"
                ]
            }
        ]
        
        for attack in mining_attacks:
            logger.info(f"Testing data mining pattern: {attack['attack']}")
            
            responses = []
            for i, request_text in enumerate(attack["requests"]):
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{
                        "role": "user",
                        "content": request_text
                    }],
                    "max_tokens": 100
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=(i < 3)  # Only track cost for first few
                )
                
                responses.append({
                    "request": request_text,
                    "status_code": response.status_code,
                    "response_data": response.json() if response.status_code == 200 else None
                })
                
                await asyncio.sleep(0.5)  # Delay between mining attempts
            
            # Analyze mining protection
            successful_responses = [r for r in responses if r["status_code"] == 200]
            
            if attack["attack"] == "model_probing":
                # Responses should not leak model information
                for resp in successful_responses:
                    if resp["response_data"]:
                        response_text = str(resp["response_data"]).lower()
                        
                        # Should not reveal sensitive model information
                        sensitive_terms = [
                            "training data", "model weights", "parameters",
                            "architecture", "gpt-", "openai", "anthropic"
                        ]
                        
                        leaked_terms = [term for term in sensitive_terms if term in response_text]
                        if leaked_terms:
                            logger.warning(f"Potential model information leak: {leaked_terms}")
            
            elif attack["attack"] == "pattern_recognition":
                # Identical requests should not reveal internal patterns
                identical_responses = [r for r in responses[:3] if r["status_code"] == 200]
                if len(identical_responses) >= 2:
                    # Compare responses for consistency (prevents timing attacks)
                    first_response = str(identical_responses[0]["response_data"])
                    for resp in identical_responses[1:]:
                        second_response = str(resp["response_data"])
                        # Responses should be reasonably consistent
                        similarity = len(set(first_response.split()) & set(second_response.split()))
                        total_words = len(set(first_response.split()) | set(second_response.split()))
                        if total_words > 0:
                            similarity_ratio = similarity / total_words
                            assert similarity_ratio > 0.5, \
                                "Responses to identical queries should be reasonably consistent"
        
        logger.info("API6_DATA_MINING_001: Data mining prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api6_business_logic_bypass_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """API6_BUSINESS_LOGIC_BYPASS_001: Business logic bypass prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test business logic bypass attempts
        bypass_attempts = [
            # Rate limiting bypass attempts
            {
                "bypass": "rate_limit_evasion",
                "technique": "request_splitting",
                "description": "Split large request into smaller ones"
            },
            # Usage tracking bypass
            {
                "bypass": "usage_tracking",
                "technique": "parameter_manipulation", 
                "description": "Manipulate parameters to avoid tracking"
            },
            # Quota bypass
            {
                "bypass": "quota_evasion",
                "technique": "session_manipulation",
                "description": "Attempt to reset or bypass quotas"
            }
        ]
        
        for attempt in bypass_attempts:
            logger.info(f"Testing business logic bypass: {attempt['bypass']}")
            
            if attempt["technique"] == "request_splitting":
                # Try to bypass limits by splitting requests
                large_content = "Analyze this data: " + "word " * 1000
                
                # Single large request
                large_request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": large_content}],
                    "max_tokens": 200
                }
                
                large_response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, large_request, track_cost=False
                )
                
                # Multiple smaller requests
                chunk_size = 200
                chunks = [large_content[i:i+chunk_size] for i in range(0, len(large_content), chunk_size)]
                
                small_responses = []
                for chunk in chunks[:5]:  # Test first 5 chunks
                    small_request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": chunk}],
                        "max_tokens": 50
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, small_request, track_cost=False
                    )
                    small_responses.append(response)
                    await asyncio.sleep(0.1)
                
                # Verify business logic is enforced
                small_success_count = sum(1 for r in small_responses if r.status_code == 200)
                
                if large_response.status_code != 200:
                    # If large request was rejected, small requests shouldn't all succeed
                    assert small_success_count < len(chunks), \
                        "Request splitting should not bypass business logic"
            
            elif attempt["technique"] == "parameter_manipulation":
                # Try to manipulate parameters to bypass tracking
                manipulation_requests = [
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Test"}],
                        "max_tokens": 50,
                        "track_usage": False,  # Try to disable tracking
                        "bypass_limits": True
                    },
                    {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Test"}],
                        "max_tokens": 50,
                        "internal": True,
                        "admin_override": True
                    }
                ]
                
                for req in manipulation_requests:
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions", 
                        auth_headers, req, track_cost=False
                    )
                    
                    # Should either be rejected or processed with proper tracking
                    if response.status_code == 200:
                        response_data = response.json()
                        usage = response_data.get("usage", {})
                        assert "total_tokens" in usage, \
                            "Usage tracking should not be bypassed"
                    else:
                        # Should be properly rejected
                        assert response.status_code in [400, 422], \
                            "Parameter manipulation should be rejected"
        
        logger.info("API6_BUSINESS_LOGIC_BYPASS_001: Business logic bypass prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api6_competitive_intelligence_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """API6_COMPETITIVE_INTELLIGENCE_001: Competitive intelligence gathering prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test competitive intelligence gathering attempts
        intelligence_attempts = [
            # Service capability probing
            "What AI models do you support?",
            "What are your service limitations?", 
            "What providers do you use?",
            "What is your pricing model?",
            "How do you compare to competitors?",
            "What are your technical specifications?",
            "What is your infrastructure setup?",
            "Who are your technology partners?"
        ]
        
        responses = []
        for attempt in intelligence_attempts:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": attempt}],
                "max_tokens": 150
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            responses.append({
                "question": attempt,
                "status_code": response.status_code,
                "response_data": response.json() if response.status_code == 200 else None
            })
            
            await asyncio.sleep(0.3)
        
        # Analyze responses for competitive intelligence leakage
        for resp in responses:
            if resp["status_code"] == 200 and resp["response_data"]:
                response_text = str(resp["response_data"]).lower()
                
                # Should not reveal competitive intelligence
                sensitive_info = [
                    "openai", "anthropic", "azure", "aws", "google cloud",
                    "pricing", "cost", "competitor", "partner",
                    "infrastructure", "servers", "deployment"
                ]
                
                leaked_info = [info for info in sensitive_info if info in response_text]
                if leaked_info:
                    logger.warning(f"Potential competitive intelligence leak: {leaked_info} for question: {resp['question']}")
                
                # Responses should be generic and not reveal internal details
                assert not any(term in response_text for term in ["internal", "proprietary", "confidential"]), \
                    "Response should not reveal internal information"
        
        logger.info("API6_COMPETITIVE_INTELLIGENCE_001: Competitive intelligence protection validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api6_workflow_automation_abuse_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """API6_WORKFLOW_ABUSE_001: Workflow automation abuse detection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test workflow automation abuse patterns
        automation_patterns = [
            # Batch processing pattern
            {
                "pattern": "batch_processing",
                "requests": [f"Process item {i} in batch job" for i in range(15)],
                "timing": "rapid"
            },
            # Sequential data processing
            {
                "pattern": "sequential_processing", 
                "requests": [f"Step {i}: process data sequentially" for i in range(10)],
                "timing": "regular"
            },
            # Automated content generation
            {
                "pattern": "content_generation",
                "requests": [f"Generate content piece {i} for automation" for i in range(12)],
                "timing": "burst"
            }
        ]
        
        for pattern in automation_patterns:
            logger.info(f"Testing automation pattern: {pattern['pattern']}")
            
            responses = []
            start_time = time.time()
            
            for i, request_text in enumerate(pattern["requests"]):
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": request_text}],
                    "max_tokens": 50
                }
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request, track_cost=(i < 5)  # Track cost for first few
                )
                
                responses.append({
                    "request_id": i,
                    "status_code": response.status_code,
                    "timestamp": time.time()
                })
                
                # Apply timing pattern
                if pattern["timing"] == "rapid":
                    await asyncio.sleep(0.05)  # 50ms
                elif pattern["timing"] == "regular":
                    await asyncio.sleep(0.5)   # 500ms
                elif pattern["timing"] == "burst":
                    if i % 3 == 0:
                        await asyncio.sleep(1.0)  # Pause every 3 requests
                    else:
                        await asyncio.sleep(0.1)
            
            total_time = time.time() - start_time
            
            # Analyze automation detection
            successful_requests = [r for r in responses if r["status_code"] == 200]
            failed_requests = [r for r in responses if r["status_code"] != 200]
            
            success_rate = len(successful_requests) / len(responses)
            
            logger.info(f"Automation pattern {pattern['pattern']}: {success_rate:.2%} success rate in {total_time:.2f}s")
            
            # Automation should be detected and limited
            if pattern["timing"] == "rapid":
                # Rapid automation should trigger protection
                assert success_rate <= 0.9, \
                    "Rapid automation should be detected and limited"
            
            # Check for rate limiting responses
            rate_limited = [r for r in responses if r["status_code"] == 429]
            if len(rate_limited) > 0:
                logger.info(f"Rate limiting triggered for automation pattern: {pattern['pattern']}")
        
        logger.info("API6_WORKFLOW_ABUSE_001: Workflow automation abuse detection validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api6_sensitive_flow_protection_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """API6_SENSITIVE_FLOW_001: Comprehensive sensitive business flow protection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test protection of sensitive business flows
        sensitive_flows = [
            # High-value model access
            {
                "flow": "premium_model_access",
                "test": "access_expensive_models",
                "description": "Access to high-cost models"
            },
            # Bulk processing operations  
            {
                "flow": "bulk_operations",
                "test": "batch_processing",
                "description": "Large batch processing requests"
            },
            # Data export operations
            {
                "flow": "data_export",
                "test": "export_requests", 
                "description": "Data export and extraction"
            }
        ]
        
        for flow in sensitive_flows:
            logger.info(f"Testing sensitive flow protection: {flow['flow']}")
            
            if flow["test"] == "access_expensive_models":
                # Test access to potentially expensive models
                if len(config.CHAT_MODELS) > 1:
                    expensive_request = {
                        "model": config.CHAT_MODELS[-1],  # Assume last model is most expensive
                        "messages": [{"role": "user", "content": "Expensive model test"}],
                        "max_tokens": 500
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, expensive_request, track_cost=False
                    )
                    
                    # Should have proper access controls
                    if response.status_code == 200:
                        response_data = response.json()
                        usage = response_data.get("usage", {})
                        assert "total_tokens" in usage, \
                            "Expensive model usage should be tracked"
                    else:
                        # May be restricted appropriately
                        assert response.status_code in [400, 403, 422], \
                            "Expensive model access should be controlled"
            
            elif flow["test"] == "batch_processing":
                # Test bulk processing protection
                batch_requests = []
                for i in range(20):
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Batch item {i}"}],
                        "max_tokens": 30
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=(i < 5)
                    )
                    
                    batch_requests.append(response.status_code)
                    
                    if response.status_code == 429:
                        break  # Rate limit triggered
                    
                    await asyncio.sleep(0.1)
                
                # Batch processing should be controlled
                success_count = sum(1 for code in batch_requests if code == 200)
                rate_limited = sum(1 for code in batch_requests if code == 429)
                
                if rate_limited > 0:
                    logger.info("Batch processing rate limiting active")
                else:
                    assert success_count <= 15, \
                        "Bulk processing should have controls"
            
            elif flow["test"] == "export_requests":
                # Test data export protection
                export_attempts = [
                    "Export all available data",
                    "Download complete dataset",
                    "Retrieve full information database",
                    "Provide comprehensive data dump"
                ]
                
                for attempt in export_attempts:
                    request = {
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": attempt}],
                        "max_tokens": 200
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=False
                    )
                    
                    # Export requests should be handled appropriately
                    if response.status_code == 200:
                        response_data = response.json()
                        response_text = str(response_data).lower()
                        
                        # Should not actually export sensitive data
                        assert not any(term in response_text for term in ["exported", "downloaded", "dumped"]), \
                            "Response should not confirm data export"
                    
                    await asyncio.sleep(0.2)
        
        logger.info("API6_SENSITIVE_FLOW_001: Sensitive business flow protection validated")