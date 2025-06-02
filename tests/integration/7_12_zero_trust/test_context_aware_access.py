# Section 7.12 - Zero Trust Context-Aware Access Control Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Context-Aware Access Control.md

import pytest
import httpx
import time
import datetime
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


class TestZeroTrustContextAwareAccess:
    """Zero Trust Context-Aware Access Control test cases"""
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_context_geolocation_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """ZTA_CONTEXT_GEO_001: Geolocation-based access control"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test various geolocation scenarios
        geo_contexts = [
            # Standard US location
            {
                "headers": {"X-Forwarded-For": "8.8.8.8", "X-Real-IP": "8.8.8.8"},
                "description": "US location (Google DNS)",
                "expected": "allow"
            },
            
            # Different geographic regions
            {
                "headers": {"X-Forwarded-For": "1.1.1.1", "X-Real-IP": "1.1.1.1"},
                "description": "Australia location (Cloudflare)",
                "expected": "evaluate"
            },
            
            # Suspicious/restricted locations
            {
                "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
                "description": "Localhost (suspicious)",
                "expected": "evaluate"
            },
            
            # Private IP ranges
            {
                "headers": {"X-Forwarded-For": "192.168.1.1", "X-Real-IP": "192.168.1.1"},
                "description": "Private IP range",
                "expected": "evaluate"
            },
            
            # Multiple IPs (proxy chain)
            {
                "headers": {"X-Forwarded-For": "8.8.8.8, 192.168.1.1", "X-Real-IP": "192.168.1.1"},
                "description": "Proxy chain",
                "expected": "evaluate"
            }
        ]
        
        for context in geo_contexts:
            # Merge geo headers with auth headers
            test_headers = dict(auth_headers)
            test_headers.update(context["headers"])
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Geolocation test from {context['description']}"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                test_headers, request
            )
            
            # Analyze response based on context
            if context["expected"] == "allow":
                # Should generally allow normal locations
                assert response.status_code in [200, 422], \
                    f"Normal location should be allowed: {context['description']}"
            
            elif context["expected"] == "evaluate":
                # Should either allow with additional validation or require additional auth
                if response.status_code == 200:
                    logger.info(f"Context accepted: {context['description']}")
                else:
                    # May require additional validation
                    assert response.status_code in [401, 403, 429], \
                        f"Suspicious context should be handled appropriately: {context['description']}"
            
            logger.info(f"Geolocation test: {context['description']} -> {response.status_code}")
        
        logger.info("ZTA_CONTEXT_GEO_001: Geolocation-based access control validated")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_context_device_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """ZTA_CONTEXT_DEVICE_001: Device context and fingerprinting"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test various device contexts
        device_contexts = [
            # Standard browser
            {
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "application/json",
                    "Accept-Language": "en-US,en;q=0.9"
                },
                "description": "Standard Chrome browser",
                "expected": "allow"
            },
            
            # Mobile device
            {
                "headers": {
                    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                    "Accept": "application/json"
                },
                "description": "iPhone Safari",
                "expected": "allow"
            },
            
            # Suspicious/automated user agent
            {
                "headers": {
                    "User-Agent": "curl/7.68.0",
                    "Accept": "*/*"
                },
                "description": "Curl client (automated)",
                "expected": "evaluate"
            },
            
            # Script/bot user agent
            {
                "headers": {
                    "User-Agent": "Python/3.9 urllib3/1.26.0",
                    "Accept": "application/json"
                },
                "description": "Python script",
                "expected": "evaluate"
            },
            
            # No user agent
            {
                "headers": {},
                "description": "No user agent",
                "expected": "evaluate"
            },
            
            # Malicious user agent
            {
                "headers": {
                    "User-Agent": "<script>alert('xss')</script>",
                    "Accept": "application/json"
                },
                "description": "Malicious user agent",
                "expected": "block"
            }
        ]
        
        for context in device_contexts:
            # Merge device headers with auth headers
            test_headers = dict(auth_headers)
            test_headers.update(context["headers"])
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Device test from {context['description']}"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                test_headers, request, track_cost=False
            )
            
            # Analyze response based on device context
            if context["expected"] == "allow":
                # Standard devices should be allowed
                assert response.status_code in [200, 422], \
                    f"Standard device should be allowed: {context['description']}"
            
            elif context["expected"] == "evaluate":
                # Suspicious devices may be allowed with monitoring or blocked
                if response.status_code == 200:
                    logger.info(f"Suspicious device allowed: {context['description']}")
                else:
                    assert response.status_code in [401, 403, 429], \
                        f"Suspicious device should be handled appropriately: {context['description']}"
            
            elif context["expected"] == "block":
                # Malicious devices should be blocked
                assert response.status_code in [400, 401, 403], \
                    f"Malicious device should be blocked: {context['description']}"
            
            logger.info(f"Device context test: {context['description']} -> {response.status_code}")
        
        logger.info("ZTA_CONTEXT_DEVICE_001: Device context validation completed")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_context_behavior_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """ZTA_CONTEXT_BEHAVIOR_001: Behavioral context analysis"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test various behavioral patterns
        
        # Pattern 1: Normal usage pattern
        normal_requests = []
        for i in range(5):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Normal request {i} about general topics"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            normal_requests.append({
                "request_id": i,
                "status_code": response.status_code,
                "timestamp": time.time()
            })
            
            await asyncio.sleep(2)  # Normal spacing between requests
        
        # Pattern 2: Rapid/burst pattern (potentially suspicious)
        rapid_requests = []
        for i in range(8):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Rapid request {i}"}],
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            rapid_requests.append({
                "request_id": i,
                "status_code": response.status_code,
                "timestamp": time.time()
            })
            
            await asyncio.sleep(0.1)  # Very short spacing
        
        # Pattern 3: Repetitive content pattern (potentially automated)
        repetitive_requests = []
        for i in range(6):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Identical repetitive request"}],  # Same content
                "max_tokens": 30
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            repetitive_requests.append({
                "request_id": i,
                "status_code": response.status_code,
                "timestamp": time.time()
            })
            
            await asyncio.sleep(0.5)
        
        # Analyze behavioral patterns
        
        # Normal pattern analysis
        normal_success_rate = len([r for r in normal_requests if r["status_code"] == 200]) / len(normal_requests)
        assert normal_success_rate >= 0.8, "Normal behavior pattern should have high success rate"
        
        # Rapid pattern analysis  
        rapid_success_rate = len([r for r in rapid_requests if r["status_code"] == 200]) / len(rapid_requests)
        rapid_blocked_rate = len([r for r in rapid_requests if r["status_code"] == 429]) / len(rapid_requests)
        
        logger.info(f"Rapid pattern: {rapid_success_rate:.2%} success, {rapid_blocked_rate:.2%} rate limited")
        
        # Should show signs of rate limiting or behavioral detection
        if rapid_blocked_rate == 0:
            # If no rate limiting, verify reasonable behavior
            assert rapid_success_rate <= 0.9, "Rapid pattern should trigger some protection"
        
        # Repetitive pattern analysis
        repetitive_success_rate = len([r for r in repetitive_requests if r["status_code"] == 200]) / len(repetitive_requests)
        
        logger.info(f"Repetitive pattern: {repetitive_success_rate:.2%} success rate")
        
        # Repetitive patterns may indicate automation
        if repetitive_success_rate < normal_success_rate:
            logger.info("Repetitive pattern detection active")
        
        logger.info("ZTA_CONTEXT_BEHAVIOR_001: Behavioral context analysis completed")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_context_temporal_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """ZTA_CONTEXT_TEMPORAL_001: Temporal context evaluation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test temporal context awareness
        current_time = datetime.datetime.now()
        current_hour = current_time.hour
        
        # Test current time access
        current_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": f"Current time access test at {current_hour}:00"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, current_request
        )
        
        assert response.status_code == 200, "Current time access should succeed"
        
        # Test temporal patterns
        temporal_contexts = [
            {
                "time_context": "business_hours",
                "description": f"Business hours access (hour {current_hour})",
                "expected": "allow" if 9 <= current_hour <= 17 else "evaluate"
            },
            {
                "time_context": "off_hours",
                "description": f"Off hours access (hour {current_hour})",
                "expected": "evaluate" if current_hour < 6 or current_hour > 22 else "allow"
            },
            {
                "time_context": "weekend",
                "description": f"Weekend access (weekday {current_time.weekday()})",
                "expected": "evaluate" if current_time.weekday() >= 5 else "allow"
            }
        ]
        
        for context in temporal_contexts:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Temporal test: {context['description']}"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # In most implementations, temporal context is informational
            # But the system should handle requests appropriately
            assert response.status_code in [200, 422, 429], \
                f"Temporal context should be handled appropriately: {context['description']}"
            
            logger.info(f"Temporal context: {context['description']} -> {response.status_code}")
        
        # Test session duration context
        session_duration_test = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Long session duration test"}],
            "max_tokens": 50
        }
        
        # Add session duration hint (conceptual)
        session_headers = dict(auth_headers)
        session_headers["X-Session-Duration"] = "3600"  # 1 hour session
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            session_headers, session_duration_test, track_cost=False
        )
        
        # Should handle session context appropriately
        assert response.status_code in [200, 422], \
            "Session duration context should be handled"
        
        logger.info("ZTA_CONTEXT_TEMPORAL_001: Temporal context evaluation completed")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_context_risk_scoring_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """ZTA_CONTEXT_RISK_001: Context-based risk scoring"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test various risk contexts
        risk_scenarios = [
            # Low risk context
            {
                "context": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "X-Forwarded-For": "8.8.8.8",
                    "Accept": "application/json"
                },
                "content": "Low risk request for general information",
                "risk_level": "low",
                "expected": "allow"
            },
            
            # Medium risk context
            {
                "context": {
                    "User-Agent": "curl/7.68.0",
                    "X-Forwarded-For": "192.168.1.1",
                    "Accept": "*/*"
                },
                "content": "Medium risk automated request",
                "risk_level": "medium", 
                "expected": "evaluate"
            },
            
            # High risk context
            {
                "context": {
                    "User-Agent": "Python-urllib/3.9",
                    "X-Forwarded-For": "127.0.0.1",
                    "Accept": "application/json"
                },
                "content": "High risk request with suspicious patterns",
                "risk_level": "high",
                "expected": "challenge"
            },
            
            # Very high risk context
            {
                "context": {
                    "User-Agent": "<script>alert('xss')</script>",
                    "X-Forwarded-For": "10.0.0.1, 192.168.1.1, 127.0.0.1",
                    "Accept": "*/*"
                },
                "content": "Very high risk request with malicious indicators",
                "risk_level": "very_high",
                "expected": "block"
            }
        ]
        
        for scenario in risk_scenarios:
            # Merge risk context headers with auth headers
            test_headers = dict(auth_headers)
            test_headers.update(scenario["context"])
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["content"]}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                test_headers, request, track_cost=False
            )
            
            # Analyze response based on risk level
            if scenario["expected"] == "allow":
                # Low risk should be allowed
                assert response.status_code in [200, 422], \
                    f"Low risk context should be allowed: {scenario['risk_level']}"
            
            elif scenario["expected"] == "evaluate":
                # Medium risk may be allowed with monitoring
                if response.status_code == 200:
                    logger.info(f"Medium risk context allowed: {scenario['risk_level']}")
                else:
                    assert response.status_code in [401, 403, 429], \
                        f"Medium risk should be evaluated: {scenario['risk_level']}"
            
            elif scenario["expected"] == "challenge":
                # High risk may require additional verification
                if response.status_code == 200:
                    logger.info(f"High risk context allowed (may have additional controls): {scenario['risk_level']}")
                else:
                    assert response.status_code in [401, 403, 429], \
                        f"High risk should be challenged: {scenario['risk_level']}"
            
            elif scenario["expected"] == "block":
                # Very high risk should be blocked
                assert response.status_code in [400, 401, 403], \
                    f"Very high risk should be blocked: {scenario['risk_level']}"
            
            logger.info(f"Risk scoring test: {scenario['risk_level']} -> {response.status_code}")
        
        logger.info("ZTA_CONTEXT_RISK_001: Context-based risk scoring validated")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_context_adaptive_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """ZTA_CONTEXT_ADAPTIVE_001: Adaptive context-aware access control"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Test adaptive access control based on context changes
        
        # Baseline context establishment
        baseline_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Baseline context establishment"}],
            "max_tokens": 50
        }
        
        baseline_headers = dict(auth_headers)
        baseline_headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-Forwarded-For": "8.8.8.8"
        })
        
        baseline_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            baseline_headers, baseline_request
        )
        
        assert baseline_response.status_code == 200, "Baseline context should be established"
        
        # Context change scenarios
        context_changes = [
            # Minor context change
            {
                "change": "user_agent_update",
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (updated)",
                    "X-Forwarded-For": "8.8.8.8"
                },
                "description": "Minor user agent change",
                "expected": "allow_with_monitoring"
            },
            
            # Significant context change
            {
                "change": "location_change",
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "X-Forwarded-For": "1.1.1.1"  # Different location
                },
                "description": "Geographic location change",
                "expected": "challenge_or_allow"
            },
            
            # Major context change
            {
                "change": "device_change",
                "headers": {
                    "User-Agent": "curl/7.68.0",  # Completely different device/client
                    "X-Forwarded-For": "192.168.1.1"
                },
                "description": "Major device/client change",
                "expected": "challenge_or_block"
            }
        ]
        
        for change in context_changes:
            # Apply context change
            change_headers = dict(auth_headers)
            change_headers.update(change["headers"])
            
            change_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Context change test: {change['description']}"}],
                "max_tokens": 50
            }
            
            change_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                change_headers, change_request, track_cost=False
            )
            
            # Analyze adaptive response
            if change["expected"] == "allow_with_monitoring":
                # Minor changes should be allowed
                assert change_response.status_code in [200, 422], \
                    f"Minor context change should be allowed: {change['description']}"
            
            elif change["expected"] == "challenge_or_allow":
                # Significant changes may trigger additional verification
                if change_response.status_code == 200:
                    logger.info(f"Significant context change allowed: {change['description']}")
                else:
                    assert change_response.status_code in [401, 403, 429], \
                        f"Significant context change should be handled: {change['description']}"
            
            elif change["expected"] == "challenge_or_block":
                # Major changes should trigger strong verification or blocking
                if change_response.status_code == 200:
                    logger.info(f"Major context change allowed (may have additional controls): {change['description']}")
                else:
                    assert change_response.status_code in [401, 403, 429], \
                        f"Major context change should be challenged: {change['description']}"
            
            logger.info(f"Adaptive context test: {change['description']} -> {change_response.status_code}")
            
            # Small delay between context changes
            await asyncio.sleep(1)
        
        logger.info("ZTA_CONTEXT_ADAPTIVE_001: Adaptive context-aware access control validated")
    
    @pytest.mark.zero_trust
    @pytest.mark.asyncio
    async def test_zta_context_comprehensive_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """ZTA_CONTEXT_COMPREHENSIVE_001: Comprehensive context-aware access validation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust tests disabled")
        
        # Comprehensive context evaluation combining multiple factors
        comprehensive_contexts = [
            # Trusted context (all positive indicators)
            {
                "name": "trusted_context",
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "X-Forwarded-For": "8.8.8.8",
                    "Accept": "application/json",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Referer": "https://trusted-domain.com"
                },
                "content": "Standard business request during normal hours",
                "expected_behavior": "allow_readily"
            },
            
            # Mixed context (some positive, some neutral)
            {
                "name": "mixed_context",
                "headers": {
                    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
                    "X-Forwarded-For": "1.1.1.1",
                    "Accept": "application/json"
                },
                "content": "Mobile request from different geographic region",
                "expected_behavior": "allow_with_monitoring"
            },
            
            # Suspicious context (multiple negative indicators)
            {
                "name": "suspicious_context", 
                "headers": {
                    "User-Agent": "Python-urllib/3.9",
                    "X-Forwarded-For": "192.168.1.1, 10.0.0.1",
                    "Accept": "*/*"
                },
                "content": "Automated request through multiple proxies",
                "expected_behavior": "challenge_heavily"
            },
            
            # Highly suspicious context
            {
                "name": "highly_suspicious",
                "headers": {
                    "User-Agent": "curl/7.68.0",
                    "X-Forwarded-For": "127.0.0.1",
                    "Accept": "*/*",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "content": "Suspicious automated request with conflicting headers",
                "expected_behavior": "block_or_strong_challenge"
            }
        ]
        
        context_results = []
        
        for context in comprehensive_contexts:
            # Combine context headers with auth headers
            test_headers = dict(auth_headers)
            test_headers.update(context["headers"])
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": context["content"]}],
                "max_tokens": 100
            }
            
            start_time = time.time()
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                test_headers, request, track_cost=False
            )
            response_time = time.time() - start_time
            
            result = {
                "context_name": context["name"],
                "status_code": response.status_code,
                "response_time": response_time,
                "expected": context["expected_behavior"]
            }
            
            context_results.append(result)
            
            # Validate response based on expected behavior
            if context["expected_behavior"] == "allow_readily":
                assert response.status_code in [200, 422], \
                    f"Trusted context should be allowed readily: {context['name']}"
                assert response_time < 3.0, \
                    f"Trusted context should have fast response: {context['name']}"
            
            elif context["expected_behavior"] == "allow_with_monitoring":
                assert response.status_code in [200, 422, 429], \
                    f"Mixed context should be handled appropriately: {context['name']}"
            
            elif context["expected_behavior"] == "challenge_heavily":
                if response.status_code == 200:
                    # May be allowed but should take longer (additional verification)
                    logger.info(f"Suspicious context allowed (may have additional verification): {context['name']}")
                else:
                    assert response.status_code in [401, 403, 429], \
                        f"Suspicious context should be challenged: {context['name']}"
            
            elif context["expected_behavior"] == "block_or_strong_challenge":
                # Should be blocked or heavily challenged
                if response.status_code == 200:
                    logger.warning(f"Highly suspicious context allowed: {context['name']}")
                else:
                    assert response.status_code in [400, 401, 403, 429], \
                        f"Highly suspicious context should be blocked or challenged: {context['name']}"
            
            logger.info(f"Comprehensive context test: {context['name']} -> {response.status_code} ({response_time:.2f}s)")
            
            # Brief delay between tests
            await asyncio.sleep(0.5)
        
        # Analyze overall context-aware behavior
        allowed_requests = [r for r in context_results if r["status_code"] == 200]
        challenged_requests = [r for r in context_results if r["status_code"] in [401, 403, 429]]
        
        logger.info(f"Context-aware access summary:")
        logger.info(f"  - Allowed: {len(allowed_requests)}/{len(context_results)}")
        logger.info(f"  - Challenged/Blocked: {len(challenged_requests)}/{len(context_results)}")
        
        # Context-aware access should show graduated responses
        trusted_allowed = any(r["context_name"] == "trusted_context" and r["status_code"] == 200 for r in context_results)
        suspicious_handled = any(r["context_name"] in ["suspicious_context", "highly_suspicious"] and r["status_code"] != 200 for r in context_results)
        
        assert trusted_allowed, "Trusted contexts should generally be allowed"
        
        if not suspicious_handled:
            logger.info("Suspicious contexts were allowed - ensure additional monitoring is in place")
        
        logger.info("ZTA_CONTEXT_COMPREHENSIVE_001: Comprehensive context-aware access validation completed")


import asyncio  # Add this import at the top since we use asyncio.sleep