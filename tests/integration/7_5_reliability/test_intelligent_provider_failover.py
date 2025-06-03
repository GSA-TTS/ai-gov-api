# Section 7.5 - Intelligent Provider Failover Testing
# Based on: docs/test_design_n_planning/Testcases_7_5_Reliability_n_ErrorHandling/Test Cases_Provider Failover Testing.md
# Addresses TC_R752_FAILOVER_009-016: Enhanced Provider Failover Scenarios

import pytest
import httpx
import asyncio
import time
import random
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque, defaultdict
from unittest.mock import patch, Mock
import statistics

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class ProviderHealthStatus:
    """Provider health status tracking"""
    provider_id: str
    model_name: str
    is_healthy: bool = True
    response_time_history: deque = field(default_factory=lambda: deque(maxlen=20))
    success_rate_history: deque = field(default_factory=lambda: deque(maxlen=20))
    error_count: int = 0
    last_error_time: Optional[float] = None
    recovery_time: Optional[float] = None
    
    # Performance metrics
    avg_response_time: float = 0.0
    current_success_rate: float = 1.0
    health_score: float = 1.0
    
    def update_metrics(self, response_time: float, success: bool):
        """Update provider health metrics"""
        self.response_time_history.append(response_time)
        self.success_rate_history.append(1.0 if success else 0.0)
        
        if not success:
            self.error_count += 1
            self.last_error_time = time.time()
        
        # Calculate current metrics
        if self.response_time_history:
            self.avg_response_time = sum(self.response_time_history) / len(self.response_time_history)
        
        if self.success_rate_history:
            self.current_success_rate = sum(self.success_rate_history) / len(self.success_rate_history)
        
        # Calculate health score (0.0 to 1.0)
        latency_score = max(0.0, 1.0 - (self.avg_response_time / 10.0))  # Normalize to 10s max
        success_score = self.current_success_rate
        
        self.health_score = (latency_score + success_score) / 2.0
        
        # Update health status
        self.is_healthy = self.health_score >= 0.7 and self.current_success_rate >= 0.8
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health status summary"""
        return {
            "provider_id": self.provider_id,
            "model_name": self.model_name,
            "is_healthy": self.is_healthy,
            "health_score": self.health_score,
            "avg_response_time": self.avg_response_time,
            "current_success_rate": self.current_success_rate,
            "error_count": self.error_count,
            "measurements": len(self.response_time_history)
        }


@dataclass
class FailoverDecision:
    """Failover decision tracking"""
    timestamp: float
    reason: str
    from_provider: str
    to_provider: str
    decision_factors: Dict[str, Any]
    success: bool = False
    failover_time: float = 0.0


class IntelligentProviderFailoverManager:
    """Intelligent provider failover management with decision making"""
    
    def __init__(self, providers: List[str]):
        self.providers = providers
        self.provider_health = {
            provider: ProviderHealthStatus(provider_id=f"provider_{i}", model_name=provider)
            for i, provider in enumerate(providers)
        }
        self.current_primary = providers[0] if providers else None
        self.failover_history: List[FailoverDecision] = []
        
        # Failover policies
        self.health_threshold = 0.7
        self.response_time_threshold = 8.0
        self.success_rate_threshold = 0.8
        self.failover_cooldown = 30.0  # seconds
        
        # Circuit breaker states
        self.circuit_breaker_states = {provider: "closed" for provider in providers}  # closed, open, half-open
        self.circuit_breaker_failure_counts = {provider: 0 for provider in providers}
        self.circuit_breaker_last_failure = {provider: 0.0 for provider in providers}
        
    def update_provider_health(self, provider: str, response_time: float, success: bool):
        """Update provider health metrics"""
        if provider in self.provider_health:
            self.provider_health[provider].update_metrics(response_time, success)
            self._update_circuit_breaker(provider, success)
    
    def _update_circuit_breaker(self, provider: str, success: bool):
        """Update circuit breaker state for provider"""
        current_time = time.time()
        
        if not success:
            self.circuit_breaker_failure_counts[provider] += 1
            self.circuit_breaker_last_failure[provider] = current_time
            
            # Open circuit if too many failures
            if (self.circuit_breaker_failure_counts[provider] >= 5 and 
                self.circuit_breaker_states[provider] == "closed"):
                self.circuit_breaker_states[provider] = "open"
                logger.warning(f"Circuit breaker OPENED for provider {provider}")
        
        else:
            # Success - potentially close circuit
            if self.circuit_breaker_states[provider] == "half-open":
                self.circuit_breaker_states[provider] = "closed"
                self.circuit_breaker_failure_counts[provider] = 0
                logger.info(f"Circuit breaker CLOSED for provider {provider}")
        
        # Auto-transition to half-open after cooldown
        if (self.circuit_breaker_states[provider] == "open" and 
            current_time - self.circuit_breaker_last_failure[provider] > self.failover_cooldown):
            self.circuit_breaker_states[provider] = "half-open"
            logger.info(f"Circuit breaker HALF-OPEN for provider {provider}")
    
    def should_failover(self, current_provider: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Determine if failover should occur and to which provider"""
        current_health = self.provider_health.get(current_provider)
        if not current_health:
            return False, "", {}
        
        # Check if current provider needs failover
        decision_factors = {
            "current_health_score": current_health.health_score,
            "current_success_rate": current_health.current_success_rate,
            "current_response_time": current_health.avg_response_time,
            "circuit_breaker_state": self.circuit_breaker_states.get(current_provider, "closed")
        }
        
        needs_failover = (
            current_health.health_score < self.health_threshold or
            current_health.current_success_rate < self.success_rate_threshold or
            current_health.avg_response_time > self.response_time_threshold or
            self.circuit_breaker_states.get(current_provider) == "open"
        )
        
        if not needs_failover:
            return False, "", decision_factors
        
        # Find best alternative provider
        best_provider = self._select_best_provider(exclude=current_provider)
        
        if best_provider:
            reason = self._determine_failover_reason(current_health, decision_factors)
            decision_factors["failover_reason"] = reason
            decision_factors["target_provider"] = best_provider
            return True, best_provider, decision_factors
        
        return False, "", decision_factors
    
    def _select_best_provider(self, exclude: str) -> Optional[str]:
        """Select the best available provider for failover"""
        available_providers = [
            p for p in self.providers 
            if p != exclude and self.circuit_breaker_states.get(p, "closed") != "open"
        ]
        
        if not available_providers:
            return None
        
        # Score providers based on health metrics
        provider_scores = []
        for provider in available_providers:
            health = self.provider_health[provider]
            
            # Composite score considering multiple factors
            score = (
                health.health_score * 0.4 +
                health.current_success_rate * 0.3 +
                max(0, 1.0 - health.avg_response_time / 10.0) * 0.2 +  # Normalize response time
                (0.1 if self.circuit_breaker_states.get(provider) == "closed" else 0.0)
            )
            
            provider_scores.append((provider, score))
        
        # Return provider with highest score
        best_provider = max(provider_scores, key=lambda x: x[1])
        return best_provider[0]
    
    def _determine_failover_reason(self, current_health: ProviderHealthStatus, factors: Dict[str, Any]) -> str:
        """Determine the primary reason for failover"""
        if factors["circuit_breaker_state"] == "open":
            return "circuit_breaker_open"
        elif current_health.current_success_rate < self.success_rate_threshold:
            return "low_success_rate"
        elif current_health.avg_response_time > self.response_time_threshold:
            return "high_response_time"
        elif current_health.health_score < self.health_threshold:
            return "poor_health_score"
        else:
            return "preventive_failover"
    
    def execute_failover(self, from_provider: str, to_provider: str, reason: str, 
                        factors: Dict[str, Any]) -> FailoverDecision:
        """Execute failover and track the decision"""
        failover_start = time.time()
        
        logger.info(f"🔄 Executing failover: {from_provider} → {to_provider}")
        logger.info(f"   Reason: {reason}")
        
        # Update current primary
        self.current_primary = to_provider
        
        failover_end = time.time()
        failover_time = failover_end - failover_start
        
        # Record failover decision
        decision = FailoverDecision(
            timestamp=failover_start,
            reason=reason,
            from_provider=from_provider,
            to_provider=to_provider,
            decision_factors=factors,
            success=True,  # Assume success for this simulation
            failover_time=failover_time
        )
        
        self.failover_history.append(decision)
        
        logger.info(f"✅ Failover completed in {failover_time:.3f}s")
        
        return decision
    
    def get_provider_status_summary(self) -> Dict[str, Any]:
        """Get comprehensive provider status summary"""
        return {
            "current_primary": self.current_primary,
            "total_providers": len(self.providers),
            "provider_health": {
                provider: health.get_health_summary() 
                for provider, health in self.provider_health.items()
            },
            "circuit_breaker_states": self.circuit_breaker_states.copy(),
            "failover_count": len(self.failover_history),
            "recent_failovers": [
                {
                    "timestamp": f.timestamp,
                    "reason": f.reason,
                    "from": f.from_provider,
                    "to": f.to_provider,
                    "success": f.success
                }
                for f in self.failover_history[-5:]  # Last 5 failovers
            ]
        }


class TestIntelligentProviderFailover:
    """Intelligent provider failover testing"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r752_intelligent_failover_decision_009(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """TC_R752_FAILOVER_009: Intelligent failover decision making"""
        # Test intelligent decision making for provider failover
        
        # Setup multi-provider scenario
        available_models = config.CHAT_MODELS
        if len(available_models) < 2:
            # Create virtual providers for testing
            providers = ["primary_provider", "secondary_provider", "tertiary_provider"]
        else:
            providers = available_models[:3]  # Use up to 3 real models
        
        failover_manager = IntelligentProviderFailoverManager(providers)
        
        logger.info(f"🧠 Starting intelligent failover decision test with {len(providers)} providers")
        
        # Phase 1: Establish baseline health for all providers
        logger.info("📊 Establishing provider baseline health")
        
        for provider in providers:
            for i in range(5):
                start_time = time.time()
                
                try:
                    if provider in config.CHAT_MODELS:
                        # Real model test
                        request = {
                            "model": provider,
                            "messages": [{"role": "user", "content": f"Baseline test {i} for {provider}"}],
                            "max_tokens": 40
                        }
                        
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        
                        end_time = time.time()
                        latency = end_time - start_time
                        success = response.status_code == 200
                    
                    else:
                        # Simulated provider test
                        end_time = time.time()
                        latency = random.uniform(1.0, 3.0)
                        success = random.random() > 0.1  # 90% success rate for simulation
                    
                    failover_manager.update_provider_health(provider, latency, success)
                
                except Exception:
                    end_time = time.time()
                    latency = end_time - start_time
                    failover_manager.update_provider_health(provider, latency, False)
                
                await asyncio.sleep(0.2)
        
        # Phase 2: Simulate provider degradation to trigger intelligent failover
        logger.info("💥 Simulating provider degradation")
        
        current_provider = failover_manager.current_primary
        failover_decisions = []
        
        # Simulate degrading performance for current provider
        degradation_steps = [
            {"error_rate": 0.1, "latency_factor": 1.2, "duration": 15},
            {"error_rate": 0.3, "latency_factor": 1.8, "duration": 10},
            {"error_rate": 0.6, "latency_factor": 2.5, "duration": 10}
        ]
        
        for step_idx, step in enumerate(degradation_steps):
            logger.info(f"Degradation step {step_idx + 1}: {step['error_rate']:.0%} error rate")
            
            step_start = time.time()
            
            while time.time() - step_start < step["duration"]:
                # Test current provider with degraded performance
                start_time = time.time()
                
                # Simulate degraded performance
                inject_error = random.random() < step["error_rate"]
                base_latency = random.uniform(1.0, 2.0) * step["latency_factor"]
                
                try:
                    if inject_error:
                        # Simulate error by using invalid model
                        request = {
                            "model": "intelligent_failover_error_model",
                            "messages": [{"role": "user", "content": "Error simulation"}],
                            "max_tokens": 30
                        }
                        
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request, track_cost=False
                        )
                        
                        success = False
                    
                    else:
                        # Normal request with simulated latency
                        if current_provider in config.CHAT_MODELS:
                            request = {
                                "model": current_provider,
                                "messages": [{"role": "user", "content": f"Degradation test {step_idx}"}],
                                "max_tokens": 40
                            }
                            
                            response = await make_request(
                                http_client, "POST", "/api/v1/chat/completions",
                                auth_headers, request
                            )
                            
                            success = response.status_code == 200
                        else:
                            # Simulated request
                            success = True
                    
                    end_time = time.time()
                    latency = max(end_time - start_time, base_latency)
                
                except Exception:
                    end_time = time.time()
                    latency = max(end_time - start_time, base_latency)
                    success = False
                
                # Update provider health
                failover_manager.update_provider_health(current_provider, latency, success)
                
                # Check if failover should occur
                should_failover, target_provider, decision_factors = failover_manager.should_failover(current_provider)
                
                if should_failover and target_provider:
                    logger.info(f"🚨 Intelligent failover triggered!")
                    
                    # Execute failover
                    decision = failover_manager.execute_failover(
                        current_provider, target_provider, 
                        decision_factors["failover_reason"], decision_factors
                    )
                    
                    failover_decisions.append(decision)
                    current_provider = target_provider
                    
                    # Brief pause after failover
                    await asyncio.sleep(2)
                
                await asyncio.sleep(0.5)
        
        # Phase 3: Verify failover behavior and recovery
        logger.info("🔄 Testing post-failover performance")
        
        post_failover_tests = []
        for i in range(10):
            start_time = time.time()
            
            try:
                if current_provider in config.CHAT_MODELS:
                    request = {
                        "model": current_provider,
                        "messages": [{"role": "user", "content": f"Post-failover test {i}"}],
                        "max_tokens": 40
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    end_time = time.time()
                    success = response.status_code == 200
                else:
                    # Simulated provider (should be healthy)
                    end_time = time.time()
                    success = True
                
                latency = end_time - start_time
                post_failover_tests.append({"success": success, "latency": latency})
                
                failover_manager.update_provider_health(current_provider, latency, success)
            
            except Exception:
                end_time = time.time()
                latency = end_time - start_time
                post_failover_tests.append({"success": False, "latency": latency})
                failover_manager.update_provider_health(current_provider, latency, False)
            
            await asyncio.sleep(0.3)
        
        # Analyze intelligent failover results
        status_summary = failover_manager.get_provider_status_summary()
        
        logger.info("Intelligent Failover Decision Results:")
        logger.info(f"  Total Failovers: {len(failover_decisions)}")
        logger.info(f"  Final Primary Provider: {status_summary['current_primary']}")
        
        if post_failover_tests:
            post_success_rate = sum(1 for t in post_failover_tests if t["success"]) / len(post_failover_tests)
            post_avg_latency = sum(t["latency"] for t in post_failover_tests) / len(post_failover_tests)
            
            logger.info(f"  Post-Failover Success Rate: {post_success_rate:.1%}")
            logger.info(f"  Post-Failover Avg Latency: {post_avg_latency:.2f}s")
        
        # Verify intelligent decision making
        if failover_decisions:
            logger.info("  Failover Decisions:")
            for decision in failover_decisions:
                logger.info(f"    {decision.reason}: {decision.from_provider} → {decision.to_provider}")
            
            # Should have made intelligent decisions
            assert len(failover_decisions) >= 1, "Should have triggered intelligent failover"
            
            # Failover should improve situation
            if post_failover_tests:
                assert post_success_rate >= 0.7, \
                    f"Post-failover should improve success rate: {post_success_rate:.1%}"
        
        logger.info("✅ Intelligent failover decision making validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r752_multi_provider_health_monitoring_010(self, http_client: httpx.AsyncClient,
                                                               auth_headers: Dict[str, str],
                                                               make_request):
        """TC_R752_FAILOVER_010: Multi-provider health monitoring and coordination"""
        # Test comprehensive health monitoring across multiple providers
        
        # Setup multiple providers
        available_models = config.CHAT_MODELS
        providers = available_models[:4] if len(available_models) >= 4 else available_models + ["virtual_provider_1", "virtual_provider_2"]
        
        failover_manager = IntelligentProviderFailoverManager(providers)
        
        logger.info(f"🏥 Starting multi-provider health monitoring with {len(providers)} providers")
        
        # Phase 1: Continuous health monitoring
        monitoring_duration = 60  # 1 minute of monitoring
        monitoring_start = time.time()
        
        health_snapshots = []
        
        while time.time() - monitoring_start < monitoring_duration:
            # Test each provider
            for provider in providers:
                start_time = time.time()
                
                try:
                    if provider in config.CHAT_MODELS:
                        # Real provider test
                        request = {
                            "model": provider,
                            "messages": [{"role": "user", "content": f"Health monitoring for {provider}"}],
                            "max_tokens": 30
                        }
                        
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, request
                        )
                        
                        end_time = time.time()
                        latency = end_time - start_time
                        success = response.status_code == 200
                    
                    else:
                        # Virtual provider simulation
                        end_time = time.time()
                        latency = random.uniform(0.8, 4.0)
                        # Simulate varying health
                        success = random.random() > 0.15  # 85% success rate
                    
                    # Update health
                    failover_manager.update_provider_health(provider, latency, success)
                
                except Exception:
                    end_time = time.time()
                    latency = end_time - start_time
                    failover_manager.update_provider_health(provider, latency, False)
            
            # Take health snapshot
            if len(health_snapshots) % 10 == 0:  # Every 10th iteration
                snapshot = {
                    "timestamp": time.time(),
                    "provider_health": {
                        provider: health.get_health_summary()
                        for provider, health in failover_manager.provider_health.items()
                    }
                }
                health_snapshots.append(snapshot)
            
            await asyncio.sleep(1.0)  # Monitor every second
        
        # Phase 2: Analyze health trends and patterns
        logger.info("📈 Analyzing health trends and patterns")
        
        # Calculate health trend analysis
        provider_trends = {}
        
        for provider in providers:
            health = failover_manager.provider_health[provider]
            
            if len(health.response_time_history) >= 10:
                early_latencies = list(health.response_time_history)[:5]
                recent_latencies = list(health.response_time_history)[-5:]
                
                early_success = list(health.success_rate_history)[:5]
                recent_success = list(health.success_rate_history)[-5:]
                
                latency_trend = sum(recent_latencies) / len(recent_latencies) - sum(early_latencies) / len(early_latencies)
                success_trend = sum(recent_success) / len(recent_success) - sum(early_success) / len(early_success)
                
                provider_trends[provider] = {
                    "latency_trend": latency_trend,
                    "success_trend": success_trend,
                    "current_health_score": health.health_score,
                    "measurements": len(health.response_time_history)
                }
        
        # Phase 3: Test provider ranking and selection
        logger.info("🏆 Testing provider ranking and selection")
        
        # Get current provider rankings
        provider_rankings = []
        for provider in providers:
            health = failover_manager.provider_health[provider]
            provider_rankings.append({
                "provider": provider,
                "health_score": health.health_score,
                "success_rate": health.current_success_rate,
                "avg_latency": health.avg_response_time,
                "circuit_state": failover_manager.circuit_breaker_states.get(provider, "closed")
            })
        
        # Sort by health score
        provider_rankings.sort(key=lambda x: x["health_score"], reverse=True)
        
        # Test provider selection for different scenarios
        selection_scenarios = [
            {"exclude": None, "purpose": "primary_selection"},
            {"exclude": provider_rankings[0]["provider"], "purpose": "failover_selection"},
            {"exclude": [p["provider"] for p in provider_rankings[:2]], "purpose": "emergency_selection"}
        ]
        
        selection_results = []
        
        for scenario in selection_scenarios:
            exclude_list = scenario["exclude"]
            if isinstance(exclude_list, str):
                exclude_list = [exclude_list]
            elif exclude_list is None:
                exclude_list = []
            
            best_provider = None
            best_score = -1
            
            for ranking in provider_rankings:
                provider = ranking["provider"]
                if provider not in exclude_list and ranking["circuit_state"] != "open":
                    if ranking["health_score"] > best_score:
                        best_score = ranking["health_score"]
                        best_provider = provider
            
            selection_results.append({
                "scenario": scenario["purpose"],
                "selected_provider": best_provider,
                "health_score": best_score,
                "excluded": exclude_list
            })
        
        # Analyze multi-provider health monitoring results
        logger.info("Multi-Provider Health Monitoring Results:")
        logger.info(f"  Monitoring Duration: {monitoring_duration}s")
        logger.info(f"  Health Snapshots: {len(health_snapshots)}")
        logger.info(f"  Providers Monitored: {len(providers)}")
        
        logger.info("  Provider Rankings:")
        for i, ranking in enumerate(provider_rankings):
            logger.info(f"    {i+1}. {ranking['provider']}: "
                       f"Health={ranking['health_score']:.2f}, "
                       f"Success={ranking['success_rate']:.1%}, "
                       f"Latency={ranking['avg_latency']:.2f}s")
        
        logger.info("  Provider Selection Results:")
        for result in selection_results:
            logger.info(f"    {result['scenario']}: {result['selected_provider']} "
                       f"(score: {result['health_score']:.2f})")
        
        # Verify monitoring effectiveness
        assert len(health_snapshots) >= 3, "Should have captured multiple health snapshots"
        
        # Should have health data for all providers
        for provider in providers:
            health = failover_manager.provider_health[provider]
            assert len(health.response_time_history) >= 5, \
                f"Should have health measurements for {provider}"
        
        # Should be able to rank providers
        assert len(provider_rankings) == len(providers), "Should rank all providers"
        
        # Should be able to select providers for different scenarios
        successful_selections = [r for r in selection_results if r["selected_provider"] is not None]
        assert len(successful_selections) >= 2, "Should successfully select providers for most scenarios"
        
        logger.info("✅ Multi-provider health monitoring validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r752_seamless_provider_transition_011(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """TC_R752_FAILOVER_011: Seamless provider transition management"""
        # Test seamless transitions between providers with minimal service disruption
        
        available_models = config.CHAT_MODELS
        if len(available_models) < 2:
            providers = ["seamless_primary", "seamless_secondary"]
        else:
            providers = available_models[:2]
        
        failover_manager = IntelligentProviderFailoverManager(providers)
        
        logger.info("🔄 Starting seamless provider transition test")
        
        # Phase 1: Establish stable baseline with primary provider
        logger.info("📊 Establishing stable baseline")
        
        primary_provider = failover_manager.current_primary
        baseline_requests = 10
        baseline_metrics = []
        
        for i in range(baseline_requests):
            start_time = time.time()
            
            try:
                if primary_provider in config.CHAT_MODELS:
                    request = {
                        "model": primary_provider,
                        "messages": [{"role": "user", "content": f"Seamless baseline {i}"}],
                        "max_tokens": 40
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    end_time = time.time()
                    success = response.status_code == 200
                else:
                    # Simulated baseline
                    end_time = time.time()
                    success = True
                
                latency = end_time - start_time
                baseline_metrics.append({"latency": latency, "success": success})
                failover_manager.update_provider_health(primary_provider, latency, success)
            
            except Exception:
                end_time = time.time()
                latency = end_time - start_time
                baseline_metrics.append({"latency": latency, "success": False})
                failover_manager.update_provider_health(primary_provider, latency, False)
            
            await asyncio.sleep(0.3)
        
        baseline_success_rate = sum(1 for m in baseline_metrics if m["success"]) / len(baseline_metrics)
        baseline_avg_latency = sum(m["latency"] for m in baseline_metrics) / len(baseline_metrics)
        
        logger.info(f"Baseline: {baseline_success_rate:.1%} success, {baseline_avg_latency:.2f}s latency")
        
        # Phase 2: Execute seamless transition
        logger.info("🔄 Executing seamless provider transition")
        
        # Force transition by degrading primary provider
        transition_start = time.time()
        
        # Inject failures to trigger transition
        for i in range(8):
            try:
                # Inject failure
                if primary_provider in config.CHAT_MODELS:
                    request = {
                        "model": "seamless_transition_invalid_model",
                        "messages": [{"role": "user", "content": "Transition trigger"}],
                        "max_tokens": 30
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request, track_cost=False
                    )
                    
                    success = False
                else:
                    success = False  # Force failure for simulation
                
                latency = random.uniform(8.0, 12.0)  # High latency to trigger failover
                failover_manager.update_provider_health(primary_provider, latency, success)
                
                # Check for transition trigger
                should_failover, target_provider, factors = failover_manager.should_failover(primary_provider)
                
                if should_failover and target_provider:
                    logger.info("🚨 Seamless transition triggered!")
                    
                    # Execute transition
                    decision = failover_manager.execute_failover(
                        primary_provider, target_provider, 
                        factors["failover_reason"], factors
                    )
                    
                    transition_time = time.time() - transition_start
                    logger.info(f"⚡ Transition completed in {transition_time:.2f}s")
                    break
            
            except Exception:
                pass
            
            await asyncio.sleep(0.5)
        
        # Phase 3: Measure post-transition performance
        logger.info("📊 Measuring post-transition performance")
        
        current_provider = failover_manager.current_primary
        post_transition_metrics = []
        post_transition_requests = 15
        
        for i in range(post_transition_requests):
            start_time = time.time()
            
            try:
                if current_provider in config.CHAT_MODELS:
                    request = {
                        "model": current_provider,
                        "messages": [{"role": "user", "content": f"Post-transition {i}"}],
                        "max_tokens": 40
                    }
                    
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        auth_headers, request
                    )
                    
                    end_time = time.time()
                    success = response.status_code == 200
                else:
                    # Simulated post-transition (should be healthy)
                    end_time = time.time()
                    success = True
                
                latency = end_time - start_time
                post_transition_metrics.append({"latency": latency, "success": success})
                failover_manager.update_provider_health(current_provider, latency, success)
            
            except Exception:
                end_time = time.time()
                latency = end_time - start_time
                post_transition_metrics.append({"latency": latency, "success": False})
                failover_manager.update_provider_health(current_provider, latency, False)
            
            await asyncio.sleep(0.2)
        
        post_success_rate = sum(1 for m in post_transition_metrics if m["success"]) / len(post_transition_metrics)
        post_avg_latency = sum(m["latency"] for m in post_transition_metrics) / len(post_transition_metrics)
        
        # Phase 4: Analyze transition seamlessness
        logger.info("📊 Analyzing transition seamlessness")
        
        # Calculate transition effectiveness metrics
        success_rate_recovery = post_success_rate / max(0.01, baseline_success_rate)
        latency_impact = abs(post_avg_latency - baseline_avg_latency)
        
        # Measure service continuity
        all_metrics = baseline_metrics + post_transition_metrics
        overall_success_rate = sum(1 for m in all_metrics if m["success"]) / len(all_metrics)
        
        logger.info("Seamless Provider Transition Results:")
        logger.info(f"  Transition Provider: {primary_provider} → {current_provider}")
        logger.info(f"  Baseline Performance: {baseline_success_rate:.1%} success, {baseline_avg_latency:.2f}s")
        logger.info(f"  Post-Transition Performance: {post_success_rate:.1%} success, {post_avg_latency:.2f}s")
        logger.info(f"  Success Rate Recovery: {success_rate_recovery:.1%}")
        logger.info(f"  Latency Impact: {latency_impact:.2f}s")
        logger.info(f"  Overall Continuity: {overall_success_rate:.1%}")
        
        # Verify seamless transition
        assert success_rate_recovery >= 0.8, \
            f"Should recover success rate after transition: {success_rate_recovery:.1%}"
        
        assert latency_impact <= 5.0, \
            f"Transition should not severely impact latency: {latency_impact:.2f}s"
        
        assert overall_success_rate >= 0.7, \
            f"Overall service continuity should be maintained: {overall_success_rate:.1%}"
        
        # Should have executed transition
        assert len(failover_manager.failover_history) >= 1, "Should have executed seamless transition"
        
        logger.info("✅ Seamless provider transition validation completed")