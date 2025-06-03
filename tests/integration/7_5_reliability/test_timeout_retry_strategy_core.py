# Section 7.5 - Timeout and Retry Strategy Core Tests
# Missing Core Tests: TC_R754_TIMEOUT_001, 002, 003, 004, TC_R754_RETRY_001

import pytest
import httpx
import asyncio
import time
import random
from typing import Dict, Any, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import threading

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class TimeoutConfig:
    """Timeout configuration for testing"""
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    write_timeout: float = 10.0
    pool_timeout: float = 5.0
    total_timeout: float = 60.0
    
    def to_httpx_timeout(self) -> httpx.Timeout:
        """Convert to httpx timeout"""
        return httpx.Timeout(
            connect=self.connect_timeout,
            read=self.read_timeout,
            write=self.write_timeout,
            pool=self.pool_timeout
        )


@dataclass
class RetryConfig:
    """Retry configuration for testing"""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    backoff_factor: float = 2.0
    jitter: bool = True
    retry_on_status: List[int] = field(default_factory=lambda: [500, 502, 503, 504])
    retry_on_timeout: bool = True
    retry_on_connection_error: bool = True


@dataclass
class TimeoutEvent:
    """Represents a timeout event"""
    event_type: str  # connect, read, write, pool, total
    timestamp: float
    duration: float
    request_context: Dict[str, Any]
    recovery_attempted: bool = False
    recovery_successful: bool = False


@dataclass
class RetryAttempt:
    """Represents a retry attempt"""
    attempt_number: int
    timestamp: float
    delay_before: float
    timeout_config: TimeoutConfig
    error_type: str
    error_message: str
    recovery_strategy: str
    success: bool = False


class ProgressiveTimeoutManager:
    """Manages progressive timeout strategies"""
    
    def __init__(self, base_config: TimeoutConfig):
        self.base_config = base_config
        self.timeout_history: deque = deque(maxlen=100)
        self.success_rate = 1.0
        self.adaptive_factor = 1.0
        
    def get_adaptive_timeout(self, attempt: int = 1) -> TimeoutConfig:
        """Get adaptive timeout based on history and attempt"""
        
        # Calculate adaptive factor based on recent success rate
        if len(self.timeout_history) > 5:
            recent_successes = sum(1 for event in list(self.timeout_history)[-10:] if event.get("success", False))
            self.success_rate = recent_successes / min(10, len(self.timeout_history))
            
            # Increase timeouts if success rate is low
            if self.success_rate < 0.7:
                self.adaptive_factor = min(3.0, self.adaptive_factor * 1.2)
            elif self.success_rate > 0.9:
                self.adaptive_factor = max(1.0, self.adaptive_factor * 0.95)
        
        # Progressive timeout increase with attempts
        attempt_factor = 1.0 + (attempt - 1) * 0.5
        total_factor = self.adaptive_factor * attempt_factor
        
        return TimeoutConfig(
            connect_timeout=self.base_config.connect_timeout * total_factor,
            read_timeout=self.base_config.read_timeout * total_factor,
            write_timeout=self.base_config.write_timeout * total_factor,
            pool_timeout=self.base_config.pool_timeout * total_factor,
            total_timeout=self.base_config.total_timeout * total_factor
        )
    
    def record_timeout_event(self, event_type: str, duration: float, success: bool, context: Dict[str, Any] = None):
        """Record a timeout event"""
        event = {
            "type": event_type,
            "duration": duration,
            "success": success,
            "timestamp": time.time(),
            "context": context or {}
        }
        self.timeout_history.append(event)
    
    def get_timeout_analytics(self) -> Dict[str, Any]:
        """Get timeout analytics"""
        if not self.timeout_history:
            return {"error": "no_data"}
        
        events = list(self.timeout_history)
        
        return {
            "total_events": len(events),
            "success_rate": self.success_rate,
            "adaptive_factor": self.adaptive_factor,
            "avg_duration": sum(e["duration"] for e in events) / len(events),
            "timeout_types": {t: sum(1 for e in events if e["type"] == t) 
                           for t in set(e["type"] for e in events)},
            "recent_trend": "improving" if self.success_rate > 0.8 else "degrading" if self.success_rate < 0.6 else "stable"
        }


class IntelligentRetryManager:
    """Manages intelligent retry strategies with circuit breaker integration"""
    
    def __init__(self, config: RetryConfig):
        self.config = config
        self.retry_history: List[RetryAttempt] = []
        self.circuit_breaker_states: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "state": "closed",  # closed, open, half_open
            "failure_count": 0,
            "last_failure": 0,
            "failure_threshold": 5,
            "recovery_timeout": 30.0
        })
        
    def should_retry(self, attempt: int, error: Exception, response: Optional[httpx.Response] = None) -> bool:
        """Determine if request should be retried"""
        
        if attempt >= self.config.max_attempts:
            return False
        
        # Check circuit breaker state
        error_type = type(error).__name__
        circuit_state = self.circuit_breaker_states[error_type]
        
        if circuit_state["state"] == "open":
            # Check if circuit should transition to half-open
            if time.time() - circuit_state["last_failure"] > circuit_state["recovery_timeout"]:
                circuit_state["state"] = "half_open"
                return True
            return False
        
        # Standard retry conditions
        if isinstance(error, httpx.TimeoutException) and self.config.retry_on_timeout:
            return True
        
        if isinstance(error, (httpx.ConnectError, httpx.NetworkError)) and self.config.retry_on_connection_error:
            return True
        
        if response and response.status_code in self.config.retry_on_status:
            return True
        
        return False
    
    def calculate_retry_delay(self, attempt: int) -> float:
        """Calculate retry delay with exponential backoff and jitter"""
        
        # Exponential backoff
        delay = self.config.base_delay * (self.config.backoff_factor ** (attempt - 1))
        delay = min(delay, self.config.max_delay)
        
        # Add jitter to prevent thundering herd
        if self.config.jitter:
            jitter_amount = delay * 0.1
            delay += random.uniform(-jitter_amount, jitter_amount)
        
        return max(0.1, delay)
    
    def record_retry_attempt(self, attempt: RetryAttempt):
        """Record a retry attempt"""
        self.retry_history.append(attempt)
        
        # Update circuit breaker state
        circuit_state = self.circuit_breaker_states[attempt.error_type]
        
        if attempt.success:
            if circuit_state["state"] == "half_open":
                circuit_state["state"] = "closed"
                circuit_state["failure_count"] = 0
        else:
            circuit_state["failure_count"] += 1
            circuit_state["last_failure"] = time.time()
            
            if circuit_state["failure_count"] >= circuit_state["failure_threshold"]:
                circuit_state["state"] = "open"
    
    def get_retry_analytics(self) -> Dict[str, Any]:
        """Get retry analytics"""
        if not self.retry_history:
            return {"error": "no_data"}
        
        attempts_by_error = defaultdict(list)
        for attempt in self.retry_history:
            attempts_by_error[attempt.error_type].append(attempt)
        
        success_rate = sum(1 for a in self.retry_history if a.success) / len(self.retry_history)
        
        return {
            "total_attempts": len(self.retry_history),
            "success_rate": success_rate,
            "avg_attempts_per_request": len(self.retry_history) / max(1, len(set(a.timestamp // 60 for a in self.retry_history))),
            "error_breakdown": {error: len(attempts) for error, attempts in attempts_by_error.items()},
            "circuit_breaker_states": dict(self.circuit_breaker_states),
            "strategy_effectiveness": self._analyze_strategy_effectiveness()
        }
    
    def _analyze_strategy_effectiveness(self) -> Dict[str, Any]:
        """Analyze effectiveness of retry strategies"""
        if len(self.retry_history) < 5:
            return {"insufficient_data": True}
        
        strategy_results = defaultdict(list)
        for attempt in self.retry_history:
            strategy_results[attempt.recovery_strategy].append(attempt.success)
        
        return {
            strategy: {
                "attempts": len(results),
                "success_rate": sum(results) / len(results)
            }
            for strategy, results in strategy_results.items()
        }


class TimeoutRetryTester:
    """Testing framework for timeout and retry strategies"""
    
    def __init__(self):
        self.timeout_manager = ProgressiveTimeoutManager(TimeoutConfig())
        self.retry_manager = IntelligentRetryManager(RetryConfig())
        self.test_results: List[Dict[str, Any]] = []
    
    async def test_with_retry(self, http_client: httpx.AsyncClient, 
                            auth_headers: Dict[str, str], 
                            request_config: Dict[str, Any],
                            timeout_config: Optional[TimeoutConfig] = None,
                            max_attempts: int = 3) -> Dict[str, Any]:
        """Test request with retry logic"""
        
        if timeout_config is None:
            timeout_config = self.timeout_manager.get_adaptive_timeout()
        
        attempt = 1
        last_error = None
        last_response = None
        
        while attempt <= max_attempts:
            start_time = time.time()
            
            try:
                # Update timeout for this attempt
                current_timeout = self.timeout_manager.get_adaptive_timeout(attempt)
                
                # Create client with timeout
                timeout_httpx = current_timeout.to_httpx_timeout()
                
                response = await http_client.request(
                    method="POST",
                    url=f"{config.base_url}/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request_config,
                    timeout=timeout_httpx
                )
                
                end_time = time.time()
                duration = end_time - start_time
                
                # Record successful attempt
                self.timeout_manager.record_timeout_event("success", duration, True)
                
                retry_attempt = RetryAttempt(
                    attempt_number=attempt,
                    timestamp=start_time,
                    delay_before=0 if attempt == 1 else self.retry_manager.calculate_retry_delay(attempt - 1),
                    timeout_config=current_timeout,
                    error_type="none",
                    error_message="",
                    recovery_strategy="success",
                    success=True
                )
                self.retry_manager.record_retry_attempt(retry_attempt)
                
                return {
                    "success": True,
                    "attempts": attempt,
                    "duration": duration,
                    "response": response,
                    "timeout_config": current_timeout,
                    "final_attempt": retry_attempt
                }
            
            except httpx.TimeoutException as e:
                end_time = time.time()
                duration = end_time - start_time
                last_error = e
                
                error_type = type(e).__name__
                self.timeout_manager.record_timeout_event(error_type, duration, False)
                
                retry_attempt = RetryAttempt(
                    attempt_number=attempt,
                    timestamp=start_time,
                    delay_before=0 if attempt == 1 else self.retry_manager.calculate_retry_delay(attempt - 1),
                    timeout_config=current_timeout,
                    error_type=error_type,
                    error_message=str(e),
                    recovery_strategy="timeout_retry",
                    success=False
                )
                self.retry_manager.record_retry_attempt(retry_attempt)
                
                if attempt < max_attempts and self.retry_manager.should_retry(attempt, e):
                    delay = self.retry_manager.calculate_retry_delay(attempt)
                    logger.warning(f"Timeout on attempt {attempt}, retrying in {delay:.1f}s")
                    await asyncio.sleep(delay)
                    attempt += 1
                else:
                    break
            
            except (httpx.ConnectError, httpx.NetworkError) as e:
                end_time = time.time()
                duration = end_time - start_time
                last_error = e
                
                error_type = type(e).__name__
                self.timeout_manager.record_timeout_event(error_type, duration, False)
                
                retry_attempt = RetryAttempt(
                    attempt_number=attempt,
                    timestamp=start_time,
                    delay_before=0 if attempt == 1 else self.retry_manager.calculate_retry_delay(attempt - 1),
                    timeout_config=current_timeout,
                    error_type=error_type,
                    error_message=str(e),
                    recovery_strategy="connection_retry",
                    success=False
                )
                self.retry_manager.record_retry_attempt(retry_attempt)
                
                if attempt < max_attempts and self.retry_manager.should_retry(attempt, e):
                    delay = self.retry_manager.calculate_retry_delay(attempt)
                    logger.warning(f"Connection error on attempt {attempt}, retrying in {delay:.1f}s")
                    await asyncio.sleep(delay)
                    attempt += 1
                else:
                    break
            
            except Exception as e:
                end_time = time.time()
                duration = end_time - start_time
                last_error = e
                
                error_type = type(e).__name__
                self.timeout_manager.record_timeout_event(error_type, duration, False)
                
                retry_attempt = RetryAttempt(
                    attempt_number=attempt,
                    timestamp=start_time,
                    delay_before=0 if attempt == 1 else self.retry_manager.calculate_retry_delay(attempt - 1),
                    timeout_config=current_timeout,
                    error_type=error_type,
                    error_message=str(e),
                    recovery_strategy="general_retry",
                    success=False
                )
                self.retry_manager.record_retry_attempt(retry_attempt)
                
                # Don't retry on unexpected errors unless specifically configured
                break
        
        return {
            "success": False,
            "attempts": attempt,
            "last_error": last_error,
            "timeout_config": current_timeout,
            "error_type": type(last_error).__name__ if last_error else "unknown"
        }


class TestTimeoutRetryStrategyCore:
    """Core timeout and retry strategy tests"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r754_timeout_001_connect_timeout_handling(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """TC_R754_TIMEOUT_001: Connect timeout handling and recovery"""
        # Test connect timeout scenarios and recovery mechanisms
        
        logger.info("🔌 Testing connect timeout handling")
        
        tester = TimeoutRetryTester()
        
        # Test different connect timeout configurations
        timeout_scenarios = [
            {"connect_timeout": 1.0, "description": "Very short connect timeout"},
            {"connect_timeout": 5.0, "description": "Short connect timeout"},
            {"connect_timeout": 15.0, "description": "Normal connect timeout"},
            {"connect_timeout": 30.0, "description": "Long connect timeout"}
        ]
        
        timeout_results = []
        
        for scenario in timeout_scenarios:
            logger.info(f"Testing {scenario['description']}: {scenario['connect_timeout']}s")
            
            timeout_config = TimeoutConfig(
                connect_timeout=scenario["connect_timeout"],
                read_timeout=30.0,
                write_timeout=10.0,
                total_timeout=60.0
            )
            
            request_config = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Connect timeout test"}],
                "max_tokens": 50
            }
            
            # Test multiple requests to see consistency
            scenario_attempts = 3
            successful_connects = 0
            total_connect_time = 0
            
            for attempt in range(scenario_attempts):
                start_time = time.time()
                
                try:
                    result = await tester.test_with_retry(
                        http_client, auth_headers, request_config, timeout_config, max_attempts=2
                    )
                    
                    connect_time = time.time() - start_time
                    total_connect_time += connect_time
                    
                    if result["success"]:
                        successful_connects += 1
                    
                    logger.info(f"  Attempt {attempt + 1}: {'✅' if result['success'] else '❌'} ({connect_time:.2f}s)")
                
                except Exception as e:
                    connect_time = time.time() - start_time
                    total_connect_time += connect_time
                    logger.warning(f"  Attempt {attempt + 1}: Exception {e} ({connect_time:.2f}s)")
                
                await asyncio.sleep(1.0)
            
            avg_connect_time = total_connect_time / scenario_attempts
            success_rate = successful_connects / scenario_attempts
            
            timeout_results.append({
                "scenario": scenario,
                "successful_connects": successful_connects,
                "total_attempts": scenario_attempts,
                "success_rate": success_rate,
                "avg_connect_time": avg_connect_time,
                "timeout_effective": avg_connect_time <= scenario["connect_timeout"] * 1.2
            })
        
        # Analyze timeout analytics
        timeout_analytics = tester.timeout_manager.get_timeout_analytics()
        
        logger.info("Connect Timeout Handling Results:")
        logger.info(f"  Timeout Analytics: {timeout_analytics}")
        
        for result in timeout_results:
            scenario = result["scenario"]
            logger.info(f"  {scenario['description']}:")
            logger.info(f"    Success rate: {result['success_rate']:.1%}")
            logger.info(f"    Avg connect time: {result['avg_connect_time']:.2f}s")
            logger.info(f"    Timeout effective: {'✅' if result['timeout_effective'] else '❌'}")
        
        # Verify connect timeout handling
        assert len(timeout_results) == len(timeout_scenarios), "Should test all timeout scenarios"
        
        # At least normal and long timeouts should have good success rates
        long_timeout_results = [r for r in timeout_results if r["scenario"]["connect_timeout"] >= 15.0]
        good_success_rates = sum(1 for r in long_timeout_results if r["success_rate"] >= 0.67)
        assert good_success_rates >= len(long_timeout_results) // 2, \
            "Longer timeouts should have better success rates"
        
        # Timeout effectiveness should work for most scenarios
        effective_timeouts = sum(1 for r in timeout_results if r["timeout_effective"])
        assert effective_timeouts >= len(timeout_results) // 2, \
            "Timeouts should be effective in most scenarios"
        
        logger.info("✅ Connect timeout handling validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r754_timeout_002_read_timeout_handling(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """TC_R754_TIMEOUT_002: Read timeout handling and progressive timeouts"""
        # Test read timeout scenarios with progressive timeout strategies
        
        logger.info("📖 Testing read timeout handling")
        
        tester = TimeoutRetryTester()
        
        # Test scenarios that might cause read timeouts
        read_timeout_scenarios = [
            {
                "content": "Generate a detailed response: " + "comprehensive analysis " * 100,
                "max_tokens": 500,
                "read_timeout": 10.0,
                "description": "Large content with short timeout"
            },
            {
                "content": "Generate a moderate response about API testing",
                "max_tokens": 200,
                "read_timeout": 20.0,
                "description": "Moderate content with normal timeout"
            },
            {
                "content": "Simple response test",
                "max_tokens": 50,
                "read_timeout": 30.0,
                "description": "Simple content with long timeout"
            }
        ]
        
        progressive_results = []
        
        for scenario in read_timeout_scenarios:
            logger.info(f"Testing {scenario['description']}")
            
            # Test progressive timeout increases
            base_timeout = scenario["read_timeout"]
            progressive_attempts = []
            
            for attempt in range(1, 4):  # 3 attempts with increasing timeouts
                timeout_config = TimeoutConfig(
                    connect_timeout=10.0,
                    read_timeout=base_timeout * (1.0 + (attempt - 1) * 0.5),  # Progressive increase
                    write_timeout=10.0,
                    total_timeout=base_timeout * 2 * attempt
                )
                
                request_config = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": scenario["content"]}],
                    "max_tokens": scenario["max_tokens"]
                }
                
                start_time = time.time()
                
                result = await tester.test_with_retry(
                    http_client, auth_headers, request_config, timeout_config, max_attempts=1
                )
                
                end_time = time.time()
                actual_duration = end_time - start_time
                
                progressive_attempts.append({
                    "attempt": attempt,
                    "timeout_config": timeout_config,
                    "success": result["success"],
                    "duration": actual_duration,
                    "timeout_reached": actual_duration >= timeout_config.read_timeout * 0.9
                })
                
                logger.info(f"  Attempt {attempt}: {'✅' if result['success'] else '❌'} "
                          f"({actual_duration:.1f}s, timeout: {timeout_config.read_timeout:.1f}s)")
                
                # If successful, no need to continue
                if result["success"]:
                    break
                
                await asyncio.sleep(1.0)
            
            # Analyze progressive timeout effectiveness
            successful_attempt = next((a for a in progressive_attempts if a["success"]), None)
            timeout_progression_effective = any(
                progressive_attempts[i]["success"] and not progressive_attempts[i-1]["success"]
                for i in range(1, len(progressive_attempts))
            )
            
            progressive_results.append({
                "scenario": scenario,
                "attempts": progressive_attempts,
                "final_success": successful_attempt is not None,
                "progression_effective": timeout_progression_effective,
                "attempts_needed": successful_attempt["attempt"] if successful_attempt else len(progressive_attempts)
            })
        
        # Test adaptive timeout adjustment
        logger.info("Testing adaptive timeout adjustment")
        
        # Simulate multiple requests to trigger adaptive behavior
        adaptive_test_requests = 5
        adaptive_results = []
        
        for i in range(adaptive_test_requests):
            # Alternate between fast and slow requests
            if i % 2 == 0:
                content = "Fast request test"
                max_tokens = 30
            else:
                content = "Slower request test: " + "detailed analysis " * 20
                max_tokens = 150
            
            request_config = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": content}],
                "max_tokens": max_tokens
            }
            
            result = await tester.test_with_retry(
                http_client, auth_headers, request_config, max_attempts=2
            )
            
            adaptive_results.append({
                "request_type": "fast" if i % 2 == 0 else "slow",
                "success": result["success"],
                "attempts": result["attempts"],
                "duration": result.get("duration", 0)
            })
            
            await asyncio.sleep(0.5)
        
        # Analyze results
        timeout_analytics = tester.timeout_manager.get_timeout_analytics()
        
        logger.info("Read Timeout Handling Results:")
        logger.info(f"  Timeout Analytics: {timeout_analytics}")
        
        for result in progressive_results:
            scenario = result["scenario"]
            logger.info(f"  {scenario['description']}:")
            logger.info(f"    Final success: {'✅' if result['final_success'] else '❌'}")
            logger.info(f"    Attempts needed: {result['attempts_needed']}")
            logger.info(f"    Progression effective: {'✅' if result['progression_effective'] else '❌'}")
        
        adaptive_success_rate = sum(1 for r in adaptive_results if r["success"]) / len(adaptive_results)
        logger.info(f"  Adaptive timeout success rate: {adaptive_success_rate:.1%}")
        
        # Verify read timeout handling
        successful_scenarios = sum(1 for r in progressive_results if r["final_success"])
        assert successful_scenarios >= len(progressive_results) // 2, \
            "Progressive timeouts should help most scenarios succeed"
        
        effective_progressions = sum(1 for r in progressive_results if r["progression_effective"])
        assert effective_progressions >= 1, \
            "Progressive timeout increases should be effective in some cases"
        
        assert adaptive_success_rate >= 0.6, \
            f"Adaptive timeouts should maintain good success rate: {adaptive_success_rate:.1%}"
        
        logger.info("✅ Read timeout handling validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r754_timeout_003_write_timeout_handling(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """TC_R754_TIMEOUT_003: Write timeout handling for large requests"""
        # Test write timeout scenarios when sending large requests
        
        logger.info("✍️ Testing write timeout handling")
        
        tester = TimeoutRetryTester()
        
        # Test scenarios with different request sizes that might cause write timeouts
        write_timeout_scenarios = [
            {
                "content_multiplier": 50,
                "write_timeout": 5.0,
                "description": "Moderate content with short write timeout"
            },
            {
                "content_multiplier": 200,
                "write_timeout": 10.0,
                "description": "Large content with normal write timeout"
            },
            {
                "content_multiplier": 500,
                "write_timeout": 20.0,
                "description": "Very large content with long write timeout"
            }
        ]
        
        write_results = []
        
        for scenario in write_timeout_scenarios:
            logger.info(f"Testing {scenario['description']}")
            
            # Create large request content
            base_content = "Write timeout test with large request content: "
            large_content = base_content + ("detailed analysis content " * scenario["content_multiplier"])
            
            timeout_config = TimeoutConfig(
                connect_timeout=10.0,
                read_timeout=60.0,  # Long read timeout to isolate write timeout
                write_timeout=scenario["write_timeout"],
                total_timeout=120.0
            )
            
            request_config = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": large_content}],
                "max_tokens": 100  # Reasonable response size
            }
            
            # Test with retry logic
            start_time = time.time()
            
            result = await tester.test_with_retry(
                http_client, auth_headers, request_config, timeout_config, max_attempts=3
            )
            
            end_time = time.time()
            total_duration = end_time - start_time
            
            # Estimate request size
            request_size = len(str(request_config).encode('utf-8'))
            
            write_results.append({
                "scenario": scenario,
                "success": result["success"],
                "attempts": result["attempts"],
                "duration": total_duration,
                "request_size": request_size,
                "write_timeout": scenario["write_timeout"],
                "timeout_effective": total_duration <= timeout_config.write_timeout * result["attempts"] * 1.5
            })
            
            logger.info(f"  Result: {'✅' if result['success'] else '❌'} "
                      f"({total_duration:.1f}s, {request_size} bytes, {result['attempts']} attempts)")
            
            await asyncio.sleep(1.0)
        
        # Test write timeout with streaming requests
        logger.info("Testing write timeout with streaming requests")
        
        streaming_timeout_config = TimeoutConfig(
            connect_timeout=10.0,
            read_timeout=60.0,
            write_timeout=10.0,
            total_timeout=120.0
        )
        
        streaming_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Streaming write timeout test: " + "content " * 100}],
            "max_tokens": 150,
            "stream": True
        }
        
        streaming_success = False
        streaming_duration = 0
        
        try:
            start_time = time.time()
            
            timeout_httpx = streaming_timeout_config.to_httpx_timeout()
            
            async with http_client.stream(
                "POST",
                f"{config.base_url}/api/v1/chat/completions",
                headers=auth_headers,
                json=streaming_request,
                timeout=timeout_httpx
            ) as response:
                
                if response.status_code == 200:
                    # Read some chunks to test full write/read cycle
                    chunk_count = 0
                    async for line in response.aiter_lines():
                        if line.strip():
                            chunk_count += 1
                            if chunk_count >= 5:  # Read a few chunks
                                break
                    
                    streaming_success = chunk_count > 0
            
            streaming_duration = time.time() - start_time
        
        except Exception as e:
            streaming_duration = time.time() - start_time
            logger.warning(f"Streaming write timeout test failed: {e}")
        
        # Analyze write timeout analytics
        timeout_analytics = tester.timeout_manager.get_timeout_analytics()
        
        logger.info("Write Timeout Handling Results:")
        logger.info(f"  Timeout Analytics: {timeout_analytics}")
        
        for result in write_results:
            scenario = result["scenario"]
            logger.info(f"  {scenario['description']}:")
            logger.info(f"    Success: {'✅' if result['success'] else '❌'}")
            logger.info(f"    Request size: {result['request_size']:,} bytes")
            logger.info(f"    Duration: {result['duration']:.1f}s")
            logger.info(f"    Attempts: {result['attempts']}")
            logger.info(f"    Timeout effective: {'✅' if result['timeout_effective'] else '❌'}")
        
        logger.info(f"  Streaming test: {'✅' if streaming_success else '❌'} ({streaming_duration:.1f}s)")
        
        # Verify write timeout handling
        successful_writes = sum(1 for r in write_results if r["success"])
        assert successful_writes >= len(write_results) // 2, \
            "Should successfully handle most write timeout scenarios"
        
        # Larger timeouts should generally be more successful
        long_timeout_results = [r for r in write_results if r["write_timeout"] >= 10.0]
        if long_timeout_results:
            long_timeout_success = sum(1 for r in long_timeout_results if r["success"]) / len(long_timeout_results)
            assert long_timeout_success >= 0.5, \
                f"Longer write timeouts should have better success rate: {long_timeout_success:.1%}"
        
        # Timeouts should be effective in controlling request duration
        effective_timeouts = sum(1 for r in write_results if r["timeout_effective"])
        assert effective_timeouts >= len(write_results) // 2, \
            "Write timeouts should effectively control request duration"
        
        logger.info("✅ Write timeout handling validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r754_timeout_004_total_timeout_coordination(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """TC_R754_TIMEOUT_004: Total timeout coordination across all operations"""
        # Test coordination of total timeouts across connect, read, write operations
        
        logger.info("⏱️ Testing total timeout coordination")
        
        tester = TimeoutRetryTester()
        
        # Test scenarios with different total timeout configurations
        coordination_scenarios = [
            {
                "total_timeout": 15.0,
                "component_timeouts": {"connect": 5.0, "read": 8.0, "write": 3.0},
                "description": "Short total timeout with balanced components"
            },
            {
                "total_timeout": 45.0,
                "component_timeouts": {"connect": 10.0, "read": 25.0, "write": 8.0},
                "description": "Medium total timeout with read-heavy configuration"
            },
            {
                "total_timeout": 90.0,
                "component_timeouts": {"connect": 15.0, "read": 60.0, "write": 15.0},
                "description": "Long total timeout with generous components"
            }
        ]
        
        coordination_results = []
        
        for scenario in coordination_scenarios:
            logger.info(f"Testing {scenario['description']}")
            
            timeout_config = TimeoutConfig(
                connect_timeout=scenario["component_timeouts"]["connect"],
                read_timeout=scenario["component_timeouts"]["read"],
                write_timeout=scenario["component_timeouts"]["write"],
                total_timeout=scenario["total_timeout"]
            )
            
            # Test with requests of varying complexity
            test_requests = [
                {
                    "content": "Simple coordination test",
                    "max_tokens": 50,
                    "expected_duration": "short"
                },
                {
                    "content": "Medium coordination test: " + "analysis " * 50,
                    "max_tokens": 150,
                    "expected_duration": "medium"
                },
                {
                    "content": "Complex coordination test: " + "detailed comprehensive analysis " * 100,
                    "max_tokens": 300,
                    "expected_duration": "long"
                }
            ]
            
            scenario_results = []
            
            for req_config in test_requests:
                request_config = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": req_config["content"]}],
                    "max_tokens": req_config["max_tokens"]
                }
                
                start_time = time.time()
                
                result = await tester.test_with_retry(
                    http_client, auth_headers, request_config, timeout_config, max_attempts=1
                )
                
                end_time = time.time()
                actual_duration = end_time - start_time
                
                # Check timeout coordination
                within_total_timeout = actual_duration <= timeout_config.total_timeout * 1.1
                timeout_properly_enforced = True
                
                if not result["success"] and actual_duration < timeout_config.total_timeout * 0.9:
                    # Request failed before total timeout - check if it was due to component timeout
                    component_timeout_likely = (
                        actual_duration >= timeout_config.connect_timeout * 0.9 or
                        actual_duration >= timeout_config.read_timeout * 0.9 or
                        actual_duration >= timeout_config.write_timeout * 0.9
                    )
                    timeout_properly_enforced = component_timeout_likely
                
                scenario_results.append({
                    "request": req_config,
                    "success": result["success"],
                    "duration": actual_duration,
                    "within_total_timeout": within_total_timeout,
                    "timeout_properly_enforced": timeout_properly_enforced
                })
                
                logger.info(f"    {req_config['expected_duration']} request: {'✅' if result['success'] else '❌'} "
                          f"({actual_duration:.1f}s/{timeout_config.total_timeout:.1f}s)")
                
                await asyncio.sleep(0.5)
            
            # Analyze scenario coordination
            success_rate = sum(1 for r in scenario_results if r["success"]) / len(scenario_results)
            coordination_effective = all(r["within_total_timeout"] for r in scenario_results)
            timeout_enforcement_good = sum(1 for r in scenario_results if r["timeout_properly_enforced"]) / len(scenario_results)
            
            coordination_results.append({
                "scenario": scenario,
                "results": scenario_results,
                "success_rate": success_rate,
                "coordination_effective": coordination_effective,
                "timeout_enforcement_rate": timeout_enforcement_good
            })
        
        # Test concurrent request coordination
        logger.info("Testing concurrent request timeout coordination")
        
        concurrent_timeout_config = TimeoutConfig(
            connect_timeout=10.0,
            read_timeout=30.0,
            write_timeout=10.0,
            total_timeout=60.0
        )
        
        concurrent_requests = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Concurrent test {i}"}],
                "max_tokens": 50
            }
            for i in range(5)
        ]
        
        # Execute concurrent requests
        concurrent_start = time.time()
        
        concurrent_tasks = [
            tester.test_with_retry(http_client, auth_headers, req, concurrent_timeout_config, max_attempts=1)
            for req in concurrent_requests
        ]
        
        concurrent_results = await asyncio.gather(*concurrent_tasks, return_exceptions=True)
        concurrent_end = time.time()
        concurrent_duration = concurrent_end - concurrent_start
        
        concurrent_successes = sum(1 for r in concurrent_results if isinstance(r, dict) and r.get("success", False))
        concurrent_within_timeout = concurrent_duration <= concurrent_timeout_config.total_timeout * 1.2
        
        # Analyze coordination analytics
        timeout_analytics = tester.timeout_manager.get_timeout_analytics()
        
        logger.info("Total Timeout Coordination Results:")
        logger.info(f"  Timeout Analytics: {timeout_analytics}")
        
        for result in coordination_results:
            scenario = result["scenario"]
            logger.info(f"  {scenario['description']}:")
            logger.info(f"    Success rate: {result['success_rate']:.1%}")
            logger.info(f"    Coordination effective: {'✅' if result['coordination_effective'] else '❌'}")
            logger.info(f"    Timeout enforcement: {result['timeout_enforcement_rate']:.1%}")
        
        logger.info(f"  Concurrent requests:")
        logger.info(f"    Successes: {concurrent_successes}/{len(concurrent_requests)}")
        logger.info(f"    Total duration: {concurrent_duration:.1f}s")
        logger.info(f"    Within timeout bounds: {'✅' if concurrent_within_timeout else '❌'}")
        
        # Verify total timeout coordination
        effective_coordination = sum(1 for r in coordination_results if r["coordination_effective"])
        assert effective_coordination >= len(coordination_results) // 2, \
            "Total timeout coordination should be effective in most scenarios"
        
        good_enforcement = sum(1 for r in coordination_results if r["timeout_enforcement_rate"] >= 0.67)
        assert good_enforcement >= len(coordination_results) // 2, \
            "Timeout enforcement should be good across scenarios"
        
        assert concurrent_within_timeout, \
            "Concurrent requests should complete within total timeout bounds"
        
        assert concurrent_successes >= len(concurrent_requests) // 2, \
            "Most concurrent requests should succeed with proper timeout coordination"
        
        logger.info("✅ Total timeout coordination validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r754_retry_001_intelligent_retry_strategies(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """TC_R754_RETRY_001: Intelligent retry strategies with circuit breaker integration"""
        # Test intelligent retry strategies including exponential backoff and circuit breakers
        
        logger.info("🔄 Testing intelligent retry strategies")
        
        tester = TimeoutRetryTester()
        
        # Configure retry strategy
        retry_config = RetryConfig(
            max_attempts=4,
            base_delay=1.0,
            max_delay=30.0,
            backoff_factor=2.0,
            jitter=True,
            retry_on_status=[500, 502, 503, 504],
            retry_on_timeout=True,
            retry_on_connection_error=True
        )
        tester.retry_manager = IntelligentRetryManager(retry_config)
        
        # Test scenarios that trigger different retry conditions
        retry_scenarios = [
            {
                "name": "Timeout Retry",
                "request_config": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Timeout retry test: " + "content " * 300}],
                    "max_tokens": 400
                },
                "timeout_config": TimeoutConfig(read_timeout=5.0, total_timeout=10.0),
                "expected_retry_type": "timeout"
            },
            {
                "name": "Invalid Model Retry",
                "request_config": {
                    "model": "intelligent_retry_invalid_model",
                    "messages": [{"role": "user", "content": "Invalid model retry test"}],
                    "max_tokens": 50
                },
                "timeout_config": TimeoutConfig(),
                "expected_retry_type": "client_error"
            },
            {
                "name": "Large Request Retry",
                "request_config": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Large request retry test: " + "analysis " * 200}],
                    "max_tokens": 500
                },
                "timeout_config": TimeoutConfig(write_timeout=8.0, read_timeout=20.0),
                "expected_retry_type": "timeout_or_success"
            }
        ]
        
        retry_results = []
        
        for scenario in retry_scenarios:
            logger.info(f"Testing {scenario['name']}")
            
            start_time = time.time()
            
            result = await tester.test_with_retry(
                http_client, 
                auth_headers, 
                scenario["request_config"],
                scenario["timeout_config"],
                max_attempts=4
            )
            
            end_time = time.time()
            total_duration = end_time - start_time
            
            # Analyze retry behavior
            retry_analytics = tester.retry_manager.get_retry_analytics()
            
            retry_results.append({
                "scenario": scenario,
                "success": result["success"],
                "attempts": result["attempts"],
                "duration": total_duration,
                "retry_analytics": retry_analytics
            })
            
            logger.info(f"  Result: {'✅' if result['success'] else '❌'} "
                      f"({result['attempts']} attempts, {total_duration:.1f}s)")
            
            await asyncio.sleep(2.0)
        
        # Test exponential backoff timing
        logger.info("Testing exponential backoff timing")
        
        backoff_test_start = time.time()
        
        # Force retries with invalid model to test backoff timing
        backoff_request = {
            "model": "exponential_backoff_test_invalid",
            "messages": [{"role": "user", "content": "Backoff timing test"}],
            "max_tokens": 50
        }
        
        backoff_result = await tester.test_with_retry(
            http_client, auth_headers, backoff_request, TimeoutConfig(), max_attempts=4
        )
        
        backoff_test_end = time.time()
        backoff_duration = backoff_test_end - backoff_test_start
        
        # Expected backoff: 1s + 2s + 4s = 7s minimum (plus jitter and request time)
        expected_min_backoff = 7.0
        backoff_timing_reasonable = backoff_duration >= expected_min_backoff
        
        # Test circuit breaker integration
        logger.info("Testing circuit breaker integration")
        
        # Generate multiple failures to trigger circuit breaker
        circuit_breaker_test_requests = 8
        circuit_breaker_results = []
        
        for i in range(circuit_breaker_test_requests):
            cb_request = {
                "model": "circuit_breaker_test_invalid",
                "messages": [{"role": "user", "content": f"Circuit breaker test {i}"}],
                "max_tokens": 50
            }
            
            cb_start = time.time()
            cb_result = await tester.test_with_retry(
                http_client, auth_headers, cb_request, TimeoutConfig(), max_attempts=2
            )
            cb_end = time.time()
            
            circuit_breaker_results.append({
                "request_num": i + 1,
                "success": cb_result["success"],
                "attempts": cb_result["attempts"],
                "duration": cb_end - cb_start
            })
            
            # Short delay between requests
            await asyncio.sleep(0.5)
        
        # Test circuit breaker recovery
        logger.info("Testing circuit breaker recovery")
        
        # Wait for potential circuit breaker recovery
        await asyncio.sleep(5.0)
        
        # Try normal request after circuit breaker
        recovery_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Circuit breaker recovery test"}],
            "max_tokens": 50
        }
        
        recovery_result = await tester.test_with_retry(
            http_client, auth_headers, recovery_request, TimeoutConfig(), max_attempts=2
        )
        
        # Analyze overall retry analytics
        final_analytics = tester.retry_manager.get_retry_analytics()
        
        logger.info("Intelligent Retry Strategies Results:")
        logger.info(f"  Final Analytics: {final_analytics}")
        
        for result in retry_results:
            scenario = result["scenario"]
            logger.info(f"  {scenario['name']}:")
            logger.info(f"    Success: {'✅' if result['success'] else '❌'}")
            logger.info(f"    Attempts: {result['attempts']}")
            logger.info(f"    Duration: {result['duration']:.1f}s")
        
        logger.info(f"  Exponential backoff test:")
        logger.info(f"    Duration: {backoff_duration:.1f}s (expected ≥{expected_min_backoff:.1f}s)")
        logger.info(f"    Timing reasonable: {'✅' if backoff_timing_reasonable else '❌'}")
        
        cb_failed_requests = sum(1 for r in circuit_breaker_results if not r["success"])
        cb_avg_duration = sum(r["duration"] for r in circuit_breaker_results) / len(circuit_breaker_results)
        
        logger.info(f"  Circuit breaker test:")
        logger.info(f"    Failed requests: {cb_failed_requests}/{len(circuit_breaker_results)}")
        logger.info(f"    Average duration: {cb_avg_duration:.1f}s")
        logger.info(f"    Recovery test: {'✅' if recovery_result['success'] else '❌'}")
        
        # Verify intelligent retry strategies
        assert final_analytics["total_attempts"] > len(retry_scenarios), \
            "Should have attempted retries across test scenarios"
        
        # Exponential backoff should be working
        assert backoff_timing_reasonable, \
            f"Exponential backoff timing should be reasonable: {backoff_duration:.1f}s ≥ {expected_min_backoff:.1f}s"
        
        # Circuit breaker should eventually stop retrying quickly
        if len(circuit_breaker_results) >= 6:
            later_requests = circuit_breaker_results[-3:]  # Last 3 requests
            later_avg_duration = sum(r["duration"] for r in later_requests) / len(later_requests)
            
            # Later requests should be faster (circuit breaker effect)
            assert later_avg_duration <= cb_avg_duration, \
                "Circuit breaker should reduce retry duration for repeated failures"
        
        # Recovery should work after circuit breaker
        assert recovery_result["success"], \
            "Should be able to recover after circuit breaker with valid requests"
        
        # Retry success rate should be reasonable for scenarios that can succeed
        potentially_successful_scenarios = [r for r in retry_results if r["scenario"]["name"] != "Invalid Model Retry"]
        if potentially_successful_scenarios:
            successful_retries = sum(1 for r in potentially_successful_scenarios if r["success"])
            retry_success_rate = successful_retries / len(potentially_successful_scenarios)
            assert retry_success_rate >= 0.5, \
                f"Retry strategies should help most recoverable scenarios: {retry_success_rate:.1%}"
        
        logger.info("✅ Intelligent retry strategies validation completed")