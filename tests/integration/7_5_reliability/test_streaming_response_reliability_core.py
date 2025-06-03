# Section 7.5 - Streaming Response Reliability Core Tests
# Missing Core Tests: TC_R753_PARTIAL_001, 002, 003, 004, TC_R753_QUALITY_001

import pytest
import httpx
import asyncio
import time
import json
from typing import Dict, Any, List, Optional, AsyncIterator
from dataclasses import dataclass, field
from collections import defaultdict

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class StreamChunk:
    """Represents a single streaming chunk"""
    index: int
    content: str
    timestamp: float
    chunk_size: int
    delta_time: float = 0.0
    
    def __post_init__(self):
        self.chunk_size = len(self.content.encode('utf-8'))


@dataclass
class StreamMetrics:
    """Streaming response metrics"""
    total_chunks: int = 0
    total_bytes: int = 0
    first_chunk_time: float = 0.0
    last_chunk_time: float = 0.0
    avg_chunk_size: float = 0.0
    max_chunk_gap: float = 0.0
    error_count: int = 0
    partial_chunks: int = 0
    quality_score: float = 0.0
    
    @property
    def total_duration(self) -> float:
        if self.first_chunk_time > 0 and self.last_chunk_time > 0:
            return self.last_chunk_time - self.first_chunk_time
        return 0.0
    
    @property
    def throughput_bytes_per_sec(self) -> float:
        if self.total_duration > 0:
            return self.total_bytes / self.total_duration
        return 0.0


class StreamingResponseAnalyzer:
    """Analyzes streaming response quality and reliability"""
    
    def __init__(self):
        self.chunks: List[StreamChunk] = []
        self.chunk_times: List[float] = []
        self.error_events: List[Dict[str, Any]] = []
        
    def add_chunk(self, content: str, timestamp: Optional[float] = None) -> StreamChunk:
        """Add a chunk to the analysis"""
        if timestamp is None:
            timestamp = time.time()
        
        index = len(self.chunks)
        delta_time = 0.0
        
        if self.chunk_times:
            delta_time = timestamp - self.chunk_times[-1]
        
        chunk = StreamChunk(
            index=index,
            content=content,
            timestamp=timestamp,
            chunk_size=len(content.encode('utf-8')),
            delta_time=delta_time
        )
        
        self.chunks.append(chunk)
        self.chunk_times.append(timestamp)
        
        return chunk
    
    def add_error(self, error_type: str, message: str, timestamp: Optional[float] = None):
        """Add an error event"""
        if timestamp is None:
            timestamp = time.time()
            
        self.error_events.append({
            "type": error_type,
            "message": message,
            "timestamp": timestamp,
            "chunk_index": len(self.chunks)
        })
    
    def calculate_metrics(self) -> StreamMetrics:
        """Calculate comprehensive streaming metrics"""
        if not self.chunks:
            return StreamMetrics()
        
        total_bytes = sum(chunk.chunk_size for chunk in self.chunks)
        chunk_sizes = [chunk.chunk_size for chunk in self.chunks]
        chunk_gaps = [chunk.delta_time for chunk in self.chunks[1:]]
        
        metrics = StreamMetrics(
            total_chunks=len(self.chunks),
            total_bytes=total_bytes,
            first_chunk_time=self.chunks[0].timestamp,
            last_chunk_time=self.chunks[-1].timestamp,
            avg_chunk_size=sum(chunk_sizes) / len(chunk_sizes),
            max_chunk_gap=max(chunk_gaps) if chunk_gaps else 0.0,
            error_count=len(self.error_events),
            partial_chunks=sum(1 for chunk in self.chunks if chunk.chunk_size < 10)
        )
        
        # Calculate quality score (0-100)
        metrics.quality_score = self._calculate_quality_score(metrics)
        
        return metrics
    
    def _calculate_quality_score(self, metrics: StreamMetrics) -> float:
        """Calculate streaming quality score"""
        base_score = 100.0
        
        # Penalize high error rates
        error_penalty = min(50, metrics.error_count * 5)
        base_score -= error_penalty
        
        # Penalize inconsistent chunk timing
        if metrics.max_chunk_gap > 5.0:  # > 5 second gaps
            timing_penalty = min(20, (metrics.max_chunk_gap - 5.0) * 2)
            base_score -= timing_penalty
        
        # Penalize too many partial chunks
        partial_rate = metrics.partial_chunks / max(1, metrics.total_chunks)
        if partial_rate > 0.3:  # > 30% partial chunks
            partial_penalty = min(15, (partial_rate - 0.3) * 50)
            base_score -= partial_penalty
        
        # Penalize very low throughput
        if metrics.throughput_bytes_per_sec < 100:  # < 100 bytes/sec
            throughput_penalty = min(15, (100 - metrics.throughput_bytes_per_sec) / 10)
            base_score -= throughput_penalty
        
        return max(0.0, base_score)
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect anomalies in streaming behavior"""
        anomalies = []
        
        if not self.chunks:
            return anomalies
        
        # Detect large timing gaps
        for i, chunk in enumerate(self.chunks[1:], 1):
            if chunk.delta_time > 10.0:  # > 10 second gap
                anomalies.append({
                    "type": "large_timing_gap",
                    "chunk_index": i,
                    "gap_duration": chunk.delta_time,
                    "severity": "high" if chunk.delta_time > 30.0 else "medium"
                })
        
        # Detect size anomalies
        chunk_sizes = [chunk.chunk_size for chunk in self.chunks]
        if chunk_sizes:
            avg_size = sum(chunk_sizes) / len(chunk_sizes)
            
            for chunk in self.chunks:
                if chunk.chunk_size > avg_size * 5:  # 5x larger than average
                    anomalies.append({
                        "type": "oversized_chunk",
                        "chunk_index": chunk.index,
                        "chunk_size": chunk.chunk_size,
                        "average_size": avg_size,
                        "severity": "medium"
                    })
                elif chunk.chunk_size < avg_size / 10 and chunk.chunk_size > 0:  # 10x smaller
                    anomalies.append({
                        "type": "undersized_chunk",
                        "chunk_index": chunk.index,
                        "chunk_size": chunk.chunk_size,
                        "average_size": avg_size,
                        "severity": "low"
                    })
        
        return anomalies


class StreamingReliabilityTester:
    """Testing framework for streaming response reliability"""
    
    def __init__(self):
        self.analyzers: Dict[str, StreamingResponseAnalyzer] = {}
        
    def create_analyzer(self, test_id: str) -> StreamingResponseAnalyzer:
        """Create a new analyzer for a test"""
        analyzer = StreamingResponseAnalyzer()
        self.analyzers[test_id] = analyzer
        return analyzer
    
    async def simulate_partial_stream(self, http_client: httpx.AsyncClient,
                                    auth_headers: Dict[str, str],
                                    make_request,
                                    interruption_point: float = 0.5) -> Dict[str, Any]:
        """Simulate partial stream with interruption"""
        
        analyzer = self.create_analyzer(f"partial_stream_{interruption_point}")
        
        # Start streaming request
        request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Generate a long response for partial stream testing: " + "content " * 100}],
            "max_tokens": 200,
            "stream": True
        }
        
        try:
            start_time = time.time()
            
            async with http_client.stream(
                "POST", 
                f"{config.base_url}/api/v1/chat/completions",
                headers=auth_headers,
                json=request,
                timeout=30.0
            ) as response:
                
                if response.status_code != 200:
                    analyzer.add_error("request_failed", f"Status: {response.status_code}")
                    return {"error": "request_failed", "status": response.status_code}
                
                chunks_received = 0
                total_content = ""
                interruption_triggered = False
                
                async for line in response.aiter_lines():
                    current_time = time.time()
                    elapsed = current_time - start_time
                    
                    if line.strip():
                        try:
                            if line.startswith("data: "):
                                data_str = line[6:]
                                if data_str.strip() == "[DONE]":
                                    break
                                
                                chunk_data = json.loads(data_str)
                                
                                if "choices" in chunk_data and chunk_data["choices"]:
                                    delta = chunk_data["choices"][0].get("delta", {})
                                    content = delta.get("content", "")
                                    
                                    if content:
                                        analyzer.add_chunk(content, current_time)
                                        total_content += content
                                        chunks_received += 1
                                
                                # Trigger interruption at specified point
                                if not interruption_triggered and elapsed > interruption_point * 10:
                                    interruption_triggered = True
                                    analyzer.add_error("simulated_interruption", "Connection interrupted for testing")
                                    break
                        
                        except json.JSONDecodeError as e:
                            analyzer.add_error("json_decode_error", str(e))
                        except Exception as e:
                            analyzer.add_error("chunk_processing_error", str(e))
                
                metrics = analyzer.calculate_metrics()
                anomalies = analyzer.detect_anomalies()
                
                return {
                    "success": chunks_received > 0,
                    "chunks_received": chunks_received,
                    "content_length": len(total_content),
                    "interrupted": interruption_triggered,
                    "metrics": metrics,
                    "anomalies": anomalies
                }
        
        except Exception as e:
            analyzer.add_error("stream_exception", str(e))
            metrics = analyzer.calculate_metrics()
            
            return {
                "success": False,
                "error": str(e),
                "metrics": metrics,
                "anomalies": analyzer.detect_anomalies()
            }


class TestStreamingResponseReliabilityCore:
    """Core streaming response reliability tests"""
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r753_partial_001_chunk_delivery_consistency(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """TC_R753_PARTIAL_001: Chunk delivery consistency under normal conditions"""
        # Test consistent chunk delivery timing and size
        
        logger.info("📦 Testing chunk delivery consistency")
        
        tester = StreamingReliabilityTester()
        analyzer = tester.create_analyzer("chunk_consistency")
        
        # Test streaming with various content lengths
        test_scenarios = [
            {"content": "Short response test", "max_tokens": 50, "expected_chunks": 3},
            {"content": "Medium response test: " + "analysis " * 20, "max_tokens": 100, "expected_chunks": 8},
            {"content": "Long response test: " + "detailed analysis " * 50, "max_tokens": 200, "expected_chunks": 15}
        ]
        
        results = []
        
        for scenario in test_scenarios:
            logger.info(f"Testing scenario with {scenario['max_tokens']} max tokens")
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["content"]}],
                "max_tokens": scenario["max_tokens"],
                "stream": True
            }
            
            scenario_start = time.time()
            chunks_received = 0
            chunk_times = []
            
            try:
                async with http_client.stream(
                    "POST",
                    f"{config.base_url}/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request,
                    timeout=30.0
                ) as response:
                    
                    if response.status_code == 200:
                        async for line in response.aiter_lines():
                            if line.strip() and line.startswith("data: "):
                                chunk_time = time.time()
                                data_str = line[6:]
                                
                                if data_str.strip() == "[DONE]":
                                    break
                                
                                try:
                                    chunk_data = json.loads(data_str)
                                    if "choices" in chunk_data and chunk_data["choices"]:
                                        delta = chunk_data["choices"][0].get("delta", {})
                                        content = delta.get("content", "")
                                        
                                        if content:
                                            analyzer.add_chunk(content, chunk_time)
                                            chunks_received += 1
                                            chunk_times.append(chunk_time)
                                
                                except json.JSONDecodeError:
                                    analyzer.add_error("json_decode_error", "Failed to parse chunk")
                    
                    else:
                        analyzer.add_error("request_failed", f"Status: {response.status_code}")
            
            except Exception as e:
                analyzer.add_error("stream_exception", str(e))
            
            scenario_end = time.time()
            scenario_duration = scenario_end - scenario_start
            
            # Analyze chunk timing consistency
            timing_consistency = 1.0
            if len(chunk_times) > 1:
                gaps = [chunk_times[i+1] - chunk_times[i] for i in range(len(chunk_times)-1)]
                avg_gap = sum(gaps) / len(gaps)
                gap_variance = sum((gap - avg_gap) ** 2 for gap in gaps) / len(gaps)
                timing_consistency = max(0.0, 1.0 - (gap_variance / (avg_gap ** 2 + 0.001)))
            
            results.append({
                "scenario": scenario,
                "chunks_received": chunks_received,
                "duration": scenario_duration,
                "timing_consistency": timing_consistency,
                "avg_chunk_gap": sum(chunk_times[i+1] - chunk_times[i] for i in range(len(chunk_times)-1)) / max(1, len(chunk_times)-1) if len(chunk_times) > 1 else 0
            })
            
            await asyncio.sleep(1.0)
        
        # Calculate overall metrics
        metrics = analyzer.calculate_metrics()
        anomalies = analyzer.detect_anomalies()
        
        logger.info("Chunk Delivery Consistency Results:")
        logger.info(f"  Total Chunks: {metrics.total_chunks}")
        logger.info(f"  Average Chunk Size: {metrics.avg_chunk_size:.1f} bytes")
        logger.info(f"  Max Chunk Gap: {metrics.max_chunk_gap:.2f}s")
        logger.info(f"  Quality Score: {metrics.quality_score:.1f}/100")
        logger.info(f"  Anomalies Detected: {len(anomalies)}")
        
        # Verify chunk delivery consistency
        assert metrics.total_chunks > 0, "Should have received streaming chunks"
        assert metrics.quality_score >= 70.0, f"Quality score should be good: {metrics.quality_score:.1f}/100"
        assert metrics.max_chunk_gap <= 10.0, f"Chunk gaps should be reasonable: {metrics.max_chunk_gap:.2f}s"
        
        # Verify timing consistency across scenarios
        avg_consistency = sum(r["timing_consistency"] for r in results) / len(results)
        assert avg_consistency >= 0.6, f"Timing consistency should be good: {avg_consistency:.2f}"
        
        logger.info("✅ Chunk delivery consistency validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r753_partial_002_connection_interruption_handling(self, http_client: httpx.AsyncClient,
                                                                      auth_headers: Dict[str, str],
                                                                      make_request):
        """TC_R753_PARTIAL_002: Connection interruption and recovery handling"""
        # Test behavior when streaming connections are interrupted
        
        logger.info("🔌 Testing connection interruption handling")
        
        tester = StreamingReliabilityTester()
        
        # Test interruptions at different points
        interruption_scenarios = [
            {"point": 0.2, "description": "Early interruption"},
            {"point": 0.5, "description": "Mid-stream interruption"},
            {"point": 0.8, "description": "Late interruption"}
        ]
        
        interruption_results = []
        
        for scenario in interruption_scenarios:
            logger.info(f"Testing {scenario['description']} at {scenario['point']*100:.0f}% progress")
            
            result = await tester.simulate_partial_stream(
                http_client, auth_headers, make_request, scenario["point"]
            )
            
            result["scenario"] = scenario
            interruption_results.append(result)
            
            await asyncio.sleep(2.0)
        
        # Test recovery after interruption
        logger.info("Testing recovery after interruption")
        
        recovery_success = 0
        recovery_attempts = 3
        
        for attempt in range(recovery_attempts):
            try:
                # Normal request after interruptions
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Recovery test after interruption"}],
                    "max_tokens": 50,
                    "stream": True
                }
                
                chunks_received = 0
                
                async with http_client.stream(
                    "POST",
                    f"{config.base_url}/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request,
                    timeout=30.0
                ) as response:
                    
                    if response.status_code == 200:
                        async for line in response.aiter_lines():
                            if line.strip() and line.startswith("data: "):
                                data_str = line[6:]
                                if data_str.strip() == "[DONE]":
                                    break
                                
                                try:
                                    chunk_data = json.loads(data_str)
                                    if "choices" in chunk_data and chunk_data["choices"]:
                                        delta = chunk_data["choices"][0].get("delta", {})
                                        if delta.get("content"):
                                            chunks_received += 1
                                except json.JSONDecodeError:
                                    pass
                        
                        if chunks_received > 0:
                            recovery_success += 1
                
            except Exception as e:
                logger.warning(f"Recovery attempt {attempt + 1} failed: {e}")
            
            await asyncio.sleep(1.0)
        
        recovery_rate = recovery_success / recovery_attempts
        
        logger.info("Connection Interruption Handling Results:")
        for result in interruption_results:
            scenario = result["scenario"]
            logger.info(f"  {scenario['description']}:")
            logger.info(f"    Chunks before interruption: {result.get('chunks_received', 0)}")
            logger.info(f"    Content received: {result.get('content_length', 0)} characters")
            logger.info(f"    Quality score: {result.get('metrics', {}).get('quality_score', 0):.1f}/100")
        
        logger.info(f"  Recovery rate: {recovery_rate:.1%}")
        
        # Verify interruption handling
        successful_interruptions = sum(1 for r in interruption_results if r.get("chunks_received", 0) > 0)
        assert successful_interruptions >= len(interruption_scenarios) // 2, \
            "Should successfully receive some chunks before interruption"
        
        assert recovery_rate >= 0.67, f"Recovery rate should be good: {recovery_rate:.1%}"
        
        logger.info("✅ Connection interruption handling validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r753_partial_003_partial_content_validation(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """TC_R753_PARTIAL_003: Partial content validation and completeness"""
        # Test validation of partial streaming content
        
        logger.info("🧩 Testing partial content validation")
        
        analyzer = StreamingResponseAnalyzer()
        
        # Test with different content types that can be validated partially
        validation_scenarios = [
            {
                "content": "Generate a numbered list of 10 items about AI testing",
                "max_tokens": 200,
                "validation_type": "numbered_list",
                "partial_validation": True
            },
            {
                "content": "Write a JSON response with 5 key-value pairs",
                "max_tokens": 150,
                "validation_type": "json_structure",
                "partial_validation": True
            },
            {
                "content": "Explain the concept of reliability testing in 3 paragraphs",
                "max_tokens": 300,
                "validation_type": "paragraph_structure",
                "partial_validation": True
            }
        ]
        
        validation_results = []
        
        for scenario in validation_scenarios:
            logger.info(f"Testing {scenario['validation_type']} validation")
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["content"]}],
                "max_tokens": scenario["max_tokens"],
                "stream": True
            }
            
            accumulated_content = ""
            partial_validations = []
            chunks_received = 0
            
            try:
                async with http_client.stream(
                    "POST",
                    f"{config.base_url}/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request,
                    timeout=30.0
                ) as response:
                    
                    if response.status_code == 200:
                        async for line in response.aiter_lines():
                            if line.strip() and line.startswith("data: "):
                                data_str = line[6:]
                                if data_str.strip() == "[DONE]":
                                    break
                                
                                try:
                                    chunk_data = json.loads(data_str)
                                    if "choices" in chunk_data and chunk_data["choices"]:
                                        delta = chunk_data["choices"][0].get("delta", {})
                                        content = delta.get("content", "")
                                        
                                        if content:
                                            analyzer.add_chunk(content)
                                            accumulated_content += content
                                            chunks_received += 1
                                            
                                            # Perform partial validation every few chunks
                                            if chunks_received % 3 == 0:
                                                validation = self._validate_partial_content(
                                                    accumulated_content, scenario["validation_type"]
                                                )
                                                partial_validations.append({
                                                    "chunk_count": chunks_received,
                                                    "content_length": len(accumulated_content),
                                                    "validation": validation
                                                })
                                
                                except json.JSONDecodeError:
                                    analyzer.add_error("json_decode_error", "Failed to parse chunk")
            
            except Exception as e:
                analyzer.add_error("stream_exception", str(e))
            
            # Final validation
            final_validation = self._validate_partial_content(
                accumulated_content, scenario["validation_type"]
            )
            
            validation_results.append({
                "scenario": scenario,
                "chunks_received": chunks_received,
                "content_length": len(accumulated_content),
                "partial_validations": partial_validations,
                "final_validation": final_validation,
                "validation_progression": len([v for v in partial_validations if v["validation"]["valid"]])
            })
            
            await asyncio.sleep(1.0)
        
        # Calculate validation metrics
        metrics = analyzer.calculate_metrics()
        
        logger.info("Partial Content Validation Results:")
        logger.info(f"  Total Scenarios: {len(validation_results)}")
        logger.info(f"  Quality Score: {metrics.quality_score:.1f}/100")
        
        for result in validation_results:
            scenario = result["scenario"]
            logger.info(f"  {scenario['validation_type']}:")
            logger.info(f"    Chunks: {result['chunks_received']}")
            logger.info(f"    Content length: {result['content_length']}")
            logger.info(f"    Partial validations passed: {result['validation_progression']}/{len(result['partial_validations'])}")
            logger.info(f"    Final validation: {'✅' if result['final_validation']['valid'] else '❌'}")
        
        # Verify partial content validation
        assert metrics.total_chunks > 0, "Should have received streaming chunks"
        
        # Most scenarios should have some valid partial validations
        scenarios_with_progression = sum(1 for r in validation_results if r["validation_progression"] > 0)
        assert scenarios_with_progression >= len(validation_scenarios) // 2, \
            "Should have validation progression in most scenarios"
        
        # At least some final validations should pass
        final_validations_passed = sum(1 for r in validation_results if r["final_validation"]["valid"])
        assert final_validations_passed >= 1, "Should have at least one complete valid response"
        
        logger.info("✅ Partial content validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r753_partial_004_stream_error_recovery(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """TC_R753_PARTIAL_004: Stream error recovery and continuation"""
        # Test error recovery during streaming
        
        logger.info("🔄 Testing stream error recovery")
        
        analyzer = StreamingResponseAnalyzer()
        
        # Test scenarios that might cause errors during streaming
        error_recovery_scenarios = [
            {
                "description": "Large content request",
                "content": "Generate a detailed analysis: " + "comprehensive analysis " * 200,
                "max_tokens": 500,
                "timeout": 45.0
            },
            {
                "description": "Complex formatting request",
                "content": "Create a complex formatted response with tables, lists, and code blocks",
                "max_tokens": 300,
                "timeout": 30.0
            },
            {
                "description": "Multiple language request",
                "content": "Respond in multiple languages: English, Spanish, and French",
                "max_tokens": 200,
                "timeout": 30.0
            }
        ]
        
        recovery_results = []
        
        for scenario in error_recovery_scenarios:
            logger.info(f"Testing error recovery: {scenario['description']}")
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["content"]}],
                "max_tokens": scenario["max_tokens"],
                "stream": True
            }
            
            chunks_received = 0
            errors_encountered = 0
            recovery_successful = False
            content_length = 0
            
            try:
                async with http_client.stream(
                    "POST",
                    f"{config.base_url}/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request,
                    timeout=scenario["timeout"]
                ) as response:
                    
                    if response.status_code == 200:
                        async for line in response.aiter_lines():
                            if line.strip():
                                if line.startswith("data: "):
                                    data_str = line[6:]
                                    if data_str.strip() == "[DONE]":
                                        recovery_successful = True
                                        break
                                    
                                    try:
                                        chunk_data = json.loads(data_str)
                                        if "choices" in chunk_data and chunk_data["choices"]:
                                            delta = chunk_data["choices"][0].get("delta", {})
                                            content = delta.get("content", "")
                                            
                                            if content:
                                                analyzer.add_chunk(content)
                                                chunks_received += 1
                                                content_length += len(content)
                                    
                                    except json.JSONDecodeError as e:
                                        errors_encountered += 1
                                        analyzer.add_error("json_decode_error", str(e))
                                        # Continue processing despite JSON errors
                                        continue
                                
                                elif line.startswith("event: error"):
                                    errors_encountered += 1
                                    analyzer.add_error("stream_error", "Stream error event received")
                    
                    else:
                        errors_encountered += 1
                        analyzer.add_error("request_failed", f"Status: {response.status_code}")
            
            except asyncio.TimeoutError:
                errors_encountered += 1
                analyzer.add_error("timeout_error", "Stream timeout")
                # Consider partial success if we received some chunks
                recovery_successful = chunks_received > 0
            
            except Exception as e:
                errors_encountered += 1
                analyzer.add_error("stream_exception", str(e))
                recovery_successful = chunks_received > 0
            
            recovery_results.append({
                "scenario": scenario,
                "chunks_received": chunks_received,
                "content_length": content_length,
                "errors_encountered": errors_encountered,
                "recovery_successful": recovery_successful,
                "error_rate": errors_encountered / max(1, chunks_received + errors_encountered)
            })
            
            await asyncio.sleep(2.0)
        
        # Test recovery after errors with normal request
        logger.info("Testing system recovery with normal request")
        
        normal_request_success = False
        try:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Simple recovery test"}],
                "max_tokens": 50,
                "stream": True
            }
            
            chunks_received = 0
            
            async with http_client.stream(
                "POST",
                f"{config.base_url}/api/v1/chat/completions",
                headers=auth_headers,
                json=request,
                timeout=30.0
            ) as response:
                
                if response.status_code == 200:
                    async for line in response.aiter_lines():
                        if line.strip() and line.startswith("data: "):
                            data_str = line[6:]
                            if data_str.strip() == "[DONE]":
                                break
                            
                            try:
                                chunk_data = json.loads(data_str)
                                if "choices" in chunk_data and chunk_data["choices"]:
                                    delta = chunk_data["choices"][0].get("delta", {})
                                    if delta.get("content"):
                                        chunks_received += 1
                            except json.JSONDecodeError:
                                pass
                    
                    normal_request_success = chunks_received > 0
        
        except Exception:
            normal_request_success = False
        
        # Calculate recovery metrics
        metrics = analyzer.calculate_metrics()
        
        logger.info("Stream Error Recovery Results:")
        logger.info(f"  Quality Score: {metrics.quality_score:.1f}/100")
        logger.info(f"  Total Errors: {metrics.error_count}")
        
        for result in recovery_results:
            scenario = result["scenario"]
            logger.info(f"  {scenario['description']}:")
            logger.info(f"    Chunks received: {result['chunks_received']}")
            logger.info(f"    Errors encountered: {result['errors_encountered']}")
            logger.info(f"    Recovery successful: {'✅' if result['recovery_successful'] else '❌'}")
            logger.info(f"    Error rate: {result['error_rate']:.1%}")
        
        logger.info(f"  Normal request after errors: {'✅' if normal_request_success else '❌'}")
        
        # Verify error recovery
        successful_recoveries = sum(1 for r in recovery_results if r["recovery_successful"])
        assert successful_recoveries >= len(error_recovery_scenarios) // 2, \
            "Should successfully recover from most error scenarios"
        
        assert normal_request_success, "Should be able to make normal requests after errors"
        
        # Error rates should be manageable
        avg_error_rate = sum(r["error_rate"] for r in recovery_results) / len(recovery_results)
        assert avg_error_rate <= 0.3, f"Average error rate should be acceptable: {avg_error_rate:.1%}"
        
        logger.info("✅ Stream error recovery validation completed")
    
    @pytest.mark.reliability
    @pytest.mark.asyncio
    async def test_tc_r753_quality_001_streaming_response_quality(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """TC_R753_QUALITY_001: Overall streaming response quality assessment"""
        # Comprehensive quality assessment of streaming responses
        
        logger.info("🎯 Testing streaming response quality assessment")
        
        analyzer = StreamingResponseAnalyzer()
        
        # Comprehensive quality test scenarios
        quality_scenarios = [
            {
                "name": "Consistency Test",
                "content": "Explain the importance of API reliability testing",
                "max_tokens": 150,
                "quality_factors": ["consistency", "completeness", "timing"]
            },
            {
                "name": "Performance Test",
                "content": "Generate a technical analysis of: " + "performance metrics " * 30,
                "max_tokens": 250,
                "quality_factors": ["throughput", "timing", "chunking"]
            },
            {
                "name": "Reliability Test",
                "content": "Describe best practices for streaming API implementations",
                "max_tokens": 200,
                "quality_factors": ["reliability", "completeness", "consistency"]
            }
        ]
        
        quality_results = []
        
        for scenario in quality_scenarios:
            logger.info(f"Running quality test: {scenario['name']}")
            
            scenario_analyzer = StreamingResponseAnalyzer()
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["content"]}],
                "max_tokens": scenario["max_tokens"],
                "stream": True
            }
            
            stream_start = time.time()
            chunks_received = 0
            total_content = ""
            chunk_sizes = []
            chunk_timings = []
            
            try:
                async with http_client.stream(
                    "POST",
                    f"{config.base_url}/api/v1/chat/completions",
                    headers=auth_headers,
                    json=request,
                    timeout=60.0
                ) as response:
                    
                    if response.status_code == 200:
                        last_chunk_time = stream_start
                        
                        async for line in response.aiter_lines():
                            if line.strip() and line.startswith("data: "):
                                chunk_time = time.time()
                                data_str = line[6:]
                                
                                if data_str.strip() == "[DONE]":
                                    break
                                
                                try:
                                    chunk_data = json.loads(data_str)
                                    if "choices" in chunk_data and chunk_data["choices"]:
                                        delta = chunk_data["choices"][0].get("delta", {})
                                        content = delta.get("content", "")
                                        
                                        if content:
                                            scenario_analyzer.add_chunk(content, chunk_time)
                                            analyzer.add_chunk(content, chunk_time)
                                            
                                            chunks_received += 1
                                            total_content += content
                                            chunk_sizes.append(len(content))
                                            
                                            if last_chunk_time:
                                                chunk_timings.append(chunk_time - last_chunk_time)
                                            last_chunk_time = chunk_time
                                
                                except json.JSONDecodeError:
                                    scenario_analyzer.add_error("json_decode_error", "Parse error")
                    
                    else:
                        scenario_analyzer.add_error("request_failed", f"Status: {response.status_code}")
            
            except Exception as e:
                scenario_analyzer.add_error("stream_exception", str(e))
            
            stream_end = time.time()
            total_duration = stream_end - stream_start
            
            # Calculate quality metrics for this scenario
            scenario_metrics = scenario_analyzer.calculate_metrics()
            
            # Calculate scenario-specific quality factors
            quality_assessment = {
                "consistency": self._assess_consistency(chunk_sizes, chunk_timings),
                "completeness": self._assess_completeness(total_content, scenario["max_tokens"]),
                "timing": self._assess_timing(chunk_timings, total_duration),
                "throughput": self._assess_throughput(len(total_content), total_duration),
                "chunking": self._assess_chunking(chunk_sizes),
                "reliability": self._assess_reliability(scenario_metrics)
            }
            
            overall_quality = sum(quality_assessment[factor] for factor in scenario["quality_factors"]) / len(scenario["quality_factors"])
            
            quality_results.append({
                "scenario": scenario,
                "chunks_received": chunks_received,
                "content_length": len(total_content),
                "duration": total_duration,
                "metrics": scenario_metrics,
                "quality_assessment": quality_assessment,
                "overall_quality": overall_quality
            })
            
            await asyncio.sleep(1.0)
        
        # Calculate overall quality metrics
        overall_metrics = analyzer.calculate_metrics()
        overall_anomalies = analyzer.detect_anomalies()
        
        # Aggregate quality assessment
        avg_quality_scores = {}
        for factor in ["consistency", "completeness", "timing", "throughput", "chunking", "reliability"]:
            scores = [r["quality_assessment"][factor] for r in quality_results]
            avg_quality_scores[factor] = sum(scores) / len(scores)
        
        overall_quality_score = sum(avg_quality_scores.values()) / len(avg_quality_scores)
        
        logger.info("Streaming Response Quality Assessment Results:")
        logger.info(f"  Overall Quality Score: {overall_quality_score:.1f}/100")
        logger.info(f"  System Quality Score: {overall_metrics.quality_score:.1f}/100")
        logger.info(f"  Total Chunks Processed: {overall_metrics.total_chunks}")
        logger.info(f"  Total Anomalies: {len(overall_anomalies)}")
        
        logger.info("  Quality Factor Breakdown:")
        for factor, score in avg_quality_scores.items():
            logger.info(f"    {factor.capitalize()}: {score:.1f}/100")
        
        logger.info("  Scenario Results:")
        for result in quality_results:
            scenario = result["scenario"]
            logger.info(f"    {scenario['name']}: {result['overall_quality']:.1f}/100")
        
        # Verify overall streaming quality
        assert overall_quality_score >= 70.0, f"Overall quality should be good: {overall_quality_score:.1f}/100"
        assert overall_metrics.quality_score >= 70.0, f"System quality should be good: {overall_metrics.quality_score:.1f}/100"
        
        # Most quality factors should be acceptable
        acceptable_factors = sum(1 for score in avg_quality_scores.values() if score >= 60.0)
        assert acceptable_factors >= len(avg_quality_scores) * 0.8, \
            f"Most quality factors should be acceptable: {acceptable_factors}/{len(avg_quality_scores)}"
        
        # Individual scenarios should perform reasonably
        good_scenarios = sum(1 for r in quality_results if r["overall_quality"] >= 60.0)
        assert good_scenarios >= len(quality_results) * 0.75, \
            f"Most scenarios should have good quality: {good_scenarios}/{len(quality_results)}"
        
        logger.info("✅ Streaming response quality assessment completed")
    
    def _validate_partial_content(self, content: str, validation_type: str) -> Dict[str, Any]:
        """Validate partial content based on type"""
        if validation_type == "numbered_list":
            lines = content.strip().split('\n')
            numbered_items = sum(1 for line in lines if line.strip() and any(char.isdigit() for char in line[:5]))
            return {
                "valid": numbered_items >= 1,
                "score": min(100, numbered_items * 10),
                "details": f"Found {numbered_items} numbered items"
            }
        
        elif validation_type == "json_structure":
            json_indicators = content.count('{') + content.count('[') + content.count('"')
            return {
                "valid": json_indicators >= 3,
                "score": min(100, json_indicators * 5),
                "details": f"JSON structure indicators: {json_indicators}"
            }
        
        elif validation_type == "paragraph_structure":
            paragraphs = len([p for p in content.split('\n\n') if p.strip()])
            return {
                "valid": paragraphs >= 1,
                "score": min(100, paragraphs * 33),
                "details": f"Found {paragraphs} paragraphs"
            }
        
        return {"valid": False, "score": 0, "details": "Unknown validation type"}
    
    def _assess_consistency(self, chunk_sizes: List[int], chunk_timings: List[float]) -> float:
        """Assess chunk size and timing consistency"""
        if not chunk_sizes or not chunk_timings:
            return 50.0
        
        # Size consistency
        avg_size = sum(chunk_sizes) / len(chunk_sizes)
        size_variance = sum((size - avg_size) ** 2 for size in chunk_sizes) / len(chunk_sizes)
        size_consistency = max(0, 100 - (size_variance / (avg_size + 1) * 100))
        
        # Timing consistency
        avg_timing = sum(chunk_timings) / len(chunk_timings)
        timing_variance = sum((timing - avg_timing) ** 2 for timing in chunk_timings) / len(chunk_timings)
        timing_consistency = max(0, 100 - (timing_variance / (avg_timing + 0.1) * 100))
        
        return (size_consistency + timing_consistency) / 2
    
    def _assess_completeness(self, content: str, max_tokens: int) -> float:
        """Assess content completeness"""
        content_length = len(content)
        expected_length = max_tokens * 4  # Rough estimate: 4 chars per token
        
        if content_length >= expected_length * 0.8:
            return 100.0
        elif content_length >= expected_length * 0.5:
            return 80.0
        elif content_length >= expected_length * 0.2:
            return 60.0
        else:
            return max(0, content_length / expected_length * 100)
    
    def _assess_timing(self, chunk_timings: List[float], total_duration: float) -> float:
        """Assess timing quality"""
        if not chunk_timings or total_duration <= 0:
            return 50.0
        
        # Prefer consistent, reasonable timing
        avg_gap = sum(chunk_timings) / len(chunk_timings)
        
        if avg_gap <= 1.0:  # Fast response
            return 100.0
        elif avg_gap <= 2.0:  # Good response
            return 80.0
        elif avg_gap <= 5.0:  # Acceptable response
            return 60.0
        else:  # Slow response
            return max(0, 100 - (avg_gap - 5) * 10)
    
    def _assess_throughput(self, content_length: int, duration: float) -> float:
        """Assess throughput quality"""
        if duration <= 0:
            return 50.0
        
        chars_per_sec = content_length / duration
        
        if chars_per_sec >= 100:  # High throughput
            return 100.0
        elif chars_per_sec >= 50:  # Good throughput
            return 80.0
        elif chars_per_sec >= 20:  # Acceptable throughput
            return 60.0
        else:  # Low throughput
            return max(0, chars_per_sec * 3)
    
    def _assess_chunking(self, chunk_sizes: List[int]) -> float:
        """Assess chunking quality"""
        if not chunk_sizes:
            return 50.0
        
        # Prefer moderate, consistent chunk sizes
        avg_size = sum(chunk_sizes) / len(chunk_sizes)
        
        if 10 <= avg_size <= 100:  # Good chunk size range
            return 100.0
        elif 5 <= avg_size <= 200:  # Acceptable range
            return 80.0
        elif avg_size > 0:  # Some chunking
            return 60.0
        else:
            return 0.0
    
    def _assess_reliability(self, metrics: StreamMetrics) -> float:
        """Assess overall reliability"""
        reliability_score = 100.0
        
        # Penalize errors
        if metrics.error_count > 0:
            reliability_score -= min(50, metrics.error_count * 10)
        
        # Penalize poor quality
        if metrics.quality_score < 70:
            reliability_score -= (70 - metrics.quality_score)
        
        # Reward consistent performance
        if metrics.total_chunks > 10:
            reliability_score += 10
        
        return max(0.0, reliability_score)