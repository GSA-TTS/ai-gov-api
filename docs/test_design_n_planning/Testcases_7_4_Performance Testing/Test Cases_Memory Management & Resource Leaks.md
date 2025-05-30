# Test Cases: Memory Management & Resource Leaks

This document outlines test cases for evaluating memory allocation, garbage collection performance, and detecting potential memory leaks, particularly concerning long-running processes, large LLM payloads, and streaming responses. This is based on the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing".

**Test Cases Summary: 14 (Original: 7, Enhanced: +7)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* app/main.py (FastAPI application lifecycle)
* app/providers/*/adapter_to_core.py, app/providers/*/adapter_from_core.py (provider memory management)
* app/services/billing.py:billing_queue, billing_worker (background task memory)
* app/db/session.py (database connection pooling)
* Python gc module, memory_profiler, objgraph (profiling tools)

## General Test Case Components:
* **ID:** Unique identifier (e.g., PERF_MEM_LEAK_STREAM_001)
* **Category Ref:** (e.g., PERF_MEM_LEAK, PERF_MEM_PAYLOAD, PERF_MEM_GC)
* **Description:** The specific memory management aspect or potential leak scenario being tested.
* **Exposure Point(s):** Python memory allocation, garbage collection, object lifecycle in FastAPI request handling, provider SDKs, streaming logic, background tasks like `billing_worker`.
* **Test Method/Action:** Sustained load tests, requests with large payloads, or specific scenarios designed to stress memory.
* **Prerequisites:** Performance testing environment. Monitoring tools for server memory usage (e.g., Prometheus with node exporter, `htop`, `vmstat`). Python memory profiling tools (e.g., `memory-profiler`, `objgraph`) for deeper analysis if needed.
* **Expected Secure Outcome:** Stable memory usage patterns over time. No unbounded growth in memory consumption. Efficient garbage collection. Prompt release of resources after request completion.
* **Verification Steps:** Long-term monitoring of memory metrics (RSS, VMS). Comparison of memory snapshots. Analysis of GC behavior.

---

### 1\. Memory Leak Detection Patterns

* **ID:** PERF_MEM_LEAK_ENDURANCE_LOAD_001
    * **Category Ref:** PERF_MEM_LEAK
    * **Description:** Detect memory leaks under a sustained, long-running endurance load test.
    * **Exposure Point(s):** Entire application stack over time.
    * **Test Method/Action:**
        1.  Run an endurance load test (e.g., moderate mixed workload for 4-8+ hours as per PERF_LOAD_ENDURANCE_001).
        2.  Continuously monitor the API server's memory usage (RSS and VMS).
    * **Prerequisites:** Endurance load testing setup. Continuous memory monitoring.
    * **Expected Secure Outcome:** Memory usage plateaus after an initial warm-up period and does not show a continuous upward trend throughout the test. Garbage collection activity is regular and effective in reclaiming memory.
    * **Verification Steps:**
        1.  Plot memory usage over the duration of the test.
        2.  Analyze the trend line; it should be flat or cyclical, not consistently increasing.
        3.  Check GC logs or metrics (if available) for excessive collection times or failures.

* **ID:** PERF_MEM_LEAK_STREAMING_CONNECTIONS_002
    * **Category Ref:** PERF_MEM_LEAK
    * **Description:** Test for memory leaks related to opening and closing many streaming connections, or prematurely terminated streams.
    * **Exposure Point(s):** Streaming logic (`StreamingResponse`, async generators in provider backends, adapter chunk processing), provider SDK stream handling.
    * **Test Method/Action:**
        1.  Repeatedly initiate streaming chat requests.
        2.  Scenario A: Allow streams to complete normally.
        3.  Scenario B: Prematurely close client connections for a subset of streams.
        4.  Monitor API server memory usage over a period of many such stream initiations/terminations (e.g., 1000s of streams over 30-60 minutes).
    * **Prerequisites:** Test client capable of managing and abruptly closing stream connections.
    * **Expected Secure Outcome:** Memory usage remains stable. Resources associated with each stream (e.g., generator objects, provider SDK resources) are released promptly after completion or client disconnection.
    * **Verification Steps:**
        1.  Monitor memory usage trend.
        2.  Use tools like `objgraph` in a controlled dev environment to check for accumulation of specific object types related to streaming if a leak is suspected.

* **ID:** PERF_MEM_LEAK_BILLING_QUEUE_003
    * **Category Ref:** PERF_MEM_LEAK
    * **Description:** Test for memory growth if the `billing_queue` in `app/services/billing.py` grows very large due to a slow or stuck `billing_worker`.
    * **Exposure Point(s):** `asyncio.Queue` (`billing_queue`), `billing_worker` processing.
    * **Test Method/Action:**
        1.  Mock the `billing_worker` to be very slow (e.g., add a long `asyncio.sleep()` in its loop) or to error out repeatedly, preventing queue consumption.
        2.  Send a high volume of billable API requests (chat/embeddings) to populate the queue.
        3.  Monitor the API server's memory usage.
    * **Prerequisites:** Ability to mock/alter `billing_worker` behavior.
    * **Expected Secure Outcome:** If the queue is unbounded and grows significantly, memory usage will increase. This test highlights the risk. A production-ready system might need a bounded queue or monitoring on queue size. The API should not crash due to OOM from this, but performance might degrade.
    * **Verification Steps:**
        1.  Monitor memory usage while the queue is expected to grow.
        2.  (If possible) Monitor the actual size of `billing_queue` in memory.

* **ID:** PERF_MEM_LEAK_PROVIDER_SDK_CLIENTS_004
    * **Category Ref:** PERF_MEM_LEAK
    * **Description:** Verify that provider SDK clients (e.g., `aioboto3` session clients, `google-cloud-aiplatform` clients) are managed correctly and do not leak resources over many requests.
    * **Exposure Point(s):** Provider backend modules (`BedRockBackend`, `VertexBackend`) where SDK clients are instantiated and used.
    * **Test Method/Action:**
        1.  Send a large number of requests, alternating between models from different providers if possible, over an extended period.
        2.  Focus on scenarios that might involve re-initialization or complex session management within the SDKs.
    * **Prerequisites:**
    * **Expected Secure Outcome:** Memory usage related to SDK clients remains stable. Connections or sessions managed by SDKs are properly released or reused. (Note: SDKs often manage their own connection pools).
    * **Verification Steps:**
        1.  Monitor overall API server memory.
        2.  If leaks are suspected and tools allow, try to inspect the number of active SDK client objects or related network connections.

---

### 2\. Large Payload Handling (Memory Aspect)

* **ID:** PERF_MEM_PAYLOAD_CHAT_LARGE_PROMPT_001
    * **Category Ref:** PERF_MEM_PAYLOAD
    * **Description:** Assess memory usage when processing chat requests with very large prompts (e.g., near max context window).
    * **Exposure Point(s):** FastAPI request body parsing, Pydantic model instantiation, adapter logic, provider SDK request preparation.
    * **Test Method/Action:** Send multiple requests with prompts that are large (e.g., 50KB, 100KB of text, constituting many thousands of tokens).
    * **Prerequisites:** Valid API Key.
    * **Expected Secure Outcome:** API processes the requests (may result in provider error if context limit truly exceeded). Memory usage spikes per request but is reclaimed afterward. No OOM errors in the API framework itself if payload is within server's configured max request size.
    * **Verification Steps:** Monitor peak memory usage during these requests. Ensure memory returns to baseline after requests are complete.

* **ID:** PERF_MEM_PAYLOAD_CHAT_LARGE_RESPONSE_002
    * **Category Ref:** PERF_MEM_PAYLOAD
    * **Description:** Assess memory usage when handling and sending large non-streaming chat responses.
    * **Exposure Point(s):** Provider SDK response handling, adapter logic, Pydantic response model serialization, FastAPI JSON response generation.
    * **Test Method/Action:** Send requests that will generate large non-streaming responses (e.g., by setting `max_tokens` to a high value like 4000-8000 and using a prompt that encourages verbose output).
    * **Prerequisites:** Valid API Key.
    * **Expected Secure Outcome:** API successfully receives, processes, and transmits the large response. Memory usage increases during processing but is reclaimed. No OOM errors.
    * **Verification Steps:** Monitor memory during and after these requests.

* **ID:** PERF_MEM_PAYLOAD_EMBED_LARGE_BATCH_003
    * **Category Ref:** PERF_MEM_PAYLOAD
    * **Description:** Evaluate memory usage when processing large batch embedding requests.
    * **Exposure Point(s):** FastAPI request parsing, Pydantic, adapter, provider SDK.
    * **Test Method/Action:** Send `/embeddings` requests with a large number of input strings in the batch (e.g., 1000-2000 texts, up to provider limits).
    * **Prerequisites:** Valid API Key.
    * **Expected Secure Outcome:** API processes the batch request. Memory usage is proportional to batch size but handled efficiently. No OOM errors.
    * **Verification Steps:** Monitor memory during and after these requests.

---

### 3\. Garbage Collection Impact

* **ID:** PERF_MEM_GC_BEHAVIOR_LOAD_001
    * **Category Ref:** PERF_MEM_GC
    * **Description:** Observe Python's garbage collection behavior and its potential impact on latency under sustained load.
    * **Exposure Point(s):** Python runtime GC.
    * **Test Method/Action:**
        1.  Run a sustained load test (e.g., peak load for 30 mins).
        2.  Monitor GC metrics (e.g., frequency of collections, time spent in GC pauses for different generations) using Python's `gc` module introspection or external profiling tools if available for async Python.
        3.  Correlate GC events with API request latency spikes.
    * **Prerequisites:** Load testing setup. Advanced Python profiling/monitoring tools or custom GC logging.
    * **Expected Secure Outcome:** Garbage collection occurs regularly but does not cause frequent or prolonged pauses that significantly impact p99 latency or overall throughput. No excessive promotion of objects to older generations if short-lived objects are managed well.
    * **Verification Steps:**
        1.  Analyze GC logs/metrics.
        2.  Look for correlations between long GC pauses and high request latency outliers.

---

## Enhanced Test Cases (7 Advanced Memory Management Scenarios)

### 4. Automated Memory Profiling and Trend Analysis

* **ID:** PERF_MEM_AUTOMATED_PROFILING_001
    * **Category Ref:** PERF_MEM_AUTOMATED_PROFILING
    * **Description:** Implement automated memory profiling that continuously monitors memory usage patterns and detects trend anomalies.
    * **Exposure Point(s):** Python memory allocation patterns, object lifecycle management, automated monitoring systems
    * **Test Method/Action:**
        1. Deploy continuous memory monitoring using memory_profiler and psutil
        2. Establish baseline memory usage patterns during normal operations
        3. Implement automated alerts for memory usage trend deviations
        4. Test anomaly detection accuracy with synthetic memory leak scenarios
    * **Prerequisites:** Memory profiling tools integrated, automated monitoring infrastructure, baseline data collection
    * **Expected Secure Outcome:** Automated system detects memory anomalies within 15 minutes. False positive rate <5%. Memory trend analysis provides actionable insights for optimization.
    * **Verification Steps:**
        1. Validate automated anomaly detection accuracy
        2. Test alert responsiveness and threshold tuning
        3. Verify trend analysis provides useful optimization guidance

### 5. Memory Fragmentation Analysis

* **ID:** PERF_MEM_FRAGMENTATION_ANALYSIS_002
    * **Category Ref:** PERF_MEM_FRAGMENTATION
    * **Description:** Analyze memory fragmentation patterns under various workload scenarios and their impact on performance.
    * **Exposure Point(s):** Python heap management, large object allocation patterns, memory allocator behavior
    * **Test Method/Action:**
        1. Monitor memory fragmentation using custom Python memory analysis tools
        2. Test different workload patterns (many small objects vs few large objects)
        3. Measure correlation between fragmentation and allocation performance
        4. Test memory defragmentation strategies if available
    * **Prerequisites:** Custom memory analysis tools, detailed heap monitoring capabilities
    * **Expected Secure Outcome:** Memory fragmentation remains below 20% under normal workloads. Large object allocations don't cause excessive fragmentation. Performance degradation from fragmentation is minimal.
    * **Verification Steps:**
        1. Measure fragmentation levels under different workload patterns
        2. Correlate fragmentation with allocation performance metrics
        3. Test effectiveness of fragmentation mitigation strategies

### 6. Async Task Memory Lifecycle Testing

* **ID:** PERF_MEM_ASYNC_TASK_LIFECYCLE_003
    * **Category Ref:** PERF_MEM_ASYNC_LIFECYCLE
    * **Description:** Test memory management in async tasks including proper cleanup of coroutines, futures, and async generators.
    * **Exposure Point(s):** FastAPI async request handlers, provider SDK async calls, streaming async generators
    * **Test Method/Action:**
        1. Monitor memory usage of long-running async tasks
        2. Test memory cleanup when async tasks are cancelled or timeout
        3. Verify proper cleanup of async generators used in streaming
        4. Test memory impact of concurrent async task creation/destruction
    * **Prerequisites:** Async task monitoring tools, ability to simulate task cancellation scenarios
    * **Expected Secure Outcome:** Async tasks release memory promptly upon completion. Cancelled tasks don't leak memory. Async generators are properly cleaned up when streams terminate.
    * **Verification Steps:**
        1. Monitor memory usage throughout async task lifecycles
        2. Test memory cleanup in various async task termination scenarios
        3. Verify no accumulation of unreferenced async objects

### 7. Provider SDK Memory Management

* **ID:** PERF_MEM_PROVIDER_SDK_MANAGEMENT_004
    * **Category Ref:** PERF_MEM_PROVIDER_SDK
    * **Description:** Test memory management within provider SDKs including connection pooling, response buffering, and session management.
    * **Exposure Point(s):** app/providers/bedrock/bedrock.py (aioboto3), app/providers/vertex_ai/vertexai.py (google-cloud-aiplatform)
    * **Test Method/Action:**
        1. Monitor memory usage of provider SDK sessions and connections
        2. Test memory impact of large response payloads from providers
        3. Verify proper cleanup of SDK resources after requests
        4. Test memory behavior under provider error conditions
    * **Prerequisites:** SDK-specific memory monitoring, ability to simulate various provider response scenarios
    * **Expected Secure Outcome:** Provider SDKs manage memory efficiently. Large responses don't cause memory spikes. SDK resources are properly released after errors.
    * **Verification Steps:**
        1. Monitor SDK memory usage patterns across different request types
        2. Test memory cleanup after SDK errors and timeouts
        3. Verify connection pool memory management

### 8. Memory Pressure Recovery Testing

* **ID:** PERF_MEM_PRESSURE_RECOVERY_005
    * **Category Ref:** PERF_MEM_PRESSURE_RECOVERY
    * **Description:** Test system behavior and recovery mechanisms under high memory pressure conditions.
    * **Exposure Point(s):** Python memory management, OS memory pressure, garbage collection under stress
    * **Test Method/Action:**
        1. Gradually increase memory usage to approach system limits
        2. Monitor garbage collection behavior under memory pressure
        3. Test system recovery when memory pressure is relieved
        4. Verify error handling when memory allocation fails
    * **Prerequisites:** Ability to control system memory pressure, comprehensive memory monitoring
    * **Expected Secure Outcome:** System gracefully handles memory pressure without crashes. Garbage collection becomes more aggressive under pressure. Recovery is complete when pressure is relieved.
    * **Verification Steps:**
        1. Monitor system behavior as memory pressure increases
        2. Test recovery patterns when memory pressure decreases
        3. Verify error handling for memory allocation failures

### 9. Real-time Memory Leak Detection

* **ID:** PERF_MEM_REALTIME_LEAK_DETECTION_006
    * **Category Ref:** PERF_MEM_REALTIME_LEAK
    * **Description:** Implement real-time memory leak detection that can identify leaks during production operations.
    * **Exposure Point(s):** All application components, real-time monitoring systems, leak detection algorithms
    * **Test Method/Action:**
        1. Deploy real-time memory growth monitoring with sliding window analysis
        2. Implement statistical analysis to distinguish growth from leaks
        3. Test detection accuracy with controlled leak scenarios
        4. Validate alerting and diagnostic information quality
    * **Prerequisites:** Real-time monitoring infrastructure, statistical analysis tools, controlled leak injection capability
    * **Expected Secure Outcome:** Real-time leak detection identifies true leaks within 30 minutes. False positive rate <2%. Diagnostic information pinpoints leak sources.
    * **Verification Steps:**
        1. Test detection accuracy with various leak patterns
        2. Validate diagnostic information usefulness
        3. Verify alerting responsiveness and accuracy

### 10. Memory-Optimal Request Batching

* **ID:** PERF_MEM_OPTIMAL_BATCHING_007
    * **Category Ref:** PERF_MEM_OPTIMAL_BATCHING
    * **Description:** Optimize request batching strategies to minimize memory usage while maintaining performance.
    * **Exposure Point(s):** Request batching logic, memory allocation patterns, batch size optimization
    * **Test Method/Action:**
        1. Test memory usage across different batch sizes and patterns
        2. Implement adaptive batching based on available memory
        3. Measure memory efficiency vs performance trade-offs
        4. Test memory behavior with mixed request sizes in batches
    * **Prerequisites:** Configurable batching system, memory usage measurement per batch
    * **Expected Secure Outcome:** Optimal batch sizes identified for different memory scenarios. Adaptive batching reduces memory peaks while maintaining throughput. Memory efficiency improves without performance degradation.
    * **Verification Steps:**
        1. Compare memory usage across different batching strategies
        2. Test adaptive batching effectiveness under varying memory conditions
        3. Verify performance is maintained with optimized batching

---