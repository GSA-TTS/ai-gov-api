# Test Cases: LLM-Specific Performance Metrics

This document outlines test cases for verifying the performance of specific LLM interaction metrics as defined in the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing".

**Test Cases Summary: 22 (Original: 11, Enhanced: +11)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* app/routers/api_v1.py:33-60 (Chat completions and embeddings endpoints)
* app/providers/*/adapter_to_core.py (Provider response processing)
* app/providers/bedrock/bedrock.py (Bedrock backend implementation)
* app/providers/vertex_ai/vertexai.py (Vertex AI backend implementation)
* app/config/settings.py:16-20 (Backend map configuration)

## General Test Case Components:
* **ID:** Unique identifier (e.g., PERF_LLM_TTFT_001)
* **Category Ref:** (e.g., PERF_LLM_TTFT, PERF_LLM_THROUGHPUT, PERF_LLM_CONTEXT_WINDOW, PERF_LLM_STREAM_LATENCY, PERF_LLM_EMBEDDING)
* **Description:** What specific performance metric/aspect is being tested.
* **Exposure Point(s):** API endpoint, specific parameters affecting performance, LLM provider interaction.
* **Test Method/Action:** How the test is performed (e.g., "Send N requests with X configuration, measure Y metric").
* **Prerequisites:** Valid API Key, specific model selection, load testing tools (if applicable), monitoring tools.
* **Expected Secure Outcome:** Defined performance target for the metric (e.g., "TTFT p95 < 500ms").
* **Verification Steps:** How to confirm the expected outcome (e.g., "Collect TTFT data from N runs, calculate p95").

---

### 1\. Time to First Token (TTFT) for Streaming Responses

* **ID:** PERF_LLM_TTFT_CHAT_STREAM_001
    * **Category Ref:** PERF_LLM_TTFT
    * **Description:** Measure TTFT for /chat/completions with stream:true under normal load.
    * **Exposure Point(s):** /api/v1/chat/completions, entire request pipeline (FastAPI, auth, model loading, adapter, provider SDK, network, LLM provider initial processing).
    * **Test Method/Action:**
        1.  Select a representative chat model.
        2.  Send N (e.g., 100) requests with `stream: true` and a standard short prompt (e.g., "Tell me a short story").
        3.  For each request, measure the time from sending the request to receiving the first data chunk (SSE event with content).
    * **Prerequisites:** Valid API Key. Configured chat model. Tooling to accurately measure TTFT.
    * **Expected Secure Outcome:** p95 TTFT should be < 500ms. (Target from Test Plan 7.4.1)
    * **Verification Steps:**
        1.  Collect TTFT for all N requests.
        2.  Calculate the 95th percentile of the collected TTFT values.
        3.  Assert p95 TTFT < 500ms.
        4.  Analyze outliers and distribution.

* **ID:** PERF_LLM_TTFT_CHAT_STREAM_PROVIDER_COMPARE_002
    * **Category Ref:** PERF_LLM_TTFT
    * **Description:** Compare TTFT for streaming chat completions across different LLM providers (e.g., Bedrock vs. Vertex AI).
    * **Exposure Point(s):** Provider-specific backend logic (app/providers/bedrock/bedrock.py, app/providers/vertex\_ai/vertexai.py), provider SDKs, network latency to providers.
    * **Test Method/Action:**
        1.  Select a chat model from Bedrock (e.g., "claude_3_5_sonnet") and a comparable one from Vertex AI (e.g., "gemini-2.0-flash").
        2.  For each model, send N (e.g., 100) requests with `stream: true` and the same standard short prompt.
        3.  Measure TTFT for each request.
    * **Prerequisites:** Valid API Key. Models configured for both Bedrock and Vertex AI.
    * **Expected Secure Outcome:** Both providers achieve target TTFT (e.g., p95 < 500ms). Note any significant, consistent differences in TTFT between providers.
    * **Verification Steps:**
        1.  Calculate p95 TTFT for each provider.
        2.  Compare the distributions.
        3.  Log results for provider performance characteristics.

* **ID:** PERF_LLM_TTFT_CHAT_STREAM_PROMPT_SIZE_IMPACT_003
    * **Category Ref:** PERF_LLM_TTFT
    * **Description:** Evaluate impact of initial prompt size on TTFT for streaming chat completions.
    * **Exposure Point(s):** /api/v1/chat/completions, LLM provider processing of varied prompt lengths.
    * **Test Method/Action:**
        1.  Select a chat model.
        2.  Send N requests with `stream: true` using a short prompt (e.g., 50 tokens). Measure TTFT.
        3.  Send N requests with `stream: true` using a medium prompt (e.g., 500 tokens). Measure TTFT.
        4.  Send N requests with `stream: true` using a long prompt (e.g., 2000 tokens, within context window). Measure TTFT.
    * **Prerequisites:** Valid API Key. Tooling to generate prompts of specific token lengths.
    * **Expected Secure Outcome:** TTFT may increase slightly with prompt size but should not degrade disproportionately. All should remain within acceptable SLOs (e.g., p95 TTFT < 1s for longer prompts, adjust target based on expectation).
    * **Verification Steps:**
        1.  Calculate p95 TTFT for each prompt size category.
        2.  Compare results to understand sensitivity of TTFT to prompt length.

---

### 2\. Token Generation Throughput

* **ID:** PERF_LLM_THROUGHPUT_CHAT_STREAM_001
    * **Category Ref:** PERF_LLM_THROUGHPUT
    * **Description:** Measure token generation throughput for streaming /chat/completions.
    * **Exposure Point(s):** LLM provider generation speed, API framework chunk processing efficiency (adapters, SSE formatting), network bandwidth.
    * **Test Method/Action:**
        1.  Select a representative chat model.
        2.  Send N (e.g., 50) requests with `stream: true`, a prompt that elicits a moderately long response (e.g., "Tell me a story about a brave knight, about 300 words"), and `max_tokens` set to a reasonable value (e.g., 500).
        3.  For each stream, measure the time from the first content chunk received to the last content chunk received. Count the total number of tokens generated (can be estimated from character count or via provider's reported usage if available post-stream).
        4.  Calculate tokens per second: (total completion tokens) / (time from first to last token).
    * **Prerequisites:** Valid API Key.
    * **Expected Secure Outcome:** Average token generation throughput meets target (e.g., 50-150 tokens/second, model-dependent, as per Test Plan 7.4.1).
    * **Verification Steps:**
        1.  Calculate throughput for each of the N requests.
        2.  Analyze average, p50, p95 throughput.
        3.  Compare against model-specific benchmarks.

* **ID:** PERF_LLM_THROUGHPUT_CHAT_NONSTREAM_002
    * **Category Ref:** PERF_LLM_THROUGHPUT
    * **Description:** Measure effective token generation throughput for non-streaming /chat/completions.
    * **Exposure Point(s):** LLM provider speed, API framework efficiency in handling full responses.
    * **Test Method/Action:**
        1.  Select a chat model.
        2.  Send N requests with `stream: false` (or not set), a prompt for a moderately long response, and `max_tokens` (e.g., 500).
        3.  For each request, measure total response time. Get `completion_tokens` from the `usage` object.
        4.  Effective throughput: `completion_tokens` / (total response time - estimated TTFT if TTFT were measured separately for similar prompts, or just `completion_tokens` / total response time as a simpler metric).
    * **Prerequisites:** Valid API Key.
    * **Expected Secure Outcome:** Effective throughput is reasonable for the model, though it will be lower than pure generation throughput due to full response overhead.
    * **Verification Steps:** Calculate and analyze effective throughput.

---

### 3\. Context Window Performance

* **ID:** PERF_LLM_CONTEXT_WINDOW_CHAT_LATENCY_001
    * **Category Ref:** PERF_LLM_CONTEXT_WINDOW
    * **Description:** Evaluate total response time for /chat/completions (non-streaming) as prompt size (context window utilization) increases.
    * **Exposure Point(s):** LLM provider context handling, API framework payload processing (Pydantic, JSON).
    * **Test Method/Action:**
        1.  Select a chat model.
        2.  Send N requests with a short prompt (e.g., 50 tokens). Measure total response time.
        3.  Send N requests with a medium prompt (e.g., 50% of model's context window). Measure total response time.
        4.  Send N requests with a long prompt (e.g., 90% of model's context window). Measure total response time.
        5.  (Optional) Send N requests with a prompt known to exceed context window.
        Ensure `max_tokens` for completion is small and fixed for all tests to isolate prompt processing impact.
    * **Prerequisites:** Valid API Key. Tooling to generate prompts of specific token lengths. Knowledge of model's context window.
    * **Expected Secure Outcome:**
        * Response time increases with prompt size but remains within acceptable SLOs for supported context sizes.
        * Requests exceeding the context window return a 4xx error quickly (e.g., 400, 422).
        * API framework memory usage does not grow excessively with large prompt payloads.
    * **Verification Steps:**
        1.  Calculate p95 total response time for each prompt size category.
        2.  Verify error handling for prompts exceeding limits.
        3.  Monitor API server resource utilization during tests.

* **ID:** PERF_LLM_CONTEXT_WINDOW_EMBED_LATENCY_002
    * **Category Ref:** PERF_LLM_CONTEXT_WINDOW
    * **Description:** Evaluate response time for /embeddings as input text size increases.
    * **Exposure Point(s):** Embedding model provider context handling.
    * **Test Method/Action:**
        1.  Select an embedding model.
        2.  Send N requests with short input text (e.g., 50 tokens). Measure response time.
        3.  Send N requests with medium input text (e.g., 500 tokens). Measure response time.
        4.  Send N requests with long input text (e.g., near model's max input tokens for embeddings). Measure response time.
    * **Prerequisites:** Valid API Key.
    * **Expected Secure Outcome:** Response time increases with input size but remains within SLOs for supported input sizes. Graceful error handling for inputs exceeding provider limits.
    * **Verification Steps:**
        1.  Calculate p95 response time for each input size.
        2.  Verify error handling for excessive input length.

---

### 4\. Streaming Response Latency (Inter-Chunk Latency)

* **ID:** PERF_LLM_STREAM_LATENCY_INTERCHUNK_001
    * **Category Ref:** PERF_LLM_STREAM_LATENCY
    * **Description:** Measure the typical delay between successive content chunks in a streaming response.
    * **Exposure Point(s):** LLM provider chunk generation speed, API framework processing overhead per chunk.
    * **Test Method/Action:**
        1.  Select a chat model.
        2.  Send N requests with `stream: true` and a prompt that elicits a response of at least 50-100 tokens.
        3.  For each stream, record the arrival time of each `delta.content` chunk. Calculate the time differences between consecutive content-bearing chunks.
    * **Prerequisites:** Valid API Key. Tooling for precise timing of SSE events.
    * **Expected Secure Outcome:** Average and p95 inter-chunk latency are low and consistent (e.g., 20-50ms as per Test Plan 7.4.1 targets).
    * **Verification Steps:**
        1.  Collect inter-chunk latencies for all streams.
        2.  Analyze distribution (average, p50, p95, max).
        3.  Check for excessive outliers or periods of high latency within streams.

---

### 5\. Embedding Performance

* **ID:** PERF_LLM_EMBEDDING_SINGLE_LATENCY_001
    * **Category Ref:** PERF_LLM_EMBEDDING
    * **Description:** Measure latency for generating embeddings for a single text input.
    * **Exposure Point(s):** /api/v1/embeddings, embedding model provider performance.
    * **Test Method/Action:**
        1.  Select an embedding model.
        2.  Send N (e.g., 100) requests to /embeddings, each with a single input string of typical length (e.g., 100-200 tokens).
        3.  Measure the total response time for each request.
    * **Prerequisites:** Valid API Key.
    * **Expected Secure Outcome:** p95 response time for single embeddings is low (e.g., < 100ms as per Test Plan 7.4.1).
    * **Verification Steps:** Calculate p95 response time.

* **ID:** PERF_LLM_EMBEDDING_BATCH_THROUGHPUT_002
    * **Category Ref:** PERF_LLM_EMBEDDING
    * **Description:** Measure throughput for batch embedding requests.
    * **Exposure Point(s):** /api/v1/embeddings, provider batch processing capabilities.
    * **Test Method/Action:**
        1.  Select an embedding model that supports batching.
        2.  Send N requests, each with a batch of M input strings (e.g., M=64, 128, or up to provider's documented batch limit).
        3.  For each request, measure total response time.
        4.  Calculate throughput: (M embeddings) / (total response time).
    * **Prerequisites:** Valid API Key.
    * **Expected Secure Outcome:** Batch embedding throughput is high (e.g., 1000 embeddings/second as per Test Plan 7.4.1, though this target is very ambitious and provider/model dependent). Compare throughput for different batch sizes M.
    * **Verification Steps:**
        1.  Calculate average and p95 throughput for different batch sizes.
        2.  Identify optimal batch size for throughput if observable.

## Enhanced Test Cases (11 Advanced Scenarios)

### 6. Adaptive Performance Optimization

* **ID:** PERF_LLM_ADAPTIVE_SCALING_001
    * **Category Ref:** PERF_LLM_ADAPTIVE
    * **Description:** Test adaptive performance optimization that dynamically adjusts provider selection based on real-time performance metrics.
    * **Exposure Point(s):** app/providers/dependencies.py (provider selection logic), app/config/settings.py (backend_map optimization)
    * **Test Method/Action:**
        1. Monitor baseline performance for chat completions across different providers
        2. Simulate performance degradation on primary provider (inject latency or errors)
        3. Measure system's ability to adapt and route traffic to better-performing providers
        4. Test recovery behavior when primary provider performance improves
    * **Prerequisites:** Multi-provider setup, performance monitoring, adaptive routing logic
    * **Expected Secure Outcome:** System automatically routes traffic to optimal providers based on performance. Overall user experience remains stable during provider performance fluctuations. Adaptation occurs within 30 seconds of detected degradation.
    * **Verification Steps:**
        1. Track provider selection decisions over time
        2. Measure overall latency stability during provider performance changes
        3. Verify automatic recovery to primary provider when performance improves

### 7. Cost-Performance Optimization

* **ID:** PERF_LLM_COST_PERFORMANCE_OPTIMIZATION_002
    * **Category Ref:** PERF_LLM_COST_OPTIMIZATION
    * **Description:** Evaluate trade-offs between cost and performance across different model configurations and providers.
    * **Exposure Point(s):** app/providers/bedrock/bedrock.py, app/providers/vertex_ai/vertexai.py (cost tracking), app/services/billing.py
    * **Test Method/Action:**
        1. Compare performance metrics (TTFT, throughput) across models with different cost profiles
        2. Test batch optimization strategies for embeddings to improve cost efficiency
        3. Measure cost-per-token vs performance-per-token ratios
        4. Evaluate dynamic model selection based on cost-performance targets
    * **Prerequisites:** Cost tracking enabled, multiple model tiers available, billing integration
    * **Expected Secure Outcome:** System can meet performance SLOs while optimizing for cost efficiency. Cost-performance ratios are tracked and optimized. Automated decisions favor cost-effective models when performance requirements allow.
    * **Verification Steps:**
        1. Calculate cost-per-request and performance-per-cost metrics
        2. Verify billing accuracy for different model selections
        3. Test automated cost optimization decisions

### 8. Multimodal Performance Testing

* **ID:** PERF_LLM_MULTIMODAL_PERFORMANCE_003
    * **Category Ref:** PERF_LLM_MULTIMODAL
    * **Description:** Assess performance characteristics when processing multimodal inputs (text + images) for vision-capable models.
    * **Exposure Point(s):** app/providers/*/adapter_to_core.py (image processing), multimodal model configurations
    * **Test Method/Action:**
        1. Send chat requests with various image sizes and formats (JPEG, PNG, different resolutions)
        2. Measure TTFT and total response time for text-only vs multimodal requests
        3. Test concurrent multimodal requests to evaluate memory and processing overhead
        4. Evaluate performance impact of image preprocessing and encoding
    * **Prerequisites:** Vision-capable models configured, image processing capabilities
    * **Expected Secure Outcome:** Multimodal requests maintain acceptable performance. Image processing does not cause excessive memory usage or blocking. TTFT for multimodal requests stays within 2x of text-only requests.
    * **Verification Steps:**
        1. Compare latency distributions between text-only and multimodal requests
        2. Monitor memory usage during image processing
        3. Test concurrent multimodal request handling

### 9. Concurrent Streaming Performance

* **ID:** PERF_LLM_CONCURRENT_STREAMING_004
    * **Category Ref:** PERF_LLM_CONCURRENT_STREAMING
    * **Description:** Evaluate system performance when handling hundreds of concurrent streaming connections.
    * **Exposure Point(s):** FastAPI streaming responses, app/providers/*/adapter_from_core.py (streaming logic), async event loop
    * **Test Method/Action:**
        1. Establish N concurrent streaming connections (e.g., 500-1000)
        2. Measure inter-chunk latency consistency across all streams
        3. Test stream cleanup when clients disconnect unexpectedly
        4. Evaluate server resource usage under sustained concurrent streaming
    * **Prerequisites:** High-concurrency test client, streaming-capable models
    * **Expected Secure Outcome:** Server maintains stable inter-chunk latency across all concurrent streams. Memory usage remains bounded. Unexpected client disconnections are handled gracefully without resource leaks.
    * **Verification Steps:**
        1. Monitor inter-chunk latency percentiles across all concurrent streams
        2. Test resource cleanup after client disconnections
        3. Verify server stability under maximum concurrent stream load

### 10. Contextual Caching Performance

* **ID:** PERF_LLM_CONTEXTUAL_CACHING_005
    * **Category Ref:** PERF_LLM_CACHING
    * **Description:** Test performance improvements from contextual caching for repeated prompt patterns or conversation continuations.
    * **Exposure Point(s):** Provider-specific caching mechanisms, conversation state management
    * **Test Method/Action:**
        1. Send initial requests with long context to establish cache baseline
        2. Send follow-up requests that can leverage cached context
        3. Measure performance improvements (TTFT reduction) from cache hits
        4. Test cache invalidation and refresh performance
    * **Prerequisites:** Caching-capable providers and models, conversation state tracking
    * **Expected Secure Outcome:** Cache hits provide significant TTFT improvement (>50% reduction). Cache miss performance remains within normal ranges. Cache management does not introduce significant overhead.
    * **Verification Steps:**
        1. Compare TTFT for cache hits vs cache misses
        2. Monitor cache hit ratio and effectiveness
        3. Test cache performance under various context patterns

### 11. Regional Performance Variance

* **ID:** PERF_LLM_REGIONAL_PERFORMANCE_006
    * **Category Ref:** PERF_LLM_REGIONAL
    * **Description:** Evaluate performance consistency across different geographical regions and provider availability zones.
    * **Exposure Point(s):** Provider regional configurations, network latency variations
    * **Test Method/Action:**
        1. Configure providers across multiple regions/availability zones
        2. Measure baseline performance from different geographical test locations
        3. Test regional failover performance when primary regions experience issues
        4. Evaluate network latency impact on overall response times
    * **Prerequisites:** Multi-region provider setup, distributed test infrastructure
    * **Expected Secure Outcome:** Performance remains consistent within acceptable variance across regions. Regional failover occurs smoothly. Network latency impact is minimized through optimal provider selection.
    * **Verification Steps:**
        1. Compare performance metrics across different regions
        2. Test regional failover scenarios
        3. Analyze network latency contribution to total response time

### 12. Dynamic Model Switching Performance

* **ID:** PERF_LLM_MODEL_SWITCHING_007
    * **Category Ref:** PERF_LLM_MODEL_SWITCHING
    * **Description:** Test performance characteristics when dynamically switching between models based on request characteristics or load balancing.
    * **Exposure Point(s):** app/providers/dependencies.py (model selection), dynamic routing logic
    * **Test Method/Action:**
        1. Implement request-based model selection (e.g., simple queries to fast models, complex queries to powerful models)
        2. Measure overhead of model selection decision logic
        3. Test performance under rapid model switching scenarios
        4. Evaluate model warm-up time impact on initial requests
    * **Prerequisites:** Multiple models configured, dynamic routing capabilities
    * **Expected Secure Outcome:** Model selection overhead is minimal (<10ms). Performance optimizes based on request complexity. Model switching doesn't introduce significant latency spikes.
    * **Verification Steps:**
        1. Measure model selection decision time
        2. Compare performance across different model switching patterns
        3. Test model warm-up performance impact

### 13. Quality-Performance Trade-off Analysis

* **ID:** PERF_LLM_QUALITY_PERFORMANCE_TRADEOFF_008
    * **Category Ref:** PERF_LLM_QUALITY_TRADEOFF
    * **Description:** Analyze the relationship between response quality and performance across different model configurations and parameters.
    * **Exposure Point(s):** Model parameter configurations, quality assessment integration
    * **Test Method/Action:**
        1. Test various temperature, top_p, and max_tokens configurations
        2. Measure performance impact of different quality settings
        3. Evaluate response quality metrics alongside performance metrics
        4. Test automated quality-performance optimization
    * **Prerequisites:** Quality assessment capabilities, parameter tuning support
    * **Expected Secure Outcome:** Clear understanding of quality-performance trade-offs. Automated systems can optimize for target quality within performance constraints. Performance degradation is predictable and controllable.
    * **Verification Steps:**
        1. Correlate quality scores with performance metrics
        2. Test parameter optimization algorithms
        3. Validate quality-performance trade-off models

### 14. Batch Processing Optimization

* **ID:** PERF_LLM_BATCH_OPTIMIZATION_009
    * **Category Ref:** PERF_LLM_BATCH_OPTIMIZATION
    * **Description:** Optimize batch processing performance for embeddings and batch inference scenarios.
    * **Exposure Point(s):** app/providers/*/adapter_to_core.py (batch handling), embedding batch processing
    * **Test Method/Action:**
        1. Test various batch sizes to find optimal throughput vs latency balance
        2. Implement dynamic batch sizing based on current load
        3. Measure memory efficiency of different batch processing strategies
        4. Test batch timeout and partial batch processing
    * **Prerequisites:** Batch-capable models and providers, dynamic batching logic
    * **Expected Secure Outcome:** Optimal batch sizes identified for different scenarios. Dynamic batching improves overall throughput while maintaining latency SLOs. Memory usage scales efficiently with batch size.
    * **Verification Steps:**
        1. Compare throughput across different batch sizes
        2. Test dynamic batch sizing effectiveness
        3. Monitor memory usage patterns for batch processing

### 15. Predictive Performance Scaling

* **ID:** PERF_LLM_PREDICTIVE_SCALING_010
    * **Category Ref:** PERF_LLM_PREDICTIVE_SCALING
    * **Description:** Test predictive scaling capabilities that anticipate load increases and pre-scale resources.
    * **Exposure Point(s):** Load prediction algorithms, auto-scaling integration
    * **Test Method/Action:**
        1. Implement load prediction based on historical patterns
        2. Test pre-scaling before anticipated load increases
        3. Measure prediction accuracy and scaling effectiveness
        4. Evaluate resource cost vs performance benefits of predictive scaling
    * **Prerequisites:** Historical load data, auto-scaling capabilities, prediction algorithms
    * **Expected Secure Outcome:** Predictive scaling reduces performance degradation during load spikes. Scaling decisions are cost-effective. Prediction accuracy improves over time with more data.
    * **Verification Steps:**
        1. Compare performance with and without predictive scaling
        2. Measure prediction accuracy and scaling timeliness
        3. Analyze cost-benefit of predictive vs reactive scaling

### 16. Comprehensive Performance Profiling

* **ID:** PERF_LLM_COMPREHENSIVE_PROFILING_011
    * **Category Ref:** PERF_LLM_COMPREHENSIVE_PROFILING
    * **Description:** Conduct detailed performance profiling to identify bottlenecks and optimization opportunities across the entire request lifecycle.
    * **Exposure Point(s):** Entire request pipeline from authentication to response delivery
    * **Test Method/Action:**
        1. Implement detailed request tracing and profiling
        2. Measure time spent in each component (auth, validation, provider call, response processing)
        3. Identify performance bottlenecks and optimization opportunities
        4. Test performance improvements from targeted optimizations
    * **Prerequisites:** Comprehensive monitoring and tracing infrastructure, profiling tools
    * **Expected Secure Outcome:** Complete understanding of request lifecycle performance. Bottlenecks identified and prioritized for optimization. Performance improvements validated through systematic measurement.
    * **Verification Steps:**
        1. Analyze detailed performance traces
        2. Identify and rank performance bottlenecks
        3. Validate optimization effectiveness through before/after comparisons

---