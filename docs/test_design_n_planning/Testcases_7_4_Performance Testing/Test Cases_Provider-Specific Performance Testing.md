# Test Cases: Provider-Specific Performance Testing

This document outlines test cases focused on the performance characteristics when interacting with specific downstream LLM providers (Bedrock, Vertex AI), as defined in the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing".

**Test Cases Summary: 12 (Original: 6, Enhanced: +6)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* app/providers/bedrock/bedrock.py (BedRockBackend implementation)
* app/providers/vertex_ai/vertexai.py (VertexBackend implementation)
* app/providers/dependencies.py (provider selection and routing)
* app/config/settings.py:backend_map (provider configuration)
* aioboto3, google-cloud-aiplatform (provider SDKs)

## General Test Case Components:
* **ID:** Unique identifier (e.g., PERF_PROV_BEDROCK_LATENCY_001)
* **Category Ref:** (e.g., PERF_PROV_BEDROCK, PERF_PROV_VERTEXAI, PERF_PROV_FAILOVER_PERF)
* **Description:** The specific provider interaction or characteristic being performance tested.
* **Exposure Point(s):** Specific provider backend modules (app/providers/bedrock/bedrock.py, app/providers/vertex\_ai/vertexai.py), their SDK configurations, network path to the provider, and the provider's service performance itself.
* **Test Method/Action:** Making requests to models known to be hosted on a specific provider and measuring relevant metrics.
* **Prerequisites:** Valid API Key. Models correctly configured in `settings.backend_map` for the target provider. Performance testing environment. Monitoring tools.
* **Expected Secure Outcome:** Performance metrics (latency, throughput, error rate) for the provider meet SLOs and are consistent. Failover (if applicable) is performant.
* **Verification Steps:** Analysis of collected metrics, comparison against baselines or SLOs, logs.

---

### 1\. Bedrock Performance Baseline

* **ID:** PERF_PROV_BEDROCK_CHAT_LATENCY_001
    * **Category Ref:** PERF_PROV_BEDROCK
    * **Description:** Measure baseline latency (TTFT and Total Time) for chat completions using a specific Bedrock model (e.g., Claude 3.5 Sonnet).
    * **Exposure Point(s):** BedRockBackend, aioboto3 SDK, Bedrock service (Claude model).
    * **Test Method/Action:**
        1.  Select a standard Bedrock chat model (e.g., "claude_3_5_sonnet").
        2.  Send N (e.g., 100) non-streaming requests with a standard short prompt. Measure total response time.
        3.  Send N (e.g., 100) streaming requests with the same prompt. Measure TTFT and total stream duration.
    * **Prerequisites:** Bedrock model correctly configured.
    * **Expected Secure Outcome:** p95 Total Time (non-stream) and p95 TTFT (stream) are within acceptable limits for this model (e.g., Total Time < 2s, TTFT < 500ms). Token throughput is as expected for Claude.
    * **Verification Steps:** Collect latency data, calculate percentiles, compare to established benchmarks for this model on Bedrock.

* **ID:** PERF_PROV_BEDROCK_EMBED_LATENCY_002
    * **Category Ref:** PERF_PROV_BEDROCK
    * **Description:** Measure baseline latency for embeddings using a specific Bedrock model (e.g., Cohere Embed).
    * **Exposure Point(s):** BedRockBackend, aioboto3 SDK, Bedrock service (Cohere model).
    * **Test Method/Action:**
        1.  Select a standard Bedrock embedding model (e.g., "cohere_english_v3").
        2.  Send N (e.g., 100) requests with single standard input texts. Measure total response time.
        3.  Send N requests with small batches of texts. Measure total response time and calculate per-embedding throughput.
    * **Prerequisites:** Bedrock embedding model configured.
    * **Expected Secure Outcome:** p95 latency for single embeddings is low (e.g., < 150ms). Batch throughput is efficient.
    * **Verification Steps:** Collect latency/throughput data, analyze percentiles.

* **ID:** PERF_PROV_BEDROCK_THROTTLING_BEHAVIOR_003
    * **Category Ref:** PERF_PROV_BEDROCK
    * **Description:** Observe API and Bedrock behavior when Bedrock's rate limits/quotas are intentionally exceeded.
    * **Exposure Point(s):** BedRockBackend error handling for `ThrottlingException`.
    * **Test Method/Action:**
        1.  Select a Bedrock model.
        2.  Send requests at a rate known to exceed Bedrock's TPS or token-per-minute limits for that model/region.
    * **Prerequisites:** Knowledge of Bedrock limits.
    * **Expected Secure Outcome:** API returns HTTP 429 Too Many Requests. Response may include `Retry-After` header if Bedrock provides it. API remains stable.
    * **Verification Steps:** Monitor response codes. Check for 429s. Verify `Retry-After` if present. Check server logs for `ThrottlingException` from Bedrock.

---

### 2\. Vertex AI Performance Baseline

* **ID:** PERF_PROV_VERTEXAI_CHAT_LATENCY_001
    * **Category Ref:** PERF_PROV_VERTEXAI
    * **Description:** Measure baseline latency (TTFT and Total Time) for chat completions using a specific Vertex AI model (e.g., Gemini 2.0 Flash).
    * **Exposure Point(s):** VertexBackend, google-cloud-aiplatform SDK, Vertex AI service (Gemini model).
    * **Test Method/Action:** Similar to PERF_PROV_BEDROCK_CHAT_LATENCY_001, but using a Vertex AI chat model.
    * **Prerequisites:** Vertex AI model correctly configured.
    * **Expected Secure Outcome:** p95 Total Time (non-stream) and p95 TTFT (stream) are within acceptable limits for this model on Vertex AI.
    * **Verification Steps:** Collect and analyze latency data.

* **ID:** PERF_PROV_VERTEXAI_EMBED_LATENCY_002
    * **Category Ref:** PERF_PROV_VERTEXAI
    * **Description:** Measure baseline latency for embeddings using a specific Vertex AI model (e.g., text-embedding-005).
    * **Exposure Point(s):** VertexBackend, google-cloud-aiplatform SDK, Vertex AI service (embedding model).
    * **Test Method/Action:** Similar to PERF_PROV_BEDROCK_EMBED_LATENCY_002, but using a Vertex AI embedding model.
    * **Prerequisites:** Vertex AI embedding model configured.
    * **Expected Secure Outcome:** p95 latency for single embeddings and batch throughput are efficient for this model on Vertex AI.
    * **Verification Steps:** Collect and analyze latency/throughput data.

* **ID:** PERF_PROV_VERTEXAI_QUOTA_BEHAVIOR_003
    * **Category Ref:** PERF_PROV_VERTEXAI
    * **Description:** Observe API and Vertex AI behavior when Vertex AI's quotas (e.g., requests per minute) are intentionally exceeded.
    * **Exposure Point(s):** VertexBackend error handling for `ResourceExhausted` errors.
    * **Test Method/Action:**
        1.  Select a Vertex AI model.
        2.  Send requests at a rate known to exceed Vertex AI's QPM limits.
    * **Prerequisites:** Knowledge of Vertex AI quotas.
    * **Expected Secure Outcome:** API returns HTTP 429 Too Many Requests. API remains stable.
    * **Verification Steps:** Monitor response codes (expect 429s). Check server logs for `ResourceExhausted` from Vertex AI.

---

### 3\. Provider Failover Performance (If Failover Logic is Implemented)

*(These are conceptual if automated failover between different primary providers for the same GSAi model ID is not yet implemented. If failover refers to Bedrock/Vertex AI regional failover, that's typically managed by the provider or cloud infrastructure).*

* **ID:** PERF_PROV_FAILOVER_TIME_001
    * **Category Ref:** PERF_PROV_FAILOVER_PERF
    * **Description:** Measure the time taken for the API to detect a primary provider failure and successfully switch to a backup provider.
    * **Exposure Point(s):** Hypothetical failover logic within the API framework or its dependencies.
    * **Test Method/Action:**
        1.  Configure a GSAi model ID to have a primary (e.g., Bedrock) and a secondary (e.g., Vertex AI) provider.
        2.  Simulate the primary provider becoming unresponsive or consistently erroring.
        3.  Send a request to the GSAi model ID.
        4.  Measure the time until a successful response is received from the secondary provider.
    * **Prerequisites:** Failover mechanism implemented. Ability to simulate primary provider failure.
    * **Expected Secure Outcome:** Failover time is within target (e.g., < 500ms additional latency beyond normal secondary provider latency).
    * **Verification Steps:**
        1.  Record end-to-end response time during failover.
        2.  Verify from logs or mocks that the secondary provider was indeed used.
        3.  Compare with baseline latency of the secondary provider to isolate failover overhead.

* **ID:** PERF_PROV_FAILOVER_LOAD_IMPACT_002
    * **Category Ref:** PERF_PROV_FAILOVER_PERF
    * **Description:** Evaluate the performance of the backup provider when all traffic for a model is suddenly routed to it due to primary failure.
    * **Exposure Point(s):** Backup provider capacity, API framework's ability to handle requests during failover.
    * **Test Method/Action:**
        1.  Simulate primary provider failure under moderate load.
        2.  Observe latency, error rates, and throughput on the backup provider.
    * **Prerequisites:** Failover mechanism. Load testing setup.
    * **Expected Secure Outcome:** Backup provider handles the shifted load within its SLOs. API framework remains stable during the transition and sustained operation on backup.
    * **Verification Steps:** Monitor performance metrics for requests routed to the backup provider.

---

## Enhanced Test Cases (6 Advanced Provider Performance Scenarios)

### 4. Comprehensive Provider Performance Comparison Framework

* **ID:** PERF_PROV_COMPREHENSIVE_COMPARISON_001
    * **Category Ref:** PERF_PROV_COMPARISON
    * **Description:** Establish a comprehensive framework for comparing performance across all providers using standardized benchmarks.
    * **Exposure Point(s):** All provider backends, app/providers/dependencies.py (provider selection), standardized performance metrics
    * **Test Method/Action:**
        1. Define standardized test scenarios (short/medium/long prompts, different model types)
        2. Execute identical workloads across all providers simultaneously
        3. Collect comprehensive metrics (TTFT, throughput, latency percentiles, error rates)
        4. Generate detailed performance comparison reports with statistical significance
    * **Prerequisites:** All providers configured with comparable models, standardized testing framework, statistical analysis tools
    * **Expected Secure Outcome:** Clear performance characteristics identified for each provider. Statistical significance in performance differences established. Optimal provider selection criteria defined.
    * **Verification Steps:**
        1. Validate statistical significance of performance differences
        2. Verify repeatability of comparison results
        3. Generate actionable provider selection recommendations

### 5. Dynamic Provider Load Balancing

* **ID:** PERF_PROV_DYNAMIC_LOAD_BALANCING_002
    * **Category Ref:** PERF_PROV_LOAD_BALANCING
    * **Description:** Test dynamic load balancing across providers based on real-time performance metrics and capacity.
    * **Exposure Point(s):** app/providers/dependencies.py (load balancing logic), real-time performance monitoring
    * **Test Method/Action:**
        1. Implement real-time performance monitoring for all providers
        2. Test dynamic traffic distribution based on provider performance
        3. Simulate provider performance degradation and measure rebalancing
        4. Evaluate load balancing effectiveness under various scenarios
    * **Prerequisites:** Multi-provider setup, real-time monitoring, dynamic routing capabilities
    * **Expected Secure Outcome:** Load balancing optimizes overall system performance. Traffic shifts away from degraded providers within 60 seconds. Overall user experience remains stable during rebalancing.
    * **Verification Steps:**
        1. Monitor load distribution patterns and rebalancing decisions
        2. Verify performance optimization from dynamic load balancing
        3. Test system stability during provider performance fluctuations

### 6. Provider-Specific Optimization Strategies

* **ID:** PERF_PROV_OPTIMIZATION_STRATEGIES_003
    * **Category Ref:** PERF_PROV_OPTIMIZATION
    * **Description:** Develop and test provider-specific optimization strategies based on each provider's unique characteristics.
    * **Exposure Point(s):** Provider-specific adapter logic, optimization parameters, caching strategies
    * **Test Method/Action:**
        1. Analyze provider-specific performance characteristics and bottlenecks
        2. Implement provider-specific optimizations (connection pooling, request batching, caching)
        3. Test optimization effectiveness under various load conditions
        4. Measure impact on overall system performance
    * **Prerequisites:** Deep understanding of provider characteristics, configurable optimization parameters
    * **Expected Secure Outcome:** Provider-specific optimizations improve performance by 15-30%. Optimizations don't negatively impact other providers. System maintains overall stability.
    * **Verification Steps:**
        1. Measure performance improvements from each optimization
        2. Verify optimizations don't create cross-provider interference
        3. Test optimization effectiveness under different load patterns

### 7. Provider Capacity and Scaling Analysis

* **ID:** PERF_PROV_CAPACITY_SCALING_004
    * **Category Ref:** PERF_PROV_CAPACITY
    * **Description:** Analyze provider capacity limits and scaling behavior under increasing load.
    * **Exposure Point(s):** Provider rate limits, scaling behavior, capacity planning
    * **Test Method/Action:**
        1. Gradually increase load to each provider to identify capacity limits
        2. Measure provider response time degradation patterns
        3. Test provider scaling behavior and auto-scaling capabilities
        4. Analyze cost-performance characteristics at different capacity levels
    * **Prerequisites:** Provider capacity monitoring, ability to generate high load levels
    * **Expected Secure Outcome:** Provider capacity limits clearly identified. Scaling behavior patterns documented. Cost-performance optimization strategies defined.
    * **Verification Steps:**
        1. Document capacity limits and degradation patterns for each provider
        2. Verify scaling behavior consistency across test runs
        3. Analyze cost-effectiveness at different capacity utilization levels

### 8. Cross-Provider Consistency Validation

* **ID:** PERF_PROV_CONSISTENCY_VALIDATION_005
    * **Category Ref:** PERF_PROV_CONSISTENCY
    * **Description:** Validate response consistency and quality across different providers for the same requests.
    * **Exposure Point(s):** Provider response processing, response quality metrics, consistency analysis
    * **Test Method/Action:**
        1. Send identical prompts to comparable models across all providers
        2. Analyze response consistency, quality, and format compliance
        3. Measure performance impact of response processing differences
        4. Test consistency under various load conditions
    * **Prerequisites:** Comparable models across providers, response quality assessment tools
    * **Expected Secure Outcome:** Response consistency meets quality standards across providers. Performance remains stable regardless of provider selection. Quality differences are well-documented.
    * **Verification Steps:**
        1. Measure response consistency metrics across providers
        2. Verify performance stability with different response characteristics
        3. Document quality and consistency trade-offs between providers

### 9. Provider Error Handling and Recovery Performance

* **ID:** PERF_PROV_ERROR_RECOVERY_006
    * **Category Ref:** PERF_PROV_ERROR_RECOVERY
    * **Description:** Test performance characteristics of error handling and recovery mechanisms for each provider.
    * **Exposure Point(s):** Provider error handling logic, retry mechanisms, circuit breaker patterns
    * **Test Method/Action:**
        1. Simulate various provider error scenarios (timeouts, rate limits, service errors)
        2. Measure error detection time and recovery performance
        3. Test retry mechanism effectiveness and performance impact
        4. Evaluate circuit breaker behavior and recovery timing
    * **Prerequisites:** Error simulation capabilities, comprehensive error monitoring
    * **Expected Secure Outcome:** Error detection occurs within 5 seconds. Recovery mechanisms don't significantly impact overall performance. Circuit breakers prevent cascading failures.
    * **Verification Steps:**
        1. Measure error detection and recovery timing for each provider
        2. Verify retry mechanisms don't cause performance degradation
        3. Test circuit breaker effectiveness in preventing system overload

---