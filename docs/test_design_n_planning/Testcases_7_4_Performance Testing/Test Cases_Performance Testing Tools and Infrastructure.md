# Test Cases: Performance Testing Tools and Infrastructure

This document outlines test cases related to the setup, accuracy, and representativeness of the performance testing tools and infrastructure themselves, as defined in the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing". The goal is to ensure that the performance tests yield reliable and actionable results.

**Test Cases Summary: 12 (Original: 6, Enhanced: +6)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* Performance testing infrastructure (Locust, k6, pytest-benchmark)
* Monitoring stack (Prometheus, Grafana, Jaeger)
* Test environment configuration and data generation
* Measurement accuracy and calibration methodologies

## General Test Case Components:
* **ID:** Unique identifier (e.g., PERF_INFRA_DATA_REPRESENT_001)
* **Category Ref:** (e.g., PERF_INFRA_DATA, PERF_INFRA_MONITORING, PERF_INFRA_ENVIRONMENT)
* **Description:** What specific aspect of the testing setup is being validated.
* **Exposure Point(s):** Test data generation process, monitoring stack configuration, performance test environment configuration.
* **Test Method/Action:** Review configurations, run calibration tests, compare metrics.
* **Prerequisites:** Access to test plans, data generation scripts, monitoring tools, and environment configurations.
* **Expected Secure Outcome:** The testing infrastructure is configured correctly and provides accurate, representative measurements.
* **Verification Steps:** Comparison of configurations, analysis of calibration test results, validation of metric accuracy.

---

### 1\. Test Data Representativeness and Generation

* **ID:** PERF_INFRA_DATA_REPRESENT_PROMPT_001
    * **Category Ref:** PERF_INFRA_DATA
    * **Description:** Verify that test prompts used for chat completion performance tests are representative of expected real-world usage patterns (mix of lengths, complexities, topics).
    * **Exposure Point(s):** Test data library/generation scripts for chat prompts.
    * **Test Method/Action:**
        1.  Review the set of prompts used in various load tests (baseline, peak, etc.).
        2.  Compare their characteristics (average length, token count distribution, topic diversity, inclusion of system messages, conversational depth for multi-turn scenarios) against any available data or expectations of production traffic.
    * **Prerequisites:** Defined test prompts. Understanding of expected production prompt characteristics.
    * **Expected Secure Outcome:** Test prompts cover a realistic range of scenarios, avoiding overly simplistic or uniform inputs that might not stress the system adequately or reveal true performance under varied conditions.
    * **Verification Steps:** Document analysis of prompt characteristics. Adjust test data library if significant gaps are found.

* **ID:** PERF_INFRA_DATA_REPRESENT_EMBED_002
    * **Category Ref:** PERF_INFRA_DATA
    * **Description:** Verify that input texts for embedding performance tests are representative (mix of lengths, content types relevant to embedding use cases).
    * **Exposure Point(s):** Test data library for embedding inputs.
    * **Test Method/Action:** Review input texts for diversity in length and nature.
    * **Prerequisites:** Defined test inputs for embeddings.
    * **Expected Secure Outcome:** Embedding test inputs reflect typical documents or queries that would be embedded in production.
    * **Verification Steps:** Document analysis.

* **ID:** PERF_INFRA_DATA_TOKEN_ACCURACY_003
    * **Category Ref:** PERF_INFRA_DATA
    * **Description:** Ensure that any tooling or process used to generate test data targeting specific token counts (e.g., for context window performance tests) is reasonably accurate for the models under test.
    * **Exposure Point(s):** Test data generation scripts/logic.
    * **Test Method/Action:**
        1.  Generate a sample prompt intended to be, for example, 1000 tokens long using the test data generation method.
        2.  Send this prompt to the API for the target model and check the `prompt_tokens` returned in the `usage` object.
        3.  Alternatively, use a reliable local tokenizer for the target model family to verify the generated prompt's token count.
    * **Prerequisites:** Tooling/scripts for generating token-aware test data. Access to API or local tokenizer.
    * **Expected Secure Outcome:** The actual token count of generated prompts is within an acceptable margin of error (e.g., +/- 5-10%) of the target token count.
    * **Verification Steps:** Compare generated token count with reported/actual token count. Refine generation method if discrepancies are large.

---

### 2\. Monitoring Stack Accuracy and Granularity

* **ID:** PERF_INFRA_MONITORING_LATENCY_ACCURACY_001
    * **Category Ref:** PERF_INFRA_MONITORING
    * **Description:** Validate the accuracy of latency metrics (TTFT, Total Response Time, Inter-Chunk Latency) collected by the monitoring stack and load testing tools.
    * **Exposure Point(s):** Load testing tool's reporting, Prometheus/Grafana dashboards, Jaeger traces.
    * **Test Method/Action:**
        1.  Run a small, controlled set of requests with known characteristics (e.g., to a mock endpoint with fixed processing delay).
        2.  Compare latency reported by the load generator, API server logs (duration_ms), and distributed tracing system (if available).
    * **Prerequisites:** Configured monitoring stack.
    * **Expected Secure Outcome:** Latency figures from different sources are consistent (within small margins for network hops/measurement points). Timestamps are synchronized.
    * **Verification Steps:** Cross-reference latency metrics. Investigate discrepancies.

* **ID:** PERF_INFRA_MONITORING_RESOURCE_ACCURACY_002
    * **Category Ref:** PERF_INFRA_MONITORING
    * **Description:** Verify that CPU, memory, and network utilization metrics for the API server and database are accurately captured and reported.
    * **Exposure Point(s):** Prometheus/Grafana, cloud provider monitoring tools.
    * **Test Method/Action:**
        1.  Induce a known level of CPU or memory load on a test server (outside the API) and verify monitoring tools report it correctly.
        2.  During an API load test, compare resource metrics from different sources (e.g., `docker stats` vs. Prometheus node exporter vs. cloud provider metrics).
    * **Prerequisites:** Configured monitoring stack.
    * **Expected Secure Outcome:** Resource utilization metrics are consistent and accurately reflect system state. Sampling intervals are appropriate.
    * **Verification Steps:** Compare metrics from different tools.

* **ID:** PERF_INFRA_MONITORING_GRANULARITY_TRACE_003
    * **Category Ref:** PERF_INFRA_MONITORING
    * **Description:** Ensure distributed tracing (if implemented, e.g., Jaeger) provides sufficient granularity to identify bottlenecks within the API request lifecycle (e.g., auth, adapter, provider SDK call).
    * **Exposure Point(s):** Jaeger traces.
    * **Test Method/Action:**
        1.  Make a few representative API calls (chat, stream, embed).
        2.  Inspect the generated traces in Jaeger.
    * **Prerequisites:** Distributed tracing implemented and configured.
    * **Expected Secure Outcome:** Traces show distinct spans for major processing stages within the API (e.g., middleware, authentication, routing, provider call, response adaptation). Timings for each span are plausible.
    * **Verification Steps:** Review trace structure and span durations.

---

### 3\. Performance Test Environment Fidelity

* **ID:** PERF_INFRA_ENVIRONMENT_CONFIG_MATCH_001
    * **Category Ref:** PERF_INFRA_ENVIRONMENT
    * **Description:** Verify that the performance test environment's configuration (API server, database, Uvicorn workers, Python version, key library versions) closely matches the production environment.
    * **Exposure Point(s):** Test environment deployment scripts, actual deployed configurations.
    * **Test Method/Action:** Perform a configuration audit comparing the performance test environment against production documentation or actual production settings (where observable without direct prod access).
    * **Prerequisites:** Documentation of production environment configuration. Access to inspect test environment config.
    * **Expected Secure Outcome:** Key software versions, resource allocations (CPU/memory ratios), network topology (relative to providers), and critical application settings are identical or proportionally scaled. Any differences are documented and understood.
    * **Verification Steps:** Create a checklist of critical configuration points. Compare test vs. prod.

* **ID:** PERF_INFRA_ENVIRONMENT_NETWORK_BASELINE_002
    * **Category Ref:** PERF_INFRA_ENVIRONMENT
    * **Description:** Establish baseline network latency from the performance test environment to the downstream LLM providers (Bedrock, Vertex AI regions being used).
    * **Exposure Point(s):** Network path from test environment to providers.
    * **Test Method/Action:** Use network tools (ping, traceroute, iperf if possible, or specialized cloud provider latency tests) to measure round-trip times and bandwidth to provider API endpoints from the test environment.
    * **Prerequisites:** Knowledge of provider endpoint hostnames/IPs for the target regions.
    * **Expected Secure Outcome:** Measured network latency is documented and considered when analyzing API performance results. It should be reasonably similar to what's expected from the production environment.
    * **Verification Steps:** Record baseline network metrics. If significantly different from production expectations, adjust test result interpretation or environment.

* **ID:** PERF_INFRA_ENVIRONMENT_NO_INTERFERENCE_003
    * **Category Ref:** PERF_INFRA_ENVIRONMENT
    * **Description:** Ensure the performance test environment is isolated and not affected by other activities or workloads that could skew performance results.
    * **Exposure Point(s):** Shared resources (network, underlying virtualization if not dedicated).
    * **Test Method/Action:**
        1.  Monitor baseline resource utilization in the performance environment when no load tests are running.
        2.  Run a consistent, small calibration load test at different times to check for variability in baseline performance.
    * **Prerequisites:** Dedicated or well-isolated performance testing environment.
    * **Expected Secure Outcome:** Baseline resource usage is low and stable. Calibration test results are consistent, indicating no significant external interference.
    * **Verification Steps:** Review monitoring data for unexpected activity. Analyze consistency of calibration test results.

---

## Enhanced Test Cases (6 Advanced Performance Testing Infrastructure Scenarios)

### 4. Automated Performance Test Orchestration and CI/CD Integration

* **ID:** PERF_INFRA_AUTOMATED_ORCHESTRATION_001
    * **Category Ref:** PERF_INFRA_AUTOMATION
    * **Description:** Implement automated performance test orchestration with CI/CD integration for continuous performance validation.
    * **Exposure Point(s):** CI/CD pipeline integration, automated test scheduling, performance regression detection
    * **Test Method/Action:**
        1. Implement automated performance test triggers in CI/CD pipeline
        2. Test parallel execution of different performance test scenarios
        3. Implement automated performance regression detection and alerting
        4. Validate test result aggregation and reporting automation
    * **Prerequisites:** CI/CD infrastructure, automated testing frameworks, performance baseline data
    * **Expected Secure Outcome:** Automated tests detect performance regressions within 30 minutes of code changes. Parallel test execution reduces testing time by 60-80%. Automated reporting provides actionable insights.
    * **Verification Steps:**
        1. Test automated trigger reliability and accuracy
        2. Validate parallel test execution efficiency
        3. Verify regression detection accuracy and alert responsiveness

### 5. Advanced Performance Monitoring and Observability

* **ID:** PERF_INFRA_ADVANCED_OBSERVABILITY_002
    * **Category Ref:** PERF_INFRA_OBSERVABILITY
    * **Description:** Implement advanced observability stack with distributed tracing, custom metrics, and intelligent alerting for comprehensive performance insights.
    * **Exposure Point(s):** Distributed tracing implementation, custom metrics collection, intelligent alerting systems
    * **Test Method/Action:**
        1. Implement comprehensive distributed tracing across all system components
        2. Develop custom performance metrics for specific business logic
        3. Test intelligent alerting with machine learning-based anomaly detection
        4. Validate end-to-end observability coverage and accuracy
    * **Prerequisites:** Observability infrastructure (Jaeger, Prometheus, custom metrics), ML-based alerting
    * **Expected Secure Outcome:** Complete end-to-end trace visibility achieved. Custom metrics provide business-specific insights. Intelligent alerting reduces false positives by 70-90%.
    * **Verification Steps:**
        1. Validate trace completeness and accuracy across all components
        2. Test custom metrics accuracy and usefulness
        3. Verify intelligent alerting effectiveness and false positive reduction

### 6. Performance Test Data Generation and Management

* **ID:** PERF_INFRA_TEST_DATA_MANAGEMENT_003
    * **Category Ref:** PERF_INFRA_DATA_MANAGEMENT
    * **Description:** Implement sophisticated test data generation and management for realistic and reproducible performance testing.
    * **Exposure Point(s):** Test data generation algorithms, data quality validation, test data lifecycle management
    * **Test Method/Action:**
        1. Implement realistic test data generation based on production patterns
        2. Test data quality validation and statistical representativeness
        3. Implement test data versioning and reproducibility mechanisms
        4. Validate data generation performance and scalability
    * **Prerequisites:** Production data analysis tools, statistical validation frameworks, data generation infrastructure
    * **Expected Secure Outcome:** Test data accurately represents production patterns. Data generation scales to meet testing demands. Test reproducibility achieved through data versioning.
    * **Verification Steps:**
        1. Validate test data statistical similarity to production patterns
        2. Test data generation performance and scalability
        3. Verify test reproducibility with versioned data sets

### 7. Multi-Environment Performance Testing Coordination

* **ID:** PERF_INFRA_MULTI_ENV_COORDINATION_004
    * **Category Ref:** PERF_INFRA_MULTI_ENV
    * **Description:** Coordinate performance testing across multiple environments (dev, staging, pre-prod) with consistent methodologies and comparative analysis.
    * **Exposure Point(s):** Multi-environment test coordination, environment-specific configuration management, comparative analysis
    * **Test Method/Action:**
        1. Implement consistent performance testing methodologies across environments
        2. Test environment-specific configuration management and validation
        3. Implement comparative performance analysis across environments
        4. Validate environment parity and performance correlation
    * **Prerequisites:** Multiple test environments, configuration management tools, comparative analysis frameworks
    * **Expected Secure Outcome:** Consistent testing methodologies across all environments. Environment configuration differences documented and accounted for. Performance trends correlate across environments.
    * **Verification Steps:**
        1. Validate testing methodology consistency across environments
        2. Test configuration management effectiveness
        3. Verify performance correlation and trend analysis accuracy

### 8. Performance Testing Infrastructure Scalability and Efficiency

* **ID:** PERF_INFRA_SCALABILITY_EFFICIENCY_005
    * **Category Ref:** PERF_INFRA_SCALABILITY
    * **Description:** Optimize performance testing infrastructure for scalability, efficiency, and cost-effectiveness.
    * **Exposure Point(s):** Test infrastructure scaling, resource optimization, cost management
    * **Test Method/Action:**
        1. Test infrastructure scaling capabilities for large-scale performance tests
        2. Implement resource optimization strategies for test execution
        3. Test cost-effective infrastructure provisioning and management
        4. Validate infrastructure performance under maximum load scenarios
    * **Prerequisites:** Scalable infrastructure, resource optimization tools, cost monitoring
    * **Expected Secure Outcome:** Infrastructure scales efficiently to handle 10x test load increases. Resource optimization reduces testing costs by 40-60%. Infrastructure maintains performance under maximum load.
    * **Verification Steps:**
        1. Test infrastructure scaling performance and efficiency
        2. Validate resource optimization effectiveness
        3. Verify cost reduction and infrastructure stability

### 9. Intelligent Performance Test Analysis and Insights

* **ID:** PERF_INFRA_INTELLIGENT_ANALYSIS_006
    * **Category Ref:** PERF_INFRA_INTELLIGENCE
    * **Description:** Implement AI/ML-powered performance test analysis for automated insights, pattern recognition, and optimization recommendations.
    * **Exposure Point(s):** ML-based performance analysis, pattern recognition algorithms, automated recommendation systems
    * **Test Method/Action:**
        1. Implement ML models for automated performance pattern recognition
        2. Test intelligent root cause analysis for performance issues
        3. Implement automated optimization recommendations based on test results
        4. Validate analysis accuracy and recommendation effectiveness
    * **Prerequisites:** ML/AI infrastructure, historical performance data, analysis algorithms
    * **Expected Secure Outcome:** Automated analysis identifies performance patterns with >90% accuracy. Root cause analysis reduces investigation time by 70-80%. Optimization recommendations improve performance by 20-30%.
    * **Verification Steps:**
        1. Validate ML model accuracy for pattern recognition
        2. Test root cause analysis effectiveness
        3. Verify optimization recommendation quality and impact

---
```Okay, I have generated the test case files based on the "Risk Surface Analysis for Test Plan Section 7.4.md" and the general test case components you provided.

Here are the canvas files:

**Section 7.4.1 LLM-Specific Performance Metrics**
<br>
**Title**: Test Cases for LLM-Specific Performance Metrics
<br>
**Content**:
```markdown
# Test Cases: LLM-Specific Performance Metrics

This document outlines test cases for verifying the performance of specific LLM interaction metrics as defined in the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing".

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

---