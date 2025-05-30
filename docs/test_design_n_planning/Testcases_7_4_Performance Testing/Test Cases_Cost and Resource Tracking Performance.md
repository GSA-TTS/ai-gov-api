# Test Cases: Cost and Resource Tracking Performance

This document outlines test cases focused on the efficiency of token usage, request batching, and the resource utilization of the API framework itself, which have direct implications on operational costs. This is based on the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing".

**Test Cases Summary: 14 (Original: 8, Enhanced: +6)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* app/services/billing.py (billing queue and cost tracking)
* app/providers/*/adapter_to_core.py (usage metrics processing)
* Provider SDK usage reporting and token counting
* Resource utilization monitoring and cost optimization strategies

## General Test Case Components:
* **ID:** Unique identifier (e.g., PERF_COST_TOKEN_EFFICIENT_001)
* **Category Ref:** (e.g., PERF_COST_TOKEN_USAGE, PERF_COST_BATCHING, PERF_COST_API_RESOURCE)
* **Description:** The specific aspect of cost or resource efficiency being tested.
* **Exposure Point(s):** Logic related to prompt construction, `max_tokens` handling, embedding batching strategies, and general resource consumption by API components (CPU, memory, DB connections).
* **Test Method/Action:** Specific API requests designed to test efficiency, or load tests focused on resource monitoring.
* **Prerequisites:** Valid API Key. Monitoring tools for server resources. Ability to inspect `usage` objects in responses.
* **Expected Secure Outcome:** Optimized token usage. Efficient batching where applicable. API framework operates with minimal resource overhead.
* **Verification Steps:** Analysis of `usage` data from API responses, server resource metrics (CPU, memory, network, DB connections), comparison against baselines.

---

### 1\. Efficiency of Token Usage and Request Batching

* **ID:** PERF_COST_TOKEN_PROMPT_OVERHEAD_001
    * **Category Ref:** PERF_COST_TOKEN_USAGE
    * **Description:** Verify that the API framework does not add unnecessary tokens to user prompts before sending to LLMs.
    * **Exposure Point(s):** Adapter logic (`adapter_from_core.py`) for chat requests, system prompt handling.
    * **Test Method/Action:**
        1.  Send a simple user prompt (e.g., "Hello") with no system message via `/chat/completions`.
        2.  Capture the `prompt_tokens` from the `usage` object in the response.
        3.  Compare this with the expected token count for "Hello" using a known tokenizer for the target model (if possible, or against provider's own reporting if called directly).
        4.  Repeat with a system message to see if its token count is added correctly.
    * **Prerequisites:** Tokenizer for the target model (approximate is okay) or baseline from direct provider call.
    * **Expected Secure Outcome:** `prompt_tokens` reported by the API should closely match the actual token count of the user message(s) plus any system messages, with minimal unexplained overhead from the API framework.
    * **Verification Steps:** Compare reported `prompt_tokens` with calculated/expected token count.

* **ID:** PERF_COST_TOKEN_MAXTOKENS_ENFORCEMENT_002
    * **Category Ref:** PERF_COST_TOKEN_USAGE
    * **Description:** Ensure `max_tokens` is enforced effectively to prevent over-generation and associated costs. (Functional overlap with FV_LLM_TOKEN_MAXTOKENS_RESPECTED_001 but with a cost focus).
    * **Exposure Point(s):** /chat/completions `max_tokens` parameter handling by adapters and LLM providers.
    * **Test Method/Action:**
        1.  Send a prompt that would naturally lead to a long response.
        2.  Set `max_tokens` to a small value (e.g., 10).
        3.  Observe `completion_tokens` in the response `usage` object.
    * **Prerequisites:** Valid API Key.
    * **Expected Secure Outcome:** `completion_tokens` is less than or equal to the requested `max_tokens`. `finish_reason` is "length". This prevents accidental cost overruns due to excessive generation.
    * **Verification Steps:** Check `usage.completion_tokens` and `choices[0].finish_reason`.

* **ID:** PERF_COST_BATCHING_EMBED_EFFECTIVENESS_003
    * **Category Ref:** PERF_COST_BATCHING
    * **Description:** Evaluate if batching embedding requests (where supported by provider and implemented by API) leads to better cost-per-embedding or throughput compared to single requests.
    * **Exposure Point(s):** /api/v1/embeddings, adapter logic for batching if any, provider SDK batching.
    * **Test Method/Action:**
        1.  Select an embedding model that benefits from batching.
        2.  Send N individual embedding requests for N texts. Measure total time and sum of `prompt_tokens`.
        3.  Send 1 batch embedding request with the same N texts. Measure total time and `prompt_tokens`.
    * **Prerequisites:** Valid API Key. Provider documentation on batching benefits/limits.
    * **Expected Secure Outcome:** For providers that optimize batch requests, the total time for the batch request should be significantly less than N * (average single request time). Token counting should be consistent. (Note: The current API framework passes the list of inputs as-is; effective batching is largely up to the provider SDK and backend). This test primarily verifies the pass-through works and allows provider to batch.
    * **Verification Steps:** Compare total time and token usage for individual vs. batch requests.

---

### 2\. Resource Utilization of API Framework Components

* **ID:** PERF_COST_API_RESOURCE_CPU_BASELINE_001
    * **Category Ref:** PERF_COST_API_RESOURCE
    * **Description:** Measure baseline CPU utilization of the API server under no load and light load.
    * **Exposure Point(s):** FastAPI application, Uvicorn workers, Python runtime.
    * **Test Method/Action:**
        1.  Start the API server. Monitor CPU usage when idle.
        2.  Send a very light load (e.g., 1-2 RPS of simple `/models` requests or short chat completions). Monitor CPU usage.
    * **Prerequisites:** Monitoring tools for server CPU.
    * **Expected Secure Outcome:** Idle CPU usage is very low. CPU usage under light load is minimal and scales linearly with request processing.
    * **Verification Steps:** Record CPU utilization percentages.

* **ID:** PERF_COST_API_RESOURCE_MEMORY_BASELINE_002
    * **Category Ref:** PERF_COST_API_RESOURCE
    * **Description:** Measure baseline memory footprint of the API server after startup and under light load.
    * **Exposure Point(s):** FastAPI application, Python memory management.
    * **Test Method/Action:**
        1.  Start the API server. Monitor memory usage once stable.
        2.  Send a light load. Monitor memory usage.
    * **Prerequisites:** Monitoring tools for server memory.
    * **Expected Secure Outcome:** Initial memory footprint is reasonable. Memory usage does not grow significantly under light load. No memory leaks.
    * **Verification Steps:** Record memory utilization (RSS, VMS).

* **ID:** PERF_COST_API_RESOURCE_DB_CONNECTIONS_IDLE_003
    * **Category Ref:** PERF_COST_API_RESOURCE
    * **Description:** Monitor idle database connections held by the API server when there is no traffic.
    * **Exposure Point(s):** SQLAlchemy connection pool (`app/db/session.py`).
    * **Test Method/Action:**
        1.  Start the API server.
        2.  After initial startup (and any initial DB checks like health check), monitor active connections to the database from the API application when no requests are being made.
    * **Prerequisites:** Database monitoring tools to see active connections.
    * **Expected Secure Outcome:** Number of idle connections should be minimal, ideally matching the configured pool's minimum or idle settings, and not grow over time.
    * **Verification Steps:** Check active connections in PostgreSQL (`pg_stat_activity`).

* **ID:** PERF_COST_API_RESOURCE_LOGGING_OVERHEAD_004
    * **Category Ref:** PERF_COST_API_RESOURCE
    * **Description:** Assess the CPU and I/O overhead of the logging system (`app/logs/middleware.py`, `app/logs/logging_config.py`).
    * **Exposure Point(s):** Logging components.
    * **Test Method/Action:**
        1.  Run a load test with LOG_LEVEL set to a production-like level (e.g., INFO). Measure request latency and server CPU/IO.
        2.  Run the same load test with LOG_LEVEL set to a minimal level (e.g., ERROR or CRITICAL), or with logging heavily stubbed/disabled if possible. Measure request latency and server CPU/IO.
    * **Prerequisites:** Ability to change log level. Load testing tools. Server resource monitoring.
    * **Expected Secure Outcome:** The difference in performance and resource utilization between the two runs indicates the logging overhead. This overhead should be acceptably small (e.g., < 5-10% impact on latency/throughput).
    * **Verification Steps:** Compare latency, throughput, CPU, and Disk I/O metrics from the two test runs.

* **ID:** PERF_COST_API_RESOURCE_BILLING_WORKER_005
    * **Category Ref:** PERF_COST_API_RESOURCE
    * **Description:** Monitor resource consumption of the `billing_worker` background task (`app/services/billing.py`) under load.
    * **Exposure Point(s):** `billing_worker` async task.
    * **Test Method/Action:**
        1.  Run a load test that generates a high rate of billable events (chat and embeddings).
        2.  Monitor CPU and memory usage of the API server process, paying attention to any growth that could be attributed to the billing worker or its queue.
    * **Prerequisites:** Load testing tools. Server resource monitoring.
    * **Expected Secure Outcome:** The `billing_worker` processes events efficiently without consuming disproportionate CPU or memory, and without causing the `billing_queue` to grow indefinitely (which would consume memory).
    * **Verification Steps:** Monitor overall server CPU/memory. If possible, profile the `billing_worker` task or monitor the `billing_queue` size.

---

## Enhanced Test Cases (6 Advanced Cost and Resource Tracking Scenarios)

### 3. Real-Time Cost Optimization and Monitoring

* **ID:** PERF_COST_REALTIME_OPTIMIZATION_001
    * **Category Ref:** PERF_COST_REALTIME_OPTIMIZATION
    * **Description:** Implement real-time cost monitoring and optimization that dynamically adjusts provider selection and request parameters based on cost efficiency.
    * **Exposure Point(s):** app/services/billing.py (real-time cost tracking), cost-aware provider selection, dynamic optimization algorithms
    * **Test Method/Action:**
        1. Implement real-time cost per request monitoring across all providers
        2. Test cost-aware provider selection algorithms
        3. Implement dynamic request optimization based on cost efficiency metrics
        4. Measure cost savings from real-time optimization strategies
    * **Prerequisites:** Real-time cost monitoring infrastructure, provider cost APIs, optimization algorithms
    * **Expected Secure Outcome:** Real-time optimization reduces costs by 15-25% without significant performance impact. Cost monitoring provides accurate per-request cost tracking. Optimization decisions made within 50ms.
    * **Verification Steps:**
        1. Monitor cost reduction from real-time optimization
        2. Verify cost tracking accuracy across providers
        3. Test optimization decision latency and effectiveness

### 4. Advanced Token Usage Analytics and Optimization

* **ID:** PERF_COST_TOKEN_ANALYTICS_002
    * **Category Ref:** PERF_COST_TOKEN_ANALYTICS
    * **Description:** Implement advanced token usage analytics to identify optimization opportunities and reduce token waste.
    * **Exposure Point(s):** Token usage pattern analysis, prompt optimization, response length optimization
    * **Test Method/Action:**
        1. Implement detailed token usage analytics across different request types
        2. Identify token waste patterns and optimization opportunities
        3. Test prompt optimization strategies for token efficiency
        4. Implement adaptive max_tokens based on request characteristics
    * **Prerequisites:** Token usage analytics tools, prompt optimization algorithms, usage pattern analysis
    * **Expected Secure Outcome:** Token usage optimization reduces costs by 20-30%. Token waste identified and minimized. Adaptive max_tokens improves efficiency without quality impact.
    * **Verification Steps:**
        1. Measure token usage reduction from optimization strategies
        2. Analyze token waste patterns and mitigation effectiveness
        3. Verify quality maintenance with optimized token usage

### 5. Cost-Performance Trade-off Optimization

* **ID:** PERF_COST_PERFORMANCE_TRADEOFF_003
    * **Category Ref:** PERF_COST_PERFORMANCE_TRADEOFF
    * **Description:** Optimize the balance between cost and performance to achieve optimal cost-effectiveness for different use cases.
    * **Exposure Point(s):** Cost-performance modeling, use case optimization, provider selection algorithms
    * **Test Method/Action:**
        1. Develop cost-performance models for different request types and providers
        2. Test dynamic optimization based on cost-performance targets
        3. Implement use case-specific optimization strategies
        4. Measure optimal cost-performance balance across scenarios
    * **Prerequisites:** Cost-performance modeling tools, optimization algorithms, use case classification
    * **Expected Secure Outcome:** Optimal cost-performance balance achieved for different use cases. Cost efficiency improved by 25-40% while maintaining performance SLOs. Dynamic optimization responds to changing requirements.
    * **Verification Steps:**
        1. Validate cost-performance models accuracy
        2. Test optimization effectiveness across different use cases
        3. Verify maintenance of performance SLOs with cost optimization

### 6. Resource Utilization Efficiency Analysis

* **ID:** PERF_COST_RESOURCE_EFFICIENCY_004
    * **Category Ref:** PERF_COST_RESOURCE_EFFICIENCY
    * **Description:** Analyze and optimize resource utilization efficiency to minimize infrastructure costs while maintaining performance.
    * **Exposure Point(s):** CPU utilization optimization, memory efficiency, connection pooling efficiency, infrastructure cost optimization
    * **Test Method/Action:**
        1. Monitor resource utilization patterns and identify inefficiencies
        2. Implement resource optimization strategies (CPU, memory, connections)
        3. Test infrastructure scaling efficiency and cost optimization
        4. Measure infrastructure cost reduction from efficiency improvements
    * **Prerequisites:** Resource monitoring tools, optimization algorithms, infrastructure cost tracking
    * **Expected Secure Outcome:** Resource utilization efficiency improved by 30-50%. Infrastructure costs reduced while maintaining performance. Optimal resource allocation achieved.
    * **Verification Steps:**
        1. Measure resource utilization improvements
        2. Monitor infrastructure cost reduction
        3. Verify performance maintenance with optimized resource usage

### 7. Predictive Cost Management and Budgeting

* **ID:** PERF_COST_PREDICTIVE_MANAGEMENT_005
    * **Category Ref:** PERF_COST_PREDICTIVE
    * **Description:** Implement predictive cost management and budgeting to anticipate and control costs proactively.
    * **Exposure Point(s):** Cost forecasting algorithms, budget management, usage prediction, cost alerting
    * **Test Method/Action:**
        1. Implement cost forecasting based on usage patterns and trends
        2. Test budget management and cost alerting systems
        3. Implement proactive cost control measures
        4. Validate cost prediction accuracy and budget adherence
    * **Prerequisites:** Historical usage data, forecasting algorithms, budget management tools
    * **Expected Secure Outcome:** Cost forecasting accuracy >90%. Budget adherence maintained. Proactive cost control prevents budget overruns. Cost alerts provide timely warnings.
    * **Verification Steps:**
        1. Validate cost forecasting accuracy over time
        2. Test budget management effectiveness
        3. Verify proactive cost control measures

### 8. Comprehensive Cost Attribution and Chargeback

* **ID:** PERF_COST_ATTRIBUTION_CHARGEBACK_006
    * **Category Ref:** PERF_COST_ATTRIBUTION
    * **Description:** Implement detailed cost attribution and chargeback mechanisms for accurate cost allocation across users, applications, and use cases.
    * **Exposure Point(s):** app/services/billing.py (detailed cost attribution), chargeback mechanisms, cost allocation algorithms
    * **Test Method/Action:**
        1. Implement granular cost attribution across multiple dimensions
        2. Test chargeback accuracy and performance impact
        3. Develop cost allocation algorithms for shared resources
        4. Validate cost attribution accuracy and completeness
    * **Prerequisites:** Detailed billing infrastructure, chargeback systems, cost allocation tools
    * **Expected Secure Outcome:** Cost attribution accuracy >95%. Chargeback processing overhead <2ms per request. Comprehensive cost visibility across all dimensions.
    * **Verification Steps:**
        1. Validate cost attribution accuracy across different dimensions
        2. Test chargeback processing performance
        3. Verify comprehensive cost tracking and allocation

---