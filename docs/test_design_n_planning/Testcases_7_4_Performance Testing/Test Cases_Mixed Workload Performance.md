# Test Cases: Mixed Workload Performance

This document outlines test cases for evaluating API performance under realistic mixed workload patterns, as defined in the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing".

**Test Cases Summary: 10 (Original: 4, Enhanced: +6)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* app/routers/api_v1.py (mixed endpoint handling)
* app/providers/dependencies.py (provider workload distribution)
* app/auth/dependencies.py (authentication under mixed load)
* app/db/session.py (database performance under diverse queries)
* Load testing tools (Locust, k6) and workload pattern analysis

## General Test Case Components:
* **ID:** Unique identifier (e.g., PERF_MIXED_GW_001)
* **Category Ref:** (e.g., PERF_MIXED_GATEWAY, PERF_MIXED_FASTAPI, PERF_MIXED_RESOURCE, PERF_MIXED_PROVIDER)
* **Description:** What specific performance aspect under mixed load is being tested.
* **Exposure Point(s):** Specific components like API Gateway, FastAPI server, database, provider SDKs when handling diverse concurrent requests.
* **Test Method/Action:** Define the workload mix (e.g., 70% chat, 25% embeddings, 5% models list), concurrency level, and duration. Execute using a load testing tool.
* **Prerequisites:** Valid API Keys. Configured models for all relevant types. Load testing environment and tools (e.g., Locust, k6). Monitoring in place.
* **Expected Secure Outcome:** System remains stable, meets SLOs for latency and error rates for each request type within the mix. Resource utilization is within acceptable limits.
* **Verification Steps:** Collect and analyze metrics (latency percentiles, error rates per endpoint, throughput, resource utilization on API server and database).

---

### 1\. API Gateway / Load Balancer Performance under Mixed Load

* **ID:** PERF_MIXED_GATEWAY_STD_LOAD_001
    * **Category Ref:** PERF_MIXED_GATEWAY
    * **Description:** Evaluate API Gateway/Load Balancer (external infrastructure) performance and stability under a standard production-like mixed workload.
    * **Exposure Point(s):** API Gateway, Load Balancer.
    * **Test Method/Action:**
        1.  Define a workload mix:
            * 60% `/chat/completions` (non-streaming, mix of short/medium prompts)
            * 10% `/chat/completions` (streaming, short prompts)
            * 25% `/embeddings` (mix of single and small batch requests)
            * 5% `GET /models`
        2.  Simulate N concurrent users (e.g., 50-100) generating this mixed traffic for M minutes (e.g., 15-30 mins).
    * **Prerequisites:** Production-like gateway/LB setup.
    * **Expected Secure Outcome:** Gateway/LB maintains low latency overhead (e.g., adds < 50ms to requests). Error rates attributed to the gateway itself are negligible (<0.1%). Connections are distributed evenly to API instances.
    * **Verification Steps:**
        1.  Monitor gateway/LB metrics (request rate, error rate, latency, active connections).
        2.  Monitor health and load on backend API instances.
        3.  Compare end-to-end latency with API-internal processing time to estimate gateway overhead.

---

### 2\. FastAPI Application Server Performance under Mixed Load

* **ID:** PERF_MIXED_FASTAPI_WORKER_EFFICIENCY_001
    * **Category Ref:** PERF_MIXED_FASTAPI
    * **Description:** Test FastAPI/Uvicorn worker efficiency and stability when handling concurrent streaming, non-streaming chat, and embedding requests.
    * **Exposure Point(s):** FastAPI application, Uvicorn worker configuration, async event loop.
    * **Test Method/Action:**
        1.  Use the standard mixed workload (as in PERF_MIXED_GATEWAY_STD_LOAD_001).
        2.  Gradually increase concurrent users/request rate towards expected peak load.
        3.  Run for a sustained period (e.g., 30 minutes).
    * **Prerequisites:** API deployed with production-like Uvicorn worker settings.
    * **Expected Secure Outcome:** Application workers remain responsive. CPU and memory utilization are stable and within limits (e.g., CPU < 70-80%, memory usage not growing indefinitely). Async event loop is not blocked. Latency SLOs are met for each request type.
    * **Verification Steps:**
        1.  Monitor API server CPU, memory, network I/O, and active Python threads/async tasks.
        2.  Track latency (p50, p95, p99) and error rates for each endpoint (`/chat/completions`, `/embeddings`, `/models`).
        3.  Check for logs indicating event loop blocking or slow request processing.

---

### 3\. Shared Resource Contention under Mixed Load

* **ID:** PERF_MIXED_RESOURCE_DB_AUTH_001
    * **Category Ref:** PERF_MIXED_RESOURCE
    * **Description:** Evaluate database performance (connection pool, query latency) for authentication lookups during high-volume mixed API traffic.
    * **Exposure Point(s):** `app/db/session.py` (get_db_session), `app/auth/repositories.py` (APIKeyRepository), PostgreSQL connection pool.
    * **Test Method/Action:**
        1.  Execute a high-throughput mixed workload where all requests require authentication.
        2.  Simulate a mix of valid and a small percentage of invalid API keys to exercise different auth paths.
    * **Prerequisites:** Production-like database configuration and connection pool settings.
    * **Expected Secure Outcome:** Database connection pool does not exhaust. Latency for authentication queries remains low (e.g., p95 < 20ms). Overall API error rate due to DB issues is minimal.
    * **Verification Steps:**
        1.  Monitor database active connections, query latency for auth lookups, CPU/memory usage.
        2.  Monitor API server logs for DB connection errors or timeouts.
        3.  Track overall API request latency and error rates.

* **ID:** PERF_MIXED_RESOURCE_BILLING_QUEUE_002
    * **Category Ref:** PERF_MIXED_RESOURCE
    * **Description:** Assess the performance of the billing service queue (`app/services/billing.py`) under sustained mixed load generating many billing events.
    * **Exposure Point(s):** `billing_queue` in `app/services/billing.py`, `billing_worker` processing.
    * **Test Method/Action:**
        1.  Execute a sustained high-throughput mixed workload (chat & embeddings) for an extended period (e.g., 1 hour).
    * **Prerequisites:**
    * **Expected Secure Outcome:** The `billing_queue` size remains stable or grows minimally, indicating the `billing_worker` can keep up with the rate of incoming billing events. No significant memory increase in the API server due to queue backup. API request latency is not impacted by billing queue operations.
    * **Verification Steps:**
        1.  (If possible) Monitor the `billing_queue` size over time.
        2.  Monitor API server memory usage.
        3.  Verify that billing logs are being written consistently by the `billing_worker`.

* **ID:** PERF_MIXED_RESOURCE_CONFIG_CACHE_003
    * **Category Ref:** PERF_MIXED_RESOURCE
    * **Description:** Evaluate the performance and contention of configuration caching (`@lru_cache` on `get_settings()`) under mixed load with diverse model requests.
    * **Exposure Point(s):** `app/config/settings.py` (`get_settings`), `app/providers/dependencies.py` (model lookups in `backend_map`).
    * **Test Method/Action:**
        1.  Execute a mixed workload that frequently requests different model IDs (both valid and some invalid to test cache on miss paths).
    * **Prerequisites:**
    * **Expected Secure Outcome:** Configuration lookups are fast. `backend_map` access is efficient. `lru_cache` provides performance benefits without becoming a contention point or causing excessive memory use.
    * **Verification Steps:**
        1.  Profile internal request handling time, specifically time spent in `get_settings()` or `get_model_config_validated()`.
        2.  Monitor overall API server CPU and memory.

---

### 4\. Provider Interaction Logic under Mixed Load

* **ID:** PERF_MIXED_PROVIDER_CONCURRENCY_001
    * **Category Ref:** PERF_MIXED_PROVIDER
    * **Description:** Test concurrent interactions with multiple LLM providers (e.g., Bedrock and Vertex AI simultaneously) using their respective SDKs.
    * **Exposure Point(s):** `BedRockBackend`, `VertexBackend`, `aioboto3` and `google-cloud-aiplatform` SDKs.
    * **Test Method/Action:**
        1.  Define a workload that splits requests between models hosted on Bedrock and models hosted on Vertex AI (e.g., 50% Bedrock, 50% Vertex AI).
        2.  Simulate high concurrency.
    * **Prerequisites:** Models correctly configured for both Bedrock and Vertex AI.
    * **Expected Secure Outcome:** API server efficiently manages concurrent async calls to different provider SDKs. Performance (latency, error rate) for one provider is not significantly impacted by load on the other provider. SDK internal connection/thread pools operate correctly.
    * **Verification Steps:**
        1.  Monitor latency and error rates independently for Bedrock-routed requests and Vertex AI-routed requests.
        2.  Check API server logs for any SDK-related errors or warnings about resource contention.
        3.  Monitor CPU/memory on the API server to ensure SDK clients are not causing excessive overhead.

---

## Enhanced Test Cases (6 Advanced Mixed Workload Performance Scenarios)

### 5. Dynamic Workload Pattern Adaptation

* **ID:** PERF_MIXED_DYNAMIC_ADAPTATION_001
    * **Category Ref:** PERF_MIXED_DYNAMIC_ADAPTATION
    * **Description:** Test system adaptation to dynamically changing workload patterns throughout the day and week.
    * **Exposure Point(s):** Dynamic resource allocation, workload pattern recognition, adaptive optimization
    * **Test Method/Action:**
        1. Simulate realistic daily/weekly workload patterns with varying request type distributions
        2. Test system adaptation to changing patterns (morning chat heavy, afternoon embedding heavy, etc.)
        3. Implement workload prediction and pre-optimization strategies
        4. Measure system responsiveness to pattern changes
    * **Prerequisites:** Dynamic workload generation tools, pattern recognition algorithms, adaptive resource management
    * **Expected Secure Outcome:** System adapts to workload changes within 10 minutes. Performance remains stable during pattern transitions. Predictive optimization improves overall efficiency by 20-30%.
    * **Verification Steps:**
        1. Monitor system adaptation speed to workload pattern changes
        2. Verify performance stability during pattern transitions
        3. Test predictive optimization effectiveness

### 6. Complex Multi-Dimensional Workload Testing

* **ID:** PERF_MIXED_MULTI_DIMENSIONAL_002
    * **Category Ref:** PERF_MIXED_MULTI_DIMENSIONAL
    * **Description:** Test performance under complex workloads varying across multiple dimensions: request types, user types, geographic regions, and temporal patterns.
    * **Exposure Point(s):** Multi-dimensional resource management, complex routing logic, performance optimization across dimensions
    * **Test Method/Action:**
        1. Design workloads varying across user types (free vs premium), regions (US, EU, Asia), and request complexity
        2. Test system performance under multi-dimensional load scenarios
        3. Implement dimension-aware optimization strategies
        4. Measure performance consistency across all dimensions
    * **Prerequisites:** Multi-dimensional load testing tools, geographic distribution simulation, user type differentiation
    * **Expected Secure Outcome:** Performance remains consistent across all dimensions. No dimension significantly impacts others. Resource allocation optimized per dimension.
    * **Verification Steps:**
        1. Monitor performance metrics across all workload dimensions
        2. Verify isolation between different dimension combinations
        3. Test dimension-aware optimization effectiveness

### 7. Intelligent Workload Prioritization and QoS

* **ID:** PERF_MIXED_INTELLIGENT_PRIORITIZATION_003
    * **Category Ref:** PERF_MIXED_QOS_PRIORITIZATION
    * **Description:** Implement and test intelligent workload prioritization with Quality of Service (QoS) guarantees for different request types and users.
    * **Exposure Point(s):** Request prioritization logic, QoS implementation, resource allocation per priority level
    * **Test Method/Action:**
        1. Implement multi-level prioritization (critical, high, normal, low)
        2. Test QoS guarantees under various load conditions
        3. Implement intelligent priority assignment based on request characteristics
        4. Measure QoS adherence and priority effectiveness
    * **Prerequisites:** Prioritization algorithms, QoS monitoring, intelligent classification systems
    * **Expected Secure Outcome:** QoS guarantees maintained >95% of the time. High-priority requests maintain SLOs under high load. Intelligent prioritization improves overall system efficiency.
    * **Verification Steps:**
        1. Monitor QoS adherence across priority levels
        2. Test prioritization effectiveness under high load
        3. Verify intelligent priority assignment accuracy

### 8. Workload-Aware Resource Scaling and Optimization

* **ID:** PERF_MIXED_WORKLOAD_AWARE_SCALING_004
    * **Category Ref:** PERF_MIXED_WORKLOAD_SCALING
    * **Description:** Test workload-aware resource scaling that adjusts infrastructure based on specific workload characteristics and patterns.
    * **Exposure Point(s):** Workload analysis, resource scaling algorithms, workload-specific optimization
    * **Test Method/Action:**
        1. Implement workload characteristic analysis (CPU-heavy, memory-heavy, I/O-heavy)
        2. Test workload-aware scaling decisions
        3. Implement workload-specific resource optimization
        4. Measure scaling efficiency and resource utilization improvement
    * **Prerequisites:** Workload analysis tools, intelligent scaling algorithms, resource monitoring
    * **Expected Secure Outcome:** Workload-aware scaling improves resource efficiency by 25-40%. Scaling decisions optimize for workload characteristics. Resource utilization maximized per workload type.
    * **Verification Steps:**
        1. Monitor scaling decision accuracy for different workload types
        2. Measure resource utilization improvements
        3. Test scaling responsiveness to workload changes

### 9. Cross-Service Performance Impact Analysis

* **ID:** PERF_MIXED_CROSS_SERVICE_IMPACT_005
    * **Category Ref:** PERF_MIXED_CROSS_SERVICE
    * **Description:** Analyze performance impact across different services when handling mixed workloads to identify and mitigate cross-service interference.
    * **Exposure Point(s):** Service interaction patterns, resource contention, cross-service optimization
    * **Test Method/Action:**
        1. Monitor cross-service resource contention under mixed workloads
        2. Identify services that negatively impact each other's performance
        3. Implement service isolation and resource allocation strategies
        4. Test cross-service performance optimization effectiveness
    * **Prerequisites:** Cross-service monitoring, service isolation tools, resource allocation mechanisms
    * **Expected Secure Outcome:** Cross-service interference minimized. Service isolation maintains independent performance. Resource allocation prevents service starvation.
    * **Verification Steps:**
        1. Monitor cross-service performance interference patterns
        2. Test service isolation effectiveness
        3. Verify resource allocation fairness across services

### 10. Advanced Mixed Workload Analytics and Optimization

* **ID:** PERF_MIXED_ADVANCED_ANALYTICS_006
    * **Category Ref:** PERF_MIXED_ANALYTICS
    * **Description:** Implement advanced analytics for mixed workload patterns to identify optimization opportunities and predict performance issues.
    * **Exposure Point(s):** Workload pattern analytics, performance prediction, optimization recommendation systems
    * **Test Method/Action:**
        1. Implement comprehensive workload pattern analysis and visualization
        2. Develop predictive models for performance under different workload mixes
        3. Test automated optimization recommendations based on analytics
        4. Validate analytics accuracy and optimization effectiveness
    * **Prerequisites:** Advanced analytics tools, machine learning capabilities, optimization algorithms
    * **Expected Secure Outcome:** Analytics provide actionable insights for workload optimization. Predictive models achieve >85% accuracy. Automated recommendations improve performance by 15-25%.
    * **Verification Steps:**
        1. Validate analytics accuracy and insight quality
        2. Test predictive model performance
        3. Measure optimization recommendation effectiveness

---