# Test Cases: Load Testing Scenarios

This document outlines test cases for various load testing scenarios as defined in the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing". These tests aim to evaluate the API's stability, resource limits, and behavior under different intensities of load.

**Test Cases Summary: 14 (Original: 6, Enhanced: +8)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* app/main.py (FastAPI application setup)
* app/routers/api_v1.py:33-60 (API endpoints)
* app/providers/dependencies.py (provider selection)
* app/auth/dependencies.py (authentication flow)
* app/db/session.py (database connection management)
* app/services/billing.py (billing queue processing)

## General Test Case Components:
* **ID:** Unique identifier (e.g., PERF_LOAD_BASELINE_001)
* **Category Ref:** (e.g., PERF_LOAD_BASELINE, PERF_LOAD_PEAK, PERF_LOAD_STRESS, PERF_LOAD_SPIKE, PERF_LOAD_ENDURANCE)
* **Description:** The specific load scenario being tested and its objectives.
* **Exposure Point(s):** Entire application stack (FastAPI, Uvicorn, provider SDKs, database, logging, billing queue), and external dependencies (LLM providers).
* **Test Method/Action:** Detailed configuration for the load testing tool (e.g., Locust, k6), including:
    * Number of concurrent users/virtual users (VUs).
    * Request rate (RPS).
    * Workload mix (e.g., 70% chat, 25% embeddings, 5% models list with specific prompt characteristics).
    * Ramp-up period.
    * Test duration.
* **Prerequisites:** Dedicated performance testing environment mirroring production. Load testing tool setup. Monitoring tools (Prometheus, Grafana, Jaeger) configured. Valid API keys for load generation.
* **Expected Secure Outcome:** Specific success criteria for the load scenario, including:
    * Target success rate (e.g., >99%).
    * Latency SLOs (e.g., p95 < 2s for chat, p99 < 5s).
    * Error rate (e.g., <1%).
    * Resource utilization thresholds (e.g., CPU < 70%, Memory < 80%).
    * System stability (no crashes, no cascading failures).
* **Verification Steps:** Detailed analysis of metrics collected during and after the test from monitoring tools and load testing tool reports.

---

### 1\. Baseline Load Test

* **ID:** PERF_LOAD_BASELINE_001
    * **Category Ref:** PERF_LOAD_BASELINE
    * **Description:** Establish baseline performance under normal expected load.
    * **Exposure Point(s):** Entire system under typical operational conditions.
    * **Test Method/Action:**
        * **Tool:** Locust
        * **Concurrent Users:** 100 VUs
        * **Target RPS:** 50 RPS
        * **Workload Mix:** Production-like (e.g., 70% chat short/medium prompts, 25% embeddings single/small batch, 5% /models)
        * **Ramp-up:** 5 minutes
        * **Duration:** 30 minutes at full load.
    * **Prerequisites:** Performance environment ready.
    * **Expected Secure Outcome:**
        * Success Rate: >= 99.5%
        * Latency (Chat): p95 <= 1.5s, p99 <= 3s
        * Latency (Embeddings): p95 <= 0.5s, p99 <= 1s
        * Latency (/models): p95 <= 0.2s
        * Error Rate: <= 0.5% (excluding expected 4xx from client errors if simulated)
        * CPU Utilization (API Server): Average < 60%
        * Memory Utilization (API Server): Stable, no leaks.
    * **Verification Steps:**
        1.  Analyze Locust report for RPS achieved, request success/failure rates, response time distributions (min, max, avg, median, p90, p95, p99).
        2.  Check Prometheus/Grafana for API server and database CPU, memory, network I/O, and connection pool metrics.
        3.  Review API server logs for any errors or warnings.
        4.  Verify billing queue processing keeps up with generated events.

---

### 2\. Peak Load Test

* **ID:** PERF_LOAD_PEAK_001
    * **Category Ref:** PERF_LOAD_PEAK
    * **Description:** Test system performance and stability at anticipated peak load.
    * **Exposure Point(s):** System bottlenecks, provider rate limits, resource limits.
    * **Test Method/Action:**
        * **Tool:** Locust
        * **Concurrent Users:** 500 VUs
        * **Target RPS:** 250 RPS
        * **Workload Mix:** Peak hour production-like mix.
        * **Ramp-up:** 10 minutes
        * **Duration:** 1 hour at full load.
    * **Prerequisites:** Performance environment.
    * **Expected Secure Outcome:**
        * Success Rate: >= 99%
        * Latency (Chat): p95 <= 3s, p99 <= 7s
        * Latency (Embeddings): p95 <= 1s, p99 <= 2s
        * Error Rate: <= 1% (some 429s from providers might be acceptable if handled gracefully).
        * CPU Utilization (API Server): Average < 80-85%.
        * System remains stable; auto-scaling (if configured) functions correctly.
    * **Verification Steps:**
        1.  Locust report analysis (RPS, success/failure, response times).
        2.  Prometheus/Grafana monitoring for server resources, database performance, and provider metrics (if available).
        3.  Log analysis for errors, especially 429s (Too Many Requests) or 503s (Service Unavailable).
        4.  Verify graceful degradation if limits are hit (i.e., API returns proper errors, doesn't crash).

---

### 3\. Stress Test

* **ID:** PERF_LOAD_STRESS_001
    * **Category Ref:** PERF_LOAD_STRESS
    * **Description:** Identify system breaking points and observe failure modes by gradually increasing load beyond peak.
    * **Exposure Point(s):** Weakest component in the system, error handling under extreme load.
    * **Test Method/Action:**
        * **Tool:** Locust
        * **Concurrent Users:** Start at peak load (e.g., 500 VUs) and incrementally increase VUs/RPS every 5-10 minutes (e.g., by +100 VUs / +50 RPS) until system shows significant degradation (high error rates, unacceptable latencies) or fails.
        * **Workload Mix:** Peak hour mix.
        * **Duration:** Until breaking point is found or a predefined max load is reached. Monitor recovery after load is reduced.
    * **Prerequisites:** Performance environment, ability to isolate from production.
    * **Expected Secure Outcome:**
        * Identify the bottleneck (CPU, memory, DB, provider limits, network).
        * System degrades gracefully (e.g., increased latency, then 429/503 errors, rather than crashes or 500s for all requests).
        * System recovers to normal performance levels within X minutes after the stress load is removed.
    * **Verification Steps:**
        1.  Carefully monitor Locust metrics and server-side metrics in real-time.
        2.  Note the load level (VUs, RPS) at which performance degrades significantly (e.g., error rate > 5-10%, p99 latency > 15-20s).
        3.  Identify the first component to fail or become a bottleneck through logs and metrics.
        4.  Observe recovery behavior after reducing load.

---

### 4\. Spike Test

* **ID:** PERF_LOAD_SPIKE_001
    * **Category Ref:** PERF_LOAD_SPIKE
    * **Description:** Evaluate system response to sudden, short bursts of very high load.
    * **Exposure Point(s):** Auto-scaling responsiveness, connection handling, queueing mechanisms.
    * **Test Method/Action:**
        * **Tool:** Locust (or k6 for rapid ramp-up)
        * **Load Profile:** Start with low/baseline load. Suddenly increase load to 2-3x peak (e.g., 500-750 RPS) for a short duration (e.g., 2-5 minutes). Then return to baseline load.
        * **Workload Mix:** Focus on fast, common requests (e.g., short chat completions, single embeddings).
    * **Prerequisites:** Performance environment.
    * **Expected Secure Outcome:**
        * System handles the spike without crashing.
        * Some errors (429s, 503s) are acceptable during the peak of the spike.
        * System recovers quickly to baseline performance and error rates once the spike subsides (e.g., within 1-2 minutes).
        * Auto-scaling (if applicable) triggers and scales back appropriately.
    * **Verification Steps:**
        1.  Monitor RPS, error rates, and latency during the spike and recovery phases.
        2.  Observe auto-scaling actions in cloud provider console (if applicable).
        3.  Measure time to return to normal performance metrics after the spike.

---

### 5\. Endurance Test (Soak Test)

* **ID:** PERF_LOAD_ENDURANCE_001
    * **Category Ref:** PERF_LOAD_ENDURANCE
    * **Description:** Test system stability and resource consumption under sustained moderate load over an extended period.
    * **Exposure Point(s):** Memory leaks, connection pool leaks, log/data accumulation issues, long-term provider stability.
    * **Test Method/Action:**
        * **Tool:** Locust
        * **Concurrent Users/RPS:** Sustained moderate load (e.g., 50-75% of peak load, or 100-150 RPS).
        * **Workload Mix:** Production-like mix.
        * **Duration:** 4-8 hours (or longer, e.g., 24 hours, if feasible).
    * **Prerequisites:** Stable performance environment. Automated monitoring and alerting for key metrics.
    * **Expected Secure Outcome:**
        * Stable performance metrics (latency, error rate) throughout the test.
        * No continuous increase in memory usage (indicative of leaks) on API servers or database.
        * No connection pool exhaustion (DB, provider SDKs).
        * Log storage does not fill up unexpectedly.
        * Billing queue processes events consistently without growing indefinitely.
    * **Verification Steps:**
        1.  Monitor key performance and resource metrics (CPU, memory, network, disk I/O, DB connections, queue sizes) over the entire duration.
        2.  Analyze trends for any signs of degradation or resource leakage.
        3.  Check for any errors or crashes that occur only after prolonged operation.

---

### 6\. Basic Performance Tests in CI Pipeline (Regression Prevention)

* **ID:** PERF_LOAD_CI_REGRESSION_001
    * **Category Ref:** PERF_LOAD_BASELINE (CI subset)
    * **Description:** Lightweight performance tests on critical API paths to detect major regressions early in CI/CD.
    * **Exposure Point(s):** Core functionality of /chat/completions and /embeddings.
    * **Test Method/Action:**
        * **Tool:** Pytest with `pytest-benchmark` or simple timed requests.
        * **Scope:**
            * Send a small number of requests (e.g., 10-20 sequential or minimally concurrent) to `/chat/completions` with a standard prompt and model.
            * Send a small number of requests to `/embeddings` with standard input.
        * **Metrics:** Measure average and p95 response time.
        * **Duration:** Should complete within 1-2 minutes.
    * **Prerequisites:** Test environment accessible from CI. Predefined baseline performance numbers.
    * **Expected Secure Outcome:** Response times remain within a defined threshold (e.g., +/- 20%) of the established baseline for these specific tests. No errors.
    * **Verification Steps:**
        1.  Compare measured response times against historical baselines.
        2.  Fail CI build if a significant performance regression is detected.

---

## Enhanced Test Cases (8 Advanced Load Testing Scenarios)

### 7. Chaos Engineering Load Tests

* **ID:** PERF_LOAD_CHAOS_PROVIDER_FAILURE_001
    * **Category Ref:** PERF_LOAD_CHAOS
    * **Description:** Test system resilience when primary LLM providers fail during peak load conditions.
    * **Exposure Point(s):** app/providers/bedrock/bedrock.py, app/providers/vertex_ai/vertexai.py (error handling), provider failover logic
    * **Test Method/Action:**
        * **Tool:** Locust + Chaos Monkey for provider simulation
        * **Load Profile:** Maintain 75% peak load (200 RPS)
        * **Chaos Injection:** Randomly fail 50% of requests to primary provider for 5-minute windows
        * **Duration:** 45 minutes with multiple chaos windows
    * **Prerequisites:** Multi-provider setup, chaos testing tools, provider failure simulation
    * **Expected Secure Outcome:** System maintains >95% success rate despite provider failures. Automatic failover to secondary providers occurs within 30 seconds. No cascading failures or service crashes.
    * **Verification Steps:**
        1. Monitor overall success rate during chaos windows
        2. Verify failover behavior and recovery times
        3. Check for error rate spikes and service stability

### 8. Adaptive Load Scaling

* **ID:** PERF_LOAD_ADAPTIVE_SCALING_002
    * **Category Ref:** PERF_LOAD_ADAPTIVE
    * **Description:** Test automated scaling behavior under gradually increasing and decreasing load patterns.
    * **Exposure Point(s):** Auto-scaling infrastructure, resource allocation, app/main.py (worker configuration)
    * **Test Method/Action:**
        * **Tool:** Locust with dynamic user scaling
        * **Load Pattern:** Gradual ramp from 10 to 1000 users over 2 hours, then gradual decrease
        * **Metrics:** Scale-out/scale-in timing, resource utilization efficiency
        * **Workload:** Production-like mixed requests
    * **Prerequisites:** Auto-scaling enabled, cloud infrastructure monitoring
    * **Expected Secure Outcome:** Auto-scaling triggers appropriately (scale-out at 70% CPU, scale-in at 30% CPU). Performance remains stable during scaling events. Resource costs optimize based on actual demand.
    * **Verification Steps:**
        1. Monitor scaling events and their timing
        2. Verify performance stability during scaling
        3. Analyze cost efficiency of scaling decisions

### 9. Burst Pattern Load Testing

* **ID:** PERF_LOAD_BURST_PATTERNS_003
    * **Category Ref:** PERF_LOAD_BURST
    * **Description:** Test system response to realistic burst patterns including morning rushes, batch processing windows, and viral content spikes.
    * **Exposure Point(s):** Connection pooling, request queuing, async request handling
    * **Test Method/Action:**
        * **Tool:** k6 with complex load profiles
        * **Patterns:** 
            - Morning rush: 3x baseline for 30 minutes
            - Batch window: 5x baseline for 10 minutes every hour
            - Viral spike: 10x baseline for 5 minutes randomly
        * **Duration:** 8 hours with multiple pattern overlaps
    * **Prerequisites:** Realistic load pattern modeling, comprehensive monitoring
    * **Expected Secure Outcome:** System handles burst patterns without degradation. Queue management prevents request timeouts. Recovery to baseline performance occurs quickly after bursts.
    * **Verification Steps:**
        1. Analyze performance during different burst patterns
        2. Monitor queue depths and request timeout rates
        3. Verify rapid recovery to baseline performance

### 10. Multi-Tenant Load Isolation

* **ID:** PERF_LOAD_MULTI_TENANT_ISOLATION_004
    * **Category Ref:** PERF_LOAD_ISOLATION
    * **Description:** Test performance isolation between different API key users under heavy load conditions.
    * **Exposure Point(s):** app/auth/dependencies.py (API key validation), rate limiting, resource allocation per tenant
    * **Test Method/Action:**
        * **Tool:** Locust with multiple API key simulation
        * **Scenario:** Simulate high-usage tenant (80% of requests) and normal tenants (20% of requests)
        * **Load:** 300 RPS total load maintained for 1 hour
        * **Metrics:** Per-tenant latency, error rates, rate limiting effectiveness
    * **Prerequisites:** Multiple API keys configured, per-tenant monitoring capabilities
    * **Expected Secure Outcome:** High-usage tenant doesn't impact normal tenant performance. Rate limiting works fairly across tenants. Resource allocation prevents tenant starvation.
    * **Verification Steps:**
        1. Compare latency distributions per tenant
        2. Verify rate limiting fairness and effectiveness
        3. Monitor resource consumption per tenant

### 11. Database Connection Storm Testing

* **ID:** PERF_LOAD_DB_CONNECTION_STORM_005
    * **Category Ref:** PERF_LOAD_DB_STORM
    * **Description:** Test database connection pool behavior under sudden high connection demand.
    * **Exposure Point(s):** app/db/session.py (connection pooling), app/auth/repositories.py (database queries)
    * **Test Method/Action:**
        * **Tool:** Custom test harness + Locust
        * **Pattern:** Sudden spike from 10 to 500 concurrent database-heavy requests
        * **Focus:** Authentication queries, API key lookups, concurrent connection management
        * **Duration:** 30 minutes with multiple connection storms
    * **Prerequisites:** Database connection pool monitoring, configurable pool limits
    * **Expected Secure Outcome:** Connection pool handles spikes without exhaustion. No connection leaks or timeouts. Database performance remains stable under high connection load.
    * **Verification Steps:**
        1. Monitor connection pool utilization during spikes
        2. Check for connection timeouts or pool exhaustion
        3. Verify database query performance stability

### 12. Long-Running Request Endurance

* **ID:** PERF_LOAD_LONG_RUNNING_ENDURANCE_006
    * **Category Ref:** PERF_LOAD_LONG_RUNNING
    * **Description:** Test system stability when handling many concurrent long-running requests (large context windows, high max_tokens).
    * **Exposure Point(s):** Async request handling, memory management, streaming response handling
    * **Test Method/Action:**
        * **Tool:** Locust with custom request profiles
        * **Request Types:** 
            - Long context chat requests (90% context window usage)
            - High max_tokens requests (4000+ tokens)
            - Long-running embedding batches
        * **Concurrency:** 100 concurrent long-running requests
        * **Duration:** 2 hours sustained load
    * **Prerequisites:** Models supporting large contexts, memory monitoring tools
    * **Expected Secure Outcome:** System maintains stability with long-running requests. Memory usage remains bounded. No timeouts or connection issues for legitimate long requests.
    * **Verification Steps:**
        1. Monitor system memory and resource usage trends
        2. Track completion rates for long-running requests
        3. Verify no resource leaks or performance degradation

### 13. Provider Rate Limit Cascade Testing

* **ID:** PERF_LOAD_PROVIDER_RATE_LIMIT_CASCADE_007
    * **Category Ref:** PERF_LOAD_RATE_LIMIT_CASCADE
    * **Description:** Test system behavior when multiple LLM providers simultaneously hit rate limits.
    * **Exposure Point(s):** Provider error handling, rate limit detection, fallback mechanisms
    * **Test Method/Action:**
        * **Tool:** Locust + provider rate limit simulation
        * **Scenario:** Push all providers to rate limits simultaneously during peak load
        * **Load:** 400 RPS targeting all available providers
        * **Metrics:** Error handling, user experience during provider saturation
    * **Prerequisites:** Multiple providers configured, rate limit simulation capabilities
    * **Expected Secure Outcome:** Graceful degradation when all providers hit limits. Clear error messages to users. No service crashes or unlimited retries. Proper backoff and retry strategies.
    * **Verification Steps:**
        1. Monitor error rates and response codes during provider saturation
        2. Verify graceful error handling and user communication
        3. Test automatic recovery when rate limits reset

### 14. Streaming Connection Avalanche

* **ID:** PERF_LOAD_STREAMING_AVALANCHE_008
    * **Category Ref:** PERF_LOAD_STREAMING_AVALANCHE
    * **Description:** Test system limits when handling thousands of simultaneous streaming connections.
    * **Exposure Point(s):** FastAPI streaming responses, async connection management, WebSocket-like behavior
    * **Test Method/Action:**
        * **Tool:** Custom streaming client + load orchestration
        * **Pattern:** Rapidly establish 2000+ concurrent streaming connections
        * **Hold Time:** Maintain connections for 10+ minutes each
        * **Request Mix:** Various prompt lengths and expected response lengths
    * **Prerequisites:** High connection limit configuration, streaming performance monitoring
    * **Expected Secure Outcome:** System handles maximum realistic concurrent streams. Memory usage scales linearly with connections. Connection cleanup works properly. No stream corruption or cross-talk.
    * **Verification Steps:**
        1. Monitor concurrent connection counts and system resources
        2. Verify stream quality and independence across all connections
        3. Test connection cleanup and resource reclamation

---