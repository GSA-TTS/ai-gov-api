# Test Cases: Application Server & Framework Performance

This document outlines test cases for evaluating the performance of the core application server (FastAPI, Uvicorn) and framework components, as defined in the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing".

**Test Cases Summary: 16 (Original: 8, Enhanced: +8)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* app/main.py (FastAPI application setup and middleware)
* app/routers/ (API routing and endpoint configuration)
* app/logs/middleware.py (logging middleware performance)
* Uvicorn server configuration and worker management
* FastAPI dependency injection and async performance

## General Test Case Components:
* **ID:** Unique identifier (e.g., PERF_APP_WORKER_001)
* **Category Ref:** (e.g., PERF_APP_WORKER, PERF_APP_FASTAPI_CONFIG, PERF_APP_UVICORN, PERF_APP_LIFECYCLE)
* **Description:** The specific aspect of application server or framework performance being tested.
* **Exposure Point(s):** FastAPI application settings, Uvicorn worker configuration, middleware stack, async request handling.
* **Test Method/Action:** Specific configurations or load patterns to stress targeted components.
* **Prerequisites:** Performance testing environment. Load testing tools. Monitoring tools.
* **Expected Secure Outcome:** Efficient request handling, optimal worker utilization, stable performance under load, minimal framework overhead.
* **Verification Steps:** Analysis of latency, throughput, error rates, and server resource utilization (CPU, memory).

---

### 1\. FastAPI Application Server Configuration & Worker Management

* **ID:** PERF_APP_WORKER_SINGLE_VS_MULTI_001
    * **Category Ref:** PERF_APP_WORKER
    * **Description:** Compare performance with a single Uvicorn worker versus multiple Uvicorn workers.
    * **Exposure Point(s):** Uvicorn worker configuration (e.g., `uvicorn app.main:app --workers N`), Dockerfile `CMD` or `ENTRYPOINT`.
    * **Test Method/Action:**
        1.  Run a baseline load test (mixed workload, e.g., 50 RPS for 10 mins) with `workers = 1`.
        2.  Run the same load test with `workers = C` (where C is the number of available CPU cores, or a recommended number like 2*cores + 1).
    * **Prerequisites:** Ability to configure Uvicorn worker count.
    * **Expected Secure Outcome:**
        * Multiple workers should significantly improve throughput (RPS) and potentially reduce p95/p99 latencies for CPU-bound or mixed I/O-CPU workloads, up to a point of saturation.
        * Error rates should remain low for both configurations under appropriate load.
        * Single worker configuration should show clear signs of bottlenecking (high CPU on one core, increased queueing/latency) sooner.
    * **Verification Steps:**
        1.  Compare achieved RPS, latency distributions (p50, p95, p99), and error rates between single and multi-worker configurations.
        2.  Monitor CPU utilization across all cores for both tests. Multi-worker should show more distributed CPU load.
        3.  Analyze Uvicorn logs for any worker-related issues.

* **ID:** PERF_APP_FASTAPI_ASYNC_HANDLING_002
    * **Category Ref:** PERF_APP_FASTAPI_CONFIG
    * **Description:** Verify efficient async request handling and absence of event loop blocking under high concurrency with I/O-bound operations (LLM calls).
    * **Exposure Point(s):** FastAPI route handlers (`async def`), provider SDK async calls (`aioboto3`, `google-cloud-aiplatform` async methods).
    * **Test Method/Action:**
        1.  Execute a load test with high concurrency (e.g., 200-500+ VUs) focused on chat and embedding endpoints which involve significant I/O wait time for provider responses.
        2.  Use prompts/models that result in varied provider response times.
    * **Prerequisites:** Multi-worker Uvicorn configuration.
    * **Expected Secure Outcome:** API maintains high throughput and low error rates. Event loop metrics (if available via monitoring) show minimal blocking time. Response latencies are primarily dictated by provider latencies, not by API framework inefficiencies.
    * **Verification Steps:**
        1.  Monitor throughput (RPS), latency, and error rates.
        2.  Check API server logs for any warnings related to event loop blocking or slow coroutines.
        3.  Profile request handling within the API if specific bottlenecks are suspected (e.g., using `cProfile` or `asyncio` debug mode locally).

* **ID:** PERF_APP_FASTAPI_TIMEOUT_CONFIG_003
    * **Category Ref:** PERF_APP_FASTAPI_CONFIG
    * **Description:** Test impact and effectiveness of FastAPI/Uvicorn level timeout configurations (e.g., request timeout) on long-running LLM requests.
    * **Exposure Point(s):** Uvicorn `--timeout-keep-alive`, `--timeout-graceful-shutdown` settings; FastAPI `Request` object's `scope['fastapi_route'].dependant.call_timeout` (if routes have custom timeouts).
    * **Test Method/Action:**
        1.  Configure a short server-level request timeout (e.g., 5 seconds).
        2.  Send an API request to an LLM that is known to take longer than this timeout (e.g., a very complex prompt or by mocking provider delay).
    * **Prerequisites:** Configurable server timeouts.
    * **Expected Secure Outcome:** The API server (Uvicorn/FastAPI) correctly terminates the request and returns an appropriate HTTP error (e.g., 504 Gateway Timeout or 503 Service Unavailable if Uvicorn handles it) if the LLM call exceeds the configured server timeout. The worker should be freed up.
    * **Verification Steps:**
        1.  Assert the HTTP status code and response indicate a timeout.
        2.  Verify the response time is close to the configured timeout value.
        3.  Check server logs for timeout messages and ensure the worker process handling the request is not stuck indefinitely.

* **ID:** PERF_APP_LIFECYCLE_STARTUP_TIME_004
    * **Category Ref:** PERF_APP_LIFECYCLE
    * **Description:** Measure application startup time, including initialization of settings, DB engine, provider clients, and background tasks.
    * **Exposure Point(s):** `app/main.py` lifespan manager, `app/config/settings.py` (get_settings), `app/db/session.py` (engine creation), provider `__init__` methods, `billing_worker` startup.
    * **Test Method/Action:** Time the duration from when the Uvicorn process starts to when the application logs "Application startup complete" (or equivalent indicating it's ready to serve requests, including health check passing).
    * **Prerequisites:** Mechanism to measure startup time accurately.
    * **Expected Secure Outcome:** Startup time is within acceptable limits (e.g., < 5-10 seconds). No errors during startup. Health check endpoint (`/health`) becomes responsive quickly and indicates readiness.
    * **Verification Steps:**
        1.  Record startup duration over multiple runs.
        2.  Check logs for any errors during initialization.
        3.  Poll health check endpoint to confirm readiness.

* **ID:** PERF_APP_LIFECYCLE_SHUTDOWN_GRACEFUL_005
    * **Category Ref:** PERF_APP_LIFECYCLE
    * **Description:** Verify graceful shutdown, including `engine.dispose()` and `drain_billing_queue()`.
    * **Exposure Point(s):** `app/main.py` lifespan manager (shutdown phase).
    * **Test Method/Action:**
        1.  Send some in-flight requests or ensure items are in `billing_queue`.
        2.  Send a SIGINT or SIGTERM signal to the Uvicorn process.
        3.  Observe shutdown logs and behavior.
    * **Prerequisites:**
    * **Expected Secure Outcome:** Application attempts to complete in-flight requests (within Uvicorn's graceful shutdown period). `engine.dispose()` is called. `drain_billing_queue()` attempts to process remaining items. Application exits cleanly without errors.
    * **Verification Steps:**
        1.  Check logs for messages indicating `engine.dispose()` and `drain_billing_queue()` execution.
        2.  Verify no data loss in billing if items were queued (requires checking where billing worker logs/persists).
        3.  Uvicorn exits with a successful status code.

---

## Enhanced Test Cases (8 Advanced Application Server Performance Scenarios)

### 6. Advanced Async Performance Optimization

* **ID:** PERF_APP_ASYNC_OPTIMIZATION_001
    * **Category Ref:** PERF_APP_ASYNC_OPTIMIZATION
    * **Description:** Optimize FastAPI async performance through event loop tuning, coroutine pool management, and async bottleneck identification.
    * **Exposure Point(s):** FastAPI async request handlers, event loop configuration, coroutine lifecycle management
    * **Test Method/Action:**
        1. Monitor event loop performance metrics under various async workload patterns
        2. Test different event loop policies and configurations
        3. Implement async request batching and pooling strategies
        4. Measure performance impact of async context switching overhead
    * **Prerequisites:** Event loop monitoring tools, async performance profiling capabilities
    * **Expected Secure Outcome:** Event loop blocking time <1ms per request. Async overhead <5% of total request time. Optimal coroutine pool utilization achieved.
    * **Verification Steps:**
        1. Monitor event loop blocking time and context switching overhead
        2. Measure async performance improvements from optimization
        3. Verify event loop stability under high async load

### 7. Middleware Performance Stack Analysis

* **ID:** PERF_APP_MIDDLEWARE_STACK_002
    * **Category Ref:** PERF_APP_MIDDLEWARE_ANALYSIS
    * **Description:** Analyze and optimize the middleware stack performance impact on request processing.
    * **Exposure Point(s):** app/logs/middleware.py, authentication middleware, CORS middleware, custom middleware stack
    * **Test Method/Action:**
        1. Profile individual middleware performance impact
        2. Test middleware execution order optimization
        3. Implement selective middleware application based on request type
        4. Measure cumulative middleware overhead
    * **Prerequisites:** Middleware profiling tools, configurable middleware stack
    * **Expected Secure Outcome:** Total middleware overhead <20ms per request. Individual middleware components optimized. Middleware execution order optimized for performance.
    * **Verification Steps:**
        1. Profile each middleware component's performance contribution
        2. Test middleware optimization effectiveness
        3. Verify minimal impact on request processing time

### 8. FastAPI Dependency Injection Optimization

* **ID:** PERF_APP_DEPENDENCY_INJECTION_003
    * **Category Ref:** PERF_APP_DEPENDENCY_OPTIMIZATION
    * **Description:** Optimize FastAPI dependency injection performance for high-frequency dependencies like database sessions and authentication.
    * **Exposure Point(s):** FastAPI dependency injection system, app/auth/dependencies.py, app/db/session.py
    * **Test Method/Action:**
        1. Profile dependency injection overhead for common dependencies
        2. Implement dependency caching strategies where appropriate
        3. Test dependency resolution performance under high concurrency
        4. Optimize dependency hierarchy and initialization patterns
    * **Prerequisites:** Dependency injection profiling, performance monitoring tools
    * **Expected Secure Outcome:** Dependency injection overhead <5ms per request. Dependency caching improves performance by 30-50%. No dependency resolution bottlenecks.
    * **Verification Steps:**
        1. Measure dependency injection performance impact
        2. Test dependency caching effectiveness
        3. Verify dependency resolution scalability

### 9. Request Routing and Path Operation Optimization

* **ID:** PERF_APP_ROUTING_OPTIMIZATION_004
    * **Category Ref:** PERF_APP_ROUTING_OPTIMIZATION
    * **Description:** Optimize FastAPI request routing and path operation matching for improved request processing speed.
    * **Exposure Point(s):** app/routers/ routing configuration, FastAPI path operation matching
    * **Test Method/Action:**
        1. Profile request routing performance for different endpoint patterns
        2. Optimize route ordering and path parameter patterns
        3. Test route caching and preprocessing strategies
        4. Measure routing overhead for complex API structures
    * **Prerequisites:** Routing performance profiling tools, configurable route structures
    * **Expected Secure Outcome:** Route matching time <1ms per request. Optimized route ordering improves performance. No routing bottlenecks under high load.
    * **Verification Steps:**
        1. Profile route matching performance across different endpoints
        2. Test route optimization strategies effectiveness
        3. Verify routing scalability under load

### 10. Memory-Efficient Request Processing

* **ID:** PERF_APP_MEMORY_EFFICIENT_PROCESSING_005
    * **Category Ref:** PERF_APP_MEMORY_EFFICIENCY
    * **Description:** Implement memory-efficient request processing patterns to minimize memory allocation and garbage collection overhead.
    * **Exposure Point(s):** Request/response object lifecycle, memory allocation patterns, garbage collection optimization
    * **Test Method/Action:**
        1. Monitor memory allocation patterns during request processing
        2. Implement object pooling for frequently used objects
        3. Optimize request/response serialization and deserialization
        4. Test memory efficiency under sustained load
    * **Prerequisites:** Memory profiling tools, object lifecycle monitoring
    * **Expected Secure Outcome:** Memory allocation per request reduced by 20-40%. Garbage collection overhead minimized. Consistent memory usage patterns.
    * **Verification Steps:**
        1. Measure memory allocation per request type
        2. Test object pooling effectiveness
        3. Monitor garbage collection impact on performance

### 11. High-Concurrency Connection Management

* **ID:** PERF_APP_CONCURRENCY_CONNECTION_006
    * **Category Ref:** PERF_APP_CONCURRENCY
    * **Description:** Optimize connection management and concurrent request handling for maximum throughput.
    * **Exposure Point(s):** Uvicorn worker configuration, connection pooling, concurrent request limits
    * **Test Method/Action:**
        1. Test various worker configurations and connection limits
        2. Implement optimal connection pooling strategies
        3. Optimize concurrent request handling patterns
        4. Test system behavior at maximum concurrency limits
    * **Prerequisites:** High-concurrency testing capabilities, connection monitoring tools
    * **Expected Secure Outcome:** Maximum concurrent connections handle efficiently. Connection overhead minimized. Optimal worker configuration identified.
    * **Verification Steps:**
        1. Test performance across different concurrency levels
        2. Verify connection pooling efficiency
        3. Monitor system stability at maximum concurrency

### 12. Application Warm-up and Cold Start Optimization

* **ID:** PERF_APP_WARMUP_COLDSTART_007
    * **Category Ref:** PERF_APP_WARMUP
    * **Description:** Optimize application startup time and implement effective warm-up strategies for consistent performance.
    * **Exposure Point(s):** Application initialization, dependency loading, provider SDK initialization
    * **Test Method/Action:**
        1. Measure cold start performance and initialization bottlenecks
        2. Implement application warm-up procedures
        3. Test pre-loading strategies for dependencies and configurations
        4. Optimize startup sequence and lazy loading patterns
    * **Prerequisites:** Startup performance monitoring, configurable initialization procedures
    * **Expected Secure Outcome:** Cold start time <30 seconds. Warm-up procedures reduce initial request latency. Consistent performance after warm-up.
    * **Verification Steps:**
        1. Measure application startup time and initialization bottlenecks
        2. Test warm-up procedure effectiveness
        3. Verify consistent performance after startup

### 13. Error Handling Performance Impact

* **ID:** PERF_APP_ERROR_HANDLING_008
    * **Category Ref:** PERF_APP_ERROR_HANDLING
    * **Description:** Analyze performance impact of error handling and exception processing in the application framework.
    * **Exposure Point(s):** FastAPI exception handlers, error logging, error response generation
    * **Test Method/Action:**
        1. Measure performance overhead of different error scenarios
        2. Optimize exception handling and error response generation
        3. Test error handling performance under high error rates
        4. Implement efficient error logging strategies
    * **Prerequisites:** Error simulation capabilities, exception monitoring tools
    * **Expected Secure Outcome:** Error handling overhead <10ms per error. Error response generation optimized. High error rates don't significantly impact overall performance.
    * **Verification Steps:**
        1. Profile error handling performance across different error types
        2. Test error handling optimization effectiveness
        3. Verify system stability during high error rate scenarios

---