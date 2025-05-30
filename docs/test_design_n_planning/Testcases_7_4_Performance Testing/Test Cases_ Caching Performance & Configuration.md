# **Test Cases: Caching Performance & Configuration (Section 7.4.10)**

This document outlines test cases for evaluating the performance and effectiveness of caching mechanisms within the API framework. This primarily focuses on the @lru\_cache for application settings (get\_settings()) and the implicit caching of provider backend instances. This is based on the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing".

**Test Cases Summary: 12 (Original: 6, Enhanced: +6)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* app/config/settings.py (@lru_cache implementation)
* app/providers/dependencies.py (provider backend caching)
* functools.lru_cache (Python caching mechanism)
* Provider backend instantiation and reuse patterns

## **General Test Case Components:**

* **ID:** Unique identifier (e.g., PERF\_CACHE\_SETTINGS\_HIT\_001)  
* **Category Ref:** (e.g., PERF\_CACHE\_SETTINGS, PERF\_CACHE\_PROVIDER\_INSTANCE)  
* **Description:** The specific aspect of caching performance or configuration being tested.  
* **Exposure Point(s):** @lru\_cache(maxsize=1) on get\_settings() in app/config/settings.py. Instantiation and reuse of provider backend objects (e.g., BedRockBackend, VertexBackend) as managed by get\_provider\_client in app/providers/dependencies.py.  
* **Test Method/Action:** Specific API request patterns or micro-benchmarks to measure cache effectiveness (hit rate, latency reduction) and overhead.  
* **Prerequisites:** Performance testing environment. Profiling tools (e.g., cProfile, py-spy, Jaeger) or precise timing mechanisms.  
* **Expected Secure Outcome:** Caching mechanisms provide measurable performance benefits (reduced latency for repeated lookups/initializations). Cache overhead is minimal. Cache behaves correctly regarding hit/miss logic and intended scope (e.g., settings are loaded once per process). Provider clients are instantiated once per GSAI model ID and reused.  
* **Verification Steps:** Analysis of profiling data, cache hit/miss statistics (if available from @lru\_cache.cache\_info()), object ID comparison for provider instances.

### **1\. Application Settings Cache (get\_settings())**

* **ID:** PERF\_CACHE\_SETTINGS\_FIRST\_CALL\_LATENCY\_001  
  * **Category Ref:** PERF\_CACHE\_SETTINGS  
  * **Description:** Measure the latency of the first call to get\_settings(), which involves loading and validating settings from environment variables and potentially .env files.  
  * **Exposure Point(s):** get\_settings() function in app/config/settings.py before @lru\_cache populates. Settings Pydantic model instantiation and validation.  
  * **Test Method/Action:**  
    1. In a controlled environment (e.g., a unit test or a script that imports and calls get\_settings() for the first time in a process), precisely time the execution of the first call to get\_settings().  
    2. This can be done using time.perf\_counter() before and after the call, or with profiling tools.  
  * **Prerequisites:** Clean process environment for each run to ensure it's truly the first call.  
  * **Expected Secure Outcome:** The first call latency is reasonable (e.g., \< 50-100ms, depending on number of settings and complexity of validation). This establishes the cost that caching avoids on subsequent calls.  
  * **Verification Steps:** Record and average the first-call latency over several runs.  
* **ID:** PERF\_CACHE\_SETTINGS\_SUBSEQUENT\_CALL\_LATENCY\_002  
  * **Category Ref:** PERF\_CACHE\_SETTINGS  
  * **Description:** Measure the latency of subsequent calls to get\_settings() to verify the effectiveness of @lru\_cache.  
  * **Exposure Point(s):** @lru\_cache(maxsize=1) on get\_settings().  
  * **Test Method/Action:**  
    1. In a controlled environment, call get\_settings() once to populate the cache.  
    2. Precisely time the execution of several subsequent calls to get\_settings().  
    3. Check get\_settings.cache\_info() to verify hits.  
  * **Prerequisites:**  
  * **Expected Secure Outcome:** Latency of subsequent calls should be extremely low (microseconds, near the overhead of a dictionary lookup and function call), demonstrating a high cache hit rate. cache\_info() should show hits increasing and misses remaining at 1 (or 0 after clear).  
  * **Verification Steps:** Record and average subsequent-call latency. Verify it's significantly lower than first-call latency. Check get\_settings.cache\_info().hits.  
* **ID:** PERF\_CACHE\_SETTINGS\_LOAD\_IMPACT\_003  
  * **Category Ref:** PERF\_CACHE\_SETTINGS  
  * **Description:** Verify that get\_settings() being called in multiple concurrent requests (as it's a dependency for get\_model\_config\_validated) does not introduce contention or significant overhead due to the cache lookup.  
  * **Exposure Point(s):** get\_settings() called via Depends(get\_settings) or indirectly. @lru\_cache thread safety (Python's functools.lru\_cache is thread-safe).  
  * **Test Method/Action:**  
    1. Run a load test targeting endpoints that use get\_model\_config\_validated (which depends on get\_settings), such as /chat/completions or /embeddings.  
    2. Use a profiler (like py-spy or Jaeger traces if get\_settings calls are instrumented as spans) to observe the cumulative time spent in get\_settings() across many requests.  
  * **Prerequisites:** Load testing tools. Profiling tools.  
  * **Expected Secure Outcome:** The time spent per request within get\_settings() (after the initial call) should be negligible. The @lru\_cache mechanism should not become a bottleneck under concurrent access.  
  * **Verification Steps:** Analyze profiling data. Total time in get\_settings should be very small relative to overall request processing or I/O times.

### **2\. Provider Backend Instance Caching/Re-use (Implicit via get\_provider\_client)**

* **ID:** PERF\_CACHE\_PROVIDER\_INSTANCE\_REUSE\_001  
  * **Category Ref:** PERF\_CACHE\_PROVIDER\_INSTANCE  
  * **Description:** Verify that provider backend instances (e.g., BedRockBackend, VertexBackend) are instantiated once per unique GSAI model ID configuration and reused across multiple requests for that same model ID.  
  * **Exposure Point(s):** get\_provider\_client(model\_config: ModelConfig \= Depends(get\_model\_config\_validated)) in app/providers/dependencies.py. The model\_backends\_cache dictionary.  
  * **Test Method/Action:**  
    1. In a test environment, add print statements or simple logging within the \_\_init\_\_ methods of BedRockBackend, VertexBackend, etc., and within get\_provider\_client when a new instance is created versus retrieved from model\_backends\_cache.  
    2. Send multiple (e.g., 5-10) sequential API requests to an endpoint (e.g., /chat/completions) using the *same* model ID (e.g., "claude\_3\_5\_sonnet").  
    3. Observe the logs/print statements.  
    4. Then, send requests using a *different* model ID that maps to the same provider type but potentially different underlying model details (e.g., another Bedrock model "titan\_image\_generator"). Observe logs.  
    5. Then, send requests using a model ID that maps to a *different provider type* (e.g., "gemini-2.0-flash" for Vertex AI). Observe logs.  
  * **Prerequisites:** Ability to add temporary logging/prints or use a debugger.  
  * **Expected Secure Outcome:**  
    * For the first request to a specific GSAI model ID (e.g., "claude\_3\_5\_sonnet"), the corresponding provider backend (e.g., BedRockBackend) \_\_init\_\_ is called once, and get\_provider\_client logs a "cache miss" and creation.  
    * Subsequent requests for the *same* GSAI model ID ("claude\_3\_5\_sonnet") should *not* trigger \_\_init\_\_ again for that specific configuration; get\_provider\_client should log a "cache hit" from model\_backends\_cache. The same instance object ID should be returned.  
    * A request for a *different* GSAI model ID that maps to the *same provider type* (e.g., another Bedrock model) will result in a new entry in model\_backends\_cache if its ModelConfig is different (e.g., different actual\_model\_id or region\_name), leading to another \_\_init\_\_ and "cache miss" for that new config.  
    * A request for a model ID mapping to a *different provider type* (e.g., Vertex AI) will also result in its own \_\_init\_\_ and "cache miss" for that provider type and config.  
  * **Verification Steps:**  
    1. Analyze logs for \_\_init\_\_ calls and "cache hit/miss" messages from get\_provider\_client.  
    2. Verify that for a given, identical ModelConfig (derived from GSAI model ID), the provider client object ID logged by get\_provider\_client is the same across multiple requests.  
* **ID:** PERF\_CACHE\_PROVIDER\_INSTANCE\_INIT\_LATENCY\_002  
  * **Category Ref:** PERF\_CACHE\_PROVIDER\_INSTANCE  
  * **Description:** Measure the latency of instantiating provider backend clients (e.g., BedRockBackend(), VertexBackend()), as this happens on the first request for a given model configuration.  
  * **Exposure Point(s):** \_\_init\_\_ methods of provider backends, which may initialize SDK clients (e.g., boto3.Session().client('bedrock-runtime'), VertexAIModelGardenServiceClient()).  
  * **Test Method/Action:**  
    1. Similar to PERF\_CACHE\_SETTINGS\_FIRST\_CALL\_LATENCY\_001, precisely time the execution of get\_provider\_client for a model ID configuration that has not been accessed yet in the process. This timing should capture the BackendClass(model\_config=model\_config) instantiation.  
    2. Repeat for each provider type (Bedrock, Vertex, etc.) to understand their respective client initialization costs.  
  * **Prerequisites:** Clean process/cache for each first call measurement. Precise timing.  
  * **Expected Secure Outcome:** The initialization latency for each provider client is reasonable (e.g., potentially tens to a few hundreds of milliseconds, as SDKs might do some initial setup or credential loading). This cost is incurred only once per unique model configuration per API server process.  
  * **Verification Steps:** Record and average the first-call instantiation latency for each provider type.

---

## Enhanced Test Cases (6 Advanced Caching Performance Scenarios)

### 3. Multi-Level Cache Hierarchy Optimization

* **ID:** PERF_CACHE_MULTI_LEVEL_HIERARCHY_001
    * **Category Ref:** PERF_CACHE_HIERARCHY
    * **Description:** Implement and test multi-level caching hierarchy for optimal performance across different data types and access patterns.
    * **Exposure Point(s):** L1 cache (in-memory), L2 cache (Redis/external), configuration caching, response caching
    * **Test Method/Action:**
        1. Implement tiered caching strategy with in-memory and external cache layers
        2. Test cache hit ratios and performance across different cache levels
        3. Optimize cache eviction policies and TTL strategies
        4. Measure cache coherency and consistency across levels
    * **Prerequisites:** Redis or external cache infrastructure, cache monitoring tools
    * **Expected Secure Outcome:** Multi-level caching improves hit ratios by 40-60%. Cache access latency optimized per level. Cache coherency maintained across tiers.
    * **Verification Steps:**
        1. Monitor cache hit ratios and access patterns across cache levels
        2. Test cache coherency during updates and invalidations
        3. Measure performance improvements from multi-level strategy

### 4. Adaptive Cache Size and TTL Management

* **ID:** PERF_CACHE_ADAPTIVE_MANAGEMENT_002
    * **Category Ref:** PERF_CACHE_ADAPTIVE
    * **Description:** Implement adaptive cache management that dynamically adjusts cache sizes and TTL based on usage patterns and system load.
    * **Exposure Point(s):** Dynamic cache sizing algorithms, TTL optimization, memory pressure awareness
    * **Test Method/Action:**
        1. Monitor cache usage patterns and hit/miss ratios over time
        2. Implement dynamic cache sizing based on available memory and access patterns
        3. Test adaptive TTL strategies based on data volatility
        4. Measure cache efficiency improvements from adaptive management
    * **Prerequisites:** Memory monitoring, cache usage analytics, adaptive algorithms
    * **Expected Secure Outcome:** Adaptive management improves cache efficiency by 25-40%. Memory usage optimized based on system load. TTL strategies reduce stale data while maintaining performance.
    * **Verification Steps:**
        1. Monitor cache efficiency metrics before and after adaptive management
        2. Test cache behavior under varying system load conditions
        3. Verify optimal memory utilization and hit ratio improvements

### 5. Cache Warming and Preloading Strategies

* **ID:** PERF_CACHE_WARMING_PRELOADING_003
    * **Category Ref:** PERF_CACHE_WARMING
    * **Description:** Implement intelligent cache warming and preloading strategies to minimize cold cache performance impact.
    * **Exposure Point(s):** Application startup cache warming, predictive preloading, background cache refresh
    * **Test Method/Action:**
        1. Implement cache warming procedures during application startup
        2. Test predictive preloading based on usage patterns
        3. Implement background cache refresh for frequently accessed data
        4. Measure cache warm-up time and effectiveness
    * **Prerequisites:** Usage pattern analysis, background task scheduling, cache preloading mechanisms
    * **Expected Secure Outcome:** Cache warming reduces cold start latency by 60-80%. Predictive preloading improves hit ratios by 20-30%. Background refresh maintains cache freshness.
    * **Verification Steps:**
        1. Measure application performance improvements from cache warming
        2. Test predictive preloading accuracy and effectiveness
        3. Monitor cache freshness and background refresh performance

### 6. Cache Performance Under High Concurrency

* **ID:** PERF_CACHE_HIGH_CONCURRENCY_004
    * **Category Ref:** PERF_CACHE_CONCURRENCY
    * **Description:** Test caching performance and thread safety under high concurrent access patterns.
    * **Exposure Point(s):** Concurrent cache access, lock contention, cache consistency under load
    * **Test Method/Action:**
        1. Generate high concurrent access to cached data
        2. Monitor cache performance under various concurrency levels
        3. Test cache consistency and thread safety mechanisms
        4. Measure cache overhead and latency under concurrent load
    * **Prerequisites:** High-concurrency testing tools, cache performance monitoring
    * **Expected Secure Outcome:** Cache maintains performance under high concurrency. No data corruption or inconsistency. Cache access latency remains stable under load.
    * **Verification Steps:**
        1. Monitor cache performance metrics under increasing concurrency
        2. Verify cache data consistency across concurrent operations
        3. Test cache behavior at maximum concurrent access levels

### 7. Cache Invalidation and Refresh Performance

* **ID:** PERF_CACHE_INVALIDATION_REFRESH_005
    * **Category Ref:** PERF_CACHE_INVALIDATION
    * **Description:** Optimize cache invalidation and refresh strategies for minimal performance impact and maximum data freshness.
    * **Exposure Point(s):** Cache invalidation mechanisms, refresh strategies, data consistency
    * **Test Method/Action:**
        1. Test various cache invalidation strategies (time-based, event-based, manual)
        2. Implement efficient cache refresh mechanisms
        3. Measure invalidation overhead and refresh performance
        4. Test cache consistency during invalidation and refresh cycles
    * **Prerequisites:** Cache invalidation tools, refresh mechanism implementation
    * **Expected Secure Outcome:** Cache invalidation overhead <5ms per operation. Refresh strategies maintain data freshness. Consistency preserved during cache updates.
    * **Verification Steps:**
        1. Measure cache invalidation and refresh performance
        2. Test data consistency during cache update operations
        3. Verify optimal balance between freshness and performance

### 8. Cache Monitoring and Analytics Integration

* **ID:** PERF_CACHE_MONITORING_ANALYTICS_006
    * **Category Ref:** PERF_CACHE_MONITORING
    * **Description:** Implement comprehensive cache monitoring and analytics for performance optimization and troubleshooting.
    * **Exposure Point(s):** Cache metrics collection, performance analytics, alerting systems
    * **Test Method/Action:**
        1. Implement detailed cache metrics collection (hit ratios, latency, memory usage)
        2. Develop cache performance analytics and visualization
        3. Test cache alerting and anomaly detection systems
        4. Validate cache performance insights and optimization recommendations
    * **Prerequisites:** Monitoring infrastructure, analytics tools, alerting systems
    * **Expected Secure Outcome:** Comprehensive cache visibility achieved. Performance analytics provide actionable insights. Alerting systems detect cache issues within 5 minutes.
    * **Verification Steps:**
        1. Validate cache metrics accuracy and completeness
        2. Test analytics and visualization effectiveness
        3. Verify alerting system responsiveness and accuracy

---