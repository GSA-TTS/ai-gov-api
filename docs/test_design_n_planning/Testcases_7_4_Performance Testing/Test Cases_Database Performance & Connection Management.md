# Test Cases: Database Performance & Connection Management

This document outlines test cases for evaluating database connection pooling, query performance, and session management, particularly as they affect authentication, billing, and user operations related to LLM API access. This is based on the "Risk Surface Analysis for Test Plan Section 7.4: Performance Testing".

**Test Cases Summary: 14 (Original: 8, Enhanced: +6)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.4.md
* app/db/session.py (SQLAlchemy connection pool management)
* app/auth/repositories.py (APIKeyRepository database queries)
* app/users/repositories.py (UserRepository database operations)
* app/auth/dependencies.py (authentication database dependencies)
* SQLAlchemy, PostgreSQL (database technology stack)

## General Test Case Components:
* **ID:** Unique identifier (e.g., PERF_DB_POOL_001)
* **Category Ref:** (e.g., PERF_DB_POOL, PERF_DB_QUERY, PERF_DB_SESSION, PERF_DB_CONFIG)
* **Description:** The specific aspect of database performance or connection management being tested.
* **Exposure Point(s):** SQLAlchemy connection pool (`app/db/session.py`), `APIKeyRepository` and `UserRepository` queries, FastAPI dependency injection of DB sessions.
* **Test Method/Action:** Specific API request patterns or load scenarios designed to stress database interactions.
* **Prerequisites:** Performance testing environment with a production-like PostgreSQL setup. Monitoring tools for database performance (e.g., `pg_stat_activity`, `pg_stat_statements`, Prometheus with PostgreSQL exporter). Valid API keys.
* **Expected Secure Outcome:** Efficient connection pool usage, fast query execution, stable database performance under load, minimal impact on overall API latency from database operations.
* **Verification Steps:** Analysis of database metrics (active connections, query latencies, CPU/memory usage, lock contention), API response times, and error rates.

---

### 1\. Connection Pool Management

* **ID:** PERF_DB_POOL_EXHAUSTION_001
    * **Category Ref:** PERF_DB_POOL
    * **Description:** Test behavior when the number of concurrent API requests requiring database access approaches and potentially exceeds the configured connection pool size.
    * **Exposure Point(s):** SQLAlchemy `create_async_engine` pool settings (e.g., `pool_size`, `max_overflow` if configured, though defaults are often used by `async_sessionmaker`). `get_db_session` dependency.
    * **Test Method/Action:**
        1.  Determine the effective connection pool size (FastAPI default with `async_sessionmaker` might be around 5-10, plus overflow if any).
        2.  Generate a high number of concurrent API requests that all perform database lookups (e.g., any authenticated endpoint like `/models` or `/chat/completions`). The concurrency should significantly exceed the pool size (e.g., 50-100 VUs if pool size is 10).
        3.  Sustain this load for a few minutes.
    * **Prerequisites:** Load testing tool.
    * **Expected Secure Outcome:**
        * Requests are queued by the connection pool or FastAPI if connections are unavailable, leading to increased latency but not immediate errors for all exceeding requests.
        * API should not crash.
        * A small percentage of requests might time out (HTTP 503 or 504) if they wait too long for a connection, but most should eventually succeed.
        * The database server itself remains stable.
    * **Verification Steps:**
        1.  Monitor API response times (expect increased p95/p99).
        2.  Monitor API error rates (expect some timeouts if load is excessive).
        3.  Monitor active connections on the PostgreSQL server (`SELECT count(*) FROM pg_stat_activity WHERE state = 'active';`). This should not exceed pool size + overflow by too much (some connections might be idle in transaction).
        4.  Check API server logs for connection pool timeout errors (e.g., from SQLAlchemy or `asyncpg`).

* **ID:** PERF_DB_POOL_RECOVERY_002
    * **Category Ref:** PERF_DB_POOL
    * **Description:** Verify the connection pool recovers correctly after a period of high demand or transient database connectivity issues.
    * **Exposure Point(s):** Connection pool health and recovery mechanisms.
    * **Test Method/Action:**
        1.  Induce connection pool stress as in PERF_DB_POOL_EXHAUSTION_001.
        2.  Reduce the load back to normal.
        3.  (Alternatively) Briefly simulate database unavailability or network partition, then restore connectivity.
    * **Prerequisites:**
    * **Expected Secure Outcome:** The connection pool returns to a healthy state. API response times and error rates return to baseline levels. No orphaned/stuck connections.
    * **Verification Steps:**
        1.  Monitor API performance metrics as load is reduced or DB connectivity is restored.
        2.  Check `pg_stat_activity` for stale or errored connections.
        3.  Ensure new requests are processed successfully with normal latency.

---

### 2\. Query Performance

* **ID:** PERF_DB_QUERY_AUTH_KEY_LOOKUP_001
    * **Category Ref:** PERF_DB_QUERY
    * **Description:** Measure the performance of API key lookup queries (`APIKeyRepository.get_by_api_key_value`) under load.
    * **Exposure Point(s):** `APIKeyRepository.get_by_api_key_value` method, `api_keys` table index on `hashed_key`.
    * **Test Method/Action:**
        1.  Populate the `api_keys` table with a significant number of keys (e.g., 10,000-100,000).
        2.  Send a high volume of authenticated requests using various valid API keys.
        3.  Use database query monitoring tools (e.g., `pg_stat_statements` extension in PostgreSQL, or application-level timing) to measure the average execution time of the `SELECT ... FROM api_keys WHERE hashed_key = ...` query.
    * **Prerequisites:** Populated database. DB query monitoring enabled.
    * **Expected Secure Outcome:** Average API key lookup query time remains very low (e.g., < 1-2ms) even under load, indicating effective indexing on `hashed_key`.
    * **Verification Steps:**
        1.  Analyze query execution times from `pg_stat_statements`.
        2.  Ensure the query plan shows index usage on `ix_api_keys_hashed_key`.

* **ID:** PERF_DB_QUERY_BILLING_WRITE_002 (Conceptual, as it's async)
    * **Category Ref:** PERF_DB_QUERY
    * **Description:** Assess the performance impact of billing data writes on the database if the `billing_worker` performs direct DB inserts/updates.
    * **Exposure Point(s):** `billing_worker`'s database interaction logic (if it writes to a DB table directly rather than just logging).
    * **Test Method/Action:**
        1.  Generate a high rate of billable API events (chat/embeddings).
        2.  Monitor database write performance (IOPS, write latency, lock contention) on tables related to billing.
    * **Prerequisites:** Billing worker implemented to write to DB. DB performance monitoring.
    * **Expected Secure Outcome:** Billing writes are efficient and do not cause significant contention or performance degradation for other database operations (like auth lookups).
    * **Verification Steps:** Monitor DB write metrics. Check for long-running transactions or lock waits related to billing tables.

---

### 3\. Session Lifecycle and Transaction Overhead

* **ID:** PERF_DB_SESSION_OVERHEAD_001
    * **Category Ref:** PERF_DB_SESSION
    * **Description:** Measure the overhead associated with creating and closing SQLAlchemy async sessions for each request.
    * **Exposure Point(s):** `get_db_session` dependency, SQLAlchemy `AsyncSession` lifecycle.
    * **Test Method/Action:**
        1.  Profile a simple authenticated API request (e.g., `/models`) that primarily involves an API key lookup.
        2.  Isolate the time spent specifically within the `get_db_session` context manager (session creation, yield, session close).
    * **Prerequisites:** Profiling tools (e.g., `cProfile`, or custom timing decorators).
    * **Expected Secure Outcome:** The overhead of session management per request is minimal (e.g., a few milliseconds).
    * **Verification Steps:** Analyze profiling data to quantify session management overhead.

---

### 4\. Database Configuration Impact

* **ID:** PERF_DB_CONFIG_ECHO_LOGGING_001
    * **Category Ref:** PERF_DB_CONFIG
    * **Description:** Evaluate the performance impact of SQLAlchemy's `echo=True` (SQL query logging) setting.
    * **Exposure Point(s):** `database_echo` setting in `app/config/settings.py`, SQLAlchemy engine configuration.
    * **Test Method/Action:**
        1.  Run a baseline load test with `database_echo = False`.
        2.  Run the same load test with `database_echo = True`.
    * **Prerequisites:** Ability to change `database_echo` setting. Load testing tools.
    * **Expected Secure Outcome:** `database_echo = True` should significantly degrade performance (increased latency, reduced throughput) due to I/O for logging. This test confirms it's off for performance-critical environments.
    * **Verification Steps:**
        1.  Compare RPS, latency, and API server CPU/IO between the two runs.
        2.  Confirm that `database_echo` is `False` in production-like configurations.

---

## Enhanced Test Cases (6 Advanced Database Performance Scenarios)

### 5. Database Resilience and Failover Testing

* **ID:** PERF_DB_RESILIENCE_FAILOVER_001
    * **Category Ref:** PERF_DB_RESILIENCE
    * **Description:** Test database connection resilience and automatic recovery during database connectivity issues.
    * **Exposure Point(s):** app/db/session.py (connection pool resilience), SQLAlchemy connection retry logic, database failover mechanisms
    * **Test Method/Action:**
        1. Establish baseline performance with stable database connection
        2. Simulate database connectivity issues (network latency, brief outages)
        3. Measure connection pool recovery time and request success rates
        4. Test automatic reconnection and connection pool health recovery
    * **Prerequisites:** Database failover simulation capabilities, connection monitoring tools
    * **Expected Secure Outcome:** Connection pool recovers within 30 seconds of connectivity restoration. Request success rate returns to >99% within 60 seconds. No permanent connection leaks during recovery.
    * **Verification Steps:**
        1. Monitor connection pool status during simulated outages
        2. Measure recovery time to baseline performance
        3. Verify connection pool health after recovery

### 6. Database Query Optimization and Indexing

* **ID:** PERF_DB_QUERY_OPTIMIZATION_002
    * **Category Ref:** PERF_DB_OPTIMIZATION
    * **Description:** Analyze and optimize database query performance through indexing and query plan optimization.
    * **Exposure Point(s):** app/auth/repositories.py (API key queries), app/users/repositories.py (user queries), database indexing strategy
    * **Test Method/Action:**
        1. Analyze current query execution plans for authentication and user operations
        2. Implement optimized indexes for frequently accessed columns
        3. Test query performance improvements under various load scenarios
        4. Measure impact on overall API response times
    * **Prerequisites:** Database performance monitoring, query analysis tools, index management capabilities
    * **Expected Secure Outcome:** Query execution time improves by 50-80% for indexed operations. Overall API latency decreases. Database CPU utilization decreases under load.
    * **Verification Steps:**
        1. Compare query execution plans before and after optimization
        2. Measure query response time improvements
        3. Monitor database resource utilization changes

### 7. Connection Pool Burst Handling

* **ID:** PERF_DB_CONNECTION_BURST_003
    * **Category Ref:** PERF_DB_BURST_HANDLING
    * **Description:** Test connection pool behavior during sudden bursts of database-intensive requests.
    * **Exposure Point(s):** SQLAlchemy connection pool configuration, concurrent database session management
    * **Test Method/Action:**
        1. Configure connection pool with realistic limits (max_connections, pool_size)
        2. Generate sudden bursts of database-heavy requests (authentication lookups)
        3. Monitor connection pool utilization and queue behavior
        4. Test pool overflow handling and connection creation dynamics
    * **Prerequisites:** Configurable connection pool parameters, burst load generation capabilities
    * **Expected Secure Outcome:** Connection pool handles bursts without exhaustion. Queue wait times remain <100ms. Pool efficiently scales up and down with demand.
    * **Verification Steps:**
        1. Monitor connection pool metrics during burst scenarios
        2. Measure connection wait times and pool utilization
        3. Verify pool scaling behavior and efficiency

### 8. Database Transaction Performance Under Load

* **ID:** PERF_DB_TRANSACTION_PERFORMANCE_004
    * **Category Ref:** PERF_DB_TRANSACTION
    * **Description:** Evaluate database transaction performance and isolation behavior under concurrent load.
    * **Exposure Point(s):** Database transaction management, concurrent transaction handling, isolation levels
    * **Test Method/Action:**
        1. Generate concurrent database transactions (user operations, API key updates)
        2. Monitor transaction commit times and lock contention
        3. Test various isolation levels and their performance impact
        4. Measure deadlock frequency and resolution time
    * **Prerequisites:** Transaction monitoring tools, ability to generate concurrent database operations
    * **Expected Secure Outcome:** Transaction commit times remain <50ms under normal load. Deadlock frequency <0.1%. Lock contention doesn't significantly impact performance.
    * **Verification Steps:**
        1. Monitor transaction metrics and commit times
        2. Analyze lock contention and deadlock patterns
        3. Test performance across different isolation levels

### 9. Database Backup and Maintenance Impact

* **ID:** PERF_DB_BACKUP_MAINTENANCE_005
    * **Category Ref:** PERF_DB_MAINTENANCE
    * **Description:** Test API performance impact during database backup and maintenance operations.
    * **Exposure Point(s):** Database backup processes, maintenance operations, online schema changes
    * **Test Method/Action:**
        1. Establish baseline API performance metrics
        2. Execute database backup operations during normal API load
        3. Test online maintenance operations (VACUUM, ANALYZE, index rebuilds)
        4. Measure API performance degradation during maintenance windows
    * **Prerequisites:** Database backup and maintenance tools, performance monitoring during maintenance
    * **Expected Secure Outcome:** API performance degradation <20% during backup operations. Maintenance operations complete without causing request timeouts. Database remains responsive throughout.
    * **Verification Steps:**
        1. Monitor API latency during backup operations
        2. Measure database responsiveness during maintenance
        3. Verify minimal impact on user experience

### 10. Database Scaling and Capacity Planning

* **ID:** PERF_DB_SCALING_CAPACITY_006
    * **Category Ref:** PERF_DB_SCALING
    * **Description:** Evaluate database scaling behavior and capacity planning for future growth.
    * **Exposure Point(s):** Database capacity limits, scaling mechanisms, performance degradation patterns
    * **Test Method/Action:**
        1. Gradually increase database load to identify capacity limits
        2. Monitor database performance degradation patterns
        3. Test vertical and horizontal scaling options if available
        4. Develop capacity planning models based on observed patterns
    * **Prerequisites:** Scalable database infrastructure, capacity monitoring tools, load generation capabilities
    * **Expected Secure Outcome:** Database capacity limits clearly identified. Scaling mechanisms work effectively. Performance degradation is predictable and manageable.
    * **Verification Steps:**
        1. Document database capacity limits and bottlenecks
        2. Test scaling mechanism effectiveness
        3. Validate capacity planning models against observed behavior

---

---