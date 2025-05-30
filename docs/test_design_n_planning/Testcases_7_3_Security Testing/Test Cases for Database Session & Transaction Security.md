# **Test Cases for Database Session & Transaction Security**

## **Introduction**

This document outlines test cases for **Database Session Security & Transaction Integrity** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md" (Section 3). These tests focus on the security and reliability of database interactions, especially concerning authentication, authorization, and billing data which are critical for controlling and tracking LLM API usage.  
**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 3\. Session Management & Database Security)  
* app/db/session.py (SQLAlchemy async session management)  
* app/auth/repositories.py (APIKey repository, database queries)  
* app/users/repositories.py (User repository)  
* app/services/billing.py (Interaction with database for billing, if any beyond queue)  
* app/auth/models.py, app/users/models.py (Database models)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** DB \- Session & Transaction Security  
* **Description:** What specific database security or integrity aspect is being tested.  
* **Exposure Point(s):** Database connection logic, session handling in get\_db\_session, repository query methods, transaction management (session.commit, session.rollback).  
* **Test Method/Action:** Simulate database errors, concurrent access, or malformed data affecting DB operations.  
* **Prerequisites:** API running with database connection. May require ability to mock database responses or induce specific DB error conditions.  
* **Expected Secure Outcome:** Database operations are secure, transactions maintain ACID properties, and errors are handled gracefully without data corruption, security bypasses, or info leakage.  
* **Verification Steps:** Check API responses, server logs, and database state.

## **Test Cases**

### **Session Security & Management**

* **ID:** DBSEC\_SESSION\_HIJACK\_001 (Conceptual/Difficult to test at API level)  
  * **Category Ref:** DB \- Session & Transaction Security  
  * **Description:** Attempt to test for database connection/session hijacking vulnerabilities.  
  * **Exposure Point(s):** app/db/session.py connection handling, FastAPI dependency injection of sessions.  
  * **Test Method/Action:** This is very hard to test directly via API calls. It would involve attempting to interfere with or reuse database sessions across different requests or users if the session management were flawed.  
  * **Prerequisites:** Deep understanding of async session management in FastAPI and SQLAlchemy.  
  * **Expected Secure Outcome:** Each API request gets its own isolated database session as managed by get\_db\_session. No session data or state bleeds between concurrent requests or different users.  
  * **Verification Steps:** Primarily code review of get\_db\_session to ensure new sessions are created per request and properly closed. Load testing might reveal issues if sessions are not closed, leading to connection pool exhaustion.  
* **ID:** DBSEC\_CONN\_POOL\_EXHAUST\_001  
  * **Category Ref:** DB \- Session & Transaction Security  
  * **Description:** Test behavior when the database connection pool is exhausted during high LLM API usage.  
  * **Exposure Point(s):** SQLAlchemy connection pool configured in app/db/session.py:9-10 (create_async_engine), async_sessionmaker at lines 18-20, get_db_session dependency at lines 23-32.  
  * **Test Method/Action:** Simulate high concurrent API requests that all require database access (e.g., for API key validation). This might require a load testing tool.  
  * **Prerequisites:** API running. Ability to generate high concurrent load.  
  * **Expected Secure Outcome:** The API should handle connection pool exhaustion gracefully. Requests that cannot obtain a DB connection should fail with an appropriate error (e.g., 503 Service Unavailable). The system should recover once load decreases or connections become available. It should not lead to persistent deadlocks or crashes.  
  * **Verification Steps:**  
    1. Under high load, observe API responses for 503 errors or increased latency.  
    2. Check server logs for connection pool timeout errors.  
    3. Verify the system recovers after the load subsides.  
  * **Code Reference:** Database engine creation in app/db/session.py:9-10, session factory in lines 18-20, session lifecycle management in get_db_session at lines 23-32.

### **Transaction Integrity**

* **ID:** DBSEC\_TXN\_AUTH\_ROLLBACK\_001  
  * **Category Ref:** DB \- Session & Transaction Security  
  * **Description:** Verify that if an error occurs during API key validation after some DB reads but before a (hypothetical) write, the transaction is rolled back.  
  * **Exposure Point(s):** APIKeyRepository methods, get_db_session's try/except/finally block at app/db/session.py:26-32, session.rollback() at line 29.  
  * **Test Method/Action:**  
    1. Mock a method within APIKeyRepository.get_by_api_key_value (after an initial successful read, if any) to raise an exception.  
    2. Make an API request that triggers this path.  
  * **Prerequisites:** Mocking capability.  
  * **Expected Secure Outcome:** The database session is rolled back by get_db_session. No partial changes are committed. Subsequent requests operate on a clean session.  
  * **Verification Steps:** Check server logs for rollback messages (if any). Verify database state is consistent (no partial updates).  
  * **Code Reference:** Session error handling in app/db/session.py:26-32, rollback operation at line 29, APIKeyRepository in app/auth/repositories.py.  
* **ID:** DBSEC\_TXN\_BILLING\_CONCURRENCY\_001  
  * **Category Ref:** DB \- Session & Transaction Security  
  * **Description:** Test for race conditions if billing data were written directly to the DB by concurrent LLM requests (current design uses an async queue, which mitigates this at the DB write stage if the worker is single-threaded or handles DB ops carefully).  
  * **Exposure Point(s):** app/services/billing.py's billing\_worker if it performs database writes.  
  * **Test Method/Action:** Send many concurrent LLM requests that generate billing events.  
  * **Prerequisites:** API running.  
  * **Expected Secure Outcome:** Billing data in the database (if written directly and not just logged from queue) should be consistent and accurate, with no lost updates or race conditions. The async queue design helps serialize writes if the worker processes items one by one.  
  * **Verification Steps:** Inspect billing data for accuracy and completeness after a burst of concurrent requests.  
* **ID:** DBSEC\_TXN\_USER\_CREATE\_UNIQUE\_001  
  * **Category Ref:** DB \- Session & Transaction Security  
  * **Description:** Test enforcement of unique constraints (e.g., user email) during concurrent user creation attempts (admin function).  
  * **Exposure Point(s):** UserRepository.create in app/users/repositories.py:12-20, User.email unique constraint in app/users/models.py:13, DuplicateResourceError at app/users/repositories.py:14-16.  
  * **Test Method/Action:** Attempt to create two users with the same email address concurrently via the /users/create admin endpoint.  
  * **Prerequisites:** Admin API key.  
  * **Expected Secure Outcome:** One creation should succeed, the other should fail due to the unique constraint, raising an IntegrityError caught by db_integrity_exception_handler in app/main.py, resulting in a 400 or 409 error. No duplicate user created.  
  * **Verification Steps:**  
    1. Verify HTTP status codes (one 20x, one 400/409).  
    2. Check database to ensure only one user with that email exists.  
  * **Code Reference:** UserRepository.create in app/users/repositories.py:12-20, duplicate check at lines 14-16, User.email unique constraint.

### **Data Integrity & SQL Injection**

* **ID:** DBSEC\_SQLI\_APIKEY\_LOOKUP\_001  
  * **Category Ref:** DB \- Session & Transaction Security  
  * **Description:** Attempt SQL injection via the API key string during authentication.  
  * **Exposure Point(s):** APIKeyRepository.get_by_api_key_value at app/auth/repositories.py:32-39, hashed key generation at lines 34-35, SQLAlchemy query at lines 36-38.  
  * **Test Method/Action:** Send an API key in the Authorization: Bearer \<key\> header that contains SQL injection payloads (e.g., test\_prefix\_'; SELECT pg\_sleep(10); \--).  
  * **Prerequisites:** API running.  
  * **Expected Secure Outcome:** The input API key is treated as a literal string, hashed, and then used in a parameterized query (SQLAlchemy default). The SQL injection payload should not be executed. The request should fail with 401 Unauthorized ("Missing or invalid API key") because the hashed malicious string won't match any valid hashed key. No database errors or unexpected delays (like pg\_sleep) should occur.  
  * **Verification Steps:**  
    1. Verify HTTP status code is 401\.  
    2. Confirm no SQL errors in server logs.  
    3. Confirm no unexpected database behavior (like a 10-second sleep).  
  * **Code Reference:** APIKeyRepository.get_by_api_key_value in app/auth/repositories.py:32-39, SHA256 hashing at lines 34-35, parameterized query at lines 36-38.  
* **ID:** DBSEC\_SQLI\_USER\_EMAIL\_PARAM\_001  
  * **Category Ref:** DB \- Session & Transaction Security  
  * **Description:** Attempt SQL injection via email parameter in admin user lookup (/users/{email}).  
  * **Exposure Point(s):** UserRepository.get_by_email in app/users/repositories.py:31-38, SQLAlchemy query with User.email filter at lines 33-35.  
  * **Test Method/Action:** Make a GET request to /users/admin'%3B%20SELECT%20pg\_sleep(10)%3B%20--%40example.com (URL encoded SQLi).  
  * **Prerequisites:** Admin API key.  
  * **Expected Secure Outcome:** SQLAlchemy uses parameterized queries, so the injection should fail or be treated as part of the literal email string, leading to a "user not found" (404 via ResourceNotFoundError) or a validation error if the email format itself becomes invalid due to injection characters. No SQL execution.  
  * **Verification Steps:**  
    1. Verify HTTP status code (e.g., 404).  
    2. Confirm no SQL errors in server logs or unexpected delays.  
  * **Code Reference:** UserRepository.get_by_email in app/users/repositories.py:31-38, parameterized query at lines 33-35, ResourceNotFoundError at lines 36-37.  
* **ID:** DBSEC\_DATA\_CONSISTENCY\_KEY\_DELETION\_001 (Conceptual \- if key deletion cascades)  
  * **Category Ref:** DB \- Session & Transaction Security  
  * **Description:** If deleting a User cascades to their APIKeys (current User model: api\_keys=relationship("APIKey", back\_populates="manager") does not specify cascade delete, so this is more about ORM behavior if not handled), ensure this is intended and doesn't leave orphaned billing records or other inconsistencies.  
  * **Exposure Point(s):** User deletion logic (if implemented) and its effect on related APIKey and billing data.  
  * **Test Method/Action:**  
    1. Create a user, assign API keys, generate usage/billing data.  
    2. Delete the user (hypothetical admin function).  
  * **Prerequisites:** User with API keys and usage data. Admin rights for user deletion.  
  * **Expected Secure Outcome:** Either API keys are also deleted/invalidated, or they are handled according to a defined policy (e.g., reassigned, marked as ownerless but inactive). Billing records should remain for historical purposes but be clearly disassociated from an active user if necessary. No orphaned data that causes integrity issues.  
  * **Verification Steps:** Inspect database state for APIKey and billing data after user deletion.  
  * **Code Reference:** User-APIKey relationship in app/users/models.py:21, APIKey manager relationship in app/auth/models.py.

### **Connection Security & Authentication**

* **ID:** DBSEC\_CONNECTION\_LEAK\_001
  * **Category Ref:** DB \- Session & Transaction Security
  * **Description:** Test for database connection leaks during normal and error conditions to ensure connections are properly closed.
  * **Exposure Point(s):** Session lifecycle management in get_db_session at app/db/session.py:23-32, finally block at lines 31-32.
  * **Test Method/Action:**
    1. Monitor database connection count before test.
    2. Send multiple API requests that succeed and fail.
    3. Monitor connection count during and after requests.
    4. Trigger various error conditions to test cleanup paths.
  * **Prerequisites:** Database monitoring tools, ability to trigger various error conditions.
  * **Expected Secure Outcome:** Connection count should return to baseline after requests complete. No persistent connection leaks should occur even during error conditions.
  * **Verification Steps:**
    1. Monitor database connection metrics over time.
    2. Verify connection count stability under normal load.
    3. Test connection cleanup during various error scenarios.
    4. Verify no memory leaks or resource accumulation.
  * **Code Reference:** Session cleanup in app/db/session.py:31-32, async session context management at lines 25-32.

* **ID:** DBSEC\_ISOLATION\_LEVEL\_001
  * **Category Ref:** DB \- Session & Transaction Security
  * **Description:** Verify database isolation levels prevent dirty reads and phantom reads between concurrent transactions.
  * **Exposure Point(s):** Database transaction isolation settings, concurrent session handling, SQLAlchemy transaction management.
  * **Test Method/Action:**
    1. Start concurrent transactions that read and modify overlapping data.
    2. Test various timing scenarios for commit/rollback operations.
    3. Verify data consistency between concurrent operations.
  * **Prerequisites:** Understanding of SQL isolation levels, ability to control transaction timing.
  * **Expected Secure Outcome:** Transactions should be properly isolated according to configured isolation level. No dirty reads, non-repeatable reads, or phantom reads should occur.
  * **Verification Steps:**
    1. Verify consistent data reads within transactions.
    2. Test concurrent modification scenarios.
    3. Verify proper isolation between different user operations.
    4. Check for proper deadlock detection and resolution.
  * **Code Reference:** Database engine configuration in app/db/session.py:9-10, transaction handling in get_db_session.

* **ID:** DBSEC\_QUERY\_TIMEOUT\_001
  * **Category Ref:** DB \- Session & Transaction Security
  * **Description:** Test protection against long-running queries that could cause resource exhaustion.
  * **Exposure Point(s):** Database query execution, SQLAlchemy engine configuration, query timeout settings.
  * **Test Method/Action:**
    1. Craft queries designed to run for extended periods.
    2. Test complex joins or expensive operations.
    3. Monitor query execution time and server response.
  * **Prerequisites:** Understanding of database query patterns, ability to craft expensive queries.
  * **Expected Secure Outcome:** Long-running queries should be terminated after reasonable timeout periods. Server should remain responsive during query execution.
  * **Verification Steps:**
    1. Verify queries timeout after configured period.
    2. Test server responsiveness during expensive operations.
    3. Check for proper error handling of timed-out queries.
    4. Verify resource cleanup after query termination.
  * **Code Reference:** Database engine configuration with timeout settings, query execution patterns in repository classes.

### **Data Integrity & Audit**

* **ID:** DBSEC\_CONCURRENT\_MODIFICATION\_001
  * **Category Ref:** DB \- Session & Transaction Security
  * **Description:** Test protection against lost update problems during concurrent modifications of the same data.
  * **Exposure Point(s):** Concurrent updates to APIKey status, user information, simultaneous database modifications.
  * **Test Method/Action:**
    1. Initiate concurrent modifications to the same API key status.
    2. Test concurrent user updates via admin interface.
    3. Verify proper handling of version conflicts.
  * **Prerequisites:** Multiple admin API keys, ability to send concurrent requests.
  * **Expected Secure Outcome:** Concurrent modifications should be handled properly with appropriate conflict resolution. Last writer should not silently overwrite previous changes.
  * **Verification Steps:**
    1. Verify proper conflict detection and resolution.
    2. Test optimistic locking behavior if implemented.
    3. Check for proper error messages during conflicts.
    4. Verify data consistency after concurrent operations.
  * **Code Reference:** Update operations in repository classes, transaction handling in app/db/session.py.

* **ID:** DBSEC\_AUDIT\_TRAIL\_001
  * **Category Ref:** DB \- Session & Transaction Security
  * **Description:** Verify database operations maintain proper audit trails for security-sensitive operations.
  * **Exposure Point(s):** API key creation/modification, user management operations, database change logging.
  * **Test Method/Action:**
    1. Perform API key lifecycle operations (create, activate, deactivate).
    2. Perform user management operations.
    3. Check for proper logging and audit trail creation.
  * **Prerequisites:** Admin API keys, understanding of audit requirements.
  * **Expected Secure Outcome:** Security-sensitive database operations should create appropriate audit trails. Changes should be traceable to specific users and timestamps.
  * **Verification Steps:**
    1. Verify audit logs for API key operations.
    2. Check user management operation logging.
    3. Verify timestamp accuracy and user attribution.
    4. Test audit log integrity and tamper protection.
  * **Code Reference:** Logging operations, database modification patterns, timestamping in models.

* **ID:** DBSEC\_BACKUP\_RECOVERY\_001
  * **Category Ref:** DB \- Session & Transaction Security
  * **Description:** Test database backup and recovery procedures to ensure data integrity during disaster scenarios.
  * **Exposure Point(s):** Database backup processes, recovery procedures, data consistency verification.
  * **Test Method/Action:**
    1. Create test data across all critical tables.
    2. Simulate backup and recovery procedures.
    3. Verify data integrity after recovery.
  * **Prerequisites:** Database backup/recovery tools, test environment for recovery testing.
  * **Expected Secure Outcome:** Backup and recovery should maintain data integrity. No data loss or corruption should occur during recovery procedures.
  * **Verification Steps:**
    1. Verify backup completeness and integrity.
    2. Test recovery procedures with various failure scenarios.
    3. Verify data consistency after recovery.
    4. Test application functionality after database recovery.
  * **Code Reference:** Database schema definitions, relationship integrity constraints.

### **Performance & Resource Management**

* **ID:** DBSEC\_DEADLOCK\_DETECTION\_001
  * **Category Ref:** DB \- Session & Transaction Security
  * **Description:** Test database deadlock detection and resolution under concurrent access patterns.
  * **Exposure Point(s):** Concurrent database operations, transaction ordering, deadlock resolution mechanisms.
  * **Test Method/Action:**
    1. Create scenarios likely to cause database deadlocks.
    2. Test concurrent operations with different lock ordering.
    3. Verify proper deadlock detection and resolution.
  * **Prerequisites:** Understanding of deadlock-prone scenarios, ability to coordinate concurrent operations.
  * **Expected Secure Outcome:** Database should detect deadlocks and resolve them appropriately. Operations should either succeed or fail gracefully with clear error messages.
  * **Verification Steps:**
    1. Monitor for deadlock detection and resolution.
    2. Verify proper error handling for deadlock scenarios.
    3. Test system recovery after deadlock resolution.
    4. Verify no permanent blocking or resource contention.
  * **Code Reference:** Transaction handling patterns, error handling in repository operations.

* **ID:** DBSEC\_MEMORY\_USAGE\_001
  * **Category Ref:** DB \- Session & Transaction Security
  * **Description:** Test database memory usage patterns to prevent memory exhaustion during large operations.
  * **Exposure Point(s):** Large result set handling, query result buffering, session memory management.
  * **Test Method/Action:**
    1. Execute queries that return large result sets.
    2. Test bulk operations with many records.
    3. Monitor server memory usage during operations.
  * **Prerequisites:** Ability to generate large datasets, memory monitoring tools.
  * **Expected Secure Outcome:** Database operations should use memory efficiently. Large operations should not cause memory exhaustion or server instability.
  * **Verification Steps:**
    1. Monitor memory usage during large operations.
    2. Verify proper result set pagination if implemented.
    3. Test server stability under memory pressure.
    4. Verify proper cleanup of large operation resources.
  * **Code Reference:** Query execution patterns, result handling in repository classes.

* **ID:** DBSEC\_INDEX\_PERFORMANCE\_001
  * **Category Ref:** DB \- Session & Transaction Security
  * **Description:** Verify database indexes provide adequate performance for security-critical operations.
  * **Exposure Point(s):** API key lookup performance, user authentication queries, index utilization.
  * **Test Method/Action:**
    1. Test performance of API key validation queries.
    2. Monitor query execution plans and index usage.
    3. Test performance under various data volumes.
  * **Prerequisites:** Database query analysis tools, performance monitoring capabilities.
  * **Expected Secure Outcome:** Security-critical queries should execute efficiently with proper index utilization. Performance should remain acceptable under load.
  * **Verification Steps:**
    1. Analyze query execution plans for key operations.
    2. Verify proper index utilization for security queries.
    3. Test performance scalability with data growth.
    4. Monitor for query performance degradation over time.
  * **Code Reference:** Database schema indexes, query patterns in authentication and authorization code.