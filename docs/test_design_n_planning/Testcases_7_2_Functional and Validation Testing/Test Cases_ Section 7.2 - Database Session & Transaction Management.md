# **Test Cases: Section 7.2 \- Database Session & Transaction Management**

This document outlines test cases for database session management, transaction integrity, and migration impacts, particularly concerning authentication, billing, and LLM access control. This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_DBM\_...)  
* **Category Ref:** (e.g., FV\_DBM\_SESSION, FV\_DBM\_TX, FV\_DBM\_MIGRATE, FV\_DBM\_CONCURRENCY)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** app/db/session.py, database operations in repositories (auth, users, billing), Alembic migrations.  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** Database setup, ability to inspect DB state, potentially mock DB operations or induce errors.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (e.g., "Database transaction rolled back on error").  
* **Verification Steps:** How to confirm the expected secure outcome (e.g., "Query database to confirm no partial data was committed").

## **1\. Session Management (FastAPI Dependencies)**

FastAPI's dependency injection system typically handles session per request. These tests verify this behavior under various conditions.

### **FV\_DBM\_SESSION\_PER\_REQUEST\_001**

* **Category Ref:** FV\_DBM\_SESSION  
* **Description:** Verify that a database session is correctly opened and closed for a single successful API request requiring DB access (e.g., API key validation).  
* **Exposure Point(s):** get\_db\_session dependency in app/db/session.py, API key validation logic.  
* **Test Method/Action:** Make a successful authenticated request to /chat/completions.  
* **Prerequisites:** Valid API Key with models:inference scope. Ability to monitor database connections/sessions (e.g., through database logs or admin tools, if feasible, otherwise this is an implicit test).  
* **Expected Secure Outcome:** The request is processed successfully. The database session used for API key lookup is closed after the request, releasing the connection. No connection leaks.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * (If monitoring DB) Observe session creation and closure corresponding to the request.  
  * Over many requests, ensure the number of active DB connections does not grow indefinitely.  
* **Code Reference:** Session lifecycle management in app/db/session.py:23-32, async session context manager with try/finally.

### **FV\_DBM\_SESSION\_ERROR\_HANDLING\_001**

* **Category Ref:** FV\_DBM\_SESSION  
* **Description:** Verify database session handling when an error occurs mid-request *after* a DB operation but *before* request completion (e.g., an error in provider logic after API key validation).  
* **Exposure Point(s):** FastAPI error handling, get\_db\_session dependency's finally block.  
* **Test Method/Action:**  
  1. Make an authenticated request that successfully validates the API key (reads from DB).  
  2. Mock a downstream service (e.g., LLM provider SDK) to raise an exception *after* API key validation.  
* **Prerequisites:** Valid API Key with models:inference scope. Ability to mock downstream services.  
* **Expected Secure Outcome:** The API returns an appropriate error (e.g., 500, 502). The database session is still closed correctly, even though an error occurred in later request processing stages.  
* **Verification Steps:**  
  * Assert HTTP status code is as expected for the mocked error.  
  * (If monitoring DB) Verify session closure.  
  * Ensure no DB transaction related to the API key read is inadvertently rolled back if it was read-only and successful. The key point is session closure.  
* **Code Reference:** Error handling in app/db/session.py:28-32, session rollback and cleanup logic.

### **FV\_DBM\_SESSION\_POOL\_EXHAUSTION\_001 (Stress Test)**

* **Category Ref:** FV\_DBM\_SESSION  
* **Description:** Test API behavior under high load that might stress the database connection pool.  
* **Exposure Point(s):** Database connection pool settings, async_sessionmaker configuration in app/db/session.py.  
* **Test Method/Action:** Send a high number of concurrent authenticated requests that all require database access (e.g., to /chat/completions). The number should exceed typical pool size settings.  
* **Prerequisites:** Valid API Key with models:inference scope. Load testing tool.  
* **Expected Secure Outcome:** The API continues to function, possibly with increased latency as requests wait for connections. Requests should eventually succeed or timeout gracefully (if API timeout is shorter than DB connection acquisition timeout). No unhandled exceptions related to connection pool exhaustion.  
* **Verification Steps:**  
  * Monitor API responses: most should be 200 OK, some might be 503 if timeouts occur but should be graceful.  
  * Check server logs for errors like "TimeoutError: QueuePool limit of size \<pool\_size\> overflow \<max\_overflow\> reached".  
  * Ensure the API recovers after the load subsides.  
* **Code Reference:** Database engine configuration in app/db/session.py:9-10, async_sessionmaker setup at lines 18-20.

### **FV\_DBM\_SESSION\_ROLLBACK\_ON\_EXCEPTION\_001**

* **Category Ref:** FV\_DBM\_SESSION  
* **Description:** Verify that database session automatically rolls back when an exception occurs during request processing.  
* **Exposure Point(s):** Exception handling in get_db_session context manager.  
* **Test Method/Action:** Create a scenario where a database write operation fails (e.g., constraint violation during API key creation).  
* **Prerequisites:** Database access. Ability to trigger constraint violations.  
* **Expected Secure Outcome:** Session automatically calls rollback() when exception occurs, preventing partial commits.  
* **Verification Steps:**  
  * Trigger database operation that raises exception.  
  * Verify session.rollback() is called automatically.  
  * Confirm no partial data is committed to database.  
* **Code Reference:** Automatic rollback logic in app/db/session.py:28-30.

## **2\. Transaction Integrity**

These tests focus on operations that modify the database, such as user/key creation or updates to billing-related records (if any are done synchronously).

### **FV\_DBM\_TX\_USER\_CREATE\_SUCCESS\_001**

* **Category Ref:** FV\_DBM\_TX  
* **Description:** Verify successful user creation and API key generation commits data correctly. (Assuming user/key creation involves a single logical transaction).  
* **Exposure Point(s):** User/API key creation logic in app/users/repositories.py, app/auth/repositories.py.  
* **Test Method/Action:** Use the user creation script (scripts/create\_admin\_user.py) or an admin API (if available) to create a new user and an associated API key.  
* **Prerequisites:** Database access.  
* **Expected Secure Outcome:** User and API key are created in the database. All related fields are populated correctly. The transaction is committed.  
* **Verification Steps:**  
  * Query the users table for the new user. Assert presence and correct data.  
  * Query the api\_keys table for the new API key. Assert presence, correct user\_id, scopes, etc.  
  * Use the new API key to make a request to confirm it's active.  
* **Code Reference:** Transactional user creation in scripts/create_admin_user.py:28-51, session.begin() context manager usage.

### **FV\_DBM\_TX\_USER\_CREATE\_ROLLBACK\_001**

* **Category Ref:** FV\_DBM\_TX  
* **Description:** Test transaction rollback if an error occurs during a multi-step database operation (e.g., creating a user but failing to create their initial API key within the same transaction).  
* **Exposure Point(s):** User/API key creation logic.  
* **Test Method/Action:**  
  1. Modify user/key creation logic (or mock a DB call within it) to successfully write the user record but then raise an exception *before* committing the transaction (or before writing a related mandatory record like an API key if they are in the same transaction).  
* **Prerequisites:** Ability to modify/mock parts of the repository methods.  
* **Expected Secure Outcome:** The entire transaction is rolled back. The user record (and any partial related data) should NOT be present in the database.  
* **Verification Steps:**  
  * Trigger the modified creation logic.  
  * Query the users table for the user that supposedly failed creation. Assert the user is NOT found.  
  * Query any related tables (e.g., api\_keys) for partially created data. Assert NOT found.  
* **Code Reference:** Transaction rollback behavior in scripts/create_admin_user.py:30-51, session.begin() ensuring atomicity.

### **FV\_DBM\_TX\_BILLING\_RECORD\_FAIL\_001 (If billing involves synchronous DB writes)**

* **Category Ref:** FV\_DBM\_TX  
* **Description:** If the billing service involves direct, synchronous database writes (e.g., updating usage counters or ledgers) and an error occurs, ensure transaction rollback. (Note: Current design uses a queue, so this might be less relevant unless the billing\_worker itself does complex DB transactions).  
* **Exposure Point(s):** app/services/billing.py if it performs DB transactions.  
* **Test Method/Action:** If applicable: Mock an error during a database update within the billing service's transaction.  
* **Prerequisites:** Billing service performs DB transactions.  
* **Expected Secure Outcome:** Partial updates are rolled back. Database remains consistent.  
* **Verification Steps:** Inspect DB state before and after the failed operation.  
* **Code Reference:** Billing queue implementation in app/services/billing.py:7-14, current design uses async queue without direct DB transactions.

### **FV\_DBM\_TX\_CONSTRAINT\_VIOLATION\_HANDLING\_001**

* **Category Ref:** FV\_DBM\_TX  
* **Description:** Test transaction handling when database constraint violations occur (e.g., unique constraint on email).  
* **Exposure Point(s):** Repository methods, database constraint enforcement.  
* **Test Method/Action:** Attempt to create a user with an email that already exists in the database.  
* **Prerequisites:** Existing user in database. User creation capability.  
* **Expected Secure Outcome:** Database constraint violation is caught and handled gracefully. Transaction is rolled back. Appropriate error is returned.  
* **Verification Steps:**  
  * Attempt duplicate user creation.  
  * Verify appropriate error response (e.g., 400 Bad Request).  
  * Confirm no partial data is committed.  
  * Verify original data remains intact.  
* **Code Reference:** Constraint handling in user creation logic, repository error handling patterns.

## **3\. Alembic Migrations Impact**

### **FV\_DBM\_MIGRATE\_APPLY\_ALL\_001**

* **Category Ref:** FV\_DBM\_MIGRATE  
* **Description:** Verify that all Alembic migrations can be applied successfully to an empty database.  
* **Exposure Point(s):** Alembic migration scripts in alembic/versions/.  
* **Test Method/Action:**  
  1. Start with an empty database (or a new schema).  
  2. Run alembic upgrade head.  
* **Prerequisites:** Alembic configured. Empty target database.  
* **Expected Secure Outcome:** All migrations apply without error. The database schema matches the current state defined by all models.  
* **Verification Steps:**  
  * Alembic command completes successfully.  
  * Inspect the database schema (tables, columns, constraints) and verify it matches the SQLAlchemy models in app/db/models.py, app/users/models.py, app/auth/models.py.  
  * Check the alembic\_version table to confirm the latest migration version is recorded.  
* **Code Reference:** Migration files in alembic/versions/, database models in app/db/models.py:5-6 Base class definition.

### **FV\_DBM\_MIGRATE\_DOWNGRADE\_UPGRADE\_001**

* **Category Ref:** FV\_DBM\_MIGRATE  
* **Description:** Test downgrading a migration and then upgrading again (if down() methods are properly implemented).  
* **Exposure Point(s):** down() methods in Alembic migration scripts.  
* **Test Method/Action:**  
  1. Apply all migrations: alembic upgrade head.  
  2. Downgrade one step: alembic downgrade \-1.  
  3. Upgrade again: alembic upgrade head.  
* **Prerequisites:** Migrations have correctly implemented down() functions.  
* **Expected Secure Outcome:** Downgrade and subsequent upgrade complete without errors. Database schema returns to the latest state. No data loss if data transformations were involved and reversible (though often down() might not guarantee data preservation).  
* **Verification Steps:**  
  * Alembic commands complete successfully.  
  * Schema after final upgrade matches the state after initial upgrade.  
  * (If data was present) Check for data integrity if down() was supposed to preserve/revert it.  
* **Code Reference:** Migration implementations in alembic/versions/, upgrade() and downgrade() functions.

### **FV\_DBM\_MIGRATE\_NEW\_MODEL\_FIELD\_001**

* **Category Ref:** FV\_DBM\_MIGRATE  
* **Description:** After adding a new non-nullable field to a model (without a default in Python and DB), ensure generating and applying a migration handles it correctly (e.g., prompts for default, or requires manual handling if table has data).  
* **Exposure Point(s):** Alembic auto-generation, new model fields.  
* **Test Method/Action:**  
  1. Add a new Column(String, nullable=False) to an existing SQLAlchemy model (e.g., User model).  
  2. Generate a new migration: alembic revision \-m "add new\_field to user"  
  3. Inspect the generated migration script.  
  4. (If table has existing data) Attempt to apply it: alembic upgrade head.  
* **Prerequisites:** Existing database with some data in the target table.  
* **Expected Secure Outcome:**  
  * If Alembic autogenerates and the field is non-nullable without a DB default, the migration script might need manual adjustment (e.g., to add a server\_default or update existing rows first, or make it nullable initially).  
  * Applying the migration to a table with data without such handling would fail if the DB enforces non-nullability.  
  * The test is to ensure this process is understood and migrations are created correctly.  
* **Verification Steps:**  
  * Review generated migration script for correctness (e.g., op.add\_column with appropriate nullability).  
  * If applying to populated DB: Migration succeeds if handled correctly, or fails predictably if not (e.g., DB error about NULL constraint). This highlights need for careful migration creation.  
* **Code Reference:** Alembic configuration in alembic.ini, model definitions that would trigger migrations.

### **FV\_DBM\_MIGRATE\_DATA\_MIGRATION\_001**

* **Category Ref:** FV\_DBM\_MIGRATE  
* **Description:** Test a migration that involves data transformation (not just schema changes).  
* **Exposure Point(s):** Data manipulation in migration scripts.  
* **Test Method/Action:** Create a migration that modifies existing data (e.g., updates field values based on business logic changes).  
* **Prerequisites:** Migration with data transformation logic. Test data in database.  
* **Expected Secure Outcome:** Data is transformed correctly according to migration logic. No data corruption or loss occurs.  
* **Verification Steps:**  
  * Apply migration with data transformation.  
  * Verify data has been modified as expected.  
  * Ensure no data corruption or unexpected side effects.  
  * Test rollback if supported by the migration.  
* **Code Reference:** Data migration patterns in Alembic, custom migration script implementations.

## **4\. Concurrent Database Access (Functional Correctness)**

### **FV\_DBM\_CONCURRENCY\_KEY\_LOOKUP\_001**

* **Category Ref:** FV\_DBM\_CONCURRENCY  
* **Description:** Test concurrent read operations on the api\_keys table (e.g., multiple simultaneous API requests validating different keys).  
* **Exposure Point(s):** APIKeyRepository.get\_by\_hashed\_key().  
* **Test Method/Action:** Send many concurrent authenticated requests using different valid API keys.  
* **Prerequisites:** Multiple valid API keys with models:inference scope. Load testing tool.  
* **Expected Secure Outcome:** All requests are authenticated correctly. No deadlocks or read errors from the database. API responses are successful (200 OK).  
* **Verification Steps:** All requests return 200 OK. Check logs for DB errors (should be none).  
* **Code Reference:** API key repository methods in app/auth/repositories.py, concurrent session handling.

### **FV\_DBM\_CONCURRENCY\_USER\_CREATION\_001 (If exposed via API)**

* **Category Ref:** FV\_DBM\_CONCURRENCY  
* **Description:** Test concurrent attempts to create users with unique usernames/emails.  
* **Exposure Point(s):** User creation logic, unique constraints on User model.  
* **Test Method/Action:** If user creation is via an API: Make concurrent requests to create users with the *same* username/email.  
* **Prerequisites:** User creation API endpoint.  
* **Expected Secure Outcome:** One request succeeds in creating the user. Subsequent concurrent requests for the same unique fields fail with a specific error (e.g., 400 or 409 Conflict) due to unique constraint violation. No database corruption.  
* **Verification Steps:**  
  * One request returns 201 Created (or similar success).  
  * Other requests return 400/409.  
  * Query DB: only one user with that username/email exists.  
* **Code Reference:** User model constraints, repository creation methods, concurrent access handling.

### **FV\_DBM\_CONCURRENCY\_SESSION\_ISOLATION\_001**

* **Category Ref:** FV\_DBM\_CONCURRENCY  
* **Description:** Test that concurrent database sessions don't interfere with each other's transactions.  
* **Exposure Point(s):** Session isolation levels, concurrent transaction handling.  
* **Test Method/Action:** Create multiple concurrent transactions that read and modify different records simultaneously.  
* **Prerequisites:** Multiple database operations. Concurrent execution capability.  
* **Expected Secure Outcome:** Each session operates independently. No dirty reads or transaction interference occurs.  
* **Verification Steps:**  
  * Verify each transaction completes successfully.  
  * Confirm no data corruption from concurrent access.  
  * Check that session isolation is maintained.  
* **Code Reference:** Session configuration in app/db/session.py:18-20, isolation level settings.

### **FV\_DBM\_CONCURRENCY\_CONNECTION\_CLEANUP\_001**

* **Category Ref:** FV\_DBM\_CONCURRENCY  
* **Description:** Test that database connections are properly cleaned up under concurrent load.  
* **Exposure Point(s):** Connection pool management, session lifecycle.  
* **Test Method/Action:** Generate high concurrent load and monitor connection cleanup behavior.  
* **Prerequisites:** High concurrent load testing capability. Database monitoring tools.  
* **Expected Secure Outcome:** Connections are properly returned to pool after use. No connection leaks occur under load.  
* **Verification Steps:**  
  * Monitor active connection count during and after load test.  
  * Verify connection pool size remains stable.  
  * Check for any connection timeout or exhaustion errors.  
* **Code Reference:** Connection management in app/db/session.py:23-32, session cleanup logic.

*(Note: Testing for deadlocks often requires specific scenarios and higher concurrency levels, potentially with a mix of read/write operations that are hard to orchestrate precisely without direct DB manipulation during tests.)*