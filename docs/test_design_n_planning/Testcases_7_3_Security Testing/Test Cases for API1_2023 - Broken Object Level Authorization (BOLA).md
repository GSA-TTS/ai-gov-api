# **Test Cases for API1:2023 - Broken Object Level Authorization (BOLA)**

## **Introduction**

This document outlines test cases for **API1:2023 - Broken Object Level Authorization (BOLA)** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md". These tests aim to verify that an agency/user cannot access or manipulate LLM resources or data belonging to another agency/user.

**References:**
* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 1.API1:2023)
* app/auth/dependencies.py (especially get\_current\_active\_user\_with\_api\_key and how manager\_id is used)
* app/auth/repositories.py:19-23 (CRITICAL: APIKeyRepository.get() lacks manager_id filtering)
* app/services/billing.py:7-14 (usage data associated with manager\_id)
* app/auth/models.py:17 (APIKey.manager_id field)

## **General Test Case Components Template**
* **ID:** Unique identifier
* **Category Ref:** API1:2023 - BOLA
* **Description:** What specific feature/vulnerability is being tested.
* **Exposure Point(s):** API endpoints potentially allowing access to other users' LLM-related resources (chat sessions, model usage data, future fine-tuned models if applicable). Database queries scoped by manager\_id.
* **Test Method/Action:** Specific API calls with manipulated identifiers or context.
* **Prerequisites:** Multiple users/agencies (simulated by API keys with different manager\_id) and some associated resources (e.g., billing entries).
* **Expected Secure Outcome:** Access denied (e.g., 403 Forbidden or 404 Not Found if the resource existence isn't to be revealed) for unauthorized attempts. Data returned should always be scoped to the authenticated manager\_id.
* **Verification Steps:** Check HTTP status codes, response bodies for data leakage, and server logs for unauthorized access attempts (if logged).

---

## **Test Cases**

### **Critical BOLA Vulnerabilities**

* **ID:** BOLA\_API\_KEY\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** **CRITICAL VULNERABILITY**: Verify that API key management endpoints correctly scope actions to the managing user's keys only.
  * **Exposure Point(s):** /tokens/is_active/{id} endpoint in app/routers/tokens.py:33-45, APIKeyRepository.get() and set_is_active() methods in app/auth/repositories.py:19-30.
  * **Test Method/Action:**
    1. Admin A creates API key with id=1 for their organization (manager_id_A).
    2. Admin B (different organization, manager_id_B) attempts to deactivate Admin A's key via POST /tokens/is_active/1?is_active=false.
    3. Test GET /tokens/is_active/1 access from Admin B.
    4. Test setting is_active to both true and false values.
  * **Prerequisites:**
    * Two admin API keys from different organizations (different manager_id values).
    * API key created by Admin A with known ID.
  * **Expected Secure Outcome:** Admin B's request should fail with 403 Forbidden. **CURRENT IMPLEMENTATION ALLOWS CROSS-ORGANIZATION ACCESS - THIS IS A HIGH-RISK BOLA VULNERABILITY**.
  * **Verification Steps:**
    1. Verify HTTP status code should be 403 (currently may be 200 - vulnerability).
    2. Verify Admin A's API key status is not changed by Admin B's request.
    3. Verify proper manager_id scoping is implemented in queries.
    4. Check server logs for unauthorized access attempts.
  * **Code Reference:** **VULNERABLE** implementation in app/auth/repositories.py:19-23 (APIKeyRepository.get() lacks manager_id filtering), endpoint in app/routers/tokens.py:33-45.
  * **BOLA Risk:** **CRITICAL** - Current APIKeyRepository.get() method doesn't filter by manager_id, allowing cross-organization API key access and manipulation.

* **ID:** BOLA\_API\_KEY\_ENUMERATION\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test for API key ID enumeration attacks across organizations using the vulnerable APIKeyRepository.get() method.
  * **Exposure Point(s):** Sequential API key IDs, APIKeyRepository.get() method without manager_id filtering in app/auth/repositories.py:19-23.
  * **Test Method/Action:**
    1. Admin A creates several API keys (observing sequential IDs).
    2. Admin B attempts to access API keys with IDs around Admin A's keys using /tokens/is_active/{id}.
    3. Test systematic enumeration of key IDs (1-1000).
    4. Test both GET and POST operations on enumerated key IDs.
    5. Analyze response patterns to identify valid key IDs.
  * **Prerequisites:**
    * Two admin API keys from different organizations.
    * Knowledge of approximate API key ID ranges.
  * **Expected Secure Outcome:** Admin B should not be able to access information about Admin A's API key IDs. Should return 404 Not Found (not 403, to avoid ID enumeration).
  * **Verification Steps:**
    1. Verify consistent 404 responses for unauthorized key IDs.
    2. Verify no information leakage about key existence through response timing or error messages.
    3. Test large ranges of key IDs for enumeration patterns.
    4. Verify no behavioral differences between existing and non-existing keys.
  * **Code Reference:** **VULNERABLE** APIKeyRepository.get() in app/auth/repositories.py:19-23 lacks manager_id filtering.
  * **BOLA Risk:** **HIGH** - Enables complete enumeration of all API keys across organizations.

### **LLM Resource Access Control**

* **ID:** BOLA\_LLM\_USAGE\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Attempt to access LLM usage/billing data of another organization through future reporting endpoints.
  * **Exposure Point(s):** Future billing/usage endpoints, billing data storage in app/services/billing.py:7-14, manager_id association in APIKey model at app/auth/models.py:17.
  * **Test Method/Action:**
    1. Organization A (manager_id_A) makes several LLM calls to /api/v1/chat/completions and /api/v1/embeddings.
    2. Organization B (manager_id_B) attempts to access Organization A's usage data through any available endpoints.
    3. Test direct database queries if exposed through admin interfaces.
    4. Test billing queue data access and manipulation.
    5. Attempt to view usage statistics and cost information cross-organization.
  * **Prerequisites:**
    * Two API keys with different manager_id values (different organizations).
    * LLM usage by Organization A generating billing entries.
    * Future usage/billing reporting endpoints.
  * **Expected Secure Outcome:** Organization B cannot access Organization A's usage data. All billing queries must be scoped by manager_id.
  * **Verification Steps:**
    1. Verify proper manager_id scoping in all billing queries.
    2. Test any future billing endpoints for proper authorization.
    3. Verify billing queue data includes proper organization context.
    4. Check that usage metrics are properly isolated between organizations.
  * **Code Reference:** APIKey.manager_id field in app/auth/models.py:17, billing system in app/services/billing.py:7-14, billing queue processing.

* **ID:** BOLA\_CHAT\_SESSION\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test chat session isolation and verify no cross-organization access to conversation data.
  * **Exposure Point(s):** Future chat session storage, conversation history endpoints, current stateless implementation in app/routers/api_v1.py:33-60.
  * **Test Method/Action:**
    1. Organization A makes multiple chat completion requests with conversation context.
    2. Organization B attempts to access Organization A's conversation data through any future session endpoints.
    3. Test for conversation data leakage through logs or debug endpoints.
    4. Test session token manipulation to access other organizations' sessions.
    5. Verify request/response isolation in streaming scenarios.
  * **Prerequisites:**
    * Two API keys from different organizations.
    * Future chat session storage implementation.
    * Conversation history tracking capabilities.
  * **Expected Secure Outcome:** Organizations cannot access each other's conversation data. All session data must be properly scoped by manager_id.
  * **Verification Steps:**
    1. Verify proper session isolation between organizations.
    2. Test any future session endpoints for authorization.
    3. Verify no conversation data leakage in logs or responses.
    4. Check that conversation context is properly scoped.
    5. Test streaming response isolation.
  * **Code Reference:** Current stateless implementation in app/routers/api_v1.py:33-60, future session storage must include manager_id scoping.

* **ID:** BOLA\_MODEL\_ACCESS\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test model access controls and prevent unauthorized use of organization-specific models.
  * **Exposure Point(s):** Model selection in chat/completions requests, backend_map configuration in app/config/settings.py:16-20, future fine-tuned model endpoints, /models endpoint in app/routers/api_v1.py:25-30.
  * **Test Method/Action:**
    1. Configure organization-specific model access controls (future feature).
    2. Organization A has access to specific models (e.g., gpt-4, claude-3).
    3. Organization B attempts to use Organization A's restricted models in /api/v1/chat/completions.
    4. Test future fine-tuned model management endpoints.
    5. Test model enumeration through /models endpoint for organization-specific filtering.
    6. Attempt to access models not in organization's backend_map configuration.
  * **Prerequisites:**
    * Two API keys from different organizations.
    * Organization-specific model access controls.
    * Future fine-tuned model features.
  * **Expected Secure Outcome:** Organizations can only use their authorized models. Unauthorized model access returns 422 Unprocessable Entity with appropriate error messages.
  * **Verification Steps:**
    1. Verify model access is properly scoped by organization.
    2. Test model usage restrictions in chat/completions and embeddings.
    3. Verify future model management endpoints include proper authorization.
    4. Check that /models endpoint returns only organization-authorized models.
    5. Test fine-tuned model isolation between organizations.
  * **Code Reference:** Backend_map in app/config/settings.py:16-20, model access in app/routers/api_v1.py:33-60, /models endpoint in app/routers/api_v1.py:25-30.

### **User Management BOLA**

* **ID:** BOLA\_USER\_ACCESS\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test unauthorized access to user information across different organizations.
  * **Exposure Point(s):** /users/{email} endpoint in app/routers/users.py:27-35, user repository queries, user creation and management.
  * **Test Method/Action:**
    1. Admin A creates user for their organization.
    2. Admin B attempts to GET /users/{admin_a_user_email}.
    3. Test user enumeration through email guessing.
    4. Attempt to modify user properties across organizations.
    5. Test user deletion attempts across organizations.
  * **Prerequisites:**
    * Two admin API keys from different organizations.
    * User created by Admin A.
  * **Expected Secure Outcome:** Admin B should not be able to access Admin A's users. Should return 403 Forbidden or 404 Not Found.
  * **Verification Steps:**
    1. Verify appropriate error response for unauthorized access.
    2. Verify no user data leakage across organizations.
    3. Check for proper user scoping by organization.
    4. Test user enumeration protection.
    5. Verify user modification restrictions.
  * **Code Reference:** User management endpoints in app/routers/users.py:27-35, user repository access patterns, user scoping implementation.

* **ID:** BOLA\_USER\_ENUMERATION\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test for user enumeration attacks across organizations.
  * **Exposure Point(s):** User lookup mechanisms, email-based user identification, response timing analysis.
  * **Test Method/Action:**
    1. Admin A creates users with known email patterns.
    2. Admin B attempts to enumerate users through systematic email guessing.
    3. Test response timing differences between existing and non-existing users.
    4. Test error message analysis for user existence confirmation.
    5. Attempt bulk user enumeration through API endpoints.
  * **Prerequisites:**
    * Two admin API keys from different organizations.
    * Known user email patterns or domains.
  * **Expected Secure Outcome:** User enumeration should be prevented. Consistent responses regardless of user existence.
  * **Verification Steps:**
    1. Verify consistent response times for existing and non-existing users.
    2. Check error message consistency.
    3. Test large-scale enumeration resistance.
    4. Verify no information leakage about user existence.
  * **Code Reference:** User lookup implementation, error handling consistency, timing attack prevention.

### **Advanced BOLA Testing**

* **ID:** BOLA\_CONCURRENT\_ACCESS\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test BOLA protections under concurrent access scenarios and race conditions.
  * **Exposure Point(s):** Database session isolation in app/db/session.py:23-32, concurrent API key operations, transaction boundaries.
  * **Test Method/Action:**
    1. Simulate concurrent requests from different organizations accessing resources.
    2. Test race conditions in authorization checks during API key operations.
    3. Verify session isolation prevents cross-organization data access under load.
    4. Test concurrent API key creation/deletion operations.
    5. Test concurrent billing data generation and access.
  * **Prerequisites:**
    * Multiple API keys from different organizations.
    * Ability to send concurrent requests.
    * Load testing capabilities.
  * **Expected Secure Outcome:** Concurrent access should not create BOLA vulnerabilities. Session isolation should prevent data leakage under all conditions.
  * **Verification Steps:**
    1. Verify no authorization bypass under concurrent load.
    2. Test session isolation effectiveness under stress.
    3. Verify consistent BOLA protections under load.
    4. Check for race condition vulnerabilities.
    5. Test database transaction isolation.
  * **Code Reference:** Database session management in app/db/session.py:23-32, concurrent access patterns, transaction isolation levels.

* **ID:** BOLA\_PARAMETER\_MANIPULATION\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test parameter manipulation attacks to bypass object-level authorization.
  * **Exposure Point(s):** Request parameter handling, ID parameters in URLs and request bodies, Pydantic validation.
  * **Test Method/Action:**
    1. Test manipulation of ID parameters in requests (negative IDs, large numbers, UUID format changes).
    2. Test SQL injection attempts in ID parameters.
    3. Test array/object injection in ID fields.
    4. Test parameter pollution attacks (multiple ID parameters).
    5. Test encoding attacks (URL encoding, JSON encoding bypass).
  * **Prerequisites:**
    * API endpoints that accept ID parameters.
    * Different organizations' resources with known IDs.
  * **Expected Secure Outcome:** Parameter manipulation should not bypass authorization. Invalid parameters should be rejected safely with appropriate error messages.
  * **Verification Steps:**
    1. Verify proper parameter validation and sanitization.
    2. Test SQL injection protection in ID parameters.
    3. Verify no authorization bypass through parameter manipulation.
    4. Check Pydantic schema validation effectiveness.
    5. Test error handling for malformed parameters.
  * **Code Reference:** Parameter validation in Pydantic schemas, repository query patterns, input sanitization.

* **ID:** BOLA\_TOKEN\_MANIPULATION\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test API token manipulation to access other organizations' resources.
  * **Exposure Point(s):** API key validation in app/auth/dependencies.py, token parsing and validation logic.
  * **Test Method/Action:**
    1. Test API key modification attempts (changing parts of the key).
    2. Test key replay attacks with modified manager_id context.
    3. Test token substitution attacks.
    4. Test partial key guessing and brute force attacks.
    5. Test key format manipulation and encoding attacks.
  * **Prerequisites:**
    * Valid API keys from different organizations.
    * Understanding of API key format and structure.
  * **Expected Secure Outcome:** Token manipulation should not allow cross-organization access. Invalid tokens should be rejected.
  * **Verification Steps:**
    1. Verify robust token validation.
    2. Test token modification detection.
    3. Verify manager_id integrity in token validation.
    4. Check for token brute force protection.
    5. Test error handling for invalid tokens.
  * **Code Reference:** API key validation in app/auth/dependencies.py, token security implementation.

* **ID:** BOLA\_DATABASE\_DIRECT\_ACCESS\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test for direct database access vulnerabilities that could bypass API-level BOLA protections.
  * **Exposure Point(s):** Database query construction, SQLAlchemy ORM usage, raw SQL query potential.
  * **Test Method/Action:**
    1. Test for SQL injection that could bypass manager_id filtering.
    2. Test ORM query manipulation through parameter injection.
    3. Test database function calls that might bypass authorization.
    4. Test stored procedure access if available.
    5. Test database view access patterns.
  * **Prerequisites:**
    * Understanding of database schema and query patterns.
    * Access to application database queries.
  * **Expected Secure Outcome:** All database access should include proper manager_id scoping. No direct access should bypass authorization.
  * **Verification Steps:**
    1. Verify all queries include manager_id filtering.
    2. Test SQL injection protection in all database operations.
    3. Check ORM usage for authorization bypass potential.
    4. Verify no raw SQL queries bypass authorization.
    5. Test database-level security constraints.
  * **Code Reference:** Database query patterns, SQLAlchemy ORM usage, repository implementations.

### **Future Feature BOLA Testing**

* **ID:** BOLA\_FUTURE\_ENDPOINTS\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Test BOLA protections for future API endpoints and features.
  * **Exposure Point(s):** Future billing endpoints, session management, model fine-tuning, analytics dashboards.
  * **Test Method/Action:**
    1. Test future billing and usage reporting endpoints for proper scoping.
    2. Test session management endpoints when implemented.
    3. Test model fine-tuning endpoints for organization isolation.
    4. Test analytics and dashboard endpoints for data isolation.
    5. Test any admin or management interfaces.
  * **Prerequisites:**
    * Future endpoint implementations.
    * Organization-specific data and resources.
  * **Expected Secure Outcome:** All future endpoints should include proper BOLA protections with manager_id scoping.
  * **Verification Steps:**
    1. Verify all new endpoints include authorization checks.
    2. Test cross-organization access prevention.
    3. Check data scoping in all responses.
    4. Verify consistent authorization patterns.
    5. Test edge cases and error conditions.
  * **Code Reference:** Future endpoint implementations, consistent authorization patterns.

* **ID:** BOLA\_INTEGRATION\_TESTING\_001
  * **Category Ref:** API1:2023 - BOLA
  * **Description:** Comprehensive integration testing of BOLA protections across all system components.
  * **Exposure Point(s):** End-to-end workflows, multi-component interactions, cross-service communications.
  * **Test Method/Action:**
    1. Test complete user workflows for BOLA vulnerabilities.
    2. Test multi-step processes that span multiple endpoints.
    3. Test service-to-service communications for authorization.
    4. Test error propagation and handling across components.
    5. Test system recovery and state consistency after BOLA attempts.
  * **Prerequisites:**
    * Complete system deployment.
    * Multi-organization test scenarios.
    * End-to-end testing capabilities.
  * **Expected Secure Outcome:** BOLA protections should be consistently enforced across all system components and workflows.
  * **Verification Steps:**
    1. Test complete user journeys for authorization consistency.
    2. Verify multi-step process security.
    3. Check cross-service authorization propagation.
    4. Test system security under various failure conditions.
    5. Verify data consistency and isolation.
  * **Code Reference:** System-wide authorization patterns, service integration points, error handling consistency.