# **Test Cases for API5:2023 - Broken Function Level Authorization**

## **Introduction**

This document outlines test cases for **API5:2023 - Broken Function Level Authorization** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md". These tests aim to verify that users can only access API functions and endpoints for which they have explicit authorization, based on their roles and scopes, particularly concerning LLM-related administrative or privileged operations.  

**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 1.API5:2023)  
* app/auth/dependencies.py:48-66 (especially RequiresScope implementation)  
* app/auth/schemas.py:30 (Scope enum and scope definitions)  
* app/routers/api\_v1.py:36,65 (scope protection on LLM endpoints)  
* app/routers/tokens.py:19,37 (scope protection on token management)  
* app/routers/users.py:18,30,42 (scope protection on user management)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** API5:2023 - BFLA  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** API endpoints that should be restricted to certain roles/scopes (e.g., admin-only endpoints, specific LLM functionalities).  
* **Test Method/Action:** Attempt to access restricted endpoints/functions using API keys with insufficient scopes.  
* **Prerequisites:** API keys with different sets of scopes (e.g., a key with only models:inference, a key with admin, a key with no relevant scopes).  
* **Expected Secure Outcome:** Access to unauthorized functions is denied with a 403 Forbidden (or 401 Unauthorized if the scope check leads to an overall auth failure perception by RequiresScope).  
* **Verification Steps:** Check HTTP status codes and error messages.

## **Test Cases**

### **LLM Function Authorization**

* **ID:** BFLA\_LLM\_INFERENCE\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Attempt to use /api/v1/chat/completions with an API key that lacks the models:inference scope.  
  * **Exposure Point(s):** /api/v1/chat/completions endpoint, RequiresScope(\[Scope.MODELS\_INFERENCE\]) decorator in app/routers/api_v1.py:36.  
  * **Test Method/Action:** Make a POST request to /api/v1/chat/completions using API keys with insufficient scopes:
    1. API key with only models:embedding scope.
    2. API key with only admin scope (no model access).
    3. API key with no relevant scopes.
    4. API key with custom/invalid scopes.
  * **Prerequisites:**  
    * An API key with scopes=[Scope.MODELS_EMBEDDING] only.  
    * An API key with scopes=[] or unrelated scopes like [Scope.USERS_READ].  
    * An API key with scopes=[Scope.ADMIN] only.
  * **Expected Secure Outcome:** Request fails with 403 Forbidden and error detail "Not Authorized".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403.  
    2. Verify response body detail: {"detail":"Not Authorized"}.  
    3. Verify no partial execution or data leakage.
    4. Test multiple invalid scope combinations.
  * **Code Reference:** RequiresScope implementation in app/auth/dependencies.py:48-66, endpoint protection in app/routers/api_v1.py:36.  

* **ID:** BFLA\_LLM\_EMBEDDING\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Attempt to use /api/v1/embeddings with an API key that lacks the models:embedding scope.  
  * **Exposure Point(s):** /api/v1/embeddings endpoint, RequiresScope(\[Scope.MODELS\_EMBEDDING\]) decorator in app/routers/api_v1.py:65.  
  * **Test Method/Action:** Make a POST request to /api/v1/embeddings using API keys with insufficient scopes:
    1. API key with only models:inference scope.
    2. API key with only admin scope.
    3. API key with no model-related scopes.
    4. API key with malformed scope values.
  * **Prerequisites:** API keys with various non-embedding scope combinations.  
  * **Expected Secure Outcome:** Request fails with 403 Forbidden and error detail "Not Authorized".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403.  
    2. Verify response body detail: {"detail":"Not Authorized"}.  
    3. Verify no unauthorized embedding generation.
    4. Test scope validation consistency.
  * **Code Reference:** RequiresScope implementation in app/auth/dependencies.py:48-66, endpoint protection in app/routers/api_v1.py:65.  

* **ID:** BFLA\_MODELS\_LIST\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Verify /api/v1/models endpoint accessibility with various scopes and test for information disclosure.  
  * **Exposure Point(s):** /api/v1/models endpoint, valid\_api\_key dependency in app/routers/api_v1.py:28.  
  * **Test Method/Action:** Make a GET request to /api/v1/models using:  
    1. An API key with models:inference scope.  
    2. An API key with models:embedding scope.  
    3. An API key with admin scope.  
    4. An API key with no model-related scopes (e.g., scopes=[Scope.USERS_READ] only).
    5. Test model list filtering based on user privileges.
  * **Prerequisites:** Various API keys with different scope combinations.  
  * **Expected Secure Outcome:** All requests should succeed (200 OK) as long as the API key is valid, but model list should be appropriately filtered based on user scopes.  
  * **Verification Steps:**  
    1. Verify HTTP status code is 200 for all valid keys.  
    2. Verify response body is List[LLMModel] structure.  
    3. Verify model list doesn't expose unauthorized model information.
    4. Test for information disclosure in model descriptions.
  * **Code Reference:** Endpoint definition in app/routers/api_v1.py:25-30, valid_api_key dependency only.  

### **Administrative Function Authorization**

* **ID:** BFLA\_ADMIN\_TOKEN\_CREATE\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Attempt to use /tokens/create (for creating API keys) with an API key that lacks the Scope.ADMIN scope.  
  * **Exposure Point(s):** /tokens/create endpoint in app/routers/tokens.py:16-31, RequiresScope([Scope.ADMIN]) at line 19.  
  * **Test Method/Action:** Make a POST request to /tokens/create using:
    1. API key with only models:inference or models:embedding scopes.
    2. API key with users:read scope.
    3. API key with no scopes.
    4. API key with malformed admin scope.
  * **Prerequisites:** API keys with various non-admin scope combinations.  
  * **Expected Secure Outcome:** Request fails with 403 Forbidden and error detail "Not Authorized".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403.  
    2. Verify response body detail: {"detail":"Not Authorized"}.  
    3. Verify no API key creation occurs.
    4. Test various non-admin scope combinations.
  * **Code Reference:** Admin scope requirement in app/routers/tokens.py:19, RequiresScope implementation in app/auth/dependencies.py:48-66.  

* **ID:** BFLA\_ADMIN\_TOKEN\_SET\_ACTIVE\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Attempt to use /tokens/is\_active/{id} with a non-admin API key.  
  * **Exposure Point(s):** /tokens/is\_active/{id} endpoint in app/routers/tokens.py:33-45, RequiresScope([Scope.ADMIN]) at line 37.  
  * **Test Method/Action:** 
    1. Make a POST request to /tokens/is\_active/1?is\_active=false using a non-admin API key.
    2. Test with various non-admin scope combinations.
    3. Test attempts to modify own API key status.
    4. Test attempts to modify other users' API keys.
  * **Prerequisites:** Non-admin API keys, existing API keys with known IDs.  
  * **Expected Secure Outcome:** Request fails with 403 Forbidden and error detail "Not Authorized".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403.  
    2. Verify response body detail: {"detail":"Not Authorized"}.  
    3. Verify no API key status changes occur.
    4. Test protection against ID enumeration.
  * **Code Reference:** Admin scope requirement in app/routers/tokens.py:37, endpoint function at lines 33-45.  

### **User Management Authorization**

* **ID:** BFLA\_ADMIN\_USER\_CREATE\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Attempt to use /users/create with a non-admin API key.  
  * **Exposure Point(s):** /users/create endpoint in app/routers/users.py:15-25, RequiresScope([Scope.ADMIN]) at line 18.  
  * **Test Method/Action:** Make a POST request to /users/create using:
    1. API key with non-admin scopes like [Scope.MODELS_INFERENCE].
    2. API key with users:read scope only.
    3. API key with no scopes.
    4. Test user creation with various privilege escalation attempts.
  * **Prerequisites:** Non-admin API keys, valid user creation payloads.  
  * **Expected Secure Outcome:** Request fails with 403 Forbidden and error detail "Not Authorized".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403.  
    2. Verify response body detail: {"detail":"Not Authorized"}.  
    3. Verify no user creation occurs.
    4. Test against privilege escalation in user creation.
  * **Code Reference:** Admin scope requirement in app/routers/users.py:18, endpoint function at lines 15-25.  

* **ID:** BFLA\_ADMIN\_USER\_GET\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Attempt to use /users/{email} with a non-admin API key.  
  * **Exposure Point(s):** /users/{email} endpoint in app/routers/users.py:27-35, RequiresScope([Scope.ADMIN]) at line 30.  
  * **Test Method/Action:** Make a GET request to /users/someuser@example.com using:
    1. Non-admin API key.
    2. API key with users:read scope (if different from admin).
    3. Test access to own user information vs others.
    4. Test user enumeration through email guessing.
  * **Prerequisites:** Non-admin API keys, existing user accounts.  
  * **Expected Secure Outcome:** Request fails with 403 Forbidden and error detail "Not Authorized".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403.  
    2. Verify response body detail: {"detail":"Not Authorized"}.  
    3. Verify no user information disclosure.
    4. Test protection against user enumeration.
  * **Code Reference:** Admin scope requirement in app/routers/users.py:30, endpoint function at lines 27-35.  

* **ID:** BFLA\_ADMIN\_USER\_UPDATE\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Attempt to use /users/update/{email} with a non-admin API key.  
  * **Exposure Point(s):** /users/update/{email} endpoint in app/routers/users.py:38-49, RequiresScope([Scope.ADMIN]) at line 42.  
  * **Test Method/Action:** Make a POST request to /users/update/user@example.com using:
    1. Non-admin API key.
    2. Test attempts to update own user account.
    3. Test attempts to escalate privileges through user updates.
    4. Test parameter manipulation in user updates.
  * **Prerequisites:** Non-admin API keys, existing user accounts, valid update payloads.  
  * **Expected Secure Outcome:** Request fails with 403 Forbidden and error detail "Not Authorized".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403.  
    2. Verify response body detail: {"detail":"Not Authorized"}.  
    3. Verify no user modifications occur.
    4. Test against privilege escalation attempts.
  * **Code Reference:** Admin scope requirement in app/routers/users.py:42, endpoint function at lines 38-49.

### **Advanced Authorization Testing**

* **ID:** BFLA\_SCOPE\_COMBINATION\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Test access control with complex scope combinations and verify proper subset validation logic.  
  * **Exposure Point(s):** RequiresScope subset validation logic in app/auth/dependencies.py:60.  
  * **Test Method/Action:**  
    1. Test API key with [Scope.MODELS_INFERENCE, Scope.ADMIN] accessing /api/v1/chat/completions.  
    2. Test API key with [Scope.MODELS_EMBEDDING, Scope.USERS_READ] accessing /api/v1/embeddings.  
    3. Test API key with all scopes accessing any endpoint.
    4. Test complex multi-scope requirements.
    5. Test edge cases with overlapping scope requirements.
  * **Prerequisites:** API keys with various complex scope combinations.  
  * **Expected Secure Outcome:** Access granted when required scopes are subset of API key scopes. Proper subset validation logic works correctly.  
  * **Verification Steps:**  
    1. Verify successful access (200 OK) when scopes are sufficient.  
    2. Verify subset validation logic works correctly.  
    3. Test edge cases with multiple required scopes.
    4. Verify scope combination precedence rules.
  * **Code Reference:** Scope subset validation in app/auth/dependencies.py:60, set operations for scope checking.

* **ID:** BFLA\_SCOPE\_BYPASS\_ATTEMPT\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Test attempts to bypass scope validation through parameter manipulation, request crafting, and injection attacks.  
  * **Exposure Point(s):** RequiresScope validation logic in app/auth/dependencies.py:54, API key scope extraction.  
  * **Test Method/Action:**  
    1. Attempt to modify scope values in request headers/parameters.  
    2. Test with malformed scope strings in requests.  
    3. Attempt SQL injection or similar attacks on scope validation.
    4. Test scope spoofing through header manipulation.
    5. Test scope injection through request body parameters.
  * **Prerequisites:** API running, knowledge of scope validation implementation, HTTP manipulation tools.  
  * **Expected Secure Outcome:** Scope validation cannot be bypassed through parameter manipulation. All unauthorized access attempts are denied.  
  * **Verification Steps:**  
    1. Verify scope validation is server-side only.  
    2. Verify no bypass through request manipulation.  
    3. Verify scope values come from authenticated API key only.
    4. Test injection attack resistance.
  * **Code Reference:** Scope extraction from API key in app/auth/dependencies.py:54, scope validation logic at lines 60-66.

* **ID:** BFLA\_PRIVILEGE\_ESCALATION\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Test for privilege escalation through scope manipulation, API key modification, and horizontal privilege escalation.  
  * **Exposure Point(s):** API key scope modification, privilege escalation vectors, cross-user access.  
  * **Test Method/Action:**  
    1. Attempt to modify own API key scopes through available endpoints.  
    2. Test if non-admin user can escalate to admin privileges.  
    3. Verify no horizontal privilege escalation between different users.
    4. Test privilege escalation through session manipulation.
    5. Test scope inheritance and escalation patterns.
  * **Prerequisites:** Multiple API keys with different privilege levels, multi-user test environment.  
  * **Expected Secure Outcome:** No privilege escalation possible. Scope modification requires admin privileges only.  
  * **Verification Steps:**  
    1. Verify only admin can modify API key scopes.  
    2. Verify no self-service privilege escalation.  
    3. Verify proper isolation between different users' API keys.
    4. Test cross-user privilege escalation prevention.
  * **Code Reference:** Admin-only API key management in app/routers/tokens.py:19, 37, scope validation patterns.

### **Attack Vector Testing**

* **ID:** BFLA\_HTTP\_METHOD\_TAMPERING\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Attempt to access functions by changing HTTP methods to bypass authorization controls and access unintended functionality.  
  * **Exposure Point(s):** All endpoints, FastAPI's routing and method matching, HTTP method override attacks.  
  * **Test Method/Action:** Test various HTTP method attacks:  
    1. POST, PUT, DELETE on GET /api/v1/models.  
    2. GET, PUT, DELETE on POST /api/v1/chat/completions.  
    3. Verify no unintended function exposure through method variations.
    4. Test HTTP method override headers (X-HTTP-Method-Override).
    5. Test CORS preflight method manipulation.
  * **Prerequisites:** API running, various API keys for testing, HTTP manipulation tools.  
  * **Expected Secure Outcome:** Requests with unsupported HTTP methods result in 405 Method Not Allowed. No bypass of authorization controls.  
  * **Verification Steps:**  
    1. Verify HTTP status code is 405 for disallowed methods.  
    2. Verify no unintended function execution.  
    3. Verify authorization controls are not bypassed.
    4. Test method override attack prevention.
  * **Code Reference:** FastAPI automatic method routing, endpoint definitions in app/routers/api_v1.py.  

* **ID:** BFLA\_ENDPOINT\_DISCOVERY\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Test for unauthorized endpoint discovery, access to undocumented functions, and administrative interface exposure.  
  * **Exposure Point(s):** API endpoint enumeration, hidden or development endpoints, administrative interfaces.  
  * **Test Method/Action:**  
    1. Attempt access to common development endpoints (/debug, /admin, /test).  
    2. Test endpoint enumeration through different HTTP methods.  
    3. Verify no unprotected administrative functions are exposed.
    4. Test for backup, staging, or development endpoint exposure.
    5. Test API versioning endpoint discovery.
  * **Prerequisites:** API running, non-admin API key, endpoint discovery tools.  
  * **Expected Secure Outcome:** No unauthorized access to administrative or development endpoints. Proper 404/405 responses for non-existent endpoints.  
  * **Verification Steps:**  
    1. Verify 404 Not Found for non-existent endpoints.  
    2. Verify no administrative endpoints accessible without admin scope.  
    3. Verify proper error responses don't leak endpoint information.
    4. Test systematic endpoint enumeration resistance.
  * **Code Reference:** Router configuration in app/main.py:107-122, include_in_schema=False for non-public endpoints.

### **Concurrency and Timing Testing**

* **ID:** BFLA\_SCOPE\_VALIDATION\_TIMING\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Test scope validation timing, race conditions in authorization checks, and concurrent access patterns.  
  * **Exposure Point(s):** RequiresScope validation timing in app/auth/dependencies.py:48-66, concurrent access patterns.  
  * **Test Method/Action:**  
    1. Send concurrent requests with different scope requirements.  
    2. Test authorization during API key scope modification.  
    3. Verify consistent scope validation under load.
    4. Test race conditions in scope checking.
    5. Test authorization caching and invalidation.
  * **Prerequisites:** API running, ability to send concurrent requests, load testing tools.  
  * **Expected Secure Outcome:** Scope validation is atomic and consistent. No race conditions allow unauthorized access.  
  * **Verification Steps:**  
    1. Verify consistent authorization results under concurrent load.  
    2. Verify no timing-based authorization bypass.  
    3. Verify scope changes are immediately effective.
    4. Test authorization cache consistency.
  * **Code Reference:** RequiresScope implementation in app/auth/dependencies.py:48-66, atomic scope checking.

* **ID:** BFLA\_CONCURRENT\_AUTHORIZATION\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Test authorization consistency under concurrent access and verify no authorization bypass through concurrent requests.  
  * **Exposure Point(s):** Concurrent authorization processing, database session isolation, authorization state management.  
  * **Test Method/Action:**  
    1. Test concurrent requests from same API key with different endpoints.  
    2. Test concurrent admin operations during scope modifications.  
    3. Test authorization under database load and connection limits.
    4. Test authorization during system failover scenarios.
  * **Prerequisites:** High-concurrency testing environment, multiple API keys, database monitoring.  
  * **Expected Secure Outcome:** Authorization remains consistent under concurrent load. No bypass through concurrency exploitation.  
  * **Verification Steps:**  
    1. Verify authorization consistency under high load.  
    2. Test database session isolation for authorization.  
    3. Verify no authorization bypass through concurrent exploitation.
    4. Test authorization system resilience.
  * **Code Reference:** Database session management, authorization processing under load.

### **Resource and Data Isolation Testing**

* **ID:** BFLA\_RESOURCE\_ISOLATION\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Test proper resource isolation between different API keys and ensure no cross-key data access or unauthorized resource manipulation.  
  * **Exposure Point(s):** API key isolation, resource access controls, manager_id scoping.  
  * **Test Method/Action:**  
    1. Test that API key A cannot access resources created by API key B.  
    2. Verify proper isolation in user management endpoints.  
    3. Test resource-level authorization where applicable.
    4. Test billing and usage data isolation.
    5. Test conversation history isolation (when implemented).
  * **Prerequisites:** Multiple API keys with different managers/users, resource creation capabilities.  
  * **Expected Secure Outcome:** Proper resource isolation between different API keys. No unauthorized cross-key resource access.  
  * **Verification Steps:**  
    1. Verify API keys can only access their own resources.  
    2. Verify admin keys can access all resources as intended.  
    3. Verify no data leakage between different API key contexts.
    4. Test cross-organization resource access prevention.
  * **Code Reference:** API key manager_id field in app/auth/schemas.py:30, resource ownership validation patterns.

* **ID:** BFLA\_CROSS\_TENANT\_ACCESS\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Test cross-tenant access prevention and verify proper tenant isolation in multi-tenant scenarios.  
  * **Exposure Point(s):** Multi-tenant authorization, tenant-specific resource access, cross-tenant data leakage.  
  * **Test Method/Action:**  
    1. Test access to resources from different tenant contexts.  
    2. Test admin operations across tenant boundaries.  
    3. Test tenant-specific scope validation.
    4. Test tenant information disclosure through error messages.
    5. Test tenant enumeration and discovery attacks.
  * **Prerequisites:** Multi-tenant API configuration, multiple tenant API keys.  
  * **Expected Secure Outcome:** Strict tenant isolation. No cross-tenant resource access or information disclosure.  
  * **Verification Steps:**  
    1. Verify tenant-specific resource access controls.  
    2. Test cross-tenant access prevention.  
    3. Verify tenant information protection.
    4. Test tenant boundary enforcement.
  * **Code Reference:** Tenant isolation patterns, manager_id scoping, tenant-specific authorization.

### **Edge Case and Security Boundary Testing**

* **ID:** BFLA\_SCOPE\_EDGE\_CASES\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Test edge cases in scope validation including null scopes, empty scopes, malformed scopes, and boundary conditions.  
  * **Exposure Point(s):** Scope validation edge cases, malformed scope handling, null/empty scope processing.  
  * **Test Method/Action:**  
    1. Test API keys with null or empty scope arrays.  
    2. Test API keys with malformed or invalid scope strings.  
    3. Test scope validation with special characters and encoding.
    4. Test very large scope arrays and scope name lengths.
    5. Test case sensitivity in scope validation.
  * **Prerequisites:** API key creation with various scope configurations, scope validation testing.  
  * **Expected Secure Outcome:** Malformed scopes are handled securely. Edge cases don't bypass authorization.  
  * **Verification Steps:**  
    1. Verify proper handling of null/empty scopes.  
    2. Test malformed scope rejection.  
    3. Verify scope validation robustness.
    4. Test edge case security boundaries.
  * **Code Reference:** Scope validation logic, edge case handling in authorization.

* **ID:** BFLA\_AUTHORIZATION\_BYPASS\_COMPREHENSIVE\_001  
  * **Category Ref:** API5:2023 - BFLA  
  * **Description:** Comprehensive authorization bypass testing including all known attack vectors and novel bypass techniques.  
  * **Exposure Point(s):** Complete authorization system, all bypass vectors, comprehensive security testing.  
  * **Test Method/Action:**  
    1. Test all identified authorization bypass techniques.  
    2. Test novel bypass methods including encoding, injection, and manipulation.  
    3. Test authorization bypass through error conditions.
    4. Test authorization system under failure scenarios.
    5. Test authorization bypass through API misuse patterns.
  * **Prerequisites:** Comprehensive testing environment, all attack vector capabilities, security testing tools.  
  * **Expected Secure Outcome:** No authorization bypass possible through any tested attack vector.  
  * **Verification Steps:**  
    1. Verify all bypass attempts are prevented.  
    2. Test comprehensive security boundary enforcement.  
    3. Verify authorization system resilience.
    4. Test defense-in-depth effectiveness.
  * **Code Reference:** Complete authorization system, all security controls, comprehensive defense patterns.