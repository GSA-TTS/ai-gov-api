# **Test Cases for API2:2023 - Broken Authentication**

## **Introduction**

This document outlines test cases for **API2:2023 - Broken Authentication** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md". These tests aim to verify that the API's authentication mechanisms are robust and cannot be easily bypassed or compromised, particularly in the context of accessing LLM functionalities.  

**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 1.API2:2023)  
* app/auth/dependencies.py:14-45 (especially valid\_api\_key and HTTPBearer)  
* app/auth/repositories.py:32-39 (APIKeyRepository hash-based lookup)  
* app/auth/utils.py:4-14 (key generation and hashing)  
* app/auth/models.py:17 (APIKey model definition with manager_id)  
* app/routers/tokens.py:33-45 (JWT-based user management authentication)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** API2:2023 - Broken Authentication  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** API Key validation logic, token management endpoints, session management.  
* **Test Method/Action:** Sending requests with various invalid/malformed/compromised authentication credentials.  
* **Prerequisites:** Understanding of API key format, generation, and validation processes. Access to create/modify API key states.  
* **Expected Secure Outcome:** Unauthorized access attempts are rejected with appropriate error codes (e.g., 401 Unauthorized). Authentication mechanisms are resistant to common attacks.  
* **Verification Steps:** Check HTTP status codes, error messages for clarity and security (no info leakage), and server logs for suspicious activity.

## **Test Cases**

### **Basic Authentication Failures**

* **ID:** BA\_AUTH\_001  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Attempt API access with a completely missing Authorization header.  
  * **Exposure Point(s):** All protected API endpoints (/api/v1/models, /api/v1/chat/completions, /api/v1/embeddings), HTTPBearer validation.  
  * **Test Method/Action:** Make requests to protected endpoints without including the Authorization header.  
  * **Prerequisites:** API is running, access to protected endpoints.  
  * **Expected Secure Outcome:** Request fails with a 403 Forbidden (FastAPI's HTTPBearer default behavior when no credentials provided) and error message "Not authenticated."  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403.  
    2. Inspect response body for the expected error detail: {"detail":"Not authenticated"}.  
    3. Verify no partial access or information leakage.  
  * **Code Reference:** HTTPBearer security dependency in app/auth/dependencies.py:14, applied to valid_api_key function at app/auth/dependencies.py:16-20.  

* **ID:** BA\_AUTH\_002  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Attempt API access with malformed Authorization headers (wrong scheme, missing token, format errors).  
  * **Exposure Point(s):** All protected API endpoints, HTTPBearer validation logic, header parsing.  
  * **Test Method/Action:**  
    1. Make request with Authorization: Basic somecredentials.  
    2. Make request with Authorization: Bearer (no token).  
    3. Make request with Authorization: Bearer\<token\_without\_space\>.  
    4. Make request with Authorization: bearer \<lowercase\_scheme\>.  
    5. Make request with Authorization: BearerXYZ\<no\_space\_scheme\>.  
  * **Prerequisites:** API is running, understanding of HTTP Authorization header format.  
  * **Expected Secure Outcome:** Request fails with 403 Forbidden and error message "Not authenticated" for invalid Bearer format or wrong scheme.  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403 for each malformed header.  
    2. Inspect response body for error detail: {"detail":"Not authenticated"}.  
    3. Verify consistent error handling across all malformed formats.  
  * **Code Reference:** HTTPBearer scheme validation in app/auth/dependencies.py:14, automatic rejection of non-Bearer schemes.  

* **ID:** BA\_AUTH\_003  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Attempt API access with syntactically valid but non-existent API key.  
  * **Exposure Point(s):** APIKeyRepository.get\_by\_api\_key\_value logic in app/auth/repositories.py:32-39, hash-based lookup.  
  * **Test Method/Action:** Make requests using API key strings that follow the correct format (e.g., test\_prefix\_xxxxxxxxxxxx) but whose SHA256 hash is not present in the database.  
  * **Prerequisites:** API is running, database is accessible, understanding of API key format.  
  * **Expected Secure Outcome:** Request fails with 401 Unauthorized and error detail "Missing or invalid API key".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 401.  
    2. Verify response body detail: {"detail":"Missing or invalid API key"}.  
    3. Verify no information leakage about key format or validation process.  
  * **Code Reference:** Hash-based lookup in app/auth/repositories.py:32-39, validation logic in app/auth/dependencies.py:32-36.  

### **API Key State and Lifecycle Testing**

* **ID:** BA\_AUTH\_004  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Attempt API access with an API key that is marked as inactive (is\_active = False).  
  * **Exposure Point(s):** is\_active check in app/auth/dependencies.py:32, APIKeyRepository.set_is_active method.  
  * **Test Method/Action:**  
    1. Create an API key and set its is\_active status to False in the database.  
    2. Attempt to use this key to access a protected endpoint.  
    3. Test immediate deactivation scenarios.  
    4. Test reactivation of previously inactive keys.  
  * **Prerequisites:** API is running, ability to modify API key status in database or use APIKeyRepository.set_is_active().  
  * **Expected Secure Outcome:** Request fails with 401 Unauthorized and error detail "Missing or invalid API key".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 401.  
    2. Verify response body detail: {"detail":"Missing or invalid API key"}.  
    3. Verify no access granted during state transitions.  
    4. Test activation/deactivation state persistence.  
  * **Code Reference:** Active status validation in app/auth/dependencies.py:32, APIKeyRepository.set_is_active() method in app/auth/repositories.py:25-30.  

* **ID:** BA\_AUTH\_005  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Attempt API access with an API key that has expired (expires\_at is in the past).  
  * **Exposure Point(s):** expires\_at check in app/auth/dependencies.py:37-43, datetime comparison logic.  
  * **Test Method/Action:**  
    1. Create an API key with is\_active = True and an expires\_at timestamp in the past.  
    2. Attempt to use this key to access a protected endpoint.  
    3. Test keys expiring at exact boundary conditions (seconds before/after expiration).  
    4. Test timezone handling in expiration logic.  
  * **Prerequisites:** API is running, ability to create/modify API keys with specific expiry dates.  
  * **Expected Secure Outcome:** Request fails with 401 Unauthorized and error detail "API key is expired".  
  * **Verification Steps:**  
    1. Verify HTTP status code is 401.  
    2. Verify response body detail: {"detail":"API key is expired"}.  
    3. Test boundary conditions for expiration timing.  
    4. Verify timezone consistency in expiration checks.  
  * **Code Reference:** Expiration validation in app/auth/dependencies.py:37-43, datetime comparison logic using datetime.now().  

* **ID:** BA\_AUTH\_006  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Attempt API access with an API key that follows correct format but has hash mismatch (simulated tampering).  
  * **Exposure Point(s):** Hash-based validation in app/auth/repositories.py:32-39, SHA256 comparison logic.  
  * **Test Method/Action:**  
    1. Provide an API key string whose prefix might exist, but the random part does not match any stored hash.  
    2. Test keys with single character modifications.  
    3. Test keys with prefix modifications.  
    4. Test keys with systematic character substitutions.  
  * **Prerequisites:** API is running, understanding of key format and hashing.  
  * **Expected Secure Outcome:** Request fails with 401 Unauthorized ("Missing or invalid API key").  
  * **Verification Steps:**  
    1. Verify HTTP status code is 401.  
    2. Verify response body detail: {"detail":"Missing or invalid API key"}.  
    3. Verify no timing-based information disclosure.  
    4. Test various tampering scenarios.  
  * **Code Reference:** SHA256 hash comparison in app/auth/repositories.py:34, hash generation in app/auth/utils.py:12.  

### **Cryptographic Security Testing**

* **ID:** BA\_AUTH\_007  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test for weak API key generation and verify entropy characteristics.  
  * **Exposure Point(s):** secrets.token\_urlsafe(num\_bytes) usage in app/auth/utils.py:9, key generation randomness.  
  * **Test Method/Action:**  
    1. Review the key generation logic for cryptographic security.  
    2. Generate multiple keys and verify uniqueness and randomness characteristics.  
    3. Test key generation under various load conditions.  
    4. Analyze key distribution patterns for bias.  
  * **Prerequisites:** Access to key generation code and ability to call generate_api_key function.  
  * **Expected Secure Outcome:** Keys are generated with sufficient randomness (secrets.token\_urlsafe(32) provides 256 bits of entropy). No patterns or collisions in reasonable sample size.  
  * **Verification Steps:**  
    1. Code review confirms use of cryptographically secure random number generator (secrets module).  
    2. Verify default num\_bytes parameter is 32 (providing 256 bits of entropy).  
    3. Generate 10,000+ keys and verify no duplicates.  
    4. Test randomness distribution using statistical analysis.  
  * **Code Reference:** Key generation in app/auth/utils.py:4-14, secrets.token_urlsafe usage at line 9.  

* **ID:** BA\_AUTH\_008  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test secure storage of API keys and verify proper hashing implementation.  
  * **Exposure Point(s):** APIKey.hashed\_key field in the database, SHA256 hashing logic in app/auth/utils.py:12.  
  * **Test Method/Action:**  
    1. Create a new API key using scripts/create\_admin\_user.py. Note the plaintext key.  
    2. Inspect the api\_keys table in the database for the corresponding record.  
    3. Verify hash algorithm strength and implementation.  
    4. Test hash consistency across multiple generations.  
  * **Prerequisites:** Database access, admin user creation capability.  
  * **Expected Secure Outcome:** The hashed\_key column stores a SHA256 hash of the API key, not the plaintext key.  
  * **Verification Steps:**  
    1. Verify the value in hashed\_key is not the plaintext key.  
    2. Manually hash the plaintext key using SHA256 and compare it to the stored value.  
    3. Verify hash length is 64 characters (SHA256 hex output).  
    4. Verify hash uniqueness across multiple key generations.  
  * **Code Reference:** Hash generation in app/auth/utils.py:12, hash storage in APIKey model hashed_key field, repository lookup in app/auth/repositories.py:34.  

* **ID:** BA\_AUTH\_011  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test if API key validation is susceptible to timing attacks.  
  * **Exposure Point(s):** Hash comparison logic in app/auth/utils.py:21-22, constant-time comparison implementation.  
  * **Test Method/Action:**  
    1. Verify that constant-time comparison is used for hash validation.  
    2. Measure response times for various invalid keys to detect timing differences.  
    3. Test with keys that match partial hashes vs completely different hashes.  
    4. Analyze timing patterns across multiple requests.  
  * **Prerequisites:** Access to authentication code, valid API key for baseline timing, timing measurement tools.  
  * **Expected Secure Outcome:** Hash comparison uses secrets.compare\_digest for constant-time comparison, preventing timing attack exploitation.  
  * **Verification Steps:**  
    1. Code review confirms secrets.compare\_digest usage in app/auth/utils.py:22.  
    2. Measure response times for various invalid keys to verify consistent timing.  
    3. Verify no timing-based information leakage occurs during hash comparison.  
    4. Test under various load conditions for timing consistency.  
  * **Code Reference:** Constant-time comparison in app/auth/utils.py:21-22, secrets.compare_digest usage prevents timing attacks.  
  * **Implementation Status:** ✅ Correctly implemented with secrets.compare_digest.  

### **Attack Vector Testing**

* **ID:** BA\_AUTH\_009  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test for credential stuffing vulnerability and brute-force protection.  
  * **Exposure Point(s):** All protected endpoints, rate limiting capabilities, authentication failure handling.  
  * **Test Method/Action:**  
    1. Attempt multiple rapid authentication attempts using various invalid API keys.  
    2. Test systematic brute force attacks with different patterns.  
    3. Test distributed attacks from multiple IP addresses.  
    4. Test credential stuffing with common API key patterns.  
  * **Prerequisites:** API is running, ability to make rapid sequential requests, multiple IP addresses for testing.  
  * **Expected Secure Outcome:** The API should implement rate limiting on authentication attempts to prevent brute force attacks. **Current implementation lacks explicit rate limiting**.  
  * **Verification Steps:**  
    1. Make 100+ rapid failed authentication attempts from same IP.  
    2. Observe if rate limiting (429 Too Many Requests) is triggered.  
    3. Test account lockout mechanisms if implemented.  
    4. **Note: Current implementation in app/auth/dependencies.py lacks rate limiting - this is a security enhancement opportunity**.  
  * **Code Reference:** Authentication logic in app/auth/dependencies.py:16-45, no current rate limiting implementation identified.  
  * **Security Gap:** **HIGH PRIORITY** - Rate limiting should be added to prevent brute force attacks.  

* **ID:** BA\_AUTH\_014  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test authentication bypass through request header manipulation and injection attacks.  
  * **Exposure Point(s):** HTTPBearer header parsing, case sensitivity, encoding issues, header injection.  
  * **Test Method/Action:**  
    1. Test case variations: authorization, AUTHORIZATION, Authorization.  
    2. Test encoding variations: Bearer token, Bearer%20token, Bearer\ttoken.  
    3. Test multiple Authorization headers in single request.  
    4. Test header injection attacks with CRLF sequences.  
    5. Test Unicode and special character encoding in headers.  
  * **Prerequisites:** API is running, valid API key for comparison, HTTP manipulation tools.  
  * **Expected Secure Outcome:** Only properly formatted "Authorization: Bearer \<token\>" should be accepted. Case sensitivity and encoding manipulations should be rejected.  
  * **Verification Steps:**  
    1. Verify only correct header format is accepted.  
    2. Verify case-sensitive header name enforcement.  
    3. Verify protection against header injection attacks.  
    4. Test encoding attack resistance.  
  * **Code Reference:** HTTPBearer implementation in app/auth/dependencies.py:14, FastAPI's automatic header parsing.

* **ID:** BA\_AUTH\_015  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test API key leakage through error messages, logs, and debug information.  
  * **Exposure Point(s):** Error message content, application logging in app/logs/middleware.py:38, exception handling.  
  * **Test Method/Action:**  
    1. Send malformed API key and inspect error messages for key fragments.  
    2. Check application logs for any plaintext API key exposure.  
    3. Test various authentication failure scenarios for information disclosure.  
    4. Test error conditions that might expose internal state.  
    5. Test stack trace exposure in error responses.  
  * **Prerequisites:** API is running, access to application logs, error condition testing capabilities.  
  * **Expected Secure Outcome:** Error messages should not contain API key fragments. Logs should only contain key IDs, not plaintext keys.  
  * **Verification Steps:**  
    1. Verify error responses contain no key material.  
    2. Verify logs contain only key_id (app/auth/dependencies.py:30), not plaintext keys.  
    3. Ensure no key material in exception stack traces.  
    4. Test debug mode information disclosure.  
  * **Code Reference:** Error handling in app/auth/dependencies.py:33-43, logging of key_id in app/logs/middleware.py:38.

### **Scope and Authorization Testing**

* **ID:** BA\_AUTH\_012  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test privilege escalation through user management endpoints and scope bypass.  
  * **Exposure Point(s):** User management endpoints in app/routers/users.py, admin scope requirements, RequiresScope validation.  
  * **Test Method/Action:**  
    1. Attempt to access admin-only user management endpoints with non-admin credentials.  
    2. Test scope manipulation in API key requests.  
    3. Test privilege escalation through session manipulation.  
    4. Test cross-scope access attempts.  
  * **Prerequisites:** Non-admin user session (JWT from /auth/token), admin endpoints knowledge.  
  * **Expected Secure Outcome:** Admin-only endpoints should reject non-admin access with 403 Forbidden.  
  * **Verification Steps:**  
    1. Attempt to access /users/update/{email} with non-admin JWT.  
    2. Verify 403 Forbidden response.  
    3. Confirm RequiresScope([Scope.ADMIN]) protection is enforced.  
    4. Test scope validation consistency.  
  * **Code Reference:** Admin scope protection in app/routers/users.py, RequiresScope implementation in app/auth/dependencies.py:48-66.  
  * **Implementation Status:** ✅ Correctly protected with admin scope requirements.

* **ID:** BA\_AUTH\_013  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test scope validation for models:inference vs models:embedding access control and scope bypass attempts.  
  * **Exposure Point(s):** RequiresScope validation in app/auth/dependencies.py:48-66, endpoint scope requirements, scope enforcement.  
  * **Test Method/Action:**  
    1. Attempt to access /api/v1/chat/completions with API key having only models:embedding scope.  
    2. Attempt to access /api/v1/embeddings with API key having only models:inference scope.  
    3. Test scope manipulation through request parameters.  
    4. Test scope inheritance and escalation attempts.  
    5. Test multiple scope combinations and edge cases.  
  * **Prerequisites:** API keys with specific scopes (models:inference only, models:embedding only), understanding of scope system.  
  * **Expected Secure Outcome:** Requests fail with 403 Forbidden and error detail "Not Authorized" when accessing endpoints without required scope.  
  * **Verification Steps:**  
    1. Verify HTTP status code is 403 for scope mismatches.  
    2. Verify response body detail: {"detail":"Not Authorized"}.  
    3. Test scope validation consistency across endpoints.  
    4. Verify no scope bypass through parameter manipulation.  
  * **Code Reference:** Scope validation in app/auth/dependencies.py:60-66, endpoint scope requirements in app/routers/api_v1.py:36, 65.

### **Concurrency and State Management Testing**

* **ID:** BA\_AUTH\_016  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test concurrent authentication requests for race conditions and state corruption.  
  * **Exposure Point(s):** Database session handling in app/db/session.py:23-32, concurrent API key lookups, state management.  
  * **Test Method/Action:**  
    1. Send multiple concurrent requests using the same valid API key.  
    2. Send multiple concurrent requests using different API keys.  
    3. Test concurrent requests during API key status changes (activate/deactivate).  
    4. Test race conditions in authentication state management.  
    5. Test concurrent authentication under high load.  
  * **Prerequisites:** API is running, ability to send concurrent requests, load testing tools.  
  * **Expected Secure Outcome:** Concurrent authentication should work correctly without race conditions. No authentication bypass due to concurrent access.  
  * **Verification Steps:**  
    1. Verify all concurrent requests with valid keys succeed.  
    2. Verify no authentication bypass occurs during concurrent access.  
    3. Verify database session isolation prevents race conditions.  
    4. Test authentication consistency under load.  
  * **Code Reference:** Database session management in app/db/session.py:23-32, API key lookup in app/auth/repositories.py:32-39.

* **ID:** BA\_AUTH\_017  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test authentication state persistence, cleanup, and isolation between requests.  
  * **Exposure Point(s):** Request state management, session cleanup between requests, state isolation.  
  * **Test Method/Action:**  
    1. Make authenticated request and verify request.state.api_key_id is set.  
    2. Make subsequent request with different/invalid key and verify state isolation.  
    3. Test for any authentication state bleeding between requests.  
    4. Test state cleanup after request completion.  
    5. Test state isolation under concurrent requests.  
  * **Prerequisites:** API is running, valid and invalid API keys, request state inspection capabilities.  
  * **Expected Secure Outcome:** Authentication state should be properly isolated between requests. No state persistence should affect subsequent requests.  
  * **Verification Steps:**  
    1. Verify request.state.api_key_id is set correctly for each request.  
    2. Verify no authentication state carries over between requests.  
    3. Verify proper cleanup of authentication context.  
    4. Test state isolation consistency.  
  * **Code Reference:** Request state management in app/auth/dependencies.py:29-30, state isolation per request.

### **Advanced Authentication Security Testing**

* **ID:** BA\_AUTH\_018  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test JWT token security for user management authentication separate from API key system.  
  * **Exposure Point(s):** JWT-protected endpoints in app/routers/tokens.py:33-45, JWT validation, token lifecycle.  
  * **Test Method/Action:**  
    1. Attempt access with an expired JWT to user management endpoints.  
    2. Attempt access with a JWT signed with wrong key or alg:none.  
    3. Attempt access with a JWT with manipulated payload (user_id, scopes).  
    4. Test JWT replay attacks and token reuse.  
    5. Test JWT timing attacks and side-channel vulnerabilities.  
  * **Prerequisites:** JWT-secured endpoint, ability to generate/manipulate JWTs, JWT manipulation tools.  
  * **Expected Secure Outcome:** All invalid JWTs are rejected with 401 Unauthorized. JWT validation follows security best practices.  
  * **Verification Steps:**  
    1. Verify HTTP status codes and error messages for JWT validation failures.  
    2. Test JWT signature validation strength.  
    3. Verify proper JWT expiration handling.  
    4. Test JWT algorithm confusion attacks.  
  * **Code Reference:** JWT handling in app/routers/tokens.py:33-45, user authentication separate from API key system.  
  * **Implementation Note:** Current focus is API key authentication for LLM access, JWT used for user management.  

* **ID:** BA\_AUTH\_019  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test authentication bypass through parameter pollution and injection attacks.  
  * **Exposure Point(s):** Parameter parsing, request processing, authentication parameter handling.  
  * **Test Method/Action:**  
    1. Test parameter pollution with multiple authorization parameters.  
    2. Test parameter injection in query strings and request bodies.  
    3. Test HTTP parameter override attacks (X-HTTP-Method-Override).  
    4. Test request smuggling scenarios affecting authentication.  
    5. Test URL encoding and decoding attacks on authentication parameters.  
  * **Prerequisites:** API is running, HTTP manipulation tools, understanding of parameter processing.  
  * **Expected Secure Outcome:** Parameter manipulation should not bypass authentication. All injection attempts should be rejected.  
  * **Verification Steps:**  
    1. Verify parameter pollution resistance.  
    2. Test injection attack prevention.  
    3. Verify HTTP method override protection.  
    4. Test URL encoding attack resistance.  
  * **Code Reference:** Parameter processing in FastAPI framework, authentication parameter handling.

* **ID:** BA\_AUTH\_020  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test authentication system resilience under stress and failure conditions.  
  * **Exposure Point(s):** Authentication system performance, database connectivity, error handling under load.  
  * **Test Method/Action:**  
    1. Test authentication performance under high request volume.  
    2. Test authentication behavior during database connectivity issues.  
    3. Test authentication recovery after system failures.  
    4. Test authentication consistency during service restarts.  
    5. Test authentication behavior under memory pressure.  
  * **Prerequisites:** API is running, load testing tools, ability to simulate failure conditions.  
  * **Expected Secure Outcome:** Authentication system should fail securely under stress. No authentication bypass during failure conditions.  
  * **Verification Steps:**  
    1. Verify authentication performance under load.  
    2. Test secure failure modes during database issues.  
    3. Verify authentication recovery consistency.  
    4. Test error handling under stress conditions.  
  * **Code Reference:** Authentication resilience patterns, error handling in app/auth/dependencies.py, database failure handling.

* **ID:** BA\_AUTH\_021  
  * **Category Ref:** API2:2023 - Broken Authentication  
  * **Description:** Test cross-organization authentication isolation and prevent manager_id bypass.  
  * **Exposure Point(s):** manager_id validation, cross-organization access prevention, authentication scoping.  
  * **Test Method/Action:**  
    1. Test authentication with API keys from different organizations.  
    2. Test manager_id manipulation in authentication context.  
    3. Test cross-organization authentication state bleeding.  
    4. Test organization-specific authentication policies.  
    5. Test authentication bypass through organization spoofing.  
  * **Prerequisites:** API keys from multiple organizations, understanding of manager_id system.  
  * **Expected Secure Outcome:** Authentication should be properly scoped by organization. No cross-organization access through authentication bypass.  
  * **Verification Steps:**  
    1. Verify manager_id isolation in authentication.  
    2. Test cross-organization access prevention.  
    3. Verify authentication state scoping.  
    4. Test organization spoofing resistance.  
  * **Code Reference:** manager_id handling in app/auth/models.py:17, authentication scoping, cross-organization isolation.