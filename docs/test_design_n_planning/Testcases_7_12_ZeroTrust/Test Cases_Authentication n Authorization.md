# Test Cases for Zero Trust: Authentication & Authorization

This document outlines test cases for the Authentication & Authorization mechanisms of the GSAi API Framework, based on the Zero Trust testing strategies detailed in Section 7.12 of the TestPlan.md.

**Test Cases Summary: 19 (Original: 11, Enhanced: +8)**

**Referenced Code Components:**
* **Authentication Implementation:** app/auth/dependencies.py:16-45 valid_api_key function using HTTPBearer for API key extraction and validation
* **Authorization Framework:** app/auth/dependencies.py:48-66 RequiresScope class implementing scope-based authorization with set-based permission checking
* **Key Storage Model:** app/auth/models.py:12-32 APIKey model with hashed_key storage, scopes array, expiration, and activity tracking
* **Cryptographic Utilities:** app/auth/utils.py:4-24 secure key generation using secrets.token_urlsafe and SHA256 hashing with constant-time comparison
* **Scope Definitions:** app/auth/schemas.py:10-20 comprehensive scope enumeration including MODELS_INFERENCE, MODELS_EMBEDDING, ADMIN
* **Endpoint Protection:** All LLM endpoints in app/routers/api_v1.py:33-70 protected with RequiresScope dependencies
* **Request Context Tracking:** app/logs/middleware.py:38-39 binds API key ID to request context for comprehensive audit trails

### **ZTA_AUTH_001**
* **ID:** ZTA_AUTH_001
* **Category Ref:** Authentication & Authorization
* **Description:** Test API access with a missing API key.
* **Exposure Point(s):** API endpoints (e.g., `/api/v1/models`, `/api/v1/chat/completions`), HTTPBearer dependency (`app/auth/dependencies.py`).
* **Test Method/Action:** Send a GET request to `/api/v1/models` without an `Authorization` header.
* **Prerequisites:** API is running.
* **Expected Secure Outcome:** The API request is rejected due to missing authentication. This aligns with the Zero Trust principle of verifying every request.
* **Verification Steps:**
    1.  Verify the HTTP status code is 401 (or 403 depending on `HTTPBearer` behavior for missing header).
    2.  Verify the response body contains an appropriate error message (e.g., `{"detail": "Not authenticated"}`).
    3.  Verify no LLM processing logic is reached.
    4.  Verify server logs indicate an authentication failure.

### **ZTA_AUTH_002**
* **ID:** ZTA_AUTH_002
* **Category Ref:** Authentication & Authorization
* **Description:** Test API access with an incorrectly formatted `Authorization` header (e.g., not "Bearer <token>").
* **Exposure Point(s):** API endpoints, HTTPBearer dependency (`app/auth/dependencies.py`).
* **Test Method/Action:** Send a GET request to `/api/v1/models` with an `Authorization` header like "Token some_key" or "Bearer" (missing token).
* **Prerequisites:** API is running.
* **Expected Secure Outcome:** The API request is rejected due to malformed authentication credentials.
* **Verification Steps:**
    1.  Verify the HTTP status code is 401 (or 403).
    2.  Verify the response body indicates invalid authentication credentials (e.g., `{"detail": "Not authenticated"}` or `{"detail": "Invalid authentication credentials"}`).
    3.  Verify no LLM processing logic is reached.

### **ZTA_AUTH_003**
* **ID:** ZTA_AUTH_003
* **Category Ref:** Authentication & Authorization
* **Description:** Test API access with a non-existent API key (syntactically valid but not in the database).
* **Exposure Point(s):** `valid_api_key` function (`app/auth/dependencies.py:16-45`), `APIKeyRepository.get_by_api_key_value`.
* **Test Method/Action:** Send a GET request to `/api/v1/models` with an `Authorization` header "Bearer test_prefix_nonExistentKey123".
* **Prerequisites:** API is running. The key "test_prefix_nonExistentKey123" (and its hash) does not exist in the `api_keys` table.
* **Expected Secure Outcome:** The API request is rejected because the API key is invalid.
* **Verification Steps:**
    1.  Verify the HTTP status code is 401.
    2.  Verify the response body is `{"detail": "Missing or invalid API key"}`.
    3.  Verify server logs indicate an invalid API key attempt.

### **ZTA_AUTH_004**
* **ID:** ZTA_AUTH_004
* **Category Ref:** Authentication & Authorization
* **Description:** Test API access with an inactive API key.
* **Exposure Point(s):** `valid_api_key` function (`app/auth/dependencies.py:25-44`), `APIKey.is_active` field (`app/auth/models.py`).
* **Test Method/Action:** Send a GET request to `/api/v1/models` using an API key that is marked as `is_active = False` in the database.
* **Prerequisites:** API is running. An API key exists in the database with `is_active = False`.
* **Expected Secure Outcome:** The API request is rejected because the API key is inactive.
* **Verification Steps:**
    1.  Verify the HTTP status code is 401.
    2.  Verify the response body is `{"detail": "Missing or invalid API key"}`.
    3.  Verify server logs indicate an attempt to use an inactive key.

### **ZTA_AUTH_005**
* **ID:** ZTA_AUTH_005
* **Category Ref:** Authentication & Authorization
* **Description:** Test API access with an expired API key.
* **Exposure Point(s):** `valid_api_key` function (`app/auth/dependencies.py:25-44`), `APIKey.expires_at` field (`app/auth/models.py`).
* **Test Method/Action:** Send a GET request to `/api/v1/models` using an API key whose `expires_at` timestamp is in the past.
* **Prerequisites:** API is running. An API key exists in the database with `expires_at` set to a past date/time.
* **Expected Secure Outcome:** The API request is rejected because the API key is expired.
* **Verification Steps:**
    1.  Verify the HTTP status code is 401.
    2.  Verify the response body is `{"detail": "API key is expired"}`.
    3.  Verify server logs indicate an attempt to use an expired key.

### **ZTA_AUTH_006**
* **ID:** ZTA_AUTH_006
* **Category Ref:** Authentication & Authorization
* **Description:** Test API access to a scope-protected endpoint (e.g., `/api/v1/chat/completions`) with an API key lacking the required scope (e.g., `models:inference`).
* **Exposure Point(s):** `RequiresScope` class (`app/auth/dependencies.py:48-66`), `APIKey.scopes` field (`app/auth/models.py`), LLM endpoints in `app/routers/api_v1.py`.
* **Test Method/Action:** Send a POST request to `/api/v1/chat/completions` using a valid, active, non-expired API key that has scopes like `["models:embedding"]` but not `["models:inference"]`.
* **Prerequisites:** API is running. An API key exists with scopes that do not include `models:inference`.
* **Expected Secure Outcome:** The API request is rejected due to insufficient scope, enforcing granular authorization.
* **Verification Steps:**
    1.  Verify the HTTP status code is 401.
    2.  Verify the response body is `{"detail": "Not Authorized"}`.
    3.  Verify no LLM processing occurs for the chat completion.
    4.  Verify server logs indicate an authorization failure due to scope.

### **ZTA_AUTH_007**
* **ID:** ZTA_AUTH_007
* **Category Ref:** Authentication & Authorization
* **Description:** Test API access to `/api/v1/models` (which only requires `valid_api_key`) with an API key that has specific scopes (e.g., `models:inference`).
* **Exposure Point(s):** `valid_api_key` dependency on `/api/v1/models` endpoint.
* **Test Method/Action:** Send a GET request to `/api/v1/models` using a valid, active, non-expired API key that has `models:inference` scope.
* **Prerequisites:** API is running.
* **Expected Secure Outcome:** The API request is successful as the key is valid, and this endpoint does not require a specific scope beyond basic authentication.
* **Verification Steps:**
    1.  Verify the HTTP status code is 200.
    2.  Verify the response body contains the list of models.

### **ZTA_AUTH_008**
* **ID:** ZTA_AUTH_008
* **Category Ref:** Authentication & Authorization
* **Description:** Verify strength of API key generation.
* **Exposure Point(s):** `generate_api_key` function (`app/auth/utils.py:4-24`).
* **Test Method/Action:** This is a code review and process verification. Review the `generate_api_key` function.
* **Prerequisites:** Access to source code.
* **Expected Secure Outcome:** API keys are generated with sufficient entropy (e.g., `secrets.token_urlsafe(32)` is used) and are not guessable or predictable.
* **Verification Steps:**
    1.  Confirm `secrets.token_urlsafe` is used for key generation.
    2.  Confirm the default byte length (e.g., 32 bytes) provides adequate randomness.
    3.  Generate multiple keys and visually inspect for randomness (no obvious patterns).

### **ZTA_AUTH_009**
* **ID:** ZTA_AUTH_009
* **Category Ref:** Authentication & Authorization
* **Description:** Verify secure hashing of API keys.
* **Exposure Point(s):** `hash_api_key`, `verify_api_key` functions (`app/auth/utils.py:4-24`), `APIKey.hashed_key` storage (`app/auth/models.py`).
* **Test Method/Action:** Code review and database inspection.
* **Prerequisites:** Access to source code and database.
* **Expected Secure Outcome:** API keys are hashed using a strong algorithm (SHA256) before storage. Verification uses a constant-time comparison (`secrets.compare_digest`).
* **Verification Steps:**
    1.  Confirm `hashlib.sha256` is used for hashing.
    2.  Confirm `secrets.compare_digest` is used for verification.
    3.  Inspect the `api_keys` table in the database and confirm that the `hashed_key` column stores hashed values, not plaintext keys.

### **ZTA_AUTH_010**
* **ID:** ZTA_AUTH_010
* **Category Ref:** Authentication & Authorization
* **Description:** Test for implicit trust after initial authentication (conceptual for current per-request design).
* **Exposure Point(s):** All authenticated endpoints. `app/auth/dependencies.py`.
* **Test Method/Action:** This is primarily a design review. Verify that authentication and authorization checks are performed for every request to protected resources.
* **Prerequisites:** Understanding of the API's request processing flow.
* **Expected Secure Outcome:** Authentication (API key validation) and authorization (scope checking) are re-evaluated for each individual API request. No session or long-lived trust is established based on a single successful authentication.
* **Verification Steps:**
    1.  Review code in `app/routers/api_v1.py` to confirm that dependencies like `valid_api_key` and `RequiresScope` are applied to all relevant endpoints and thus invoked per request.
    2.  Consider a sequence of calls: Call 1 (valid key, valid scope) succeeds. Call 2 to a different endpoint (or same) with the same key but now (hypothetically) the key's scope is insufficient or key is inactive; Call 2 should fail. (This requires ability to modify key state between calls for a full test).

### **ZTA_AUTH_011**
* **ID:** ZTA_AUTH_011
* **Category Ref:** Authentication & Authorization
* **Description:** Verify that API key ID is bound to request context for audit trails.
* **Exposure Point(s):** `StructlogMiddleware` (`app/logs/middleware.py:38-39`), `valid_api_key` dependency (`app/auth/dependencies.py`).
* **Test Method/Action:** Make a successful API call with a valid API key. Inspect server logs.
* **Prerequisites:** API is running. Logging is configured.
* **Expected Secure Outcome:** The `api_key_id` (or a similar non-secret identifier of the key) is logged for authenticated requests, enabling correlation of requests with the used identity in audit trails.
* **Verification Steps:**
    1.  Make a successful request to an authenticated endpoint (e.g., `/api/v1/models`).
    2.  Inspect the server logs for that request (using `request_id`).
    3.  Confirm that a field identifying the API key (e.g., `api_key_id` containing the integer ID of the key) is present in the log entry.

---

## Enhanced Test Cases: Advanced Authentication & Authorization

### 1. Multi-Factor Authentication for Administrative Operations

* **ID:** ZTA_AUTH_012
    * **Category Ref:** Authentication & Authorization
    * **Description:** Test multi-factor authentication requirements for administrative operations including API key management and user account operations.
    * **Exposure Point(s):** Administrative endpoints, JWT authentication in app/routers/tokens.py, user management in app/routers/users.py.
    * **Test Method/Action:**
        1. Attempt administrative operations with only password authentication
        2. Test MFA token validation for administrative actions
        3. Validate MFA bypass prevention mechanisms
        4. Test administrative session management and timeout
        5. Verify audit logging for administrative authentication events
    * **Prerequisites:** MFA infrastructure, administrative test accounts, audit logging system.
    * **Expected Secure Outcome:** All administrative operations require multi-factor authentication. MFA bypass attempts are blocked and logged. Administrative sessions have appropriate timeout and audit trails.
    * **Verification Steps:** Test MFA enforcement, validate bypass prevention, verify session management, check audit logging completeness.

### 2. Risk-Based Authentication

* **ID:** ZTA_AUTH_013
    * **Category Ref:** Authentication & Authorization
    * **Description:** Test risk-based authentication that adapts authentication requirements based on request context, behavioral patterns, and threat intelligence.
    * **Exposure Point(s):** Request context in app/logs/middleware.py:17-24, authentication dependencies, risk assessment engines.
    * **Test Method/Action:**
        1. Test authentication adaptation based on client IP reputation
        2. Validate behavioral pattern analysis for authentication decisions
        3. Test threat intelligence integration for authentication risk assessment
        4. Validate adaptive authentication challenges based on risk level
        5. Test risk scoring and authentication requirement escalation
    * **Prerequisites:** Risk assessment infrastructure, threat intelligence feeds, behavioral analytics, adaptive authentication system.
    * **Expected Secure Outcome:** Authentication requirements adapt to risk level. High-risk requests face additional authentication challenges. Risk scoring accurately reflects threat level.
    * **Verification Steps:** Test risk assessment accuracy, validate adaptive challenges, verify threat intelligence integration, measure authentication adaptation effectiveness.

### 3. Continuous Authentication Validation

* **ID:** ZTA_AUTH_014
    * **Category Ref:** Authentication & Authorization
    * **Description:** Test continuous validation of authentication state throughout request processing with real-time revocation and status checking.
    * **Exposure Point(s):** API key validation in app/auth/dependencies.py:25-44, real-time status checking, revocation mechanisms.
    * **Test Method/Action:**
        1. Test real-time API key status validation during request processing
        2. Validate immediate revocation effectiveness across active sessions
        3. Test authentication state monitoring and anomaly detection
        4. Validate continuous authorization re-evaluation
        5. Test authentication cache invalidation and refresh mechanisms
    * **Prerequisites:** Real-time authentication infrastructure, revocation systems, status monitoring, cache management.
    * **Expected Secure Outcome:** Authentication status validated continuously. Revoked keys immediately blocked. Authentication anomalies detected and responded to automatically.
    * **Verification Steps:** Test continuous validation effectiveness, verify immediate revocation, validate anomaly detection, check cache management accuracy.

### 4. Advanced Scope-Based Authorization

* **ID:** ZTA_AUTH_015
    * **Category Ref:** Authentication & Authorization
    * **Description:** Test advanced scope-based authorization with hierarchical permissions, dynamic scope assignment, and context-aware authorization decisions.
    * **Exposure Point(s):** RequiresScope implementation in app/auth/dependencies.py:48-66, scope definitions in app/auth/schemas.py:10-20, dynamic authorization engines.
    * **Test Method/Action:**
        1. Test hierarchical scope inheritance and permission cascading
        2. Validate dynamic scope assignment based on context and roles
        3. Test context-aware authorization decisions using request parameters
        4. Validate scope-based resource access control and limitations
        5. Test scope escalation prevention and privilege containment
    * **Prerequisites:** Hierarchical scope framework, dynamic assignment systems, context-aware authorization, privilege management.
    * **Expected Secure Outcome:** Hierarchical scopes provide granular control. Dynamic assignment adapts to context. Authorization decisions consider all relevant factors.
    * **Verification Steps:** Test scope hierarchy effectiveness, validate dynamic assignment, verify context-aware decisions, check privilege containment.

### 5. Cryptographic Key Management Enhancement

* **ID:** ZTA_AUTH_016
    * **Category Ref:** Authentication & Authorization
    * **Description:** Test enhanced cryptographic key management with advanced algorithms, secure key storage, and automated rotation capabilities.
    * **Exposure Point(s):** Key generation in app/auth/utils.py:4-24, key storage in app/auth/models.py:14-26, rotation mechanisms.
    * **Test Method/Action:**
        1. Test implementation of post-quantum cryptographic algorithms
        2. Validate secure key storage with hardware security modules
        3. Test automated key rotation with seamless transition
        4. Validate key escrow and recovery mechanisms for compliance
        5. Test cryptographic algorithm agility and upgrade capabilities
    * **Prerequisites:** Advanced cryptographic infrastructure, HSM integration, rotation automation, escrow systems.
    * **Expected Secure Outcome:** Post-quantum algorithms provide future-proof security. Automated rotation maintains key freshness. Secure storage protects key material.
    * **Verification Steps:** Test algorithm implementation, validate rotation effectiveness, verify secure storage, check compliance capabilities.

### 6. Authentication Attack Detection and Prevention

* **ID:** ZTA_AUTH_017
    * **Category Ref:** Authentication & Authorization
    * **Description:** Test detection and prevention of authentication attacks including brute force, credential stuffing, and token manipulation attempts.
    * **Exposure Point(s):** Authentication endpoints, attack detection systems, rate limiting, security monitoring.
    * **Test Method/Action:**
        1. Test brute force attack detection and automated blocking
        2. Validate credential stuffing prevention and account protection
        3. Test token manipulation detection and response mechanisms
        4. Validate rate limiting effectiveness and adaptive thresholds
        5. Test attack pattern recognition and threat intelligence integration
    * **Prerequisites:** Attack detection systems, rate limiting infrastructure, security monitoring, threat intelligence.
    * **Expected Secure Outcome:** Authentication attacks detected and blocked automatically. Account protection prevents credential abuse. Threat intelligence enhances detection accuracy.
    * **Verification Steps:** Test attack detection accuracy, validate blocking effectiveness, verify protection mechanisms, check intelligence integration.

### 7. Federated Identity and Cross-Domain Authentication

* **ID:** ZTA_AUTH_018
    * **Category Ref:** Authentication & Authorization
    * **Description:** Test federated identity management and secure cross-domain authentication with trust relationship validation.
    * **Exposure Point(s):** External identity providers, federation protocols, trust establishment, cross-domain validation.
    * **Test Method/Action:**
        1. Test SAML and OpenID Connect federation implementation
        2. Validate trust relationship establishment and maintenance
        3. Test cross-domain authentication token validation
        4. Validate identity mapping and attribute synchronization
        5. Test federation security controls and trust boundaries
    * **Prerequisites:** Federation infrastructure, external identity providers, trust management, protocol implementations.
    * **Expected Secure Outcome:** Federated authentication maintains security across domains. Trust relationships properly validated. Identity mapping preserves security boundaries.
    * **Verification Steps:** Test federation protocols, validate trust establishment, verify token validation, check identity mapping accuracy.

### 8. Behavioral Biometrics and Advanced Identity Verification

* **ID:** ZTA_AUTH_019
    * **Category Ref:** Authentication & Authorization
    * **Description:** Test behavioral biometrics and advanced identity verification techniques for continuous authentication validation.
    * **Exposure Point(s):** Behavioral analysis systems, biometric validation, continuous verification, identity confidence scoring.
    * **Test Method/Action:**
        1. Test behavioral pattern analysis for user identification
        2. Validate biometric authentication integration and accuracy
        3. Test continuous identity verification throughout sessions
        4. Validate identity confidence scoring and threshold management
        5. Test spoofing detection and biometric liveness verification
    * **Prerequisites:** Behavioral analytics infrastructure, biometric systems, continuous verification, liveness detection.
    * **Expected Secure Outcome:** Behavioral biometrics provide continuous identity validation. Spoofing attempts detected and blocked. Identity confidence accurately reflects verification level.
    * **Verification Steps:** Test behavioral analysis accuracy, validate biometric integration, verify continuous verification, check spoofing detection effectiveness.

---