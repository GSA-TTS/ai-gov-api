# Test Cases for Zero Trust: Identity-Centric Security

This document outlines test cases for verifying Identity-Centric Security aspects of the GSAi API Framework, based on Zero Trust testing strategies detailed in Section 7.12 of the TestPlan.md.

**Test Cases Summary: 16 (Original: 8, Enhanced: +8)**

**Referenced Code Components:**
* **API Key Identity Management:** app/auth/models.py:12-32 comprehensive API key lifecycle with creation, expiration, and usage tracking
* **User Identity Framework:** app/users/models.py defines user accounts as managers of API keys with role-based access
* **Identity Creation Process:** scripts/create_admin_user.py:22-71 implements secure user and API key creation with proper hashing
* **Authentication Services:** app/routers/tokens.py provides JWT-based authentication for API key management operations
* **Identity Verification:** app/routers/users.py implements /users/me endpoint for identity validation and profile access
* **Cryptographic Foundation:** app/auth/utils.py:4-24 provides secure key generation and verification primitives

### **ZTA_ID_001**
* **ID:** ZTA_ID_001
* **Category Ref:** Identity-Centric Security Testing
* **Description:** Verify strength and randomness of API key generation.
* **Exposure Point(s):** `generate_api_key` function (`app/auth/utils.py:4-14`), `secrets.token_urlsafe`.
* **Test Method/Action:** Code review and generation of multiple keys.
* **Prerequisites:** Access to source code. Ability to call `generate_api_key` or use `scripts/create_admin_user.py`.
* **Expected Secure Outcome:** API keys are generated using a cryptographically secure random generator (`secrets.token_urlsafe`) with sufficient entropy (default 32 bytes) to be non-guessable and unique.
* **Verification Steps:**
    1.  Review `app/auth/utils.py` to confirm `secrets.token_urlsafe(32)` is used.
    2.  Generate a sample of 10-20 keys.
    3.  Visually inspect for obvious patterns (there should be none).
    4.  Confirm the length and character set are consistent with `token_urlsafe` output.

### **ZTA_ID_002**
* **ID:** ZTA_ID_002
* **Category Ref:** Identity-Centric Security Testing
* **Description:** Verify secure hashing and storage of API keys.
* **Exposure Point(s):** `APIKey.hashed_key` field (`app/auth/models.py`), `hash_api_key` function (`app/auth/utils.py`).
* **Test Method/Action:** Create an API key and inspect its representation in the database.
* **Prerequisites:** API running, database access. `scripts/create_admin_user.py`.
* **Expected Secure Outcome:** Only a strong cryptographic hash (SHA256) of the API key is stored in the database, not the plaintext key.
* **Verification Steps:**
    1.  Use `scripts/create_admin_user.py` to create a new user and API key. Note the plaintext API key shown by the script.
    2.  Query the `api_keys` table for the `hashed_key` associated with the new key (e.g., using the `key_prefix`).
    3.  Confirm the stored value is a SHA256 hash and does not match the plaintext key.

### **ZTA_ID_003**
* **ID:** ZTA_ID_003
* **Category Ref:** Identity-Centric Security Testing
* **Description:** Verify secure API key verification process.
* **Exposure Point(s):** `verify_api_key` function (`app/auth/utils.py:16-22`), `secrets.compare_digest`.
* **Test Method/Action:** Code review.
* **Prerequisites:** Access to source code.
* **Expected Secure Outcome:** API key verification uses a constant-time comparison function (`secrets.compare_digest`) to prevent timing attacks against hashes.
* **Verification Steps:**
    1.  Review `app/auth/utils.py` and confirm that `secrets.compare_digest` is used to compare the hash of the input key with the stored hash.

### **ZTA_ID_004**
* **ID:** ZTA_ID_004
* **Category Ref:** Identity-Centric Security Testing
* **Description:** Verify API key lifecycle attributes (creation, expiration, activity tracking).
* **Exposure Point(s):** `APIKey` model fields (`app/auth/models.py:12-32`): `created_at`, `updated_at`, `expires_at`, `last_used_at`, `is_active`. `valid_api_key` dependency.
* **Test Method/Action:**
    1.  Create a key and check its `created_at`, `is_active`, and `expires_at` (if set).
    2.  Make a call with the key and check if `last_used_at` is updated.
    3.  Set a key to `is_active = False` and try to use it (see ZTA_AUTH_004).
    4.  Set a key's `expires_at` to the past and try to use it (see ZTA_AUTH_005).
* **Prerequisites:** API running, database access.
* **Expected Secure Outcome:** Lifecycle attributes are correctly managed and enforced. `last_used_at` is updated upon use. `is_active` and `expires_at` correctly gate access.
* **Verification Steps:**
    1.  After key creation, query DB for `created_at`, `is_active`, `expires_at`.
    2.  Make API call. Query DB again to see `last_used_at` updated.
    3.  Verify failures for inactive/expired keys.

### **ZTA_ID_005**
* **ID:** ZTA_ID_005
* **Category Ref:** Identity-Centric Security Testing
* **Description:** Verify user account linkage to API keys.
* **Exposure Point(s):** `APIKey.manager_id` field (`app/auth/models.py`), `User` model (`app/users/models.py`).
* **Test Method/Action:** Create a user and an API key associated with that user. Inspect database.
* **Prerequisites:** API running, database access. `scripts/create_admin_user.py`.
* **Expected Secure Outcome:** API keys are correctly associated with a "manager" user account via `manager_id`, allowing for ownership and potential role-based access based on the user.
* **Verification Steps:**
    1.  Use `scripts/create_admin_user.py`. Note the created user's ID.
    2.  Query the `api_keys` table for the newly created API key.
    3.  Verify its `manager_id` matches the ID of the user created.

### **ZTA_ID_006**
* **ID:** ZTA_ID_006
* **Category Ref:** Identity-Centric Security Testing
* **Description:** Review JWT-based authentication for API key management operations (if applicable to human users).
* **Exposure Point(s):** `/auth/token` endpoint (`app/routers/tokens.py`), user authentication logic for managing keys.
* **Test Method/Action:** If a UI or separate management API uses the `/auth/token` endpoint for users to log in and manage their API keys:
    1.  Test login with valid/invalid user credentials.
    2.  Test JWT properties (expiration, signature).
    3.  Test access to key management functions with/without valid JWT.
* **Prerequisites:** User accounts exist. Understanding of how users would manage their keys (currently not via this API for end-users). The `/auth/token` seems for user login, potentially admin.
* **Expected Secure Outcome:** User authentication for key management is robust. JWTs are secure. (Risk analysis mentions "Lack of Multi-Factor Authentication (MFA) for Users Managing API Keys").
* **Verification Steps:**
    1.  Attempt login to `/auth/token` with correct and incorrect admin user credentials.
    2.  If successful, inspect JWT.
    3.  Assess if MFA is present for user login to manage keys (currently a gap).

### **ZTA_ID_007**
* **ID:** ZTA_ID_007
* **Category Ref:** Identity-Centric Security Testing
* **Description:** Review identity verification endpoint (`/users/me`).
* **Exposure Point(s):** `/users/me` endpoint (`app/routers/users.py`).
* **Test Method/Action:** Call `/users/me` with a valid JWT obtained from `/auth/token`.
* **Prerequisites:** A user is logged in (has a valid JWT).
* **Expected Secure Outcome:** The `/users/me` endpoint correctly returns profile information for the authenticated user only and does not expose other users' data.
* **Verification Steps:**
    1.  Authenticate as a user via `/auth/token` to get a JWT.
    2.  Call `/users/me` with the JWT.
    3.  Verify the response contains the correct user's details (e.g., email, name, role) and not data of other users.

### **ZTA_ID_008**
* **ID:** ZTA_ID_008
* **Category Ref:** Identity-Centric Security Testing
* **Description:** Assess gaps in identity lifecycle management (de-provisioning, rotation).
* **Exposure Point(s):** Current lack of automated key rotation or de-provisioning features. Risk analysis notes "Identity Lifecycle Gaps," "Missing automated key rotation, identity deprovisioning."
* **Test Method/Action:** This is a process and feature gap analysis.
* **Prerequisites:** Understanding of current key management capabilities.
* **Expected Secure Outcome:** (Ideal state) Clear, preferably automated, processes exist for de-provisioning API keys/user accounts when no longer needed or compromised. Automated key rotation is supported/enforced. (Current state) These are manual.
* **Verification Steps:**
    1.  Confirm there are no API endpoints or automated system for users/admins to rotate their own/others' API keys.
    2.  Confirm there's no automated de-provisioning based on inactivity or other triggers.
    3.  This test verifies the gaps mentioned in the risk analysis.

---

## Enhanced Test Cases: Advanced Identity-Centric Security

### 1. Advanced Identity Verification and Proofing

* **ID:** ZTA_ID_009
    * **Category Ref:** Identity-Centric Security Testing
    * **Description:** Test advanced identity verification with multiple proofing methods and continuous validation.
    * **Exposure Point(s):** Identity proofing systems, multi-factor verification, continuous validation, identity confidence scoring.
    * **Test Method/Action:**
        1. Test multi-factor identity proofing during account creation
        2. Validate continuous identity verification throughout session
        3. Test identity confidence scoring and threshold management
        4. Validate identity verification for high-risk operations
        5. Test identity fraud detection and prevention mechanisms
    * **Prerequisites:** Identity proofing infrastructure, multi-factor verification systems, fraud detection tools.
    * **Expected Secure Outcome:** Identity verification robust and multi-layered. Continuous validation maintains security. Fraud attempts detected and prevented.
    * **Verification Steps:** Test proofing effectiveness, validate continuous verification, verify fraud detection, check confidence scoring accuracy.

### 2. Federated Identity Management

* **ID:** ZTA_ID_010
    * **Category Ref:** Identity-Centric Security Testing
    * **Description:** Test federated identity management with external identity providers and cross-domain authentication.
    * **Exposure Point(s):** Identity federation protocols, external providers, cross-domain authentication, trust relationships.
    * **Test Method/Action:**
        1. Test SAML and OpenID Connect federation implementation
        2. Validate trust relationship establishment and maintenance
        3. Test identity attribute mapping and synchronization
        4. Validate cross-domain authorization and token validation
        5. Test federation security controls and boundary enforcement
    * **Prerequisites:** Federation infrastructure, external identity providers, protocol implementations, trust management.
    * **Expected Secure Outcome:** Federated authentication maintains security across domains. Trust relationships properly managed. Identity mapping accurate and secure.
    * **Verification Steps:** Test federation protocols, validate trust management, verify attribute mapping, check boundary enforcement.

### 3. Identity Analytics and Risk Assessment

* **ID:** ZTA_ID_011
    * **Category Ref:** Identity-Centric Security Testing
    * **Description:** Test identity analytics with behavioral pattern analysis and risk-based authentication decisions.
    * **Exposure Point(s):** Identity analytics platforms, behavioral analysis, risk assessment engines, adaptive authentication.
    * **Test Method/Action:**
        1. Test behavioral pattern analysis for identity verification
        2. Validate risk scoring based on identity attributes and behavior
        3. Test adaptive authentication based on risk assessment
        4. Validate anomaly detection for identity-related threats
        5. Test identity risk mitigation and response strategies
    * **Prerequisites:** Analytics platforms, behavioral analysis tools, risk assessment systems, adaptive authentication.
    * **Expected Secure Outcome:** Behavioral analysis enhances identity security. Risk scores accurately reflect threats. Adaptive authentication responds appropriately.
    * **Verification Steps:** Test behavioral analysis accuracy, validate risk scoring, verify adaptive responses, check anomaly detection.

### 4. Zero Trust Identity Architecture

* **ID:** ZTA_ID_012
    * **Category Ref:** Identity-Centric Security Testing
    * **Description:** Test comprehensive zero trust identity architecture with never-trust-always-verify principles.
    * **Exposure Point(s):** Zero trust identity systems, continuous verification, identity-centric controls, trust boundaries.
    * **Test Method/Action:**
        1. Test continuous identity verification for all access requests
        2. Validate identity-centric access control policies
        3. Test dynamic trust calculation and adjustment
        4. Validate identity context integration in authorization decisions
        5. Test identity-based micro-segmentation and isolation
    * **Prerequisites:** Zero trust identity platform, continuous verification systems, identity-centric policies.
    * **Expected Secure Outcome:** Identity verified continuously. Access decisions identity-centric. Trust levels dynamically adjusted based on context.
    * **Verification Steps:** Test continuous verification, validate identity-centric controls, verify dynamic trust, check micro-segmentation.

### 5. Identity Threat Detection and Response

* **ID:** ZTA_ID_013
    * **Category Ref:** Identity-Centric Security Testing
    * **Description:** Test identity-specific threat detection with automated response and incident management.
    * **Exposure Point(s):** Identity threat detection, automated response systems, incident management, forensics capabilities.
    * **Test Method/Action:**
        1. Test detection of identity-based attacks (credential stuffing, account takeover)
        2. Validate automated response to identity threats
        3. Test incident escalation and investigation workflows
        4. Validate identity forensics and evidence collection
        5. Test recovery procedures for compromised identities
    * **Prerequisites:** Threat detection systems, automated response platforms, incident management, forensics tools.
    * **Expected Secure Outcome:** Identity threats detected accurately. Automated responses contain attacks. Investigation capabilities comprehensive.
    * **Verification Steps:** Test threat detection accuracy, validate response effectiveness, verify investigation tools, check recovery procedures.

### 6. Privacy-Preserving Identity Management

* **ID:** ZTA_ID_014
    * **Category Ref:** Identity-Centric Security Testing
    * **Description:** Test privacy-preserving identity management with minimal disclosure and anonymization capabilities.
    * **Exposure Point(s):** Privacy-preserving protocols, minimal disclosure systems, anonymization techniques, consent management.
    * **Test Method/Action:**
        1. Test minimal disclosure protocols for identity verification
        2. Validate anonymization and pseudonymization techniques
        3. Test zero-knowledge proof implementations for identity
        4. Validate consent management and privacy controls
        5. Test privacy compliance with GDPR and other regulations
    * **Prerequisites:** Privacy-preserving technologies, anonymization tools, zero-knowledge systems, consent platforms.
    * **Expected Secure Outcome:** Identity verification with minimal disclosure. Privacy protected through anonymization. Compliance maintained with regulations.
    * **Verification Steps:** Test minimal disclosure, validate anonymization, verify zero-knowledge proofs, check privacy compliance.

### 7. Identity Lifecycle Automation

* **ID:** ZTA_ID_015
    * **Category Ref:** Identity-Centric Security Testing
    * **Description:** Test comprehensive identity lifecycle automation with provisioning, management, and deprovisioning workflows.
    * **Exposure Point(s):** Identity lifecycle systems, automation workflows, provisioning platforms, deprovisioning processes.
    * **Test Method/Action:**
        1. Test automated identity provisioning and onboarding
        2. Validate lifecycle management and attribute updates
        3. Test automated access reviews and recertification
        4. Validate deprovisioning and access removal processes
        5. Test emergency access procedures and break-glass scenarios
    * **Prerequisites:** Identity lifecycle platforms, automation systems, workflow engines, emergency procedures.
    * **Expected Secure Outcome:** Identity lifecycle fully automated. Provisioning and deprovisioning accurate and timely. Emergency access properly controlled.
    * **Verification Steps:** Test automation accuracy, validate lifecycle management, verify deprovisioning, check emergency procedures.

### 8. Identity Governance and Compliance

* **ID:** ZTA_ID_016
    * **Category Ref:** Identity-Centric Security Testing
    * **Description:** Test identity governance with policy compliance, regulatory adherence, and audit capabilities.
    * **Exposure Point(s):** Identity governance frameworks, compliance systems, audit capabilities, policy enforcement.
    * **Test Method/Action:**
        1. Test identity policy compliance validation and enforcement
        2. Validate regulatory compliance for identity management (SOX, GDPR, FISMA)
        3. Test identity audit trails and reporting capabilities
        4. Validate segregation of duties and conflict detection
        5. Test identity governance dashboard and analytics
    * **Prerequisites:** Identity governance platforms, compliance tools, audit systems, policy frameworks.
    * **Expected Secure Outcome:** Identity policies enforced consistently. Regulatory compliance maintained. Audit trails comprehensive and accessible.
    * **Verification Steps:** Test policy enforcement, validate regulatory compliance, verify audit capabilities, check governance analytics.

---