# Test Cases for Zero Trust: Least Privilege

This document outlines test cases for verifying the principle of Least Privilege within the GSAi API Framework, based on Zero Trust testing strategies detailed in Section 7.12 of the TestPlan.md.

**Test Cases Summary: 16 (Original: 8, Enhanced: +8)**

**Referenced Code Components:**
* **Scope Definition Framework:** app/auth/schemas.py:10-20 defines granular scopes with clear separation between inference, embedding, and administrative functions
* **Privilege Enforcement:** app/auth/dependencies.py:48-66 RequiresScope implementation with strict subset checking for minimal privilege validation
* **Administrative Key Creation:** scripts/create_admin_user.py:19-49 creates admin users with comprehensive scope assignment but potentially overly broad permissions
* **Provider Access Control:** Backend configuration through app/config/settings.py:11-21 maps models to providers with implicit privilege assumptions
* **Database Permission Model:** app/auth/models.py:18 implements scopes as PostgreSQL array for flexible permission storage
* **IAM Configuration:** Cloud provider IAM roles for Bedrock (BEDROCK_ASSUME_ROLE) and Vertex AI service accounts

### **ZTA_LP_001**
* **ID:** ZTA_LP_001
* **Category Ref:** Least Privilege
* **Description:** Verify API key with only `models:inference` scope cannot access embedding endpoints.
* **Exposure Point(s):** `RequiresScope` implementation (`app/auth/dependencies.py:48-66`), `/api/v1/embeddings` endpoint.
* **Test Method/Action:** Attempt to POST to `/api/v1/embeddings` using an API key that only has the `models:inference` scope.
* **Prerequisites:** API is running. An API key exists with `scopes = ["models:inference"]` only.
* **Expected Secure Outcome:** Access is denied, enforcing that the key only has permissions for its intended LLM interactions (chat/inference) and not for others (embedding).
* **Verification Steps:**
    1.  Verify the HTTP status code is 401.
    2.  Verify the response body is `{"detail": "Not Authorized"}`.
    3.  Verify server logs indicate an authorization failure due to scope mismatch.

### **ZTA_LP_002**
* **ID:** ZTA_LP_002
* **Category Ref:** Least Privilege
* **Description:** Verify API key with only `models:embedding` scope cannot access chat completion endpoints.
* **Exposure Point(s):** `RequiresScope` implementation (`app/auth/dependencies.py:48-66`), `/api/v1/chat/completions` endpoint.
* **Test Method/Action:** Attempt to POST to `/api/v1/chat/completions` using an API key that only has the `models:embedding` scope.
* **Prerequisites:** API is running. An API key exists with `scopes = ["models:embedding"]` only.
* **Expected Secure Outcome:** Access is denied, enforcing that the key only has permissions for embedding and not for chat.
* **Verification Steps:**
    1.  Verify the HTTP status code is 401.
    2.  Verify the response body is `{"detail": "Not Authorized"}`.
    3.  Verify server logs indicate an authorization failure.

### **ZTA_LP_003**
* **ID:** ZTA_LP_003
* **Category Ref:** Least Privilege
* **Description:** Review scope definitions for granularity.
* **Exposure Point(s):** `Scope` enum in `app/auth/schemas.py:10-20`.
* **Test Method/Action:** Code review of the `Scope` enum.
* **Prerequisites:** Access to source code.
* **Expected Secure Outcome:** Scopes are granular and provide clear separation between inference, embedding, and administrative functions, aligning with the principle of least privilege. No overly broad or ambiguous scopes are defined for general use.
* **Verification Steps:**
    1.  Confirm scopes like `MODELS_INFERENCE`, `MODELS_EMBEDDING`, `ADMIN` are present.
    2.  Verify that `ADMIN` scope is not assigned by default in user creation processes.
    3.  Confirm that scope separation prevents privilege escalation between different LLM operations.
    2.  Assess if these scopes are sufficiently fine-grained for the current functionalities.
    3.  Consider if any combined scopes (e.g., a "read-all-models-and-perform-inference" scope) exist and if they are justified or could be broken down further if needed for more roles.

### **ZTA_LP_004**
* **ID:** ZTA_LP_004
* **Category Ref:** Least Privilege
* **Description:** Assess default scope assignment for newly created API keys (if any default behavior exists beyond `create_admin_user.py`).
* **Exposure Point(s):** API key creation process (currently `scripts/create_admin_user.py`).
* **Test Method/Action:** Review the `create_admin_user.py` script and any other key creation mechanisms.
* **Prerequisites:** Access to source code.
* **Expected Secure Outcome:** Keys are not created with overly broad scopes by default. The `create_admin_user.py` assigns `ADMIN`, `MODELS_INFERENCE`, `MODELS_EMBEDDING` for the admin user, which is broad for that specific tool's purpose (creating an admin). General key creation mechanisms (if they existed for non-admins) should allow specifying minimal scopes.
* **Verification Steps:**
    1.  Review `scripts/create_admin_user.py:37` where scopes are assigned. Note that this script is for creating an *admin* user/key.
    2.  If a general user key creation mechanism existed, ensure it defaults to no scopes or minimal scopes, requiring explicit scope assignment.
    3.  The current "Administrative Scope Concerns" in the risk analysis mentions the admin scope might violate least privilege. This test case highlights the review of this.

### **ZTA_LP_005**
* **ID:** ZTA_LP_005
* **Category Ref:** Least Privilege
* **Description:** Verify that an API key with `ADMIN` scope can access an admin-protected endpoint (hypothetical, as no such endpoints are currently defined in `api_v1.py` router for LLM interaction).
* **Exposure Point(s):** `RequiresScope` dependency. (This tests the `ADMIN` scope itself).
* **Test Method/Action:** If an admin-only endpoint (e.g., `/api/v1/admin/users`) were created and protected by `Depends(RequiresScope(scopes=[Scope.ADMIN]))`, attempt to access it with a key possessing the `ADMIN` scope.
* **Prerequisites:** API is running. An API key with `ADMIN` scope. A (hypothetical) admin-protected endpoint.
* **Expected Secure Outcome:** The admin-scoped key can access the admin-only endpoint.
* **Verification Steps:**
    1.  Verify HTTP status code 200 (or success for the endpoint).
    2.  This test is more about confirming `ADMIN` scope functions if used.

### **ZTA_LP_006**
* **ID:** ZTA_LP_006
* **Category Ref:** Least Privilege
* **Description:** Verify that an API key without `ADMIN` scope cannot access an admin-protected endpoint (hypothetical).
* **Exposure Point(s):** `RequiresScope` dependency.
* **Test Method/Action:** If an admin-only endpoint were created, attempt to access it with a key lacking the `ADMIN` scope (e.g., only `models:inference`).
* **Prerequisites:** API is running. An API key without `ADMIN` scope. A (hypothetical) admin-protected endpoint.
* **Expected Secure Outcome:** Access is denied.
* **Verification Steps:**
    1.  Verify HTTP status code 401.
    2.  Verify response body `{"detail": "Not Authorized"}`.

### **ZTA_LP_007**
* **ID:** ZTA_LP_007
* **Category Ref:** Least Privilege
* **Description:** Review permissions used by the API to call downstream LLM providers (Bedrock/Vertex AI).
* **Exposure Point(s):** IAM roles/service accounts configured in `app/config/settings.py` (e.g., `BEDROCK_ASSUME_ROLE`) and used by provider backends (`app/providers/bedrock/bedrock.py`, `app/providers/vertex_ai/vertexai.py`).
* **Test Method/Action:** This is primarily a configuration and IAM policy review.
* **Prerequisites:** Access to cloud provider IAM configurations (AWS, GCP) used by the API.
* **Expected Secure Outcome:** The IAM roles/service accounts used by the API to interact with LLM providers (Bedrock, Vertex AI) grant only the necessary permissions (e.g., `bedrock:InvokeModel` on specific model ARNs, `aiplatform.endpoints.predict` for Vertex AI) and not broader permissions like listing/modifying other cloud resources.
* **Verification Steps:**
    1.  Identify the IAM role ARN (for Bedrock) or service account (for Vertex AI) used by the API application.
    2.  In AWS/GCP console, inspect the permissions policies attached to this identity.
    3.  Verify that permissions are restricted to invoking the specific LLM models and do not include unrelated actions or resources.

### **ZTA_LP_008**
* **ID:** ZTA_LP_008
* **Category Ref:** Least Privilege
* **Description:** Verify the application does not require excessive database permissions.
* **Exposure Point(s):** Database user credentials in `POSTGRES_CONNECTION` (`app/config/settings.py`), database schema (`app/auth/models.py`, `app/users/models.py`).
* **Test Method/Action:** Review the database user's grants in PostgreSQL.
* **Prerequisites:** Access to the PostgreSQL database with administrative privileges to inspect other users' grants. Knowledge of the application's runtime DB user.
* **Expected Secure Outcome:** The database user account used by the API for runtime operations only has the minimum necessary DML privileges (SELECT, INSERT, UPDATE, DELETE) on the application's tables (`api_keys`, `users`, `alembic_version`) and USAGE on sequences. It should not have DDL rights (CREATE, ALTER, DROP table), superuser rights, or access to other databases unless explicitly justified.
* **Verification Steps:**
    1.  Connect to PostgreSQL as a database administrator.
    2.  Inspect the grants for the application user (e.g., using `\du <app_user>`, `\dp <app_schema>.*`, `\dt <app_schema>.*`).
    3.  Confirm privileges are limited to necessary DML on application tables.

### **ZTA_LP_ADMIN_001**
* **ID:** ZTA_LP_ADMIN_001
* **Category Ref:** Least Privilege - Admin Scope Enhancement
* **Description:** Verify that admin user creation script no longer assigns excessive default admin scopes, following principle of least privilege.
* **Exposure Point(s):** `scripts/create_admin_user.py:19-49` admin user creation with scope assignment.
* **Test Method/Action:** Review the admin user creation script to verify that broad admin scopes are not assigned by default.
* **Prerequisites:** Access to source code and admin user creation script.
* **Expected Secure Outcome:** Admin user creation follows principle of least privilege, only assigning necessary scopes based on actual role requirements rather than broad administrative permissions.
* **Verification Steps:**
    1. Examine `scripts/create_admin_user.py` scope assignment logic.
    2. Verify that `Scope.ADMIN` is not included in default scope lists.
    3. Confirm that admin users are created with specific, justified scopes only.
    4. Test that created admin users cannot perform operations outside their assigned scopes.
* **Code Reference:** `scripts/create_admin_user.py:19` scope assignment, `app/auth/schemas.py:10-20` scope definitions.

### **ZTA_LP_ADMIN_002**
* **ID:** ZTA_LP_ADMIN_002
* **Category Ref:** Least Privilege - Admin Scope Validation
* **Description:** Test that existing admin users with broad `ADMIN` scope cannot access functionality beyond their legitimate needs.
* **Exposure Point(s):** API endpoints protected by `RequiresScope` with `ADMIN` scope checks.
* **Test Method/Action:** Test admin scope usage against actual administrative functionality requirements.
* **Prerequisites:** Admin API key with `ADMIN` scope, understanding of legitimate admin operations.
* **Expected Secure Outcome:** Admin scope should be limited to specific administrative functions and not provide blanket access to all API operations.
* **Verification Steps:**
    1. Identify all endpoints that require `ADMIN` scope.
    2. Verify each admin-scoped operation is justified and necessary.
    3. Test that admin scope doesn't grant access to regular user operations unnecessarily.
    4. Validate that admin operations are properly audited and logged.

### **ZTA_LP_ADMIN_003**
* **ID:** ZTA_LP_ADMIN_003
* **Category Ref:** Least Privilege - Scope Granularity
* **Description:** Validate that administrative functions are properly segmented into specific, granular scopes rather than using broad admin privileges.
* **Exposure Point(s):** Administrative endpoints and scope-based access control implementation.
* **Test Method/Action:** Analyze administrative functionality to determine if more granular scopes would better implement least privilege.
* **Prerequisites:** Access to administrative endpoints and scope definitions.
* **Expected Secure Outcome:** Administrative functions are protected by specific, granular scopes that limit access to only necessary operations.
* **Verification Steps:**
    1. Map all administrative operations to their scope requirements.
    2. Identify opportunities for scope subdivision (e.g., user management vs. API key management).
    3. Verify that broad admin access is justified for each operation.
    4. Test access control with more granular scope assignments.

---

## Enhanced Test Cases: Advanced Least Privilege

### 1. Dynamic Privilege Reduction

* **ID:** ZTA_LP_009
    * **Category Ref:** Least Privilege
    * **Description:** Test dynamic privilege reduction based on context, risk assessment, and operational requirements.
    * **Exposure Point(s):** Dynamic authorization systems, context-aware privilege management, risk-based access control.
    * **Test Method/Action:**
        1. Test privilege reduction during high-risk operations or suspicious activity
        2. Validate context-based privilege narrowing for specific request types
        3. Test temporal privilege restrictions based on time-of-day policies
        4. Validate automatic privilege escalation prevention mechanisms
        5. Test privilege restoration after risk mitigation
    * **Prerequisites:** Dynamic privilege management system, risk assessment engine, context analysis capabilities.
    * **Expected Secure Outcome:** Privileges automatically reduced based on risk and context. Escalation attempts blocked. Appropriate privileges restored when conditions normalize.
    * **Verification Steps:** Test privilege reduction triggers, validate escalation prevention, verify restoration mechanisms, check context analysis accuracy.

### 2. Hierarchical Scope Management

* **ID:** ZTA_LP_010
    * **Category Ref:** Least Privilege
    * **Description:** Test hierarchical scope management with inheritance, delegation, and fine-grained permission control.
    * **Exposure Point(s):** Enhanced scope framework, hierarchical permission structures, delegation mechanisms.
    * **Test Method/Action:**
        1. Test scope inheritance from parent to child permissions
        2. Validate delegation of specific scopes with time-limited constraints
        3. Test fine-grained permission subdivision within major scopes
        4. Validate scope combination restrictions and conflict resolution
        5. Test automatic scope expiration and renewal mechanisms
    * **Prerequisites:** Hierarchical scope system, delegation infrastructure, permission inheritance framework.
    * **Expected Secure Outcome:** Hierarchical scopes provide granular control without complexity. Delegation maintains security boundaries. Automatic expiration prevents privilege accumulation.
    * **Verification Steps:** Test inheritance accuracy, validate delegation controls, verify subdivision effectiveness, check conflict resolution mechanisms.

### 3. Just-In-Time (JIT) Privilege Access

* **ID:** ZTA_LP_011
    * **Category Ref:** Least Privilege
    * **Description:** Test just-in-time privilege access for elevated operations with automatic privilege expiration and approval workflows.
    * **Exposure Point(s):** JIT access systems, privilege elevation workflows, automatic expiration mechanisms.
    * **Test Method/Action:**
        1. Test privilege elevation request and approval workflows
        2. Validate automatic privilege expiration after specified duration
        3. Test emergency access procedures with enhanced monitoring
        4. Validate justification requirements and audit trail generation
        5. Test privilege de-escalation and session termination
    * **Prerequisites:** JIT access infrastructure, approval workflow systems, monitoring capabilities, audit frameworks.
    * **Expected Secure Outcome:** Elevated privileges granted only when needed with automatic expiration. Emergency access properly monitored. Complete audit trails maintained.
    * **Verification Steps:** Test elevation workflows, validate expiration mechanisms, verify monitoring accuracy, check audit completeness.

### 4. Resource-Specific Access Control

* **ID:** ZTA_LP_012
    * **Category Ref:** Least Privilege
    * **Description:** Test resource-specific access control with fine-grained permissions for individual models, endpoints, and data resources.
    * **Exposure Point(s):** Resource-level authorization, model-specific permissions, endpoint granularity controls.
    * **Test Method/Action:**
        1. Test model-specific access control preventing unauthorized model usage
        2. Validate endpoint-level permissions beyond basic scope checking
        3. Test data resource access control with content-based restrictions
        4. Validate cross-resource access prevention and isolation
        5. Test resource quota enforcement and usage limiting
    * **Prerequisites:** Resource-level authorization system, model permission framework, data access controls.
    * **Expected Secure Outcome:** Access control enforced at resource level. Model usage restricted to authorized keys. Data access properly isolated and controlled.
    * **Verification Steps:** Test resource isolation, validate model restrictions, verify data access controls, check quota enforcement.

### 5. Privilege Analytics and Optimization

* **ID:** ZTA_LP_013
    * **Category Ref:** Least Privilege
    * **Description:** Test analytics-driven privilege optimization with usage pattern analysis and automated right-sizing recommendations.
    * **Exposure Point(s):** Usage analytics systems, privilege optimization engines, right-sizing algorithms.
    * **Test Method/Action:**
        1. Test usage pattern analysis for privilege optimization opportunities
        2. Validate automated detection of unused or excessive privileges
        3. Test right-sizing recommendations based on actual usage patterns
        4. Validate privilege drift detection and correction mechanisms
        5. Test optimization impact assessment and rollback capabilities
    * **Prerequisites:** Analytics infrastructure, usage tracking systems, optimization algorithms, impact assessment tools.
    * **Expected Secure Outcome:** Analytics identify optimization opportunities. Unused privileges automatically flagged. Right-sizing maintains functionality while reducing risk.
    * **Verification Steps:** Test analytics accuracy, validate optimization recommendations, verify drift detection, check impact assessment quality.

### 6. Cross-Provider Privilege Isolation

* **ID:** ZTA_LP_014
    * **Category Ref:** Least Privilege
    * **Description:** Test isolation of privileges across different LLM providers with provider-specific access controls and credential management.
    * **Exposure Point(s):** Provider-specific IAM roles, credential isolation, cross-provider access controls.
    * **Test Method/Action:**
        1. Test provider-specific credential isolation and access controls
        2. Validate prevention of cross-provider privilege escalation
        3. Test provider-specific model access restrictions
        4. Validate credential rotation and lifecycle management per provider
        5. Test provider failure isolation and privilege containment
    * **Prerequisites:** Provider-specific IAM infrastructure, credential isolation systems, access control frameworks.
    * **Expected Secure Outcome:** Provider credentials properly isolated. Cross-provider escalation prevented. Provider failures contained without privilege spillover.
    * **Verification Steps:** Test credential isolation, validate escalation prevention, verify access restrictions, check failure containment.

### 7. Adaptive Privilege Management

* **ID:** ZTA_LP_015
    * **Category Ref:** Least Privilege
    * **Description:** Test adaptive privilege management that adjusts permissions based on user behavior, threat landscape, and organizational policies.
    * **Exposure Point(s):** Adaptive management systems, behavioral analysis, threat intelligence integration.
    * **Test Method/Action:**
        1. Test privilege adaptation based on user behavioral patterns
        2. Validate threat intelligence integration for privilege adjustment
        3. Test policy-driven privilege modifications
        4. Validate machine learning-based privilege optimization
        5. Test adaptive response to security incidents and anomalies
    * **Prerequisites:** Adaptive management infrastructure, behavioral analytics, threat intelligence feeds, ML capabilities.
    * **Expected Secure Outcome:** Privileges adapt to changing conditions and behaviors. Threat intelligence enhances security posture. ML optimization improves privilege effectiveness.
    * **Verification Steps:** Test adaptation accuracy, validate intelligence integration, verify policy enforcement, check ML optimization effectiveness.

### 8. Zero Standing Privileges

* **ID:** ZTA_LP_016
    * **Category Ref:** Least Privilege
    * **Description:** Test zero standing privileges model where all elevated access requires explicit activation and justification.
    * **Exposure Point(s):** Zero standing privilege infrastructure, activation mechanisms, justification frameworks.
    * **Test Method/Action:**
        1. Test elimination of persistent elevated privileges
        2. Validate explicit activation requirements for administrative access
        3. Test justification and approval workflows for privilege activation
        4. Validate automatic privilege deactivation after use
        5. Test emergency break-glass procedures with enhanced audit
    * **Prerequisites:** Zero standing privilege system, activation workflows, justification mechanisms, emergency procedures.
    * **Expected Secure Outcome:** No persistent elevated privileges exist. All elevation requires explicit justification. Emergency procedures provide necessary access with full audit.
    * **Verification Steps:** Verify privilege elimination, test activation workflows, validate justification requirements, check emergency procedures.

---