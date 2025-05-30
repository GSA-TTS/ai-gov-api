# Test Cases for Zero Trust: API Design Verification

This document outlines test cases for verifying Zero Trust principles in the API Design of the GSAi API Framework, based on Zero Trust testing strategies detailed in Section 7.12 of the TestPlan.md.

**Test Cases Summary: 15 (Original: 7, Enhanced: +8)**

**Referenced Code Components:**
* **Explicit Authentication:** app/auth/dependencies.py:16-45 provides mandatory API key verification with comprehensive validation checks
* **Granular Authorization:** app/auth/dependencies.py:48-66 RequiresScope decorator enforces explicit permission verification for every protected endpoint
* **Input Validation Framework:** app/providers/open_ai/schemas.py Pydantic schemas provide comprehensive request validation with type safety
* **Data Validation:** app/providers/utils.py parse_data_uri implements explicit validation for multimodal content
* **Model Authorization:** app/providers/dependencies.py Backend dependency ensures only configured and authorized models are accessible
* **Trust Boundary Enforcement:** Each endpoint in app/routers/api_v1.py:33-70 explicitly requires authentication and authorization

### **ZTA_DESIGN_001**
* **ID:** ZTA_DESIGN_001
* **Category Ref:** Zero Trust API Design Verification
* **Description:** Verify explicit authentication at API boundaries.
* **Exposure Point(s):** All API endpoints in `app/routers/api_v1.py:33-70`, `valid_api_key` dependency (`app/auth/dependencies.py:16-45`).
* **Test Method/Action:** Attempt to access each protected API endpoint without a valid `Authorization` header.
* **Prerequisites:** API is running.
* **Expected Secure Outcome:** All API endpoints that provide access to LLM functionalities or potentially sensitive data require explicit authentication. Trust is never assumed.
* **Verification Steps:**
    1.  For each endpoint (`/models`, `/chat/completions`, `/embeddings`):
        * Send a request without an `Authorization` header. Verify 401/403 response.
        * Send a request with an invalid/expired API key. Verify 401 response.
    2.  Confirm that `Depends(valid_api_key)` or a scope-requiring dependency (which includes `valid_api_key`) is present for all such endpoints in `app/routers/api_v1.py`.

### **ZTA_DESIGN_002**
* **ID:** ZTA_DESIGN_002
* **Category Ref:** Zero Trust API Design Verification
* **Description:** Verify granular authorization at API boundaries.
* **Exposure Point(s):** Scope-protected endpoints (`/chat/completions`, `/embeddings`) in `app/routers/api_v1.py`, `RequiresScope` dependency (`app/auth/dependencies.py:48-66`).
* **Test Method/Action:** Attempt to access scope-protected endpoints with a valid API key that lacks the specific required scope.
* **Prerequisites:** API is running. API keys with varying scopes.
* **Expected Secure Outcome:** Access to functionalities is strictly controlled by granular scopes. An identity authorized for one function (e.g., embeddings) cannot access another (e.g., chat completions) without the appropriate scope.
* **Verification Steps:**
    1.  Using a key with only `models:embedding` scope, attempt to POST to `/api/v1/chat/completions`. Verify 401 response (`{"detail": "Not Authorized"}`).
    2.  Using a key with only `models:inference` scope, attempt to POST to `/api/v1/embeddings`. Verify 401 response.
    3.  Confirm that `Depends(RequiresScope(scopes=[...]))` is correctly applied with the appropriate scopes for these endpoints.

### **ZTA_DESIGN_003**
* **ID:** ZTA_DESIGN_003
* **Category Ref:** Zero Trust API Design Verification
* **Description:** Verify comprehensive input validation using Pydantic schemas.
* **Exposure Point(s):** Pydantic schemas in `app/providers/open_ai/schemas.py`, request body parsing in FastAPI for `/chat/completions` and `/embeddings`.
* **Test Method/Action:** Send requests with various forms of invalid input that violate Pydantic schema definitions (missing required fields, wrong data types, out-of-range values, invalid enum values).
* **Prerequisites:** API is running. Valid API key.
* **Expected Secure Outcome:** All user-supplied input in request bodies is rigorously validated against the defined schemas before further processing. Invalid requests are rejected with informative errors.
* **Verification Steps:**
    1.  For `/chat/completions`:
        * Send request missing `model` or `messages`. Verify 422 error.
        * Send request with `temperature` as string or out of range. Verify 422 error.
        * Send request with `messages[].role` as an invalid value. Verify 422 error.
    2.  For `/embeddings`:
        * Send request missing `model` or `input`. Verify 422 error.
        * Send request with `dimensions` as a non-positive integer. Verify 422 error.
    3.  Verify error responses conform to FastAPI's 422 structure, detailing field and error type.

### **ZTA_DESIGN_004**
* **ID:** ZTA_DESIGN_004
* **Category Ref:** Zero Trust API Design Verification
* **Description:** Verify explicit validation for multimodal content (image data URIs).
* **Exposure Point(s):** `parse_data_uri` function (`app/providers/utils.py`), its usage in `app/providers/open_ai/adapter_to_core.py` when processing image content parts.
* **Test Method/Action:** Send chat completion requests with `ImageContentPart` where the `image_url.url` is malformed (wrong prefix, unsupported image type, invalid Base64).
* **Prerequisites:** API is running. Valid API key with inference scope for a multimodal model.
* **Expected Secure Outcome:** Multimodal content (specifically image data URIs) undergoes explicit validation beyond basic string type checking.
* **Verification Steps:**
    1.  Send request with `image_url.url` as "http://example.com/image.png". Verify 400 error from `InputDataError` ("Invalid or unsupported image data URI format...").
    2.  Send request with `image_url.url` as "data:image/tiff;base64,...". Verify 400 error.
    3.  Send request with `image_url.url` as "data:image/jpeg;base64,!!!not_base64!!!". Verify 400 error ("Invalid Base64 data...").

### **ZTA_DESIGN_005**
* **ID:** ZTA_DESIGN_005
* **Category Ref:** Zero Trust API Design Verification
* **Description:** Verify model authorization based on configuration.
* **Exposure Point(s):** `Backend` dependency (`app/providers/dependencies.py`), `settings.backend_map`.
* **Test Method/Action:** Attempt to use a `model_id` in chat/embedding requests that is not defined in `settings.backend_map`, or is defined but for an incompatible capability.
* **Prerequisites:** API is running. Valid API key.
* **Expected Secure Outcome:** Only models configured in the system and appropriate for the endpoint's capability can be accessed.
* **Verification Steps:**
    1.  Send a chat request with `model_id="unknown_model_123"`. Verify 422 error ("Model 'unknown_model_123' is not supported...").
    2.  Assume `embedding_model_x` is configured only for "embedding". Send a chat request with `model_id="embedding_model_x"`. Verify 422 error ("This endpoint not does support chat with the model 'embedding_model_x'.").

### **ZTA_DESIGN_006**
* **ID:** ZTA_DESIGN_006
* **Category Ref:** Zero Trust API Design Verification
* **Description:** Assess for implicit trust in internal calls (Conceptual).
* **Exposure Point(s):** Interactions between different internal functions/modules if any were to occur without re-validation.
* **Test Method/Action:** This is primarily a code review. Trace request flows within the application, particularly from routers to provider adapters and then to provider backends.
* **Prerequisites:** Access to source code.
* **Expected Secure Outcome:** The current design seems to perform auth/authZ at the API boundary (via dependencies). If internal components were to make calls to other internal components that also represent trust boundaries or require specific permissions, these calls should ideally re-verify or propagate identity/permissions securely. For this API, data flows mostly from API -> Adapter -> SDK.
* **Verification Steps:**
    1.  Review how `api_key` object or `user` object (if available from auth) is passed, if at all, to deeper service layers.
    2.  Confirm that each call to an external LLM provider is made in the context of the initially authenticated and authorized request, without assuming broader trust.

### **ZTA_DESIGN_007**
* **ID:** ZTA_DESIGN_007
* **Category Ref:** Zero Trust API Design Verification
* **Description:** Verify absence of dynamic context evaluation in current authorization (confirms known limitation).
* **Exposure Point(s):** `RequiresScope` (`app/auth/dependencies.py`).
* **Test Method/Action:** Attempt requests under various (hypothetical) contexts that a dynamic system might consider (e.g., unusual time of day, different IP for the same key shortly after).
* **Prerequisites:** API is running. Valid API key.
* **Expected Secure Outcome:** The current system makes authorization decisions based on static scopes associated with the API key. It is not expected to adapt based on dynamic context like IP reputation, request patterns, or time of day. This test verifies that this known limitation/characteristic is true.
* **Verification Steps:**
    1.  Make a successful call with a valid key and scope.
    2.  (If possible to simulate) Make another identical successful call from a different source IP shortly after. The call should still succeed if the key and scope are valid, as no IP-based dynamic context is currently implemented.
    3.  This test confirms the "Context-Aware Limitations" mentioned in the risk analysis.

---

## Enhanced Test Cases: Advanced Zero Trust API Design

### 1. Dynamic Trust Boundary Validation

* **ID:** ZTA_DESIGN_008
    * **Category Ref:** Zero Trust API Design Verification
    * **Description:** Test dynamic trust boundary validation with adaptive security controls and contextual risk assessment.
    * **Exposure Point(s):** Dynamic trust evaluation systems, contextual risk assessment, adaptive security controls.
    * **Test Method/Action:**
        1. Test dynamic adjustment of authentication requirements based on risk context
        2. Validate adaptive authorization with varying trust levels
        3. Test contextual security control activation
        4. Validate trust boundary enforcement under different threat conditions
        5. Test automatic trust level adjustment based on behavioral patterns
    * **Prerequisites:** Dynamic trust systems, risk assessment engines, adaptive controls, behavioral analytics.
    * **Expected Secure Outcome:** Trust boundaries adapt to context and risk. Security controls adjust automatically. Behavioral patterns influence trust decisions appropriately.
    * **Verification Steps:** Test trust adaptation, validate control adjustment, verify boundary enforcement, check behavioral integration.

### 2. API Contract Security Validation

* **ID:** ZTA_DESIGN_009
    * **Category Ref:** Zero Trust API Design Verification
    * **Description:** Test comprehensive API contract security with schema validation, dependency verification, and security constraint enforcement.
    * **Exposure Point(s):** OpenAPI specifications, schema validation, security constraints, contract enforcement.
    * **Test Method/Action:**
        1. Test OpenAPI security scheme validation and enforcement
        2. Validate schema-based security constraints
        3. Test API versioning security implications
        4. Validate backward compatibility security assessment
        5. Test contract violation detection and response
    * **Prerequisites:** OpenAPI security extensions, schema validation tools, contract enforcement systems.
    * **Expected Secure Outcome:** API contracts enforce security requirements. Schema violations blocked. Versioning maintains security posture.
    * **Verification Steps:** Test contract validation, verify security enforcement, check versioning security, validate violation response.

### 3. Zero Trust Microservices Architecture

* **ID:** ZTA_DESIGN_010
    * **Category Ref:** Zero Trust API Design Verification
    * **Description:** Test zero trust principles in microservices architecture with service-to-service authentication and authorization.
    * **Exposure Point(s):** Microservices communication, service mesh security, inter-service authentication.
    * **Test Method/Action:**
        1. Test mutual TLS authentication between microservices
        2. Validate service-to-service authorization policies
        3. Test service identity verification and certificate management
        4. Validate request context propagation across services
        5. Test service isolation and lateral movement prevention
    * **Prerequisites:** Microservices architecture, service mesh, mTLS infrastructure, identity management.
    * **Expected Secure Outcome:** All service communications authenticated and authorized. Service identities verified. Lateral movement prevented.
    * **Verification Steps:** Test mTLS implementation, validate authorization policies, verify identity management, check isolation effectiveness.

### 4. API Gateway Zero Trust Integration

* **ID:** ZTA_DESIGN_011
    * **Category Ref:** Zero Trust API Design Verification
    * **Description:** Test API gateway integration with zero trust principles including traffic inspection and policy enforcement.
    * **Exposure Point(s):** API gateway security, traffic inspection, policy enforcement, threat detection.
    * **Test Method/Action:**
        1. Test API gateway authentication and authorization integration
        2. Validate traffic inspection and content filtering
        3. Test rate limiting and DDoS protection
        4. Validate threat detection and automated blocking
        5. Test policy enforcement and compliance validation
    * **Prerequisites:** API gateway platform, security policies, threat detection systems, compliance frameworks.
    * **Expected Secure Outcome:** Gateway enforces zero trust policies. Traffic properly inspected and filtered. Threats detected and blocked automatically.
    * **Verification Steps:** Test gateway integration, validate traffic inspection, verify threat detection, check policy enforcement.

### 5. Context-Aware API Security

* **ID:** ZTA_DESIGN_012
    * **Category Ref:** Zero Trust API Design Verification
    * **Description:** Test context-aware API security with dynamic policy enforcement based on request context and environmental factors.
    * **Exposure Point(s):** Context analysis systems, dynamic policy engines, environmental awareness, adaptive security.
    * **Test Method/Action:**
        1. Test context extraction and analysis from API requests
        2. Validate dynamic policy selection based on context
        3. Test environmental factor integration (time, location, device)
        4. Validate adaptive security control activation
        5. Test context-based risk scoring and response
    * **Prerequisites:** Context analysis platforms, dynamic policy engines, environmental data sources, adaptive controls.
    * **Expected Secure Outcome:** API security adapts to request context. Policies selected dynamically. Environmental factors properly considered.
    * **Verification Steps:** Test context analysis, validate policy selection, verify environmental integration, check adaptive responses.

### 6. API Threat Modeling and Security Testing

* **ID:** ZTA_DESIGN_013
    * **Category Ref:** Zero Trust API Design Verification
    * **Description:** Test comprehensive API threat modeling with automated security testing and vulnerability assessment.
    * **Exposure Point(s):** Threat modeling tools, security testing frameworks, vulnerability assessment, penetration testing.
    * **Test Method/Action:**
        1. Test automated threat model generation for API endpoints
        2. Validate security testing integration in CI/CD pipelines
        3. Test vulnerability assessment and remediation tracking
        4. Validate penetration testing and red team exercises
        5. Test threat intelligence integration for API security
    * **Prerequisites:** Threat modeling tools, security testing platforms, vulnerability scanners, penetration testing frameworks.
    * **Expected Secure Outcome:** Comprehensive threat models identify risks. Automated testing detects vulnerabilities. Remediation tracked effectively.
    * **Verification Steps:** Test threat modeling accuracy, validate security testing effectiveness, verify vulnerability detection, check remediation tracking.

### 7. API Observability and Security Analytics

* **ID:** ZTA_DESIGN_014
    * **Category Ref:** Zero Trust API Design Verification
    * **Description:** Test API observability integration with security analytics for comprehensive monitoring and threat detection.
    * **Exposure Point(s):** API observability platforms, security analytics, monitoring systems, threat detection.
    * **Test Method/Action:**
        1. Test comprehensive API request/response monitoring
        2. Validate security event correlation and analysis
        3. Test anomaly detection for API usage patterns
        4. Validate threat detection and incident response integration
        5. Test performance impact monitoring and optimization
    * **Prerequisites:** Observability platforms, security analytics tools, monitoring infrastructure, incident response systems.
    * **Expected Secure Outcome:** Complete API visibility with security context. Threats detected through analytics. Performance impact minimized.
    * **Verification Steps:** Test monitoring completeness, validate analytics accuracy, verify threat detection, check performance optimization.

### 8. API Security Governance and Compliance

* **ID:** ZTA_DESIGN_015
    * **Category Ref:** Zero Trust API Design Verification
    * **Description:** Test API security governance with policy compliance, regulatory adherence, and automated validation.
    * **Exposure Point(s):** Security governance frameworks, compliance validation, policy enforcement, regulatory tracking.
    * **Test Method/Action:**
        1. Test security policy compliance validation for API design
        2. Validate regulatory requirement adherence (FISMA, SOX, GDPR)
        3. Test automated compliance checking and reporting
        4. Validate security governance workflow integration
        5. Test audit trail generation and compliance evidence collection
    * **Prerequisites:** Governance frameworks, compliance tools, policy validation systems, audit capabilities.
    * **Expected Secure Outcome:** API design complies with security policies. Regulatory requirements met. Audit trails comprehensive and accurate.
    * **Verification Steps:** Test policy compliance, validate regulatory adherence, verify automated checking, check audit capabilities.

---