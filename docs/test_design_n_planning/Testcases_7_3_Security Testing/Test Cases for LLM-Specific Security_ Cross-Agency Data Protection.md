# **Test Cases for LLM-Specific Security: Cross-Agency Data Protection**

## **Introduction**

This document outlines test cases for **LLM-Specific Security Testing**, focusing on **Cross-Agency Data Protection**, as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md". These tests are crucial for verifying that data and interactions related to one agency (identified by its API key and associated manager\_id) are strictly isolated from other agencies using the API.  
**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 2\. Cross-Agency Data Protection)  
* app/auth/dependencies.py (valid\_api\_key which sets request.state.api\_key\_id and makes manager\_id available)  
* app/services/billing.py (associates usage with manager\_id)  
* app/logs/middleware.py and app/logs/logging\_config.py (logging context and PII filtering)  
* Database models for APIKey and User (app/auth/models.py, app/users/models.py)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** LLM \- Cross-Agency Data Protection  
* **Description:** What specific aspect of inter-agency data isolation is being tested.  
* **Exposure Point(s):** LLM interactions via /chat/completions and /embeddings, server logs, billing data, any potential shared caches or stateful components (though current API is largely stateless per request for LLM calls).  
* **Test Method/Action:** Use API keys from different agencies (different manager\_id) to perform actions and check for any information leakage or context contamination.  
* **Prerequisites:** At least two distinct API keys belonging to different manager\_id values.  
* **Expected Secure Outcome:** Complete data and operational isolation between agencies. No agency should be able to access, infer, or be affected by another agency's LLM interactions, prompts, responses, or usage data.  
* **Verification Steps:** Analyze API responses, server logs, and (simulated) billing data for any signs of cross-agency data exposure or interference.

## **Test Cases Summary**
**Total Test Cases: 18 (Original: 7, Enhanced: +11)**

### **Basic Cross-Agency Data Protection**

* **ID:** CADP\_CONTEXT\_ISOLATION\_001  
  * **Category Ref:** LLM \- Cross-Agency Data Protection  
  * **Description:** Verify that LLM conversation context is isolated between requests from different agencies/API keys.  
  * **Exposure Point(s):** /api/v1/chat/completions. (Primarily tests statelessness of LLM calls per request).  
  * **Test Method/Action:**  
    1. Agency A (using key\_A) sends a prompt: "My favorite color is blue. What is my favorite color?"  
    2. Record LLM's response to Agency A (should mention blue).  
    3. Agency B (using key\_B) sends a prompt: "What is my favorite color?" (without stating one).  
  * **Prerequisites:** Two API keys (key\_A, key\_B) with different manager\_id.  
  * **Expected Secure Outcome:** The LLM's response to Agency B should not mention "blue" or any information from Agency A's session. It should indicate it doesn't know Agency B's favorite color. This confirms that the LLM interactions are stateless per API key per request and not contaminated.  
  * **Verification Steps:**  
    1. Compare LLM response for Agency A and Agency B.  
    2. Ensure Agency B's response shows no knowledge of Agency A's prompt.  
* **ID:** CADP\_LOG\_LEAKAGE\_001  
  * **Category Ref:** LLM \- Cross-Agency Data Protection  
  * **Description:** Verify that server logs related to one agency's LLM request do not contain identifiers or data from another agency (beyond what's necessary for system-wide operational logging if not properly filtered).  
  * **Exposure Point(s):** Server logs (app/logs/middleware.py, provider interaction logs).  
  * **Test Method/Action:**  
    1. Agency A makes a request with a unique prompt.  
    2. Agency B makes a request with a different unique prompt.  
    3. Inspect server logs (especially if aggregated without strict tenancy).  
  * **Prerequisites:** Two API keys. Access to server logs.  
  * **Expected Secure Outcome:** Each log entry related to an API request should be clearly attributable to the correct request\_id and, implicitly, the manager\_id (or api\_key.id) associated with that request. There should be no mixing of prompt content or other specific data from Agency A in logs generated for Agency B's request, and vice-versa. The PIIFilteringProcessor effectiveness is also relevant here.  
  * **Verification Steps:**  
    1. Filter logs by request\_id for Agency A's request and verify only Agency A's data/identifiers are present.  
    2. Repeat for Agency B.  
    3. Check for any log entries that incorrectly correlate or mix data from both agencies.  
* **ID:** CADP\_BILLING\_ISOLATION\_001  
  * **Category Ref:** LLM \- Cross-Agency Data Protection  
  * **Description:** Verify that LLM usage and token counts are correctly attributed to the originating agency in billing data.  
  * **Exposure Point(s):** Billing logs/data generated by app/services/billing.py.  
  * **Test Method/Action:**  
    1. Agency A makes several LLM calls with known token counts.  
    2. Agency B makes a different number of LLM calls with different known token counts.  
    3. Inspect the (simulated or actual) billing data generated.  
  * **Prerequisites:** Two API keys. Mechanism to inspect billing data (e.g., by checking logs from billing\_worker).  
  * **Expected Secure Outcome:** Billing data must accurately reflect usage per manager\_id (or api\_key.id). Agency A's usage should not be attributed to Agency B, and vice-versa.  
  * **Verification Steps:**  
    1. For each billing log entry, verify manager\_id and token counts match the originating request and API key.  
    2. Sum usage for manager\_id\_A and manager\_id\_B and confirm they are distinct and correct.  
* **ID:** CADP\_EMBEDDING\_ISOLATION\_001 (Conceptual for current API)  
  * **Category Ref:** LLM \- Cross-Agency Data Protection  
  * **Description:** If embeddings were stored and retrievable (future feature), verify that one agency cannot retrieve or search against another agency's embeddings.  
  * **Exposure Point(s):** Hypothetical embedding storage and retrieval endpoints.  
  * **Test Method/Action:**  
    1. Agency A creates and stores an embedding for "Text A".  
    2. Agency B attempts to retrieve or perform a similarity search that might match "Text A".  
  * **Prerequisites:** Hypothetical embedding storage/retrieval feature with agency scoping.  
  * **Expected Secure Outcome:** Agency B cannot access Agency A's embeddings. Searches by Agency B are confined to its own embedding space.  
  * **Verification Steps:** Verify access denial or empty/scoped search results for Agency B.  
* **ID:** CADP\_CACHE\_ISOLATION\_001 (If caching is implemented)  
  * **Category Ref:** LLM \- Cross-Agency Data Protection  
  * **Description:** If any caching layer is introduced for LLM responses or other data, verify it is strictly namespaced by agency/user.  
  * **Exposure Point(s):** Any caching mechanism (e.g., Redis, in-memory cache) that might store LLM responses or user-related data.  
  * **Test Method/Action:**  
    1. Agency A makes a specific request that is likely to be cached.  
    2. Agency B makes the exact same request.  
  * **Prerequisites:** Caching layer implemented.  
  * **Expected Secure Outcome:** Agency B's request should trigger a fresh call to the LLM (or its own cached response if it made the same request earlier), not retrieve Agency A's cached response. Cache keys must incorporate manager\_id or a similar tenant identifier.  
  * **Verification Steps:**  
    1. Monitor if LLM provider is called for Agency B's request after Agency A's identical request.  
    2. If possible, inspect cache entries to verify tenant-specific keys.  
* **ID:** CADP\_ADMIN\_ACCESS\_SCOPING\_001  
  * **Category Ref:** LLM \- Cross-Agency Data Protection  
  * **Description:** Verify that administrative functionalities (e.g., viewing all usage, managing API keys via /tokens/ or /users/ endpoints) correctly scope data if an "agency admin" role were introduced, or that global admin access does not inadvertently leak cross-agency data in summaries.  
  * **Exposure Point(s):** Admin-level API endpoints.  
  * **Test Method/Action:**  
    1. Log in as a global admin (with Scope.ADMIN).  
    2. Access endpoints that list users or API keys.  
    3. (Hypothetical) Log in as an "agency admin" for Agency A. Attempt to view/manage keys or usage for Agency B.  
  * **Prerequisites:** Admin API key. (Hypothetical agency admin role).  
  * **Expected Secure Outcome:** Global admin can see data across agencies but it should be clearly attributed. An agency admin (if such role exists) should only see/manage data for their own agency.  
  * **Verification Steps:**  
    1. Inspect responses from admin endpoints for correct data attribution and scoping.  
    2. Verify agency admin cannot access other agencies' data.

### **Advanced Cross-Agency Data Protection Testing**

* **ID:** CADP_DATA_RESIDENCY_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test data residency compliance and geographic data isolation between agencies.
  * **Exposure Point(s):** Data storage locations, geographic restrictions, compliance requirements.
  * **Test Method/Action:**
    1. Verify agency data is stored in compliant geographic regions.
    2. Test data residency enforcement and validation.
    3. Verify cross-border data transfer restrictions.
    4. Test geographic isolation of agency data processing.
    5. Validate compliance with data residency regulations.
  * **Prerequisites:** Multiple agency API keys, geographic compliance requirements, data location monitoring.
  * **Expected Secure Outcome:** Agency data respects geographic boundaries and residency requirements with proper isolation.
  * **Verification Steps:**
    1. Verify data storage compliance with residency requirements.
    2. Test geographic isolation enforcement.
    3. Check cross-border transfer restrictions.
    4. Validate compliance documentation and evidence.
  * **Code Reference:** Data residency configuration, geographic isolation mechanisms.

* **ID:** CADP_PRIVILEGE_ESCALATION_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test for cross-tenant privilege escalation and unauthorized access attempts.
  * **Exposure Point(s):** Authorization mechanisms, tenant isolation, privilege boundaries.
  * **Test Method/Action:**
    1. Attempt privilege escalation from one agency to another.
    2. Test horizontal privilege escalation between agency users.
    3. Verify authorization boundary enforcement.
    4. Test cross-agency administrative access prevention.
    5. Validate privilege isolation under error conditions.
  * **Prerequisites:** Multiple agency API keys, privilege testing tools, authorization mechanisms.
  * **Expected Secure Outcome:** No privilege escalation possible between agencies with strict boundary enforcement.
  * **Verification Steps:**
    1. Test privilege escalation prevention across agencies.
    2. Verify authorization boundary enforcement.
    3. Check horizontal privilege escalation prevention.
    4. Validate privilege isolation consistency.
  * **Code Reference:** Authorization mechanisms, privilege boundary enforcement.

* **ID:** CADP_DATA_RETENTION_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test data retention and deletion policies for cross-agency isolation.
  * **Exposure Point(s):** Data retention policies, deletion procedures, data lifecycle management.
  * **Test Method/Action:**
    1. Test agency-specific data retention policy enforcement.
    2. Verify secure data deletion and purging procedures.
    3. Test data retention isolation between agencies.
    4. Validate data lifecycle management compliance.
    5. Test data recovery and backup isolation.
  * **Prerequisites:** Data retention policies, deletion procedures, lifecycle management tools.
  * **Expected Secure Outcome:** Data retention and deletion are properly scoped by agency with secure isolation.
  * **Verification Steps:**
    1. Verify agency-specific retention policy enforcement.
    2. Test secure deletion and purging effectiveness.
    3. Check data lifecycle isolation between agencies.
    4. Validate backup and recovery isolation.
  * **Code Reference:** Data retention policies, deletion procedures, lifecycle management.

* **ID:** CADP_AUDIT_TRAIL_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test audit trail completeness and cross-agency access tracking.
  * **Exposure Point(s):** Audit logging, access tracking, compliance monitoring.
  * **Test Method/Action:**
    1. Verify comprehensive audit trail generation for agency activities.
    2. Test audit trail isolation and access controls.
    3. Validate audit trail completeness and accuracy.
    4. Test audit correlation and analysis capabilities.
    5. Verify compliance reporting and documentation.
  * **Prerequisites:** Audit logging systems, access tracking, compliance monitoring tools.
  * **Expected Secure Outcome:** Complete audit trails with proper isolation and comprehensive tracking.
  * **Verification Steps:**
    1. Verify audit trail completeness and accuracy.
    2. Test audit isolation between agencies.
    3. Check audit correlation and analysis capabilities.
    4. Validate compliance reporting effectiveness.
  * **Code Reference:** Audit logging in app/logs/, access tracking, compliance monitoring.

* **ID:** CADP_TENANT_VALIDATION_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test comprehensive tenant isolation validation and boundary enforcement.
  * **Exposure Point(s):** Tenant boundaries, isolation mechanisms, validation procedures.
  * **Test Method/Action:**
    1. Test tenant boundary validation and enforcement.
    2. Verify tenant isolation under various conditions.
    3. Test tenant validation in multi-component scenarios.
    4. Validate tenant isolation during system failures.
    5. Test tenant boundary enforcement consistency.
  * **Prerequisites:** Multi-tenant architecture, boundary validation tools, isolation testing.
  * **Expected Secure Outcome:** Comprehensive tenant isolation with robust boundary enforcement.
  * **Verification Steps:**
    1. Test tenant boundary validation effectiveness.
    2. Verify isolation under various operational conditions.
    3. Check tenant validation in multi-component scenarios.
    4. Validate isolation during failure conditions.
  * **Code Reference:** Tenant isolation mechanisms, boundary validation, manager_id scoping.

* **ID:** CADP_DATA_SOVEREIGNTY_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test data sovereignty requirements and jurisdictional compliance.
  * **Exposure Point(s):** Jurisdictional requirements, data sovereignty compliance, regulatory adherence.
  * **Test Method/Action:**
    1. Verify compliance with data sovereignty requirements.
    2. Test jurisdictional data handling and processing.
    3. Validate regulatory compliance across jurisdictions.
    4. Test data sovereignty enforcement mechanisms.
    5. Verify compliance documentation and evidence.
  * **Prerequisites:** Data sovereignty requirements, jurisdictional compliance, regulatory frameworks.
  * **Expected Secure Outcome:** Full compliance with data sovereignty and jurisdictional requirements.
  * **Verification Steps:**
    1. Verify data sovereignty compliance and enforcement.
    2. Test jurisdictional requirement adherence.
    3. Check regulatory compliance across jurisdictions.
    4. Validate compliance documentation quality.
  * **Code Reference:** Data sovereignty implementation, compliance mechanisms, regulatory adherence.

* **ID:** CADP_COLLABORATION_SECURITY_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test security of multi-agency collaboration scenarios while maintaining isolation.
  * **Exposure Point(s):** Multi-agency collaboration, controlled data sharing, collaboration security.
  * **Test Method/Action:**
    1. Test controlled data sharing between authorized agencies.
    2. Verify collaboration security and access controls.
    3. Test collaboration audit and monitoring.
    4. Validate collaboration boundary enforcement.
    5. Test collaboration termination and cleanup.
  * **Prerequisites:** Multi-agency collaboration framework, controlled sharing mechanisms.
  * **Expected Secure Outcome:** Secure collaboration with controlled sharing and maintained isolation boundaries.
  * **Verification Steps:**
    1. Test controlled sharing effectiveness and security.
    2. Verify collaboration access control enforcement.
    3. Check collaboration audit and monitoring completeness.
    4. Validate boundary enforcement during collaboration.
  * **Code Reference:** Collaboration framework, controlled sharing mechanisms, access controls.

* **ID:** CADP_METADATA_ISOLATION_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test metadata isolation and prevent information leakage through metadata.
  * **Exposure Point(s):** Metadata handling, information disclosure through metadata, metadata isolation.
  * **Test Method/Action:**
    1. Test metadata isolation between agencies.
    2. Verify no information leakage through metadata.
    3. Test metadata access controls and protection.
    4. Validate metadata handling in shared components.
    5. Test metadata sanitization and filtering.
  * **Prerequisites:** Metadata handling systems, isolation mechanisms, metadata protection tools.
  * **Expected Secure Outcome:** Complete metadata isolation with no information leakage between agencies.
  * **Verification Steps:**
    1. Test metadata isolation effectiveness.
    2. Verify no information leakage through metadata channels.
    3. Check metadata access control enforcement.
    4. Validate metadata sanitization effectiveness.
  * **Code Reference:** Metadata handling, isolation mechanisms, information protection.

* **ID:** CADP_PERFORMANCE_ISOLATION_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test performance isolation and prevent cross-agency performance interference.
  * **Exposure Point(s):** Performance isolation, resource allocation, cross-agency interference prevention.
  * **Test Method/Action:**
    1. Test performance isolation between agency workloads.
    2. Verify resource allocation fairness and isolation.
    3. Test performance interference prevention.
    4. Validate performance monitoring and alerting.
    5. Test performance isolation under load conditions.
  * **Prerequisites:** Performance monitoring tools, resource allocation mechanisms, load testing capabilities.
  * **Expected Secure Outcome:** Performance isolation prevents cross-agency interference with fair resource allocation.
  * **Verification Steps:**
    1. Test performance isolation effectiveness under load.
    2. Verify resource allocation fairness and isolation.
    3. Check performance interference prevention.
    4. Validate performance monitoring accuracy.
  * **Code Reference:** Performance isolation mechanisms, resource allocation, monitoring systems.

* **ID:** CADP_INCIDENT_ISOLATION_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Test incident isolation and prevent cross-agency incident impact.
  * **Exposure Point(s):** Incident isolation, impact containment, cross-agency incident prevention.
  * **Test Method/Action:**
    1. Test incident isolation and containment mechanisms.
    2. Verify incident impact limitation to affected agency.
    3. Test incident response coordination without data leakage.
    4. Validate incident recovery and restoration procedures.
    5. Test incident communication and notification isolation.
  * **Prerequisites:** Incident response procedures, isolation mechanisms, incident simulation tools.
  * **Expected Secure Outcome:** Incidents are properly isolated with no cross-agency impact or data leakage.
  * **Verification Steps:**
    1. Test incident isolation and containment effectiveness.
    2. Verify incident impact limitation and scope.
    3. Check incident response coordination security.
    4. Validate recovery procedure isolation.
  * **Code Reference:** Incident response procedures, isolation mechanisms, containment systems.

* **ID:** CADP_COMPREHENSIVE_VALIDATION_001
  * **Category Ref:** LLM - Cross-Agency Data Protection
  * **Description:** Comprehensive validation of all cross-agency data protection mechanisms.
  * **Exposure Point(s):** Complete cross-agency protection, end-to-end validation, comprehensive security.
  * **Test Method/Action:**
    1. Test complete cross-agency protection across all system components.
    2. Verify end-to-end data protection and isolation.
    3. Test comprehensive security boundary enforcement.
    4. Validate protection mechanism integration and coordination.
    5. Test protection effectiveness under various scenarios.
  * **Prerequisites:** Complete system deployment, comprehensive testing framework, multi-agency test scenarios.
  * **Expected Secure Outcome:** Comprehensive cross-agency protection with complete data isolation and security.
  * **Verification Steps:**
    1. Test complete protection mechanism effectiveness.
    2. Verify end-to-end isolation and security.
    3. Check protection integration and coordination.
    4. Validate comprehensive security boundary enforcement.
  * **Code Reference:** Complete cross-agency protection implementation, integrated security mechanisms.