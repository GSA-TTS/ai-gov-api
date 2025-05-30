# Test Cases for Zero Trust: Identity Lifecycle and Key Management

This document outlines test cases related to Identity Lifecycle and Key Management for the GSAi API Framework, based on Zero Trust testing strategies detailed in Section 7.12 of the TestPlan.md.

**Test Cases Summary: 13 (Original: 5, Enhanced: +8)**

**Referenced Code Components:**
* **Manual Key Creation:** scripts/create_admin_user.py:22-71 requires manual execution for user and API key creation
* **Key Storage:** app/auth/models.py:14-26 supports expiration dates and activity tracking but lacks automated lifecycle management
* **No Rotation Framework:** Missing automated key rotation capabilities or rotation scheduling
* **Static Lifecycle:** app/auth/utils.py:4-24 provides key generation but no automated lifecycle management
* **Manual Deprovisioning:** No automated processes for key deactivation or user account cleanup
* **Usage Tracking:** app/auth/models.py:25 last_used_at tracking but no automated lifecycle decisions

### **ZTA_ILKM_001**
* **ID:** ZTA_ILKM_001
* **Category Ref:** Identity Lifecycle and Key Management
* **Description:** Verify manual API key creation process using `scripts/create_admin_user.py`.
* **Exposure Point(s):** `scripts/create_admin_user.py:22-71`.
* **Test Method/Action:** Execute the `create_admin_user.py` script with appropriate inputs.
* **Prerequisites:** Development environment set up to run the script, database accessible.
* **Expected Secure Outcome:** The script successfully creates a user and an associated API key with the specified (or default admin) scopes. The key is hashed in the database. The plaintext key is displayed by the script for manual recording. This confirms the current manual provisioning process.
* **Verification Steps:**
    1.  Run the script (e.g., `uv run python scripts/create_admin_user.py --email test@example.com --password testpassword`).
    2.  Note the plaintext API key output by the script.
    3.  Verify a new user is created in the `users` table with the provided email.
    4.  Verify a new API key is created in the `api_keys` table, linked to the user, with correct scopes and a hashed key.
    5.  Attempt to use the new API key to access `/api/v1/models`. It should succeed.

### **ZTA_ILKM_002**
* **ID:** ZTA_ILKM_002
* **Category Ref:** Identity Lifecycle and Key Management
* **Description:** Verify key expiration is functional but not automatically managed beyond initial setting.
* **Exposure Point(s):** `APIKey.expires_at` field (`app/auth/models.py:14-26`), `valid_api_key` dependency.
* **Test Method/Action:**
    1.  Create/select an API key and manually set its `expires_at` field in the database to a future date. Verify access.
    2.  Manually set `expires_at` to a past date. Verify access is denied.
* **Prerequisites:** API running, database access.
* **Expected Secure Outcome:** The `expires_at` field, when set, is correctly enforced. However, there is no automated process for setting expirations during creation (unless manually coded into a script using `create_admin_user.py` logic) or for notifying about upcoming expirations.
* **Verification Steps:**
    1.  Key with future `expires_at`: Successful API call (HTTP 200).
    2.  Key with past `expires_at`: Failed API call (HTTP 401, `{"detail": "API key is expired"}`).
    3.  Confirm no built-in API mechanism for users to set/update their own key's expiration.

### **ZTA_ILKM_003**
* **ID:** ZTA_ILKM_003
* **Category Ref:** Identity Lifecycle and Key Management
* **Description:** Verify absence of automated API key rotation framework.
* **Exposure Point(s):** Lack of automated key rotation feature. Risk analysis notes "No Rotation Framework."
* **Test Method/Action:** Review API capabilities and codebase for any key rotation features.
* **Prerequisites:** Access to source code and API documentation.
* **Expected Secure Outcome:** (Current state) The system does not provide automated API key rotation capabilities (e.g., scheduled rotation, API-triggered rotation for users). Key rotation would be a manual process (create new key, update clients, deactivate old key). This test confirms this gap.
* **Verification Steps:**
    1.  Confirm no API endpoints exist for users/admins to initiate key rotation.
    2.  Confirm no background processes or configurations for scheduled key rotation are evident in the codebase.

### **ZTA_ILKM_004**
* **ID:** ZTA_ILKM_004
* **Category Ref:** Identity Lifecycle and Key Management
* **Description:** Verify key deactivation is a manual process.
* **Exposure Point(s):** `APIKey.is_active` field, lack of automated deactivation. Risk analysis notes "Manual Deprovisioning."
* **Test Method/Action:**
    1.  Select an active API key. Verify access.
    2.  Manually set `is_active = False` for this key in the database.
    3.  Attempt to use the key again.
* **Prerequisites:** API running, database access.
* **Expected Secure Outcome:** (Current state) Deactivating a key (e.g., by setting `is_active = False`) correctly revokes its access. This is a manual database operation. There is no API endpoint for users/admins to deactivate keys, nor automated de-provisioning based on inactivity.
* **Verification Steps:**
    1.  Initially, key allows access (HTTP 200).
    2.  After setting `is_active = False` in DB, API call with the key fails (HTTP 401, `{"detail": "Missing or invalid API key"}`).
    3.  Confirm no API endpoint for key deactivation.

### **ZTA_ILKM_005**
* **ID:** ZTA_ILKM_005
* **Category Ref:** Identity Lifecycle and Key Management
* **Description:** Verify `last_used_at` field is updated but does not trigger automated lifecycle decisions.
* **Exposure Point(s):** `APIKey.last_used_at` (`app/auth/models.py:25`), `valid_api_key` updates this field.
* **Test Method/Action:** Make an API call with a key. Check `last_used_at`. Wait, make another call.
* **Prerequisites:** API running, database access.
* **Expected Secure Outcome:** The `last_used_at` timestamp is updated in the database upon successful use of the API key. However, this field is not currently used by the system to drive any automated lifecycle decisions (e.g., auto-deactivating very old unused keys). This test confirms the "Limited Lifecycle Tracking" gap in terms of automation.
* **Verification Steps:**
    1.  Note current `last_used_at` for a key.
    2.  Make a successful API call with the key.
    3.  Query the database and confirm `last_used_at` has been updated to a recent timestamp.
    4.  Confirm there's no logic that deactivates keys based on `last_used_at` exceeding a certain threshold.

---

## Enhanced Test Cases: Advanced Identity Lifecycle and Key Management

### 1. Automated Identity Provisioning Workflows

* **ID:** ZTA_ILKM_006
    * **Category Ref:** Identity Lifecycle and Key Management
    * **Description:** Test automated identity provisioning workflows with self-service capabilities and approval processes.
    * **Exposure Point(s):** Provisioning automation systems, self-service portals, approval workflows, identity templates.
    * **Test Method/Action:**
        1. Test self-service identity provisioning with automated approval
        2. Validate approval workflows for administrative identities
        3. Test identity template application and customization
        4. Validate automated onboarding and welcome processes
        5. Test integration with external identity systems and HR databases
    * **Prerequisites:** Provisioning automation platform, approval workflow systems, identity templates, integration capabilities.
    * **Expected Secure Outcome:** Identity provisioning automated with appropriate approvals. Templates ensure consistent security. Integration maintains data accuracy.
    * **Verification Steps:** Test automation effectiveness, validate approval processes, verify template application, check integration accuracy.

### 2. Intelligent Key Rotation Management

* **ID:** ZTA_ILKM_007
    * **Category Ref:** Identity Lifecycle and Key Management
    * **Description:** Test intelligent key rotation with automated scheduling, risk-based rotation, and seamless transition capabilities.
    * **Exposure Point(s):** Key rotation automation, scheduling systems, risk assessment integration, transition management.
    * **Test Method/Action:**
        1. Test automated key rotation based on schedules and policies
        2. Validate risk-based rotation triggers (compromise detection, unusual activity)
        3. Test seamless key transition with zero downtime
        4. Validate client notification and update processes
        5. Test emergency rotation capabilities and rapid deployment
    * **Prerequisites:** Rotation automation infrastructure, risk assessment integration, transition management, notification systems.
    * **Expected Secure Outcome:** Key rotation automated and intelligent. Risk triggers appropriate rotation. Transitions seamless with minimal disruption.
    * **Verification Steps:** Test automation accuracy, validate risk triggers, verify seamless transitions, check notification effectiveness.

### 3. Lifecycle Analytics and Optimization

* **ID:** ZTA_ILKM_008
    * **Category Ref:** Identity Lifecycle and Key Management
    * **Description:** Test lifecycle analytics with usage pattern analysis and optimization recommendations for identity management.
    * **Exposure Point(s):** Analytics platforms, usage tracking systems, optimization engines, lifecycle metrics.
    * **Test Method/Action:**
        1. Test comprehensive lifecycle analytics and reporting
        2. Validate usage pattern analysis and trend identification
        3. Test optimization recommendations for lifecycle processes
        4. Validate cost analysis and efficiency measurements
        5. Test predictive analytics for lifecycle planning
    * **Prerequisites:** Analytics infrastructure, usage tracking, optimization algorithms, predictive modeling capabilities.
    * **Expected Secure Outcome:** Lifecycle processes optimized through analytics. Usage patterns identified and leveraged. Predictive capabilities enhance planning.
    * **Verification Steps:** Test analytics accuracy, validate pattern analysis, verify optimization recommendations, check predictive capabilities.

### 4. Automated Deprovisioning and Cleanup

* **ID:** ZTA_ILKM_009
    * **Category Ref:** Identity Lifecycle and Key Management
    * **Description:** Test automated deprovisioning with policy-driven cleanup and secure data handling throughout the process.
    * **Exposure Point(s):** Deprovisioning automation, policy engines, cleanup processes, data handling systems.
    * **Test Method/Action:**
        1. Test automated deprovisioning triggers (termination, inactivity, policy violations)
        2. Validate comprehensive access removal and resource cleanup
        3. Test data retention and secure deletion policies
        4. Validate audit trail generation throughout deprovisioning
        5. Test rollback capabilities for incorrect deprovisioning
    * **Prerequisites:** Deprovisioning automation, policy management, data handling systems, audit capabilities.
    * **Expected Secure Outcome:** Deprovisioning automated and comprehensive. Data handled according to policies. Audit trails complete and accessible.
    * **Verification Steps:** Test trigger accuracy, validate cleanup completeness, verify data handling, check audit generation.

### 5. Key Escrow and Recovery Management

* **ID:** ZTA_ILKM_010
    * **Category Ref:** Identity Lifecycle and Key Management
    * **Description:** Test key escrow and recovery systems with secure key storage and authorized recovery procedures.
    * **Exposure Point(s):** Key escrow systems, recovery procedures, secure storage, authorization frameworks.
    * **Test Method/Action:**
        1. Test secure key escrow with proper encryption and access controls
        2. Validate authorized recovery procedures and multi-party approval
        3. Test emergency recovery capabilities and procedures
        4. Validate key reconstruction and verification processes
        5. Test audit and compliance tracking for recovery operations
    * **Prerequisites:** Key escrow infrastructure, recovery systems, multi-party approval, audit capabilities.
    * **Expected Secure Outcome:** Key escrow secure and accessible when authorized. Recovery procedures robust and audited. Emergency capabilities available.
    * **Verification Steps:** Test escrow security, validate recovery procedures, verify emergency capabilities, check audit completeness.

### 6. Lifecycle Compliance and Governance

* **ID:** ZTA_ILKM_011
    * **Category Ref:** Identity Lifecycle and Key Management
    * **Description:** Test lifecycle compliance with regulatory requirements and governance frameworks throughout identity management processes.
    * **Exposure Point(s):** Compliance systems, governance frameworks, regulatory tracking, audit capabilities.
    * **Test Method/Action:**
        1. Test compliance validation throughout identity lifecycle
        2. Validate regulatory requirement adherence (SOX, GDPR, FISMA)
        3. Test governance policy enforcement and exception handling
        4. Validate compliance reporting and audit trail generation
        5. Test regulatory change impact assessment and adaptation
    * **Prerequisites:** Compliance platforms, governance frameworks, regulatory databases, audit systems.
    * **Expected Secure Outcome:** Lifecycle processes compliant with regulations. Governance policies enforced consistently. Audit trails comprehensive.
    * **Verification Steps:** Test compliance validation, verify regulatory adherence, check governance enforcement, validate audit generation.

### 7. Cross-Platform Identity Synchronization

* **ID:** ZTA_ILKM_012
    * **Category Ref:** Identity Lifecycle and Key Management
    * **Description:** Test cross-platform identity synchronization with federated management and consistent lifecycle processes.
    * **Exposure Point(s):** Identity federation, synchronization systems, cross-platform management, consistency frameworks.
    * **Test Method/Action:**
        1. Test identity synchronization across multiple platforms and systems
        2. Validate consistent lifecycle processes across federated environments
        3. Test conflict resolution and data consistency management
        4. Validate cross-platform audit and compliance tracking
        5. Test disaster recovery and backup synchronization
    * **Prerequisites:** Federation infrastructure, synchronization systems, conflict resolution, disaster recovery capabilities.
    * **Expected Secure Outcome:** Identities synchronized consistently across platforms. Lifecycle processes unified. Conflicts resolved appropriately.
    * **Verification Steps:** Test synchronization accuracy, validate consistency, verify conflict resolution, check disaster recovery.

### 8. AI-Powered Lifecycle Optimization

* **ID:** ZTA_ILKM_013
    * **Category Ref:** Identity Lifecycle and Key Management
    * **Description:** Test AI-powered lifecycle optimization with machine learning-based predictions and automated improvements.
    * **Exposure Point(s):** AI optimization systems, machine learning models, predictive analytics, automation frameworks.
    * **Test Method/Action:**
        1. Test AI-based prediction of lifecycle events and requirements
        2. Validate machine learning optimization of lifecycle processes
        3. Test automated improvement recommendations and implementation
        4. Validate anomaly detection and proactive intervention
        5. Test continuous learning and model adaptation
    * **Prerequisites:** AI optimization platform, machine learning infrastructure, predictive modeling, continuous learning systems.
    * **Expected Secure Outcome:** AI provides accurate lifecycle predictions. Optimization improves efficiency and security. Continuous learning enhances capabilities.
    * **Verification Steps:** Test prediction accuracy, validate optimization effectiveness, verify improvement implementation, check learning capabilities.

---