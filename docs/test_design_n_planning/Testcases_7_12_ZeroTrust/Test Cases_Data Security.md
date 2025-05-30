# Test Cases for Zero Trust: Data Security

This document outlines test cases for verifying Data Security aspects of the GSAi API Framework, based on Zero Trust testing strategies detailed in Section 7.12 of the TestPlan.md.

**Test Cases Summary: 15 (Original: 7, Enhanced: +8)**

**Referenced Code Components:**
* **Encryption In Transit:** LLM provider SDKs use HTTPS by default for secure communication to Bedrock and Vertex AI
* **Database Connections:** app/config/settings.py:41-45 PostgreSQL connection string without explicit SSL/TLS configuration
* **Client Communications:** HTTPS termination typically handled at infrastructure level (load balancer/API gateway)
* **API Key Security:** app/auth/utils.py:12-22 implements SHA256 hashing with secure comparison using secrets.compare_digest
* **User Data Storage:** app/users/models.py stores PII (email, name) without explicit encryption beyond database-level protection
* **Memory Security:** LLM prompts/responses processed in application memory without explicit secure memory handling
* **Database Encryption:** Relies on PostgreSQL database-level encryption (infrastructure responsibility)

### **ZTA_DS_001**
* **ID:** ZTA_DS_001
* **Category Ref:** Data Security
* **Description:** Verify client-to-API communication is over HTTPS in production.
* **Exposure Point(s):** API endpoint accessibility. Typically handled by infrastructure (load balancer, API gateway, reverse proxy).
* **Test Method/Action:** In a production-like environment, attempt to connect to the API using HTTP.
* **Prerequisites:** Production-like deployment environment that is expected to enforce HTTPS.
* **Expected Secure Outcome:** HTTP requests are either rejected or redirected to HTTPS. Direct HTTP access to the API, especially for transmitting data, is not permitted.
* **Verification Steps:**
    1.  Attempt to make an API call using an `http://` URL (e.g., `curl http://<api_host>/api/v1/models`).
    2.  Verify the request fails, is redirected to HTTPS, or connection is refused.
    3.  Successfully make a call using `https://`.
    4.  Inspect TLS certificate details for validity and strength.

### **ZTA_DS_002**
* **ID:** ZTA_DS_002
* **Category Ref:** Data Security
* **Description:** Verify API-to-LLM provider communication uses HTTPS.
* **Exposure Point(s):** LLM provider SDKs (`aioboto3` for Bedrock, `google-cloud-aiplatform` for Vertex AI).
* **Test Method/Action:** Code review of SDK usage and reliance on SDK defaults.
* **Prerequisites:** Access to source code.
* **Expected Secure Outcome:** LLM provider SDKs use HTTPS by default for all communications with the provider endpoints. The application code does not override these defaults to use insecure connections.
* **Verification Steps:**
    1.  Confirm through SDK documentation that HTTPS is the default.
    2.  Review `app/providers/bedrock/bedrock.py` and `app/providers/vertex_ai/vertexai.py` to ensure no insecure settings (like disabling SSL) are applied during client initialization or request.

### **ZTA_DS_003**
* **ID:** ZTA_DS_003
* **Category Ref:** Data Security
* **Description:** Verify API-to-database communication can be configured for encryption.
* **Exposure Point(s):** PostgreSQL connection string in `app/config/settings.py:41-45` (`POSTGRES_CONNECTION`).
* **Test Method/Action:** Review how the `POSTGRES_CONNECTION` string is configured in a production-like environment.
* **Prerequisites:** Access to deployment configuration for the database connection string.
* **Expected Secure Outcome:** The PostgreSQL connection string is configured to use SSL/TLS (e.g., by appending `?ssl=require` or similar, depending on `asyncpg` driver options) if the database is not on localhost or within a trusted, isolated network segment. (Risk analysis notes "Database Connection Gaps: PostgreSQL connection lacks explicit SSL/TLS enforcement"). This test verifies that gap or its resolution.
* **Verification Steps:**
    1.  Inspect the `POSTGRES_CONNECTION` string used in the deployed environment.
    2.  Verify if SSL/TLS parameters are included and enforced if the database is remote.
    3.  If the database is on localhost within the same trusted boundary (e.g. Docker network), encryption might be deemed less critical but is still best practice.

### **ZTA_DS_004**
* **ID:** ZTA_DS_004
* **Category Ref:** Data Security
* **Description:** Verify secure storage of API keys (hashing).
* **Exposure Point(s):** `APIKey.hashed_key` field (`app/auth/models.py`), `generate_api_key` and `hash_api_key` functions (`app/auth/utils.py:4-22`).
* **Test Method/Action:** Create a new API key. Inspect its stored representation in the database.
* **Prerequisites:** API running, database access. Script `scripts/create_admin_user.py` can be used to create a key.
* **Expected Secure Outcome:** Raw API keys are not stored. Only a cryptographically strong hash (SHA256) of the API key is stored in the `hashed_key` field.
* **Verification Steps:**
    1.  Generate a new API key (e.g., using `create_admin_user.py` or by direct insertion for testing). Note the plaintext key.
    2.  Query the `api_keys` table for this key's record.
    3.  Confirm the `hashed_key` column contains a SHA256 hash and not the plaintext key.
    4.  Verify `secrets.compare_digest` is used for comparison during key validation in `app/auth/utils.py`.

### **ZTA_DS_005**
* **ID:** ZTA_DS_005
* **Category Ref:** Data Security
* **Description:** Review storage of user PII in the database.
* **Exposure Point(s):** `User` model (`app/users/models.py`) storing `email` and `name`.
* **Test Method/Action:** This is a design and database review.
* **Prerequisites:** Access to source code and database schema.
* **Expected Secure Outcome:** PII (email, name) is stored as plaintext in the database. This implies that database-level security (encryption at rest for the database, access controls) is critical and relied upon. The application itself does not apply further encryption to these fields before storage.
* **Verification Steps:**
    1.  Inspect the `User` model in `app/users/models.py`.
    2.  Confirm `email` and `name` fields are standard SQLAlchemy `String` types without application-level encryption wrappers.
    3.  This test verifies the current state, highlighting reliance on infrastructure for at-rest encryption of this PII.

### **ZTA_DS_006**
* **ID:** ZTA_DS_006
* **Category Ref:** Data Security
* **Description:** Assess secure memory handling for LLM prompts/responses (Conceptual).
* **Exposure Point(s):** Application memory during request processing of LLM prompts and responses. Risk analysis notes "Memory Security Concerns: No explicit secure memory handling".
* **Test Method/Action:** This is primarily a code review and conceptual analysis. Look for practices that might inadvertently prolong the life of sensitive data in memory or write it to insecure temporary locations.
* **Prerequisites:** Access to source code, especially provider adapters and router logic.
* **Expected Secure Outcome:** While Python's memory management is largely automatic, the application should avoid patterns like:
    * Storing full prompts/responses in global variables or long-lived objects unnecessarily.
    * Logging sensitive data from memory (covered by logging tests).
    * Explicitly writing sensitive data to temporary files without secure permissions and cleanup.
    The application should process and forward data promptly.
* **Verification Steps:**
    1.  Review how request and response data (especially `ChatCompletionRequest.messages[].content` and `ChatCompletionResponse.choices[].message.content`) is handled in memory within `app/routers/api_v1.py` and provider adapters.
    2.  Confirm that data is typically passed as arguments or local variables and not stored in broader scopes beyond the request lifecycle.
    3.  Note that this is a challenging area to test without specialized tools, and the focus is on avoiding obvious bad practices in the application code.

### **ZTA_DS_007**
* **ID:** ZTA_DS_007
* **Category Ref:** Data Security
* **Description:** Verify that LLM provider credentials are not exposed or insecurely managed by the API application environment.
* **Exposure Point(s):** How the API application authenticates to Bedrock (e.g., `BEDROCK_ASSUME_ROLE`) and Vertex AI (Application Default Credentials). Configuration in `app/config/settings.py`.
* **Test Method/Action:** Review configuration loading and provider client initialization.
* **Prerequisites:** Access to source code.
* **Expected Secure Outcome:** Credentials (like role ARNs or paths to service account keys if ADC wasn't used) are loaded securely from environment variables. The application does not log these credentials or make them accessible via API endpoints.
* **Verification Steps:**
    1.  Confirm in `app/config/settings.py` that sensitive values like `BEDROCK_ASSUME_ROLE` are loaded from the environment (e.g., using Pydantic's `Field(default=...)`).
    2.  Review provider client initialization in `app/providers/bedrock/bedrock.py` and `app/providers/vertex_ai/vertexai.py` to ensure credentials are handled by the SDKs based on secure environment setup (assumed roles, ADC).
    3.  Ensure these credentials are not logged (covered by other logging tests).

---

## Enhanced Test Cases: Advanced Data Security

### 1. End-to-End Encryption Validation

* **ID:** ZTA_DS_008
    * **Category Ref:** Data Security
    * **Description:** Test comprehensive end-to-end encryption for all data flows with cryptographic validation and certificate management.
    * **Exposure Point(s):** TLS implementation, certificate management, encryption validation, end-to-end data protection.
    * **Test Method/Action:**
        1. Test TLS 1.3 implementation and cipher suite validation
        2. Validate certificate pinning and certificate authority verification
        3. Test perfect forward secrecy and key exchange mechanisms
        4. Validate data integrity checks and tampering detection
        5. Test certificate rotation and renewal processes
    * **Prerequisites:** TLS infrastructure, certificate management systems, cryptographic validation tools.
    * **Expected Secure Outcome:** All communications use TLS 1.3 with strong ciphers. Certificate validation prevents man-in-the-middle attacks. Perfect forward secrecy protects historical data.
    * **Verification Steps:** Test TLS implementation, validate certificate handling, verify cipher strength, check forward secrecy implementation.

### 2. Advanced Key Management and HSM Integration

* **ID:** ZTA_DS_009
    * **Category Ref:** Data Security
    * **Description:** Test hardware security module integration for cryptographic key management with secure key storage and operations.
    * **Exposure Point(s):** HSM integration, key storage, cryptographic operations, secure key lifecycle management.
    * **Test Method/Action:**
        1. Test HSM integration for cryptographic key storage and operations
        2. Validate secure key generation and random number generation
        3. Test key access controls and authentication to HSM
        4. Validate cryptographic operations performed within HSM boundaries
        5. Test key backup, recovery, and disaster recovery procedures
    * **Prerequisites:** Hardware security module, HSM integration software, cryptographic infrastructure.
    * **Expected Secure Outcome:** Cryptographic keys stored and operated within HSM. Key operations tamper-resistant. Secure backup and recovery available.
    * **Verification Steps:** Test HSM integration, validate key security, verify access controls, check backup procedures.

### 3. Data Loss Prevention (DLP) Integration

* **ID:** ZTA_DS_010
    * **Category Ref:** Data Security
    * **Description:** Test data loss prevention capabilities with content inspection, classification, and protection for LLM interactions.
    * **Exposure Point(s):** DLP systems, content inspection, data classification, protection mechanisms.
    * **Test Method/Action:**
        1. Test real-time content inspection for sensitive data patterns
        2. Validate automatic data classification and labeling
        3. Test protection mechanisms for sensitive data transmission
        4. Validate policy enforcement and violation detection
        5. Test integration with incident response for data protection violations
    * **Prerequisites:** DLP platform, content inspection engines, data classification systems, policy enforcement tools.
    * **Expected Secure Outcome:** Sensitive data detected and protected automatically. Policy violations prevented and reported. Incident response triggered for violations.
    * **Verification Steps:** Test content inspection accuracy, validate classification effectiveness, verify protection mechanisms, check incident response integration.

### 4. Homomorphic Encryption for Secure Processing

* **ID:** ZTA_DS_011
    * **Category Ref:** Data Security
    * **Description:** Test homomorphic encryption implementation for processing encrypted data without decryption.
    * **Exposure Point(s):** Homomorphic encryption systems, encrypted data processing, secure computation frameworks.
    * **Test Method/Action:**
        1. Test homomorphic encryption of sensitive input data
        2. Validate processing operations on encrypted data
        3. Test result decryption and verification
        4. Validate performance impact and optimization
        5. Test integration with existing data processing workflows
    * **Prerequisites:** Homomorphic encryption libraries, secure computation infrastructure, performance optimization tools.
    * **Expected Secure Outcome:** Sensitive data processed while remaining encrypted. Computation results accurate and verifiable. Performance impact acceptable for use cases.
    * **Verification Steps:** Test encryption effectiveness, validate computation accuracy, verify performance metrics, check workflow integration.

### 5. Quantum-Resistant Cryptography

* **ID:** ZTA_DS_012
    * **Category Ref:** Data Security
    * **Description:** Test implementation of quantum-resistant cryptographic algorithms for future-proof data protection.
    * **Exposure Point(s):** Post-quantum cryptography, quantum-resistant algorithms, cryptographic agility frameworks.
    * **Test Method/Action:**
        1. Test implementation of NIST-approved post-quantum algorithms
        2. Validate quantum-resistant key exchange and encryption
        3. Test hybrid classical-quantum resistant modes
        4. Validate performance impact and optimization strategies
        5. Test cryptographic agility and algorithm transition capabilities
    * **Prerequisites:** Post-quantum cryptography libraries, quantum-resistant algorithms, performance testing tools.
    * **Expected Secure Outcome:** Quantum-resistant algorithms protect against future quantum attacks. Performance impact minimized through optimization. Agility enables smooth transitions.
    * **Verification Steps:** Test algorithm implementation, validate quantum resistance, verify performance optimization, check transition capabilities.

### 6. Secure Multi-Party Computation (SMPC)

* **ID:** ZTA_DS_013
    * **Category Ref:** Data Security
    * **Description:** Test secure multi-party computation for collaborative processing while maintaining data privacy.
    * **Exposure Point(s):** SMPC protocols, privacy-preserving computation, collaborative processing systems.
    * **Test Method/Action:**
        1. Test SMPC protocol implementation for collaborative data processing
        2. Validate privacy preservation during computation
        3. Test result accuracy and verification mechanisms
        4. Validate participant authentication and authorization
        5. Test protocol security against malicious participants
    * **Prerequisites:** SMPC framework, privacy-preserving protocols, participant management systems.
    * **Expected Secure Outcome:** Collaborative computation maintains data privacy. Results accurate and verifiable. Protection against malicious participants.
    * **Verification Steps:** Test protocol implementation, validate privacy preservation, verify result accuracy, check security against attacks.

### 7. Data Residency and Sovereignty Compliance

* **ID:** ZTA_DS_014
    * **Category Ref:** Data Security
    * **Description:** Test data residency controls and sovereignty compliance with geographic restrictions and regulatory requirements.
    * **Exposure Point(s):** Geographic data controls, sovereignty enforcement, compliance monitoring, residency validation.
    * **Test Method/Action:**
        1. Test geographic restrictions for data storage and processing
        2. Validate sovereignty compliance with jurisdictional requirements
        3. Test data flow monitoring and cross-border transfer controls
        4. Validate compliance reporting and audit capabilities
        5. Test emergency data access procedures while maintaining compliance
    * **Prerequisites:** Geographic compliance systems, sovereignty enforcement tools, monitoring infrastructure.
    * **Expected Secure Outcome:** Data remains within required geographic boundaries. Sovereignty requirements met. Cross-border transfers properly controlled and audited.
    * **Verification Steps:** Test geographic controls, validate sovereignty compliance, verify transfer monitoring, check audit capabilities.

### 8. Advanced Threat Protection for Data

* **ID:** ZTA_DS_015
    * **Category Ref:** Data Security
    * **Description:** Test advanced threat protection for data with machine learning-based detection and automated response.
    * **Exposure Point(s):** Threat detection systems, ML-based protection, automated response, data security analytics.
    * **Test Method/Action:**
        1. Test ML-based detection of data exfiltration attempts
        2. Validate anomaly detection for unusual data access patterns
        3. Test automated response to data security threats
        4. Validate threat intelligence integration for data protection
        5. Test forensics and investigation capabilities for data incidents
    * **Prerequisites:** ML-based threat detection, security analytics, automated response systems, forensics tools.
    * **Expected Secure Outcome:** Data threats detected accurately using ML. Automated responses contain threats effectively. Forensics provide investigation capabilities.
    * **Verification Steps:** Test threat detection accuracy, validate response effectiveness, verify forensics capabilities, check intelligence integration.

---