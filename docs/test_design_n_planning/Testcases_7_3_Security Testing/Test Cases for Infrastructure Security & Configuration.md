# **Test Cases for Infrastructure Security & Configuration**

## **Introduction**

This document outlines test cases for **Infrastructure Security & Configuration** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md" (Section 3). These tests focus on the security of the underlying infrastructure supporting the LLM API, including container configurations, network settings, cloud IAM roles, and secrets management.  
**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 3\. Infrastructure Security & Configuration)  
* Dockerfile, docker-compose.yml  
* Cloud provider console/CLI for IAM and network settings (AWS, GCP)  
* app/config/settings.py (for understanding what secrets/cloud resources are used)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** Infra \- Security & Configuration  
* **Description:** What specific infrastructure security aspect is being tested.  
* **Exposure Point(s):** Container runtime, network policies, IAM roles, secrets storage/access.  
* **Test Method/Action:** Review configurations, scan container images, test network access, audit IAM policies.  
* **Prerequisites:** Access to deployment configurations, Dockerfile, cloud provider accounts.  
* **Expected Secure Outcome:** Infrastructure is configured according to the principle of least privilege, minimizes attack surface, and securely manages secrets and access to cloud resources used by LLMs.  
* **Verification Steps:** Inspect configurations, run scans, review IAM policies, test network connectivity.

## **Test Cases Summary**
**Total Test Cases: 20 (Original: 10, Enhanced: +10)**

### **Container Security**

* **ID:** INFRA\_CONTAINER\_VULN\_SCAN\_001  
  * **Category Ref:** Infra \- Security & Configuration  
  * **Description:** Scan final application Docker image (gsai-container) for known OS and application library vulnerabilities. (Overlaps with SCS\_CONTAINER\_BASE\_IMAGE\_001 but focuses on the final image).  
  * **Exposure Point(s):** Application Docker image.  
  * **Test Method/Action:** Use a container image scanner (e.g., Trivy, Clair, Docker Scout) on the built gsai-container image.  
  * **Prerequisites:** Built application Docker image. Scanner tool.  
  * **Expected Secure Outcome:** The final application image is free from known critical/high vulnerabilities in its OS packages and Python libraries.  
  * **Verification Steps:** Run scanner and review report.  
* **ID:** INFRA\_CONTAINER\_LEAST\_PRIVILEGE\_001  
  * **Category Ref:** Infra \- Security & Configuration  
  * **Description:** Verify the application inside the Docker container runs as a non-root user.  
  * **Exposure Point(s):** Dockerfile (USER directive), running container process.  
  * **Test Method/Action:**  
    1. Review Dockerfile for a USER directive setting a non-root user.  
    2. Inspect a running container instance to check the UID of the application process.  
  * **Prerequisites:** Dockerfile, running container instance.  
  * **Expected Secure Outcome:** The application process within the container runs as a dedicated, unprivileged user, not as root. (Current Dockerfile does not explicitly set a non-root USER, this is an improvement area).  
  * **Verification Steps:**  
    1. Check Dockerfile for USER \<non-root-user\>.  
    2. Exec into a running container and run id or whoami.  
* **ID:** INFRA\_CONTAINER\_FILESYSTEM\_READONLY\_001 (Advanced)  
  * **Category Ref:** Infra \- Security & Configuration  
  * **Description:** Assess if the container's root filesystem can be mounted as read-only, with specific writable paths for temp/logs if necessary.  
  * **Exposure Point(s):** Container runtime options. Application's need to write to filesystem.  
  * **Test Method/Action:** Attempt to run the container with \--read-only flag (Docker) or equivalent. Identify necessary writable paths (e.g., for temporary files, logs if not stdout) and mount them as tmpfs or volumes.  
  * **Prerequisites:** Understanding of application's disk write requirements.  
  * **Expected Secure Outcome:** Application functions correctly with a read-only root filesystem and explicitly defined writable temporary storage, reducing attack surface.  
  * **Verification Steps:** Test application functionality with read-only rootfs.

### **Network Security**

* **ID:** INFRA\_NETWORK\_PORT\_EXPOSURE\_001  
  * **Category Ref:** Infra \- Security & Configuration  
  * **Description:** Verify that only necessary ports are exposed by the container and host.  
  * **Exposure Point(s):** EXPOSE directive in Dockerfile, ports mapping in docker-compose.yml, host firewall, cloud security groups.  
  * **Test Method/Action:**  
    1. Review Dockerfile for EXPOSE (currently 8080).  
    2. Review docker-compose.yml for port mappings (currently 8080:8080).  
    3. Scan the host running the container for open ports.  
  * **Prerequisites:** Running container/application. Port scanning tool (e.g., nmap).  
  * **Expected Secure Outcome:** Only the application port (e.g., 8080 for the API) is exposed. No unnecessary ports (e.g., database port if DB is in same Docker network but shouldn't be host-exposed) are open on the host.  
  * **Verification Steps:**  
    1. Check Dockerfile and docker-compose.yml.  
    2. Run nmap \-p- \<host\_ip\> on the container host.  
* **ID:** INFRA\_NETWORK\_SEGMENTATION\_001 (Cloud context)  
  * **Category Ref:** Infra \- Security & Configuration  
  * **Description:** Verify network segmentation rules (e.g., AWS Security Groups, GCP Firewall Rules) restrict traffic to the API and from the API to downstream LLM providers and database.  
  * **Exposure Point(s):** Cloud provider network configurations.  
  * **Test Method/Action:** Review security group/firewall rules. Attempt connections from unauthorized sources/to unauthorized destinations.  
  * **Prerequisites:** Access to cloud provider console/configurations.  
  * **Expected Secure Outcome:**  
    * Ingress to API: Only from allowed sources (e.g., specific IPs, load balancer) on the API port.  
    * Egress from API: Only to whitelisted LLM provider endpoints (specific IPs/domains and ports) and the database endpoint. All other egress blocked.  
  * **Verification Steps:** Inspect cloud firewall rules. Test connectivity from disallowed IPs.  
* **ID:** INFRA\_NETWORK\_PROVIDER\_ENCRYPTION\_001  
  * **Category Ref:** Infra \- Security & Configuration  
  * **Description:** Confirm that communication between the API framework and LLM providers (Bedrock, Vertex AI) is over HTTPS.  
  * **Exposure Point(s):** Provider SDK usage in app/providers/bedrock/bedrock.py and app/providers/vertex\_ai/vertexai.py.  
  * **Test Method/Action:** Code review of SDK initialization and calls. (Optional: network traffic capture in a test environment, though SDKs use HTTPS by default).  
  * **Prerequisites:** Access to code.  
  * **Expected Secure Outcome:** Provider SDKs are configured to use HTTPS for all communications.  
  * **Verification Steps:** Confirm SDKs (aioboto3, google-cloud-aiplatform) use HTTPS by default. No insecure HTTP endpoints configured.

### **Cloud IAM & Secrets Management**

* **ID:** INFRA\_IAM\_LEAST\_PRIVILEGE\_LLM\_001  
  * **Category Ref:** Infra \- Security & Configuration  
  * **Description:** Re-verify IAM roles/service accounts for Bedrock and Vertex AI access grant only necessary permissions (e.g., bedrock:InvokeModel on specific models, not bedrock:\*). (Same as SMISC\_CLOUD\_IAM\_PERMISSIONS\_001).  
  * **Exposure Point(s):** AWS IAM role for Bedrock, GCP service account for Vertex AI.  
  * **Test Method/Action:** Review IAM policies.  
  * **Prerequisites:** Cloud console access.  
  * **Expected Secure Outcome:** Least privilege is enforced.  
  * **Verification Steps:** Inspect IAM policy documents.  
* **ID:** INFRA\_SECRETS\_PROVIDER\_KEYS\_001  
  * **Category Ref:** Infra \- Security & Configuration  
  * **Description:** Verify how LLM provider credentials/keys/roles (e.g., BEDROCK\_ASSUME\_ROLE, GOOGLE\_APPLICATION\_CREDENTIALS path) are managed and made available to the application environment.  
  * **Exposure Point(s):** Environment variable injection in docker-compose.yml (env\_file: .env), Kubernetes secrets, cloud provider secret management services. app/config/settings.py loads these.  
  * **Test Method/Action:** Review deployment configurations for how secrets from .env (or other sources) are passed to the running application.  
  * **Prerequisites:** Access to deployment configurations.  
  * **Expected Secure Outcome:** Secrets are securely injected into the application environment (e.g., as environment variables from a secure store). They are not hardcoded in container images or version control. The .env file itself is not part of the Docker image.  
  * **Verification Steps:**  
    1. Review Dockerfile (ensure no COPY .env).  
    2. Review docker-compose.yml (env\_file is common for dev, but for prod, secrets should come from orchestrator's secret management).  
    3. Confirm production deployment uses a secure method for injecting secrets.  
* **ID:** INFRA\_SECRETS\_DB\_CONN\_STRING\_001  
  * **Category Ref:** Infra \- Security & Configuration  
  * **Description:** Verify the database connection string (including password) is managed as a secret.  
  * **Exposure Point(s):** POSTGRES\_CONNECTION derived from db\_user, db\_pass, etc., in app/config/settings.py.  
  * **Test Method/Action:** Review how DB\_USER, DB\_PASS are provided to the application.  
  * **Prerequisites:** Access to deployment configurations.  
  * **Expected Secure Outcome:** Database credentials are treated as secrets and securely injected.  
  * **Verification Steps:** Similar to INFRA\_SECRETS\_PROVIDER\_KEYS\_001.

### **Advanced Infrastructure Security Testing**

* **ID:** INFRA_RUNTIME_SECURITY_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Test runtime security monitoring and threat detection for containers and infrastructure.
  * **Exposure Point(s):** Runtime security monitoring, threat detection, container behavior analysis.
  * **Test Method/Action:**
    1. Test runtime security monitoring for containers and infrastructure.
    2. Verify threat detection and behavioral analysis capabilities.
    3. Test security policy enforcement during runtime.
    4. Validate runtime anomaly detection and alerting.
    5. Test runtime security incident response and containment.
  * **Prerequisites:** Runtime security monitoring tools, threat detection systems, security policies.
  * **Expected Secure Outcome:** Comprehensive runtime security monitoring with effective threat detection and response.
  * **Verification Steps:**
    1. Test runtime monitoring coverage and accuracy.
    2. Verify threat detection effectiveness and response.
    3. Check security policy enforcement consistency.
    4. Validate anomaly detection and alerting systems.
  * **Code Reference:** Runtime security configuration, monitoring systems, threat detection mechanisms.

* **ID:** INFRA_CONTAINER_ESCAPE_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Test container escape prevention and containment security.
  * **Exposure Point(s):** Container isolation, privilege escalation prevention, breakout protection.
  * **Test Method/Action:**
    1. Test container escape prevention mechanisms.
    2. Verify privilege escalation protection and containment.
    3. Test container isolation and sandbox effectiveness.
    4. Validate security boundary enforcement and monitoring.
    5. Test escape attempt detection and response.
  * **Prerequisites:** Container security tools, privilege escalation testing, isolation testing capabilities.
  * **Expected Secure Outcome:** Robust container isolation with effective escape prevention and detection.
  * **Verification Steps:**
    1. Test container escape prevention effectiveness.
    2. Verify privilege escalation protection mechanisms.
    3. Check container isolation and sandbox security.
    4. Validate boundary enforcement and monitoring.
  * **Code Reference:** Container security configuration, isolation mechanisms, privilege controls.

* **ID:** INFRA_SECRETS_ROTATION_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Test automated secrets rotation and lifecycle management.
  * **Exposure Point(s):** Secrets rotation automation, lifecycle management, credential updates.
  * **Test Method/Action:**
    1. Test automated secrets rotation procedures and timing.
    2. Verify secrets lifecycle management and expiration.
    3. Test rotation coordination across services and components.
    4. Validate rotation audit logging and monitoring.
    5. Test rotation failure detection and recovery.
  * **Prerequisites:** Secrets management systems, rotation automation, lifecycle policies.
  * **Expected Secure Outcome:** Automated secrets rotation with comprehensive lifecycle management and audit trails.
  * **Verification Steps:**
    1. Test rotation automation and scheduling effectiveness.
    2. Verify lifecycle management and expiration handling.
    3. Check rotation coordination and synchronization.
    4. Validate audit logging and monitoring completeness.
  * **Code Reference:** Secrets management configuration, rotation automation, lifecycle management.

* **ID:** INFRA_BACKUP_SECURITY_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Test backup security and disaster recovery protection.
  * **Exposure Point(s):** Backup encryption, access controls, recovery procedures, backup integrity.
  * **Test Method/Action:**
    1. Test backup encryption and security protection.
    2. Verify backup access controls and authorization.
    3. Test backup integrity and verification procedures.
    4. Validate disaster recovery security and procedures.
    5. Test backup restoration security and validation.
  * **Prerequisites:** Backup systems, encryption tools, disaster recovery procedures.
  * **Expected Secure Outcome:** Secure backups with proper encryption, access controls, and recovery procedures.
  * **Verification Steps:**
    1. Test backup encryption and protection effectiveness.
    2. Verify access control enforcement and authorization.
    3. Check backup integrity and verification procedures.
    4. Validate recovery security and restoration procedures.
  * **Code Reference:** Backup configuration, encryption settings, disaster recovery procedures.

* **ID:** INFRA_MONITORING_SECURITY_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Test infrastructure monitoring security and data protection.
  * **Exposure Point(s):** Monitoring data security, access controls, metric protection, alerting security.
  * **Test Method/Action:**
    1. Test monitoring data encryption and protection.
    2. Verify monitoring access controls and authorization.
    3. Test metric collection security and validation.
    4. Validate alerting security and notification protection.
    5. Test monitoring system integrity and reliability.
  * **Prerequisites:** Monitoring systems, encryption tools, access control mechanisms.
  * **Expected Secure Outcome:** Secure monitoring with protected data, proper access controls, and reliable alerting.
  * **Verification Steps:**
    1. Test monitoring data protection and encryption.
    2. Verify access control effectiveness and enforcement.
    3. Check metric collection security and accuracy.
    4. Validate alerting security and notification integrity.
  * **Code Reference:** Monitoring configuration, data protection, access control systems.

* **ID:** INFRA_CLOUD_GOVERNANCE_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Test cloud governance and resource management security.
  * **Exposure Point(s):** Cloud governance policies, resource management, compliance enforcement.
  * **Test Method/Action:**
    1. Test cloud governance policy enforcement and compliance.
    2. Verify resource management security and controls.
    3. Test cloud security posture and configuration management.
    4. Validate governance automation and policy enforcement.
    5. Test compliance monitoring and reporting.
  * **Prerequisites:** Cloud governance tools, policy enforcement systems, compliance frameworks.
  * **Expected Secure Outcome:** Comprehensive cloud governance with effective policy enforcement and compliance monitoring.
  * **Verification Steps:**
    1. Test governance policy enforcement effectiveness.
    2. Verify resource management security controls.
    3. Check security posture and configuration compliance.
    4. Validate automation and policy enforcement accuracy.
  * **Code Reference:** Cloud governance configuration, policy enforcement, compliance systems.

* **ID:** INFRA_RESOURCE_TAGGING_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Test resource tagging and classification for security and compliance.
  * **Exposure Point(s):** Resource tagging policies, classification systems, metadata management.
  * **Test Method/Action:**
    1. Test resource tagging policy enforcement and consistency.
    2. Verify classification accuracy and completeness.
    3. Test tag-based access controls and security policies.
    4. Validate metadata management and protection.
    5. Test tagging compliance and audit capabilities.
  * **Prerequisites:** Tagging policies, classification systems, metadata management tools.
  * **Expected Secure Outcome:** Consistent resource tagging with effective classification and security controls.
  * **Verification Steps:**
    1. Test tagging policy enforcement and consistency.
    2. Verify classification accuracy and completeness.
    3. Check tag-based security controls effectiveness.
    4. Validate metadata protection and management.
  * **Code Reference:** Tagging configuration, classification systems, metadata management.

* **ID:** INFRA_DISASTER_RECOVERY_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Test disaster recovery security and business continuity protection.
  * **Exposure Point(s):** Disaster recovery procedures, business continuity, security preservation.
  * **Test Method/Action:**
    1. Test disaster recovery procedure security and effectiveness.
    2. Verify business continuity planning and implementation.
    3. Test recovery time and point objectives under security constraints.
    4. Validate security preservation during recovery operations.
    5. Test recovery testing and validation procedures.
  * **Prerequisites:** Disaster recovery plans, business continuity procedures, recovery testing tools.
  * **Expected Secure Outcome:** Secure disaster recovery with effective business continuity and security preservation.
  * **Verification Steps:**
    1. Test recovery procedure security and effectiveness.
    2. Verify business continuity implementation and testing.
    3. Check security preservation during recovery.
    4. Validate recovery objectives and testing procedures.
  * **Code Reference:** Disaster recovery configuration, business continuity procedures, security preservation.

* **ID:** INFRA_CONFIGURATION_DRIFT_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Test configuration drift detection and remediation for security compliance.
  * **Exposure Point(s):** Configuration drift detection, compliance monitoring, automated remediation.
  * **Test Method/Action:**
    1. Test configuration drift detection and monitoring.
    2. Verify compliance validation and enforcement.
    3. Test automated remediation and correction procedures.
    4. Validate drift alerting and notification systems.
    5. Test configuration baseline management and maintenance.
  * **Prerequisites:** Configuration management tools, drift detection systems, compliance frameworks.
  * **Expected Secure Outcome:** Effective configuration drift detection with automated remediation and compliance enforcement.
  * **Verification Steps:**
    1. Test drift detection accuracy and timeliness.
    2. Verify compliance validation and enforcement.
    3. Check automated remediation effectiveness.
    4. Validate alerting and notification systems.
  * **Code Reference:** Configuration management, drift detection, automated remediation systems.

* **ID:** INFRA_COMPREHENSIVE_SECURITY_001
  * **Category Ref:** Infra - Security & Configuration
  * **Description:** Comprehensive infrastructure security testing and validation.
  * **Exposure Point(s):** Complete infrastructure security, end-to-end protection, integrated security controls.
  * **Test Method/Action:**
    1. Test complete infrastructure security across all components.
    2. Verify end-to-end security integration and coordination.
    3. Test comprehensive threat protection and response.
    4. Validate security control effectiveness and coverage.
    5. Test infrastructure security resilience and recovery.
  * **Prerequisites:** Complete infrastructure deployment, comprehensive security testing framework.
  * **Expected Secure Outcome:** Comprehensive infrastructure security with complete protection and effective integration.
  * **Verification Steps:**
    1. Test complete security coverage and effectiveness.
    2. Verify end-to-end integration and coordination.
    3. Check comprehensive protection and response.
    4. Validate security resilience and recovery capabilities.
  * **Code Reference:** Complete infrastructure security integration, comprehensive protection mechanisms.