# **Test Cases for Supply Chain Security**

## **Introduction**

This document outlines test cases for **Supply Chain Security** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md" (Section 3). These tests focus on mitigating risks from third-party dependencies, provider SDKs, and the software build/distribution process that could compromise the LLM API framework.  
**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 3\. Supply Chain Security)  
* pyproject.toml (list of dependencies)  
* Dockerfile (build process, base image)  
* LLM Provider SDKs (e.g., aioboto3 for Bedrock, google-cloud-aiplatform for Vertex AI)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** SupplyChain \- Security  
* **Description:** What specific supply chain vulnerability is being tested/verified.  
* **Exposure Point(s):** Project dependencies, build pipeline, container images, provider SDKs.  
* **Test Method/Action:** Dependency scanning, image scanning, review of build processes, verification of source integrity.  
* **Prerequisites:** Access to pyproject.toml, Dockerfile, CI/CD pipeline configuration. Tools for scanning.  
* **Expected Secure Outcome:** Dependencies are free of known critical/high vulnerabilities. Build process is secure. Container images are hardened. Provider SDKs are obtained from trusted sources.  
* **Verification Steps:** Review scan reports, audit build logs, inspect image layers.

## **Test Cases Summary**
**Total Test Cases: 18 (Original: 7, Enhanced: +11)**

### **Dependency Security Testing**

* **ID:** SCS\_DEPENDENCY\_VULN\_001  
  * **Category Ref:** SupplyChain \- Security  
  * **Description:** Scan project dependencies in pyproject.toml for known vulnerabilities.  
  * **Exposure Point(s):** Third-party Python packages (FastAPI, Pydantic, SQLAlchemy, aioboto3, google-cloud-aiplatform, etc.).  
  * **Test Method/Action:** Use a dependency vulnerability scanner (e.g., uv pip audit, safety, pip-audit, Snyk, GitHub Dependabot) against pyproject.toml or the installed environment.  
  * **Prerequisites:** pyproject.toml file. Scanner tool installed.  
  * **Expected Secure Outcome:** No known critical or high-severity vulnerabilities are present in direct or transitive dependencies. A process is in place for addressing medium/low vulnerabilities.  
  * **Verification Steps:**  
    1. Run the chosen scanner tool.  
    2. Review the vulnerability report.  
    3. Verify that any identified critical/high vulnerabilities have patches applied or mitigation plans.  
* **ID:** SCS\_PROVIDER\_SDK\_INTEGRITY\_001  
  * **Category Ref:** SupplyChain \- Security  
  * **Description:** Verify that LLM provider SDKs (aioboto3, google-cloud-aiplatform) are obtained from official/trusted sources and their versions are pinned.  
  * **Exposure Point(s):** pyproject.toml dependency specification for provider SDKs.  
  * **Test Method/Action:** Review pyproject.toml to ensure SDKs are fetched from PyPI (default for uv/pip) and have specific versions pinned (not loose ranges like \* or \>=).  
  * **Prerequisites:** pyproject.toml.  
  * **Expected Secure Outcome:** Provider SDKs are sourced from official repositories (PyPI). Versions are pinned to known, vetted versions to prevent unexpected updates or inclusion of compromised newer versions.  
  * **Verification Steps:**  
    1. Inspect pyproject.toml for boto3, aioboto3, google-cloud-aiplatform entries.  
    2. Confirm versions are specified (e.g., boto3 \= "^1.34.0" rather than boto3 \= "\*").  
* **ID:** SCS\_CONTAINER\_BASE\_IMAGE\_001  
  * **Category Ref:** SupplyChain \- Security  
  * **Description:** Scan the Docker container base image (specified in Dockerfile) for known vulnerabilities.  
  * **Exposure Point(s):** FROM python:3.11-slim-bullseye line in Dockerfile.  
  * **Test Method/Action:** Use a container image scanner (e.g., Trivy, Clair, Docker Scout) on the base image and the final application image.  
  * **Prerequisites:** Dockerfile. Container scanner tool.  
  * **Expected Secure Outcome:** The base image and final application image are free from known critical/high OS-level vulnerabilities. A process exists for updating the base image when patches are available.  
  * **Verification Steps:**  
    1. Run scanner on python:3.11-slim-bullseye.  
    2. Run scanner on the built application image (gsai-container).  
    3. Review vulnerability reports.  
* **ID:** SCS\_BUILD\_PROCESS\_INTEGRITY\_001  
  * **Category Ref:** SupplyChain \- Security  
  * **Description:** Review the container build process (Dockerfile) for secure practices.  
  * **Exposure Point(s):** Dockerfile instructions.  
  * **Test Method/Action:**  
    1. Review Dockerfile for unnecessary tools, exposed ports, or secrets baked into the image.  
    2. Ensure multi-stage builds are used if applicable to reduce final image size and attack surface.  
    3. Verify non-root user is used to run the application in the container.  
  * **Prerequisites:** Dockerfile.  
  * **Expected Secure Outcome:** Dockerfile follows security best practices: minimal layers, no hardcoded secrets, runs as non-root user, removes build-time dependencies from final image.  
  * **Verification Steps:** Manual review of Dockerfile. (Current Dockerfile is reasonable, uses python:3.11-slim-bullseye, copies requirements, then app code. It does not explicitly create a non-root user to run the app, which is an improvement area).  
* **ID:** SCS\_DEPENDENCY\_CONFUSION\_001 (Conceptual)  
  * **Category Ref:** SupplyChain \- Security  
  * **Description:** Assess risk of dependency confusion if private package names are used that could conflict with public PyPI package names.  
  * **Exposure Point(s):** pyproject.toml, package installation process.  
  * **Test Method/Action:** Review pyproject.toml for any custom/internal package names. Check if identically named packages exist on public PyPI.  
  * **Prerequisites:** pyproject.toml.  
  * **Expected Secure Outcome:** If private packages are used, ensure the build system prioritizes the private repository or that names are unique enough not to clash with public packages. (The current pyproject.toml only lists public packages).  
  * **Verification Steps:** Review package names. If private feeds are used, verify uv or pip configuration to prioritize them.  
* **ID:** SCS\_ARTIFACT\_INTEGRITY\_001 (If pre-built artifacts are used)  
  * **Category Ref:** SupplyChain \- Security  
  * **Description:** If any pre-built binaries or libraries (not from PyPI) are included, verify their source and integrity (e.g., via checksums).  
  * **Exposure Point(s):** Any non-PyPI dependencies.  
  * **Test Method/Action:** Identify any such artifacts. Verify their origin and compare checksums with official sources if available.  
  * **Prerequisites:** List of all dependencies and their sources.  
  * **Expected Secure Outcome:** All components are sourced from trusted locations and their integrity can be verified. (Currently, all Python deps appear to be from PyPI).  
  * **Verification Steps:** Review dependency sources.

### **Advanced Supply Chain Security Testing**

* **ID:** SCS_LICENSE_COMPLIANCE_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Verify license compliance and identify any dependencies with restrictive or incompatible licenses.
  * **Exposure Point(s):** All third-party dependencies in pyproject.toml, license information in package metadata.
  * **Test Method/Action:**
    1. Use license scanning tools (e.g., pip-licenses, FOSSA, Black Duck) to identify all dependency licenses.
    2. Review licenses for compliance with organizational policies and legal requirements.
    3. Identify copyleft licenses that may require source code disclosure.
    4. Check for license compatibility conflicts between dependencies.
  * **Prerequisites:** pyproject.toml file, license scanning tools, organizational license policy.
  * **Expected Secure Outcome:** All dependencies have compatible licenses that comply with organizational policies. No unexpected copyleft or restrictive license obligations.
  * **Verification Steps:**
    1. Generate complete license inventory for all dependencies.
    2. Review each license against organizational compliance requirements.
    3. Verify no license conflicts or incompatibilities exist.
    4. Document any license obligations and compliance measures.
  * **Code Reference:** Dependency licenses in package metadata, license compliance documentation.

* **ID:** SCS_SBOM_GENERATION_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Generate and validate Software Bill of Materials (SBOM) for the application.
  * **Exposure Point(s):** Complete application dependencies, SBOM generation tools, supply chain transparency.
  * **Test Method/Action:**
    1. Generate SBOM using tools like syft, cyclonedx-python, or SPDX tools.
    2. Verify SBOM completeness includes all direct and transitive dependencies.
    3. Validate SBOM format compliance (SPDX, CycloneDX standards).
    4. Test SBOM integrity and signature verification if implemented.
    5. Verify SBOM includes vulnerability information and supplier details.
  * **Prerequisites:** SBOM generation tools, dependency information, SBOM format specifications.
  * **Expected Secure Outcome:** Complete, accurate SBOM that provides full supply chain visibility and meets industry standards.
  * **Verification Steps:**
    1. Generate SBOM and verify completeness against actual dependencies.
    2. Validate SBOM format compliance with standards.
    3. Check SBOM includes all required metadata and vulnerability information.
    4. Test SBOM signature verification and integrity checks.
  * **Code Reference:** SBOM generation process, dependency inventory, supply chain documentation.

* **ID:** SCS_CI_CD_PIPELINE_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Test CI/CD pipeline security and verify secure build processes.
  * **Exposure Point(s):** Build pipeline, CI/CD configuration, artifact generation, deployment process.
  * **Test Method/Action:**
    1. Review CI/CD pipeline configuration for security best practices.
    2. Test pipeline isolation and access controls.
    3. Verify secure handling of secrets and credentials in pipeline.
    4. Test artifact signing and verification in build process.
    5. Verify pipeline audit logging and monitoring.
  * **Prerequisites:** CI/CD pipeline access, pipeline configuration files, security scanning tools.
  * **Expected Secure Outcome:** CI/CD pipeline follows security best practices with proper isolation, secure secret handling, and comprehensive audit logging.
  * **Verification Steps:**
    1. Review pipeline configuration for security controls.
    2. Test pipeline access controls and isolation mechanisms.
    3. Verify secret management and credential security.
    4. Check artifact signing and verification processes.
  * **Code Reference:** CI/CD pipeline configuration, build scripts, deployment automation.

* **ID:** SCS_ARTIFACT_SIGNING_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Test artifact signing and verification for build outputs and container images.
  * **Exposure Point(s):** Container images, build artifacts, signing keys, verification processes.
  * **Test Method/Action:**
    1. Verify container images are signed with trusted keys.
    2. Test artifact signature verification in deployment process.
    3. Validate signing key management and rotation procedures.
    4. Test signature verification failure handling.
    5. Verify cosign or similar tool integration for container signing.
  * **Prerequisites:** Signing tools (cosign, GPG), signing keys, artifact registry access.
  * **Expected Secure Outcome:** All artifacts are properly signed and verification is enforced during deployment.
  * **Verification Steps:**
    1. Verify artifact signatures are present and valid.
    2. Test signature verification process and failure handling.
    3. Check signing key management and rotation procedures.
    4. Validate integration with artifact registry and deployment tools.
  * **Code Reference:** Artifact signing configuration, key management, deployment verification.

* **ID:** SCS_DEPENDENCY_UPDATE_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Test dependency update policies and automated security patch management.
  * **Exposure Point(s):** Dependency update mechanisms, automated patching, version pinning policies.
  * **Test Method/Action:**
    1. Review dependency update policies and procedures.
    2. Test automated dependency scanning and update notifications.
    3. Verify security patch application timeliness.
    4. Test dependency update testing and rollback procedures.
    5. Validate version pinning and compatibility testing.
  * **Prerequisites:** Dependency management tools, update policies, testing procedures.
  * **Expected Secure Outcome:** Dependencies are regularly updated with security patches while maintaining system stability.
  * **Verification Steps:**
    1. Review dependency update policies and automation.
    2. Test security patch detection and notification systems.
    3. Verify update testing and rollback procedures.
    4. Check version compatibility and stability testing.
  * **Code Reference:** Dependency management configuration, update automation, testing procedures.

* **ID:** SCS_VENDOR_ASSESSMENT_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Assess security practices of key vendors and third-party providers.
  * **Exposure Point(s):** LLM provider security (AWS Bedrock, Google Vertex AI), critical dependency maintainers, infrastructure providers.
  * **Test Method/Action:**
    1. Review vendor security certifications and compliance status.
    2. Assess vendor incident response and vulnerability disclosure practices.
    3. Verify vendor supply chain security measures.
    4. Test vendor API security and data protection measures.
    5. Review vendor security assessments and audit reports.
  * **Prerequisites:** Vendor security documentation, compliance reports, assessment criteria.
  * **Expected Secure Outcome:** All vendors meet organizational security requirements and maintain acceptable security postures.
  * **Verification Steps:**
    1. Review vendor security certifications and compliance status.
    2. Assess vendor security practices and incident response capabilities.
    3. Verify vendor supply chain security measures.
    4. Check vendor API security and data protection implementation.
  * **Code Reference:** Vendor assessment documentation, compliance verification, security requirements.

* **ID:** SCS_SOURCE_CODE_INTEGRITY_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Verify source code integrity and prevent tampering in development and build processes.
  * **Exposure Point(s):** Source code repositories, commit signing, branch protection, code review processes.
  * **Test Method/Action:**
    1. Verify Git commit signing is enabled and enforced.
    2. Test branch protection rules and mandatory code reviews.
    3. Verify source code integrity checks and tamper detection.
    4. Test access controls for source code repositories.
    5. Validate code provenance and traceability.
  * **Prerequisites:** Git repository access, signing keys, branch protection configuration.
  * **Expected Secure Outcome:** Source code integrity is maintained throughout development lifecycle with proper access controls and tamper detection.
  * **Verification Steps:**
    1. Verify commit signing enforcement and key management.
    2. Test branch protection and code review requirements.
    3. Check source code integrity verification mechanisms.
    4. Validate repository access controls and audit logging.
  * **Code Reference:** Git configuration, branch protection rules, commit signing setup.

* **ID:** SCS_THIRD_PARTY_RISK_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Assess and manage risks from third-party components and services.
  * **Exposure Point(s):** All third-party dependencies, external services, vendor integrations.
  * **Test Method/Action:**
    1. Conduct risk assessment for all third-party components.
    2. Test third-party component isolation and sandboxing.
    3. Verify third-party service security controls and monitoring.
    4. Test incident response procedures for third-party security issues.
    5. Validate third-party risk mitigation strategies.
  * **Prerequisites:** Third-party inventory, risk assessment framework, security monitoring tools.
  * **Expected Secure Outcome:** Third-party risks are properly assessed, monitored, and mitigated with appropriate controls.
  * **Verification Steps:**
    1. Complete risk assessment for all third-party components.
    2. Test third-party isolation and containment measures.
    3. Verify security monitoring and alerting for third-party services.
    4. Check incident response procedures and risk mitigation effectiveness.
  * **Code Reference:** Third-party risk assessment, security controls, monitoring configuration.

* **ID:** SCS_SUPPLY_CHAIN_MONITORING_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Test continuous monitoring and alerting for supply chain security events.
  * **Exposure Point(s):** Dependency monitoring, vulnerability alerting, supply chain threat intelligence.
  * **Test Method/Action:**
    1. Test automated vulnerability scanning and alerting systems.
    2. Verify supply chain threat intelligence integration.
    3. Test incident detection and response for supply chain events.
    4. Validate monitoring coverage for all supply chain components.
    5. Test alerting thresholds and notification procedures.
  * **Prerequisites:** Security monitoring tools, threat intelligence feeds, alerting systems.
  * **Expected Secure Outcome:** Comprehensive monitoring provides early detection and rapid response to supply chain security threats.
  * **Verification Steps:**
    1. Test vulnerability scanning automation and alert generation.
    2. Verify threat intelligence integration and correlation.
    3. Check incident detection accuracy and response timeliness.
    4. Validate monitoring coverage and alerting effectiveness.
  * **Code Reference:** Monitoring configuration, alerting systems, threat intelligence integration.

* **ID:** SCS_COMPLIANCE_VALIDATION_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Validate compliance with supply chain security frameworks and regulations.
  * **Exposure Point(s):** NIST Secure Software Development Framework (SSDF), SLSA framework, regulatory requirements.
  * **Test Method/Action:**
    1. Assess compliance with NIST SSDF practices.
    2. Verify SLSA (Supply Chain Levels for Software Artifacts) framework implementation.
    3. Test compliance with relevant regulatory requirements (FISMA, FedRAMP).
    4. Validate supply chain security documentation and evidence.
    5. Test audit trail completeness for supply chain activities.
  * **Prerequisites:** Compliance frameworks, regulatory requirements, audit documentation.
  * **Expected Secure Outcome:** Full compliance with applicable supply chain security frameworks and regulatory requirements.
  * **Verification Steps:**
    1. Assess NIST SSDF practice implementation and documentation.
    2. Verify SLSA framework compliance and attestation.
    3. Check regulatory requirement compliance and evidence.
    4. Validate audit trail completeness and documentation quality.
  * **Code Reference:** Compliance documentation, framework implementation, audit evidence.

* **ID:** SCS_INCIDENT_RESPONSE_001
  * **Category Ref:** SupplyChain - Security
  * **Description:** Test incident response procedures for supply chain security events.
  * **Exposure Point(s):** Supply chain incident detection, response procedures, recovery processes.
  * **Test Method/Action:**
    1. Test incident detection and classification procedures.
    2. Verify supply chain incident response team activation.
    3. Test communication and notification procedures for supply chain incidents.
    4. Validate recovery and remediation procedures.
    5. Test lessons learned and improvement processes.
  * **Prerequisites:** Incident response plan, response team, communication procedures.
  * **Expected Secure Outcome:** Effective incident response capabilities for supply chain security events with rapid detection, response, and recovery.
  * **Verification Steps:**
    1. Test incident detection accuracy and timeliness.
    2. Verify response team activation and coordination.
    3. Check communication effectiveness and stakeholder notification.
    4. Validate recovery procedures and system restoration.
  * **Code Reference:** Incident response procedures, communication plans, recovery documentation.