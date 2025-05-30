# Test Cases for Zero Trust: Network Segmentation

This document outlines test cases for verifying Network Segmentation and Micro-segmentation within the GSAi API Framework, based on Zero Trust testing strategies detailed in Section 7.12 of the TestPlan.md.

**Test Cases Summary: 14 (Original: 6, Enhanced: +8)**

**Referenced Code Components:**
* **Container Networking:** docker-compose.yml:37-38 defines basic backend network isolation between API and database services
* **Service Communication:** docker-compose.yml:12-20 exposes API on port 8080 with network aliases for service discovery
* **Database Isolation:** docker-compose.yml:22-35 isolates PostgreSQL database in backend network with explicit service dependencies
* **Missing Security Policies:** No network security policies, traffic filtering, or micro-segmentation controls in container configuration
* **Provider Communication:** LLM provider connections via internet without explicit network controls or traffic inspection
* **Infrastructure Dependencies:** Relies on external infrastructure for network security including VPC, security groups, and WAF protection

### **ZTA_NET_001**
* **ID:** ZTA_NET_001
* **Category Ref:** Network Segmentation (Micro-segmentation)
* **Description:** Review container networking for basic isolation.
* **Exposure Point(s):** `docker-compose.yml` (`networks` definition, service network assignments).
* **Test Method/Action:** Inspect the `docker-compose.yml` file.
* **Prerequisites:** Access to the `docker-compose.yml` file.
* **Expected Secure Outcome:** Services (API, database) are defined on a backend network, providing basic network namespace isolation as per `docker-compose.yml:37-38`. The API is exposed on a specific port (e.g., 8080).
* **Verification Steps:**
    1.  Confirm `docker-compose.yml` defines a custom network (e.g., `backend-network`).
    2.  Confirm the API service (`ai-gov-api-backend`) and database service (`ai-gov-api-db`) are assigned to this network.
    3.  Confirm the API service exposes a port (e.g., `8080:8080`).
    4.  Confirm the database service does not expose its port externally in the `docker-compose.yml` unless explicitly required and firewalled.

### **ZTA_NET_002**
* **ID:** ZTA_NET_002
* **Category Ref:** Network Segmentation (Micro-segmentation)
* **Description:** Assess lack of fine-grained network policies within Docker Compose.
* **Exposure Point(s):** `docker-compose.yml`. Risk analysis notes "No network security policies, traffic filtering, or micro-segmentation controls in container configuration."
* **Test Method/Action:** Review `docker-compose.yml` for any advanced network policy definitions.
* **Prerequisites:** Access to `docker-compose.yml`.
* **Expected Secure Outcome:** (Based on risk analysis) The current `docker-compose.yml` is expected to lack fine-grained network security policies (like Docker network plugins providing firewalling). This test verifies that gap. For a more secure setup, such policies would be desired.
* **Verification Steps:**
    1.  Confirm the absence of specific traffic filtering rules, explicit port restrictions between services on the internal network, or other micro-segmentation features within the `docker-compose.yml` itself. (This confirms the gap noted in the risk analysis).

### **ZTA_NET_003**
* **ID:** ZTA_NET_003
* **Category Ref:** Network Segmentation (Micro-segmentation)
* **Description:** Test API's ability to connect to arbitrary internet locations (Egress Control).
* **Exposure Point(s):** API application's outbound network capabilities from its container/host. Risk: "Overly permissive egress rules."
* **Test Method/Action:** This is an advanced test. If possible, from within the running API container (e.g., `docker exec -it <api_container_id> /bin/sh`), attempt to make network requests (e.g., `curl`, `ping`) to arbitrary external websites not related to LLM providers.
* **Prerequisites:** Running API container, shell access to the container or ability to deploy a test version with network tools. Secure environment to conduct such a test.
* **Expected Secure Outcome:** Ideally, in a Zero Trust environment, egress traffic from the API container should be restricted by network policies (e.g., firewall, proxy, service mesh egress gateways) to only allow connections to explicitly whitelisted LLM provider endpoints and other necessary services (like the database). Unfettered internet access would be a risk.
* **Verification Steps:**
    1.  Attempt to connect to `google.com` or another non-LLM internet host from the API container.
    2.  If the connection succeeds, it indicates permissive egress. If it fails (and legitimate LLM calls work), it indicates some egress control is in place.
    3.  This test primarily highlights the need for egress filtering at the infrastructure level (not in the application code itself).

### **ZTA_NET_004**
* **ID:** ZTA_NET_004
* **Category Ref:** Network Segmentation (Micro-segmentation)
* **Description:** Review database network exposure.
* **Exposure Point(s):** Database service configuration in `docker-compose.yml:22-35`, and actual deployment environment.
* **Test Method/Action:** Inspect `docker-compose.yml` for database port exposure. In a deployed environment, attempt to connect to the database port from outside the defined backend network (e.g., from the public internet or a different VPC segment).
* **Prerequisites:** Access to `docker-compose.yml` and information about the deployed environment's network configuration. Network scanning tools (e.g., `nmap`) if testing a live environment (use with extreme caution and authorization).
* **Expected Secure Outcome:** The database port should not be exposed to the public internet. Access should be restricted to the API application's network/host. The `docker-compose.yml` does not expose the DB port in `ports:` for the `ai-gov-api-db` service.
* **Verification Steps:**
    1.  Confirm the `ai-gov-api-db` service in `docker-compose.yml` does not have a `ports:` section mapping its internal port (5432) to the host or external network. (Current `docker-compose.yml` is good here).
    2.  In a deployed environment, verify that firewall rules or security groups prevent direct access to the database port from untrusted networks.

### **ZTA_NET_005**
* **ID:** ZTA_NET_005
* **Category Ref:** Network Segmentation (Micro-segmentation)
* **Description:** Verify LLM provider connections occur over standard, secured protocols (HTTPS).
* **Exposure Point(s):** LLM provider SDKs used in `app/providers/bedrock/bedrock.py` and `app/providers/vertex_ai/vertexai.py`.
* **Test Method/Action:** Code review of SDK initialization and usage. Optionally, use network monitoring tools (e.g., Wireshark, tcpdump) in a controlled test environment to observe traffic from the API to LLM providers (complex to set up for encrypted traffic details beyond confirming destination and port).
* **Prerequisites:** Access to source code.
* **Expected Secure Outcome:** Communications with LLM providers (AWS Bedrock, Google Vertex AI) are made over HTTPS (typically port 443), as handled by their respective SDKs (`aioboto3`, `google-cloud-aiplatform`).
* **Verification Steps:**
    1.  Confirm through SDK documentation that they use HTTPS by default.
    2.  Review application code to ensure no insecure overrides are made (e.g., disabling SSL verification, which is not present).
    3.  (Optional, advanced) If network traffic is captured, verify connections to provider endpoints are on TCP port 443.

### **ZTA_NET_006**
* **ID:** ZTA_NET_006
* **Category Ref:** Network Segmentation (Micro-segmentation)
* **Description:** Assess infrastructure-level network security (VPC, Security Groups, WAF) - Conceptual.
* **Exposure Point(s):** Deployment environment infrastructure (AWS VPC, Security Groups, GCP VPC, Firewall Rules, Web Application Firewall).
* **Test Method/Action:** This is a review of the deployed infrastructure's network security configuration, not a direct API test.
* **Prerequisites:** Access to cloud infrastructure configuration details or diagrams.
* **Expected Secure Outcome:** The API and database are deployed within a secure VPC. Security Groups/Firewall rules restrict ingress traffic to the API to necessary ports (e.g., 443 from trusted sources) and restrict traffic between the API and database. A WAF may be deployed in front of the API for additional protection. (This confirms the "Infrastructure Security Gaps" are addressed).
* **Verification Steps:**
    1.  Review VPC design and subnet configurations.
    2.  Review Security Group/Firewall rules for the API instances and database instances.
    3.  Check if a WAF is implemented and its rules.

---

## Enhanced Test Cases: Advanced Network Segmentation

### 1. Software-Defined Perimeter (SDP) Implementation

* **ID:** ZTA_NET_007
    * **Category Ref:** Network Segmentation (Micro-segmentation)
    * **Description:** Test software-defined perimeter implementation for dynamic network access control and identity-based network segmentation.
    * **Exposure Point(s):** SDP infrastructure, identity-based network access, dynamic perimeter controls.
    * **Test Method/Action:**
        1. Test identity-based network access through SDP gateways
        2. Validate dynamic perimeter establishment based on user context
        3. Test network cloaking and service invisibility for unauthorized users
        4. Validate encrypted tunnel establishment and maintenance
        5. Test access revocation and perimeter update mechanisms
    * **Prerequisites:** SDP infrastructure, identity management integration, encrypted tunnel capabilities.
    * **Expected Secure Outcome:** Network access granted only to verified identities. Services remain invisible to unauthorized users. Encrypted tunnels protect all communications.
    * **Verification Steps:** Test identity verification, validate service cloaking, verify tunnel encryption, check access revocation effectiveness.

### 2. Zero Trust Network Architecture (ZTNA)

* **ID:** ZTA_NET_008
    * **Category Ref:** Network Segmentation (Micro-segmentation)
    * **Description:** Test comprehensive zero trust network architecture with identity verification for every network connection.
    * **Exposure Point(s):** ZTNA infrastructure, identity verification, connection monitoring, micro-tunnel implementation.
    * **Test Method/Action:**
        1. Test identity verification for every network connection attempt
        2. Validate micro-tunnel creation for authorized connections
        3. Test continuous connection monitoring and re-verification
        4. Validate network isolation between different user segments
        5. Test automatic connection termination for policy violations
    * **Prerequisites:** ZTNA platform, identity verification systems, micro-tunnel infrastructure, monitoring capabilities.
    * **Expected Secure Outcome:** Every network connection verified and monitored. Unauthorized access prevented. Policy violations result in immediate disconnection.
    * **Verification Steps:** Test connection verification, validate micro-tunnels, verify monitoring accuracy, check isolation effectiveness.

### 3. Application-Layer Traffic Inspection

* **ID:** ZTA_NET_009
    * **Category Ref:** Network Segmentation (Micro-segmentation)
    * **Description:** Test deep packet inspection and application-layer traffic analysis for LLM communications with threat detection.
    * **Exposure Point(s):** Deep packet inspection systems, application-layer gateways, traffic analysis engines.
    * **Test Method/Action:**
        1. Test deep packet inspection of API traffic for malicious content
        2. Validate application-layer protocol analysis and filtering
        3. Test detection of suspicious LLM interaction patterns
        4. Validate content filtering and data loss prevention
        5. Test real-time threat detection and response
    * **Prerequisites:** DPI infrastructure, application gateways, threat detection systems, content filtering capabilities.
    * **Expected Secure Outcome:** Malicious traffic detected and blocked. Application protocols properly analyzed. Suspicious patterns identified and investigated.
    * **Verification Steps:** Test DPI accuracy, validate protocol analysis, verify threat detection, check content filtering effectiveness.

### 4. Service Mesh Security

* **ID:** ZTA_NET_010
    * **Category Ref:** Network Segmentation (Micro-segmentation)
    * **Description:** Test service mesh implementation with mutual TLS, traffic policies, and microsegmentation for container communications.
    * **Exposure Point(s):** Service mesh infrastructure, mTLS implementation, traffic policies, microsegmentation controls.
    * **Test Method/Action:**
        1. Test mutual TLS authentication between all service communications
        2. Validate service-to-service authorization policies
        3. Test traffic encryption and certificate management
        4. Validate microsegmentation rules and enforcement
        5. Test service discovery security and access controls
    * **Prerequisites:** Service mesh platform (Istio/Linkerd), certificate infrastructure, policy management systems.
    * **Expected Secure Outcome:** All service communications mutually authenticated. Traffic encrypted between services. Microsegmentation prevents unauthorized access.
    * **Verification Steps:** Test mTLS implementation, validate authorization policies, verify encryption, check microsegmentation effectiveness.

### 5. Dynamic Network Segmentation

* **ID:** ZTA_NET_011
    * **Category Ref:** Network Segmentation (Micro-segmentation)
    * **Description:** Test dynamic network segmentation that adapts to changing threat conditions and security posture.
    * **Exposure Point(s):** Dynamic segmentation systems, threat intelligence integration, adaptive network controls.
    * **Test Method/Action:**
        1. Test automatic network segmentation based on threat intelligence
        2. Validate dynamic isolation of compromised or suspicious resources
        3. Test adaptive traffic routing based on security posture
        4. Validate emergency segmentation capabilities for incident response
        5. Test restoration of normal network connectivity after threat mitigation
    * **Prerequisites:** Dynamic segmentation platform, threat intelligence feeds, automated response systems.
    * **Expected Secure Outcome:** Network segments adapt to threats automatically. Compromised resources isolated immediately. Normal connectivity restored safely.
    * **Verification Steps:** Test threat-based segmentation, validate isolation effectiveness, verify adaptive routing, check restoration procedures.

### 6. Container Network Security

* **ID:** ZTA_NET_012
    * **Category Ref:** Network Segmentation (Micro-segmentation)
    * **Description:** Test advanced container network security with network policies, runtime protection, and container traffic analysis.
    * **Exposure Point(s):** Container network policies, runtime security systems, traffic analysis for containers.
    * **Test Method/Action:**
        1. Test Kubernetes network policies for pod-to-pod communication
        2. Validate container runtime network monitoring and protection
        3. Test container traffic analysis for anomaly detection
        4. Validate network policy enforcement and violation detection
        5. Test container network isolation and breakout prevention
    * **Prerequisites:** Container orchestration platform, network policy engine, runtime security tools, traffic analysis systems.
    * **Expected Secure Outcome:** Container communications properly restricted. Runtime protection prevents network attacks. Traffic anomalies detected and investigated.
    * **Verification Steps:** Test network policies, validate runtime protection, verify traffic analysis, check isolation effectiveness.

### 7. Edge Computing Network Security

* **ID:** ZTA_NET_013
    * **Category Ref:** Network Segmentation (Micro-segmentation)
    * **Description:** Test network security for edge computing deployments with distributed API instances and local processing capabilities.
    * **Exposure Point(s):** Edge computing infrastructure, distributed network controls, local processing security.
    * **Test Method/Action:**
        1. Test secure connectivity between edge nodes and central infrastructure
        2. Validate local network segmentation at edge locations
        3. Test edge-to-edge secure communication and data synchronization
        4. Validate edge device authentication and authorization
        5. Test isolation of edge processing from local networks
    * **Prerequisites:** Edge computing platform, distributed security controls, edge device management systems.
    * **Expected Secure Outcome:** Edge nodes securely connected and isolated. Local processing protected from network threats. Inter-edge communication secured.
    * **Verification Steps:** Test edge connectivity, validate local segmentation, verify inter-edge security, check device authentication.

### 8. Network Analytics and Behavioral Monitoring

* **ID:** ZTA_NET_014
    * **Category Ref:** Network Segmentation (Micro-segmentation)
    * **Description:** Test network analytics and behavioral monitoring for anomaly detection and automated threat response.
    * **Exposure Point(s):** Network analytics systems, behavioral monitoring, anomaly detection, automated response.
    * **Test Method/Action:**
        1. Test network traffic analysis for behavioral anomaly detection
        2. Validate machine learning-based threat pattern recognition
        3. Test automated network response to detected anomalies
        4. Validate network forensics and incident investigation capabilities
        5. Test integration with security orchestration platforms
    * **Prerequisites:** Network analytics platform, ML-based detection systems, automated response capabilities, forensics tools.
    * **Expected Secure Outcome:** Network anomalies detected accurately. Automated responses contain threats effectively. Forensics provide comprehensive investigation capabilities.
    * **Verification Steps:** Test anomaly detection accuracy, validate automated responses, verify forensics capabilities, check orchestration integration.

---