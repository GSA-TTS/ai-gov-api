# Test Cases for Zero Trust: Observability Testing

This document outlines test cases for verifying Zero Trust Observability aspects of the GSAi API Framework, based on Zero Trust testing strategies detailed in Section 7.12 of the TestPlan.md.

**Test Cases Summary: 16 (Original: 8, Enhanced: +8)**

**Referenced Code Components:**
* **Comprehensive Logging Framework:** app/logs/middleware.py:11-47 captures request lifecycle, timing, and security context
* **Identity Tracking:** app/logs/middleware.py:38-39 binds API key ID to request context for identity-centric monitoring
* **LLM Interaction Monitoring:** app/providers/vertex_ai/vertexai.py:80-99-116 logs model usage, latency, and token consumption
* **Security Event Logging:** Authentication failures and authorization decisions captured through structured logging
* **Context Enrichment:** app/logs/middleware.py:17-24 includes client IP, user agent, and request parameters for security analysis
* **Missing SIEM Integration:** No external monitoring system integration or security analytics platform connectivity found

### **ZTA_OBS_001**
* **ID:** ZTA_OBS_001
* **Category Ref:** Zero Trust Observability Testing
* **Description:** Verify comprehensive logging of request lifecycle, timing, and security context.
* **Exposure Point(s):** `StructlogMiddleware` (`app/logs/middleware.py:11-47`).
* **Test Method/Action:** Make various API calls (successful and unsuccessful) and inspect the details logged by the middleware.
* **Prerequisites:** API running with logging configured.
* **Expected Secure Outcome:** Logs capture sufficient detail about each request's lifecycle (start, end), processing time (`duration_ms`), and key security context attributes (`request_id`, `client_ip`, `user_agent`, `method`, `path`, `status_code`, `api_key_id`) to enable security monitoring and reconstruction of events.
* **Verification Steps:**
    1.  Make an API request.
    2.  Inspect the server logs associated with the `request_id`.
    3.  Confirm the presence and correctness of: `timestamp`, `level`, `event` (log message), `request_id`, `method`, `path`, `client_ip`, `user_agent`, `status_code`, `duration_ms`, and `api_key_id` (if authenticated).

### **ZTA_OBS_002**
* **ID:** ZTA_OBS_002
* **Category Ref:** Zero Trust Observability Testing
* **Description:** Verify identity tracking in logs for identity-centric monitoring.
* **Exposure Point(s):** `StructlogMiddleware` (`app/logs/middleware.py:38-39` binding `api_key_id`), logging in `app/auth/dependencies.py`.
* **Test Method/Action:** Make authenticated API calls, including some that result in authentication or authorization failures. Inspect logs.
* **Prerequisites:** API running.
* **Expected Secure Outcome:** Logs consistently include the `api_key_id` (or a similar persistent, non-secret identifier for the acting identity) for all authenticated interactions, and for auth/authZ failure events where an identity could be partially determined. This allows tracing activity back to an identity.
* **Verification Steps:**
    1.  Successful authenticated call: Log includes `api_key_id`.
    2.  Call with an expired/inactive key (that exists in DB): Log for auth failure includes the `api_key_id` of the problematic key.
    3.  Call with a non-existent key: Log for auth failure indicates key not found.
    4.  Call with insufficient scope: Log for auth failure includes `api_key_id`.

### **ZTA_OBS_003**
* **ID:** ZTA_OBS_003
* **Category Ref:** Zero Trust Observability Testing
* **Description:** Verify logging of LLM interaction details (model usage, latency, token consumption).
* **Exposure Point(s):** Logging within provider backends (e.g., `app/providers/vertex_ai/vertexai.py:80-99-116`, `app/providers/bedrock/bedrock.py`), and billing logs (`app/services/billing.py`).
* **Test Method/Action:** Make successful calls to various LLM models. Inspect logs.
* **Prerequisites:** API running.
* **Expected Secure Outcome:** Logs capture model ID used, latency metrics, and token consumption for each LLM interaction, providing visibility into LLM resource usage.
* **Verification Steps:**
    1.  Inspect logs from provider adapters/backends. For Vertex, look for "vertex_ai_response_metrics". For Bedrock, look for logged metrics.
    2.  Inspect billing logs for `model`, `prompt_tokens`, `completion_tokens`.
    3.  Correlate these with the `request_id`.

### **ZTA_OBS_004**
* **ID:** ZTA_OBS_004
* **Category Ref:** Zero Trust Observability Testing
* **Description:** Verify logging of security-relevant events (authN/authZ decisions).
* **Exposure Point(s):** Logging in `app/auth/dependencies.py` and `StructlogMiddleware` for HTTP status codes indicating authN/authZ failures.
* **Test Method/Action:** Trigger various authentication failures (invalid key, expired key) and authorization failures (insufficient scope). Inspect logs.
* **Prerequisites:** API running.
* **Expected Secure Outcome:** All authentication and authorization decisions (success implied by 2xx, explicit failures by 401/403) are logged with sufficient context to understand who attempted what and why it failed/succeeded.
* **Verification Steps:**
    1.  Trigger an "invalid API key" event. Check logs for corresponding warning/error with context.
    2.  Trigger an "API key expired" event. Check logs.
    3.  Trigger a "Not Authorized" (scope) event. Check logs.
    4.  Ensure logs include `request_id`, `api_key_id` (if available), `client_ip`, and the type of failure.

### **ZTA_OBS_005**
* **ID:** ZTA_OBS_005
* **Category Ref:** Zero Trust Observability Testing
* **Description:** Assess richness of context in logs for security analysis.
* **Exposure Point(s):** `StructlogMiddleware` (`app/logs/middleware.py:17-24`).
* **Test Method/Action:** Review the fields logged by `StructlogMiddleware` for each request.
* **Prerequisites:** API running.
* **Expected Secure Outcome:** Logs include contextual information beyond just the event, such as `client_ip`, `user_agent`, `method`, `path`, `query_params` (if any), `status_code`, `duration_ms`, `request_id`, and `api_key_id`, which are valuable for security analysis and anomaly detection.
* **Verification Steps:**
    1.  Make a request and inspect the full log entry produced by the middleware.
    2.  Confirm all listed fields are present and correctly populated.

### **ZTA_OBS_006**
* **ID:** ZTA_OBS_006
* **Category Ref:** Zero Trust Observability Testing
* **Description:** Assess lack of SIEM integration or advanced security analytics (Confirms Gap).
* **Exposure Point(s):** Logging pipeline, overall security monitoring architecture. Risk analysis notes "Missing SIEM Integration," "Security Analytics Gaps."
* **Test Method/Action:** This is a review of the logging and monitoring infrastructure.
* **Prerequisites:** Understanding of the deployment environment's logging and security monitoring tools.
* **Expected Secure Outcome:** (Ideal state) Logs are shipped to a SIEM or security analytics platform where they can be correlated, analyzed for anomalies, and used to generate alerts. (Current state) This integration is likely missing.
* **Verification Steps:**
    1.  Inquire or review documentation about whether logs are currently sent to a SIEM.
    2.  Determine if any automated security analytics or anomaly detection tools are processing these logs.
    3.  This test verifies the gaps noted in the risk analysis.

### **ZTA_OBS_007**
* **ID:** ZTA_OBS_007
* **Category Ref:** Zero Trust Observability Testing
* **Description:** Assess potential for delayed detection due to log processing.
* **Exposure Point(s):** Log ingestion and processing pipeline.
* **Test Method/Action:** This is a conceptual review. Consider the path from log generation to availability for analysis.
* **Prerequisites:** Understanding of the logging pipeline.
* **Expected Secure Outcome:** Logs are processed and made available for analysis in near real-time to enable timely detection of attacks or misuse. Significant delays would hinder observability.
* **Verification Steps:**
    1.  If logs are centrally collected, assess the typical ingestion delay.
    2.  If logs are only stored locally on containers/hosts, this represents a significant delay and risk for timely detection.

### **ZTA_OBS_008**
* **ID:** ZTA_OBS_008
* **Category Ref:** Zero Trust Observability Testing
* **Description:** Assess ability to correlate events from different components.
* **Exposure Point(s):** Consistent use of `request_id` across log entries from different sources (middleware, auth, providers, billing).
* **Test Method/Action:** Make a complex API call that involves multiple components (e.g., a successful chat completion). Trace the `request_id` through various log messages.
* **Prerequisites:** API running.
* **Expected Secure Outcome:** The `request_id` is consistently logged by all relevant components involved in processing a single API request, allowing analysts to reconstruct the full sequence of events for that request.
* **Verification Steps:**
    1.  Make an API call.
    2.  Identify the `request_id`.
    3.  Search logs for this `request_id`.
    4.  Confirm entries from `StructlogMiddleware` (start/end), auth checks (if any specific logging occurs there beyond middleware), provider interaction logs, and billing logs all share this `request_id`.

---

## Enhanced Test Cases: Advanced Observability

### 1. Real-Time Security Event Correlation

* **ID:** ZTA_OBS_009
    * **Category Ref:** Zero Trust Observability Testing
    * **Description:** Test real-time correlation of security events across multiple data sources with intelligent threat detection.
    * **Exposure Point(s):** Event correlation engines, real-time analytics, threat detection systems, multi-source data integration.
    * **Test Method/Action:**
        1. Test correlation of authentication events across multiple API keys
        2. Validate real-time detection of coordinated attack patterns
        3. Test intelligent threat scoring based on correlated events
        4. Validate cross-system event correlation and analysis
        5. Test automated alert generation and escalation
    * **Prerequisites:** Event correlation platform, real-time analytics, threat detection systems, multi-source integration.
    * **Expected Secure Outcome:** Security events correlated in real-time across sources. Attack patterns detected automatically. Intelligent scoring enhances threat assessment.
    * **Verification Steps:** Test correlation accuracy, validate detection effectiveness, verify scoring algorithms, check alert generation.

### 2. Distributed Tracing and Performance Monitoring

* **ID:** ZTA_OBS_010
    * **Category Ref:** Zero Trust Observability Testing
    * **Description:** Test comprehensive distributed tracing with end-to-end observability and performance monitoring.
    * **Exposure Point(s):** Distributed tracing systems, observability platforms, performance monitoring, trace correlation.
    * **Test Method/Action:**
        1. Test end-to-end request tracing from client to LLM provider
        2. Validate trace correlation across microservices and components
        3. Test performance monitoring and bottleneck identification
        4. Validate error propagation tracking and root cause analysis
        5. Test trace sampling and storage optimization
    * **Prerequisites:** Distributed tracing infrastructure, observability tools, performance monitoring systems.
    * **Expected Secure Outcome:** Complete trace visibility across all components. Performance bottlenecks identified accurately. Root cause analysis simplified.
    * **Verification Steps:** Test trace completeness, validate correlation accuracy, verify performance monitoring, check error tracking.

### 3. Security Metrics and KPI Dashboards

* **ID:** ZTA_OBS_011
    * **Category Ref:** Zero Trust Observability Testing
    * **Description:** Test comprehensive security metrics collection and KPI dashboard visualization for operational security.
    * **Exposure Point(s):** Metrics collection systems, dashboard platforms, KPI calculation engines, visualization tools.
    * **Test Method/Action:**
        1. Test collection of security-relevant metrics and KPIs
        2. Validate real-time dashboard updates and visualization
        3. Test metric aggregation and trend analysis
        4. Validate alerting thresholds and notification systems
        5. Test historical analysis and reporting capabilities
    * **Prerequisites:** Metrics infrastructure, dashboard platforms, alerting systems, historical storage.
    * **Expected Secure Outcome:** Security metrics collected comprehensively. Dashboards provide real-time visibility. Trends and alerts enable proactive security.
    * **Verification Steps:** Test metrics accuracy, validate dashboard functionality, verify trend analysis, check alerting effectiveness.

### 4. Behavioral Analytics Integration

* **ID:** ZTA_OBS_012
    * **Category Ref:** Zero Trust Observability Testing
    * **Description:** Test integration with behavioral analytics for user and system behavior monitoring and anomaly detection.
    * **Exposure Point(s):** Behavioral analytics platforms, user behavior monitoring, system behavior tracking, anomaly detection.
    * **Test Method/Action:**
        1. Test behavioral pattern establishment and baseline creation
        2. Validate anomaly detection for unusual behavior patterns
        3. Test behavioral scoring and risk assessment
        4. Validate integration with security response systems
        5. Test behavioral trend analysis and prediction
    * **Prerequisites:** Behavioral analytics platform, baseline establishment, anomaly detection, risk assessment tools.
    * **Expected Secure Outcome:** Behavioral patterns monitored accurately. Anomalies detected with high precision. Risk assessment enhances security posture.
    * **Verification Steps:** Test pattern recognition, validate anomaly detection, verify risk scoring, check response integration.

### 5. Threat Intelligence Integration

* **ID:** ZTA_OBS_013
    * **Category Ref:** Zero Trust Observability Testing
    * **Description:** Test integration with threat intelligence feeds for context-aware monitoring and enhanced threat detection.
    * **Exposure Point(s):** Threat intelligence platforms, IOC matching, context enrichment, intelligence-driven monitoring.
    * **Test Method/Action:**
        1. Test integration with multiple threat intelligence feeds
        2. Validate IOC matching and context enrichment
        3. Test intelligence-driven monitoring and alerting
        4. Validate threat landscape awareness and adaptive monitoring
        5. Test threat hunting capabilities and investigation support
    * **Prerequisites:** Threat intelligence platforms, IOC databases, context enrichment, threat hunting tools.
    * **Expected Secure Outcome:** Threat intelligence enhances monitoring effectiveness. IOC matching provides context. Threat hunting capabilities improved.
    * **Verification Steps:** Test intelligence integration, validate IOC matching, verify context enrichment, check hunting capabilities.

### 6. Compliance Monitoring and Reporting

* **ID:** ZTA_OBS_014
    * **Category Ref:** Zero Trust Observability Testing
    * **Description:** Test automated compliance monitoring with regulatory framework adherence and audit-ready reporting.
    * **Exposure Point(s):** Compliance monitoring systems, regulatory frameworks, audit reporting, evidence collection.
    * **Test Method/Action:**
        1. Test continuous compliance monitoring for regulatory requirements
        2. Validate automated violation detection and reporting
        3. Test audit trail generation and evidence collection
        4. Validate compliance dashboard and reporting capabilities
        5. Test regulatory change impact assessment and adaptation
    * **Prerequisites:** Compliance platforms, regulatory databases, audit systems, reporting tools.
    * **Expected Secure Outcome:** Compliance monitored continuously. Violations detected and reported automatically. Audit evidence readily available.
    * **Verification Steps:** Test compliance monitoring, validate violation detection, verify audit capabilities, check reporting accuracy.

### 7. Advanced Log Analytics and Search

* **ID:** ZTA_OBS_015
    * **Category Ref:** Zero Trust Observability Testing
    * **Description:** Test advanced log analytics with machine learning-based pattern recognition and intelligent search capabilities.
    * **Exposure Point(s):** Log analytics platforms, ML-based analysis, pattern recognition, intelligent search engines.
    * **Test Method/Action:**
        1. Test ML-based log pattern recognition and anomaly detection
        2. Validate intelligent log search and query optimization
        3. Test automated log classification and categorization
        4. Validate predictive analytics for log-based insights
        5. Test log correlation and relationship discovery
    * **Prerequisites:** Advanced analytics platforms, ML capabilities, search optimization, predictive modeling.
    * **Expected Secure Outcome:** Log patterns recognized intelligently. Search capabilities enhanced. Predictive insights improve security posture.
    * **Verification Steps:** Test pattern recognition, validate search effectiveness, verify classification accuracy, check predictive capabilities.

### 8. Observability as Code Integration

* **ID:** ZTA_OBS_016
    * **Category Ref:** Zero Trust Observability Testing
    * **Description:** Test observability as code with infrastructure-as-code integration and automated observability deployment.
    * **Exposure Point(s):** Infrastructure-as-code platforms, automated deployment, observability configuration, version control.
    * **Test Method/Action:**
        1. Test observability configuration as code and version control
        2. Validate automated deployment of monitoring infrastructure
        3. Test configuration drift detection and remediation
        4. Validate observability pipeline automation and orchestration
        5. Test integration with CI/CD for observability updates
    * **Prerequisites:** Infrastructure-as-code tools, automation platforms, configuration management, CI/CD integration.
    * **Expected Secure Outcome:** Observability infrastructure managed as code. Deployments automated and consistent. Configuration drift prevented.
    * **Verification Steps:** Test configuration management, validate automation, verify drift detection, check CI/CD integration.

---