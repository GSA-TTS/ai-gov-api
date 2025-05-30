# **Test Cases: Section 7.2 \- Logging, Monitoring & Request Processing Middleware**

This document outlines test cases for verifying logging mechanisms, request/response lifecycle monitoring, and middleware behavior, ensuring audit compliance, debugging capability, and no sensitive data leakage in logs. This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_LOG\_...)  
* **Category Ref:** (e.g., FV\_LOG\_REQUEST, FV\_LOG\_SENSITIVE, FV\_LOG\_PERF, FV\_LOG\_CORRELATION)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** app/logs/logging\_config.py, app/logs/logging\_context.py, app/logs/middleware.py, application logs.  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** Access to application logs, ability to make API requests.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (e.g., "Request details logged without PII").  
* **Verification Steps:** How to confirm the expected secure outcome (e.g., "Inspect log entry for specific fields and absence of sensitive data").

## **1\. Request & Response Logging (Middleware)**

### **FV\_LOG\_REQUEST\_SUCCESS\_CHAT\_001**

* **Category Ref:** FV\_LOG\_REQUEST  
* **Description:** Verify logging of a successful /chat/completions request and response by the StructlogMiddleware.  
* **Exposure Point(s):** StructlogMiddleware in app/logs/middleware.py:11-47, application logs.  
* **Test Method/Action:** Make a successful POST request to /api/v1/chat/completions with valid API key and models:inference scope.  
* **Prerequisites:** Valid API Key with models:inference scope. Log level configured to capture INFO level from the middleware.  
* **Expected Secure Outcome:** Log entries are created for request start and completion.  
  * **Request Start Log:** Contains "Request started" message with request_id, method (POST), path (/api/v1/chat/completions), client_ip, user_agent, and query_params (app/logs/middleware.py:17-27).  
  * **Request Completion Log:** Contains "Request completed" message with request_id, status_code (200), duration_ms, and key_id from request.state.api_key_id (app/logs/middleware.py:36-44).  
  * Request/response body content should NOT be logged by StructlogMiddleware - it only logs metadata.  
* **Verification Steps:**  
  * Inspect application logs for "Request started" and "Request completed" entries with matching request_id.  
  * Verify presence of expected fields: request_id, method, path, client_ip, status_code, duration_ms.  
  * Verify key_id is populated when authentication succeeds.  
  * Confirm no request/response body content is present in middleware logs.
* **Code Reference:** StructlogMiddleware implementation in app/logs/middleware.py:17-27 (request start) and app/logs/middleware.py:36-44 (request completion).

### **FV\_LOG\_REQUEST\_SUCCESS\_EMBED\_001**

* **Category Ref:** FV\_LOG\_REQUEST  
* **Description:** Verify logging for a successful /embeddings request.  
* **Exposure Point(s):** StructlogMiddleware in app/logs/middleware.py:11-47, logs.  
* **Test Method/Action:** Make a successful POST request to /api/v1/embeddings with valid API key and models:embedding scope.  
* **Prerequisites:** Valid API Key with models:embedding scope. Log level at INFO or DEBUG.  
* **Expected Secure Outcome:** Similar to FV\_LOG\_REQUEST\_SUCCESS\_CHAT\_001, with path /api/v1/embeddings. StructlogMiddleware logs request metadata only, not sensitive input text.  
* **Verification Steps:** Inspect logs for "Request started" and "Request completed" entries with path=/api/v1/embeddings, verify fields, confirm no sensitive input text in middleware logs.
* **Code Reference:** Same StructlogMiddleware logic as chat completions, embeddings endpoint at app/routers/api_v1.py:62-70.

### **FV\_LOG\_REQUEST\_ERROR\_4XX\_001**

* **Category Ref:** FV\_LOG\_REQUEST  
* **Description:** Verify logging when a 4xx error occurs (e.g., validation error, auth error).  
* **Exposure Point(s):** StructlogMiddleware in app/logs/middleware.py:29-44, logs.  
* **Test Method/Action:** Trigger a 422 error by sending invalid JSON to /api/v1/chat/completions (e.g., invalid temperature value).  
* **Prerequisites:** Log level at INFO or DEBUG.  
* **Expected Secure Outcome:** Request start and completion logs are created. Completion log shows 422 status code. StructlogMiddleware logs normally for 4xx errors since they are expected HTTP responses, not exceptions.  
* **Verification Steps:** Inspect logs for "Request started" and "Request completed" with status_code=422, verify duration_ms is recorded.
* **Code Reference:** StructlogMiddleware handles 4xx responses normally in app/logs/middleware.py:36-44, FastAPI validation errors handled separately.

### **FV\_LOG\_REQUEST\_ERROR\_5XX\_001**

* **Category Ref:** FV\_LOG\_REQUEST  
* **Description:** Verify logging when a 5xx internal server error occurs.  
* **Exposure Point(s):** StructlogMiddleware exception handling in app/logs/middleware.py:29-34, main exception handler in app/main.py:84-99.  
* **Test Method/Action:** Mock an internal component to raise an unhandled exception, causing a 500 error.  
* **Prerequisites:** Log level at INFO or DEBUG. Ability to induce a 500 error.  
* **Expected Secure Outcome:** StructlogMiddleware logs "Request failed" with exception details and duration_ms when uncaught exception occurs (app/logs/middleware.py:31-34). Main exception handler returns JSON 500 response with request_id (app/main.py:93-99).  
* **Verification Steps:** Inspect logs for "Request started", then "Request failed" with exception traceback, verify duration_ms is recorded. Confirm 500 response includes request_id.
* **Code Reference:** Exception handling in app/logs/middleware.py:29-34, JSON error response in app/main.py:84-99.

## **2\. Sensitive Data in Logs**

### **FV\_LOG\_SENSITIVE\_NO\_API\_KEY\_FULL\_001**

* **Category Ref:** FV\_LOG\_SENSITIVE  
* **Description:** Ensure full API keys are never logged.  
* **Exposure Point(s):** StructlogMiddleware in app/logs/middleware.py, all log entries.  
* **Test Method/Action:** Make any authenticated API request with a valid API key.  
* **Prerequisites:** Valid API key, access to logs.  
* **Expected Secure Outcome:** StructlogMiddleware does not log request headers or body content, only metadata like method, path, client_ip (app/logs/middleware.py:17-24). Only logs key_id from request.state.api_key_id (app/logs/middleware.py:38), not the full API key.  
* **Verification Steps:** Search logs for the full API key value used in the request. It should not be present. Verify only key_id appears in completion logs, not the secret key.
* **Code Reference:** StructlogMiddleware binding in app/logs/middleware.py:17-24 excludes headers, key_id logging at app/logs/middleware.py:38.

### **FV\_LOG\_SENSITIVE\_NO\_PROMPT\_CONTENT\_INFO\_001**

* **Category Ref:** FV\_LOG\_SENSITIVE  
* **Description:** Ensure full prompt content from /chat/completions is not logged at standard/INFO levels.  
* **Exposure Point(s):** StructlogMiddleware request logging in app/logs/middleware.py:17-27.  
* **Test Method/Action:** Make a /api/v1/chat/completions request with a unique, identifiable prompt text.  
* **Prerequisites:** Log level at INFO. Valid API key with models:inference scope.  
* **Expected Secure Outcome:** StructlogMiddleware only logs request metadata (method, path, client_ip, etc.) and does not access or log request body content. Prompt content should not appear in any middleware logs.  
* **Verification Steps:** Search INFO level logs for the unique prompt text. It should not be present in StructlogMiddleware logs.
* **Code Reference:** StructlogMiddleware excludes request body in app/logs/middleware.py:17-27, only logs metadata.

### **FV\_LOG\_SENSITIVE\_NO\_COMPLETION\_CONTENT\_INFO\_001**

* **Category Ref:** FV\_LOG\_SENSITIVE  
* **Description:** Ensure full LLM completion content is not logged at standard/INFO levels.  
* **Exposure Point(s):** StructlogMiddleware response logging in app/logs/middleware.py:36-44.  
* **Test Method/Action:** Make a /api/v1/chat/completions request that yields a unique, identifiable response text.  
* **Prerequisites:** Log level at INFO. Valid API key with models:inference scope.  
* **Expected Secure Outcome:** StructlogMiddleware only logs response metadata (status_code, duration_ms) and does not access or log response body content. Completion content should not appear in middleware logs.  
* **Verification Steps:** Search INFO level logs for the unique completion text. It should not be present in StructlogMiddleware logs.
* **Code Reference:** StructlogMiddleware excludes response body in app/logs/middleware.py:36-44, only logs metadata.

### **FV\_LOG\_SENSITIVE\_NO\_EMBED\_INPUT\_INFO\_001**

* **Category Ref:** FV\_LOG\_SENSITIVE  
* **Description:** Ensure full input text for /embeddings is not logged at standard/INFO levels.  
* **Exposure Point(s):** StructlogMiddleware request logging in app/logs/middleware.py:17-27.  
* **Test Method/Action:** Make an /api/v1/embeddings request with unique, identifiable input text.  
* **Prerequisites:** Log level at INFO. Valid API key with models:embedding scope.  
* **Expected Secure Outcome:** StructlogMiddleware only logs request metadata and does not access request body content. Input text should not appear in middleware logs.  
* **Verification Steps:** Search INFO level logs for the unique input text. It should not be present in StructlogMiddleware logs.
* **Code Reference:** StructlogMiddleware excludes request body in app/logs/middleware.py:17-27, only logs metadata.

### **FV\_LOG\_SENSITIVE\_USER\_AGENT\_LOGGING\_001**

* **Category Ref:** FV\_LOG\_SENSITIVE  
* **Description:** Verify that user-agent strings are logged appropriately without exposing sensitive client information.  
* **Exposure Point(s):** StructlogMiddleware user_agent logging in app/logs/middleware.py:23.  
* **Test Method/Action:** Make API requests with various user-agent headers (including potentially sensitive client information).  
* **Prerequisites:** Valid API key. Log level at INFO or DEBUG.  
* **Expected Secure Outcome:** StructlogMiddleware logs user_agent field as-is from request headers. This is standard practice for debugging and analytics, but logs should be protected appropriately.  
* **Verification Steps:** Verify user_agent appears in "Request started" logs, ensure log access is restricted to authorized personnel.  
* **Code Reference:** User-agent logging in app/logs/middleware.py:23.

### **FV\_LOG\_SENSITIVE\_CLIENT\_IP\_LOGGING\_001**

* **Category Ref:** FV\_LOG\_SENSITIVE  
* **Description:** Verify that client IP addresses are logged for audit purposes while considering privacy implications.  
* **Exposure Point(s):** StructlogMiddleware client_ip logging in app/logs/middleware.py:22.  
* **Test Method/Action:** Make API requests from different client IP addresses (including through proxies if applicable).  
* **Prerequisites:** Valid API key. Ability to control client IP. Log level at INFO or DEBUG.  
* **Expected Secure Outcome:** StructlogMiddleware logs client_ip field from request.client.host when available. IP logging is important for security and audit but logs must be protected.  
* **Verification Steps:** Verify client_ip appears correctly in logs, test proxy scenarios where applicable.  
* **Code Reference:** Client IP logging in app/logs/middleware.py:22.

*(Note: If DEBUG logging is enabled, it needs separate scrutiny to ensure any PII/sensitive data logged is intentional, documented, and access to DEBUG logs is highly restricted.)*

## **3\. Logging Configuration & Context**

### **FV\_LOG\_CONFIG\_LEVEL\_EFFECT\_001**

* **Category Ref:** FV\_LOG\_REQUEST (Config)  
* **Description:** Verify that changing log_level in settings correctly affects log verbosity through structlog configuration.  
* **Exposure Point(s):** app/config/settings.py:25, app/logs/logging_config.py:13-14, 37, 46.  
* **Test Method/Action:**  
  1. Set log_level=WARNING in environment. Make a simple successful request.  
  2. Set log_level=DEBUG in environment. Make the same simple successful request.  
* **Prerequisites:** Ability to change log_level environment variable and restart API.  
* **Expected Secure Outcome:**  
  * With WARNING: Only WARNING, ERROR, CRITICAL logs appear. StructlogMiddleware INFO logs ("Request started", "Request completed") should be suppressed by make_filtering_bound_logger.  
  * With DEBUG: All log levels appear. StructlogMiddleware INFO logs should be visible.  
* **Verification Steps:** Compare log output verbosity between runs, verify filtering behavior matches structlog configuration.
* **Code Reference:** Log level configuration in app/logs/logging_config.py:13-14, 37, 46, settings definition at app/config/settings.py:25.

### **FV\_LOG\_CONTEXT\_REQUEST\_ID\_PRESENT\_001**

* **Category Ref:** FV\_LOG\_CORRELATION  
* **Description:** Verify that a unique request_id is present in all log entries related to a single request, facilitating tracing.  
* **Exposure Point(s):** StructlogMiddleware generates request_id using uuid4() (app/logs/middleware.py:14), binds to contextvars (app/logs/middleware.py:17-18), merge_contextvars processor includes it in all logs (app/logs/logging_config.py:16).  
* **Test Method/Action:** Make an API request to any endpoint.  
* **Prerequisites:** Log level includes INFO. StructlogMiddleware configured with merge_contextvars processor.  
* **Expected Secure Outcome:** All log lines generated during request processing contain the same request_id value. Request_id is generated as UUID4 string and bound to contextvars for automatic inclusion.  
* **Verification Steps:**  
  * Identify request_id from "Request started" log entry.  
  * Search logs for this request_id. All related log lines should share this ID, including "Request started", "Request completed", and any application logs during processing.  
* **Code Reference:** Request ID generation in app/logs/middleware.py:14, context binding at app/logs/middleware.py:17-18, merge_contextvars processor in app/logs/logging_config.py:16.

### **FV\_LOG\_CONTEXT\_REQUEST\_ID\_STREAMING\_001**

* **Category Ref:** FV\_LOG\_CORRELATION  
* **Description:** Verify request_id is consistently logged for streaming requests across the streaming lifecycle.  
* **Exposure Point(s):** StructlogMiddleware context binding persists throughout request (app/logs/middleware.py:17-18), streaming response in app/routers/api_v1.py:41-50.  
* **Test Method/Action:** Make a streaming /api/v1/chat/completions request with stream=true.  
* **Prerequisites:** Valid API key with models:inference scope. Log level includes INFO.  
* **Expected Secure Outcome:** The same request_id appears in "Request started" and "Request completed" logs. Stream processing occurs within the same request context, so any logs during streaming should share the request_id.  
* **Verification Steps:** Make streaming request, verify request_id consistency in start/completion logs. Note that StructlogMiddleware logs at request boundaries, not per stream chunk.
* **Code Reference:** Context persistence during streaming response in app/logs/middleware.py:17-18, streaming endpoint at app/routers/api_v1.py:41-50.

## **4\. Performance Impact of Logging (Conceptual \- Requires Performance Testing Rig)**

### **FV\_LOG\_PERF\_HIGH\_THROUGHPUT\_001 (Conceptual)**

* **Category Ref:** FV\_LOG\_PERF  
* **Description:** Assess if extensive logging significantly degrades API performance (latency, throughput) under high load.  
* **Exposure Point(s):** StructlogMiddleware processing in app/logs/middleware.py:12-46, structlog configuration overhead.  
* **Test Method/Action:**  
  1. Run performance tests with minimal logging (e.g., WARNING level).  
  2. Run same performance tests with verbose logging (e.g., DEBUG level with dev console renderer).  
* **Prerequisites:** Performance testing environment. Load testing tools.  
* **Expected Secure Outcome:** StructlogMiddleware overhead should be minimal. JSON renderer (production) should be more efficient than ConsoleRenderer (development).  
* **Verification Steps:** Compare latency (p95, p99) and throughput (RPS) between configurations. Monitor impact of UUID generation, context variable operations, and structlog processing.  
* **Code Reference:** StructlogMiddleware processing in app/logs/middleware.py:12-46, renderer configuration in app/logs/logging_config.py:22-29.

### **FV\_LOG\_CONFIG\_ENVIRONMENT\_DETECTION\_001**

* **Category Ref:** FV\_LOG\_REQUEST (Config)  
* **Description:** Verify that logging configuration correctly adapts based on environment (dev vs production).  
* **Exposure Point(s):** Environment-based configuration in app/logs/logging_config.py:23-29.  
* **Test Method/Action:** Test with env=dev and env=prod (or other non-dev values).  
* **Prerequisites:** Ability to change environment setting and restart API.  
* **Expected Secure Outcome:** With env=dev: Uses ConsoleRenderer with colors for human readability. With env!=dev: Uses JSONRenderer for structured logging in production.  
* **Verification Steps:** Verify log format changes between human-readable console output (dev) and JSON structured output (production).  
* **Code Reference:** Environment detection in app/logs/logging_config.py:23-29, renderer selection logic.

### **FV\_LOG\_CONTEXT\_CLEAR\_BETWEEN\_REQUESTS\_001**

* **Category Ref:** FV\_LOG\_CORRELATION  
* **Description:** Verify that context variables are properly cleared between requests to prevent context bleed.  
* **Exposure Point(s):** Context clearing in app/logs/middleware.py:13, structlog contextvars management.  
* **Test Method/Action:** Make multiple sequential API requests with different parameters.  
* **Prerequisites:** Valid API key. Sequential request capability.  
* **Expected Secure Outcome:** Each request gets a unique request_id and fresh context. Previous request context does not leak into subsequent requests.  
* **Verification Steps:** Verify each request has unique request_id and appropriate context fields without cross-contamination from previous requests.  
* **Code Reference:** Context clearing in app/logs/middleware.py:13, new context binding at app/logs/middleware.py:14-24.

## **5\. Audit Logging (Specific Requirements)**

If specific audit log requirements exist (e.g., all auth attempts, all calls to provider X, all admin actions), these need dedicated tests. The current risk analysis for 7.2 focuses on general logging via middleware.

### **FV\_LOG\_AUDIT\_BILLING\_QUEUE\_001**

* **Category Ref:** FV\_LOG\_REQUEST (Audit aspect)  
* **Description:** Verify that billing data processed by billing_worker is logged appropriately for audit purposes.  
* **Exposure Point(s):** Billing worker logging in app/services/billing.py:10-14.  
* **Test Method/Action:** Note: Current implementation does not queue billing data from API endpoints. Billing worker only logs data when received from queue. This test validates the worker's logging behavior.  
* **Prerequisites:** Log level allows seeing logs from billing service. Ability to manually add data to billing_queue for testing.  
* **Expected Secure Outcome:** Billing worker logs billing data with logger.info("billing", **billing_data) when processing queue items (app/services/billing.py:13). Logged data includes all fields from billing_data object.  
* **Verification Steps:**  
  * Add test billing data to billing_queue.  
  * Verify worker logs "billing" message with billing data fields.  
  * Note: Current API endpoints do not integrate with billing queue - this is future implementation.  
* **Code Reference:** Billing worker logging in app/services/billing.py:13, queue processing loop at app/services/billing.py:10-14.
* **Implementation Note:** Ready for future implementation when API endpoints integrate billing data collection.

### **FV\_LOG\_AUTH\_KEY\_VALIDATION\_LOGGING\_001**

* **Category Ref:** FV\_LOG\_REQUEST (Audit aspect)  
* **Description:** Verify that API key validation attempts and results are appropriately logged for security auditing.  
* **Exposure Point(s):** Authentication dependency logging in app/auth/dependencies.py, StructlogMiddleware key_id binding.  
* **Test Method/Action:** Make requests with valid API keys, invalid API keys, and missing API keys.  
* **Prerequisites:** Various API key scenarios. Log level at INFO or DEBUG.  
* **Expected Secure Outcome:** StructlogMiddleware logs key_id when authentication succeeds (app/logs/middleware.py:38). Failed authentication should result in standard HTTP error responses without exposing sensitive details.  
* **Verification Steps:** Verify successful auth shows key_id in completion logs. Verify failed auth does not expose full key values or internal authentication details.  
* **Code Reference:** Key ID binding in app/logs/middleware.py:38, authentication logic in app/auth/dependencies.py.

### **FV\_LOG\_EXCEPTION\_STACK\_TRACE\_COMPLETENESS\_001**

* **Category Ref:** FV\_LOG\_REQUEST (Error)  
* **Description:** Verify that unhandled exceptions are logged with complete stack traces for debugging.  
* **Exposure Point(s):** Exception logging in app/logs/middleware.py:31-34, structlog exception handling.  
* **Test Method/Action:** Trigger an unhandled exception in the application code.  
* **Prerequisites:** Ability to induce exceptions. Log level at INFO or DEBUG.  
* **Expected Secure Outcome:** StructlogMiddleware logs \"Request failed\" with full exception details using structlog's .exception() method, which includes stack trace information.  
* **Verification Steps:** Verify exception logs include stack trace, exception type, and error message. Ensure request_id is preserved in exception logs.  
* **Code Reference:** Exception logging in app/logs/middleware.py:31-34, structlog exception handling capabilities.

### **FV\_LOG\_QUERY\_PARAMS\_LOGGING\_001**

* **Category Ref:** FV\_LOG\_SENSITIVE  
* **Description:** Verify that query parameters are logged appropriately and do not expose sensitive information.  
* **Exposure Point(s):** Query parameter logging in app/logs/middleware.py:21.  
* **Test Method/Action:** Make API requests with various query parameters, including potentially sensitive values.  
* **Prerequisites:** Valid API key. Endpoints that accept query parameters.  
* **Expected Secure Outcome:** StructlogMiddleware logs query_params as dict conversion of request.query_params. Consider if sensitive query parameters could be included and logged.  
* **Verification Steps:** Verify query parameters appear in logs, review for potential sensitive data exposure in query string logging.  
* **Code Reference:** Query parameter logging in app/logs/middleware.py:21.

### **FV\_LOG\_DURATION\_ACCURACY\_001**

* **Category Ref:** FV\_LOG\_PERF  
* **Description:** Verify that request duration measurements are accurate and helpful for performance monitoring.  
* **Exposure Point(s):** Duration calculation in app/logs/middleware.py:15, 32, 36.  
* **Test Method/Action:** Make API requests with varying processing times (fast and slow responses).  
* **Prerequisites:** Valid API key. Ability to create requests with different response times.  
* **Expected Secure Outcome:** Duration_ms accurately reflects request processing time from middleware entry to exit, calculated using time.time() difference and rounded to 2 decimal places.  
* **Verification Steps:** Verify duration_ms values are reasonable and correlate with actual request processing time. Test both successful and failed requests.  
* **Code Reference:** Duration calculation in app/logs/middleware.py:15, 32, 36.