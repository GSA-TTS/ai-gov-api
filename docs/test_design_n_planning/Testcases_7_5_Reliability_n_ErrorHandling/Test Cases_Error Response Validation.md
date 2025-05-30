# Test Cases for Section 7.5.1: Error Response Validation

This document contains test cases for validating error responses as detailed in Section 7.5.1 of the Risk Surface Analysis.

**Test Cases Summary: 25 (Original: 17, Enhanced: +8)**

**References:**
* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.5.md
* app/main.py (global exception handlers)
* app/routers/api_v1.py (endpoint-specific error handling)
* app/common/exceptions.py (custom exception definitions)
* app/providers/exceptions.py (provider-specific errors)
* app/auth/dependencies.py (authentication error handling)

## Risk Surface: Standardization and Accuracy of HTTP Error Codes and Messages

* **ID:** TC_R751_ACCURACY_001
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify that the API does not return a 200 OK status code with an error message in the body when an error occurs.
* **Exposure Point(s):** All API endpoints (/api/v1/\*). Global exception handlers, endpoint-specific exception handling.
* **Test Method/Action:** Induce various error conditions (e.g., invalid input, server-side error) and inspect the HTTP status code and response body.
* **Prerequisites:** API is running. Ability to trigger specific error conditions.
* **Expected Reliable Outcome:** The API returns an appropriate non-2xx HTTP status code when an error occurs, and the body contains a structured error message. A 200 OK status is never accompanied by an error representation in the response body.
* **Verification Steps:** Check the HTTP status code of the response. If it's 200 OK, ensure the body does not indicate an error. If an error occurred, ensure the status code is 4xx or 5xx.

* **ID:** TC_R751_ACCURACY_002
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify that correct HTTP status codes are used for specific error conditions (e.g., 422 for validation, 401/403 for auth, 404 for not found, 503 for service unavailable).
* **Exposure Point(s):** All API endpoints. FastAPI default handlers, custom exception handlers in `app/main.py`, `app/routers/*`, `app/auth/dependencies.py`.
* **Test Method/Action:** Trigger various specific error conditions:
    * Send a request with schema validation errors (e.g., incorrect data type).
    * Send a request with a missing/invalid API key.
    * Request a non-existent endpoint.
    * Simulate a database connectivity issue (for health check or other DB-dependent operations).
    * Simulate a provider outage.
* **Prerequisites:** API is running. Ability to trigger these specific error conditions and simulate dependency failures.
* **Expected Reliable Outcome:** The API returns the correct HTTP status code for each error type: 422 for Pydantic validation, 401/403 for authentication, 404 for not found, 503 for database unavailability impacting health, specific 4xx/5xx for provider issues as mapped. 500 should not be used for client-side validation errors. 400 should not be used for a provider outage (should be 502, 503, or 504).
* **Verification Steps:** Inspect the HTTP status code for each test case and confirm it matches the expected code for the specific error condition.

* **ID:** TC_R751_ACCURACY_003
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify that error messages contain sufficient detail for client-side diagnosis, including a `request_id` for correlation.
* **Exposure Point(s):** Error responses from all API endpoints. Global exception handlers (`app/main.py`), structured logging (`app/logs/middleware.py`).
* **Test Method/Action:** Trigger various errors (e.g., 500 internal server error, 400 bad request) and inspect the response body.
* **Prerequisites:** API is running.
* **Expected Reliable Outcome:** Error responses include a `request_id`. For validation errors, field-specific information is provided. Messages are informative enough for a client to understand the issue without being overly verbose.
* **Verification Steps:** Check for the presence and format of `request_id` in error responses. For 4xx errors, verify that messages guide the client. For 5xx errors, ensure `request_id` is present for support.

* **ID:** TC_R751_ACCURACY_004
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify that error messages do not expose sensitive internal details (stack traces, internal IP addresses, raw provider-specific error details not meant for clients).
* **Exposure Point(s):** Error responses from all API endpoints, especially for 5xx errors. Exception handling logic.
* **Test Method/Action:** Induce internal server errors (e.g., unhandled exceptions, simulated downstream failures) and inspect the error response body.
* **Prerequisites:** API is running. Ability to simulate internal failures.
* **Expected Reliable Outcome:** Error messages are generic for 5xx errors (e.g., "Internal Server Error") and include a `request_id`. No stack traces, internal configurations, or verbose provider errors are present in the client-facing response.
* **Verification Steps:** Inspect the JSON response body for any sensitive information. Ensure it adheres to the defined secure error structure.

* **ID:** TC_R751_ACCURACY_005
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify consistent error schema across different types of errors and endpoints.
* **Exposure Point(s):** All API endpoints and various error types (validation, authentication, server errors).
* **Test Method/Action:** Trigger different error types on different endpoints and compare the structure of the JSON error responses.
* **Prerequisites:** API is running.
* **Expected Reliable Outcome:** All error responses follow a consistent JSON schema (e.g., containing keys like `detail` or `error`, `message`, and `request_id` where appropriate).
* **Verification Steps:** Collect sample error responses and verify their schema consistency.

* **ID:** TC_R751_ACCURACY_006
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify SQLAlchemy IntegrityError is properly mapped to an appropriate HTTP status code (e.g., 400 or 409) and not a generic 500.
* **Exposure Point(s):** Endpoints performing database writes that could violate integrity constraints (e.g., creating a user with a duplicate email if not handled at schema validation). `SQLAlchemy IntegrityError handler` in `app/main.py`.
* **Test Method/Action:** Attempt an operation that would cause a database integrity violation.
* **Prerequisites:** API is running. Database is connected. An operation that can trigger `IntegrityError` is identified.
* **Expected Reliable Outcome:** The API returns a specific client error code (e.g., 400, 409) with a clear message, not a 500.
* **Verification Steps:** Check HTTP status code and response body. Verify server logs for `IntegrityError` handling.

* **ID:** TC_R751_ACCURACY_007
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify database connection errors lead to 503 Service Unavailable instead of generic 500, especially for the health check.
* **Exposure Point(s):** Health check endpoint (`app/routers/root.py`), any endpoint upon DB connection failure. Global exception handlers.
* **Test Method/Action:** Simulate a database connection failure (e.g., stop DB service) and hit the health check endpoint or other DB-dependent endpoints.
* **Prerequisites:** API is running. Ability to simulate DB unavailability.
* **Expected Reliable Outcome:** API returns 503 Service Unavailable when the database is unreachable.
* **Verification Steps:** Check HTTP status code.

* **ID:** TC_R751_ACCURACY_008
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify session rollback failures are handled gracefully and do not affect subsequent requests.
* **Exposure Point(s):** Database session management in `app/db/session.py`, error handlers.
* **Test Method/Action:** Induce an error during a request that requires a database transaction, forcing a rollback. Then, send subsequent valid requests.
* **Prerequisites:** API is running. Identify an operation that uses a DB transaction. Ability to induce an error mid-transaction.
* **Expected Reliable Outcome:** The error is handled, session rollback occurs. Subsequent, unrelated requests are processed normally without being affected by the previous rollback failure.
* **Verification Steps:** Monitor server logs for rollback success/failure. Verify subsequent requests succeed.

* **ID:** TC_R751_ACCURACY_009
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify `request_id` is consistently propagated through error responses.
* **Exposure Point(s):** All error responses. `StructlogMiddleware` in `app/logs/middleware.py`. Global error handlers.
* **Test Method/Action:** Trigger various errors and check for `request_id` in the response.
* **Prerequisites:** API is running.
* **Expected Reliable Outcome:** All error responses (4xx and 5xx) contain the `request_id`.
* **Verification Steps:** Inspect response bodies for `request_id`.

* **ID:** TC_R751_ACCURACY_010
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify correlation between error logs and client-facing error responses using `request_id`.
* **Exposure Point(s):** Server logs, client-facing error responses.
* **Test Method/Action:** Trigger an error, note the `request_id` from the client response, and find the corresponding log entries on the server.
* **Prerequisites:** API is running. Access to server logs.
* **Expected Reliable Outcome:** The `request_id` in the client-facing error response matches a `request_id` in the server logs, allowing for easy correlation of the specific error event.
* **Verification Steps:** Compare `request_id` from response and logs.

* **ID:** TC_R751_ACCURACY_011
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify structured logging context is not lost during error handling.
* **Exposure Point(s):** Server logs during error conditions. `app/logs/middleware.py`, `app/logs/logging_context.py`.
* **Test Method/Action:** Trigger an error and inspect the server logs for that request to ensure all structured logging context (like user ID, client IP if logged) is present alongside the error details.
* **Prerequisites:** API is running. Access to server logs.
* **Expected Reliable Outcome:** Server logs for an error event contain the full structured logging context established by the middleware.
* **Verification Steps:** Inspect log entries for the presence of all expected contextual fields.

* **ID:** TC_R751_ACCURACY_012
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify graceful handling of errors in streaming responses, ensuring proper termination.
* **Exposure Point(s):** Streaming endpoints (e.g., `/api/v1/chat/completions` with `stream: true`). Stream generation logic in providers (e.g., `app/providers/vertex_ai/vertexai.py:119-121`).
* **Test Method/Action:** Induce an error mid-stream (e.g., simulate provider sending an error chunk or disconnecting) and observe client-side behavior and server logs.
* **Prerequisites:** API is running. Ability to simulate mid-stream errors.
* **Expected Reliable Outcome:** The stream terminates cleanly on the client side. If possible, an error message or signal is sent as the last part of the stream or via an error code. Server resources are released. No incomplete responses are sent without proper termination.
* **Verification Steps:** Observe client stream. Check server logs for error handling and resource cleanup. Check for "hanging" connections.

## Risk Surface: Provider Error Mapping

* **ID:** TC_R751_PROVIDERMAP_001
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify that errors from downstream LLM providers are caught and not propagated as unhandled exceptions leading to generic 500 errors.
* **Exposure Point(s):** Provider-specific backend logic (`app/providers/bedrock/bedrock.py`, `app/providers/vertex_ai/vertexai.py`). Adapter logic (`app/providers/*/adapter_to_core.py`).
* **Test Method/Action:** Simulate various errors from a downstream provider (e.g., API key error, rate limit, invalid request to provider, provider server error).
* **Prerequisites:** API is running. Ability to mock provider SDK responses/exceptions.
* **Expected Reliable Outcome:** Provider errors are caught. The GSAi API returns a mapped, standardized error response (e.g., 4xx or 5xx as appropriate), not a raw unhandled 500 error with a stack trace related to the provider SDK.
* **Verification Steps:** Inspect GSAi API response (status code, body). Check server logs for evidence of provider error being caught and handled.

* **ID:** TC_R751_PROVIDERMAP_002
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify correct mapping of provider errors to GSAi API error responses (e.g., provider rate limit to 429, provider auth error to 502/503 or specific 4xx, provider content moderation to a specific 4xx).
* **Exposure Point(s):** Provider interaction code and its exception handling. `app/providers/vertex_ai/vertexai.py:81-82, 101-102` (InvalidArgument mapping).
* **Test Method/Action:** Simulate specific provider errors:
    * Rate limit error from provider.
    * Authentication failure with the provider.
    * Content moderation error from provider.
    * Temporary provider unavailability.
    * Invalid request from GSAi to provider (e.g., malformed according to provider's spec).
* **Prerequisites:** API is running. Ability to mock these specific provider errors.
* **Expected Reliable Outcome:** Provider errors are mapped to appropriate GSAi API HTTP status codes and error messages. For example, provider rate limit should result in a 429 from GSAi. Provider's "invalid prompt" should be a 400 from GSAi. A temporary provider issue should be a 502, 503 or 504, not a 400.
* **Verification Steps:** Check GSAi API HTTP status code and response body for each simulated provider error.

* **ID:** TC_R751_PROVIDERMAP_003
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify that provider-specific error details do not leak into the GSAi API response.
* **Exposure Point(s):** Error mapping logic in provider adapters.
* **Test Method/Action:** Simulate various provider errors and inspect the GSAi API's response body.
* **Prerequisites:** API is running. Ability to mock provider errors that might contain detailed internal messages.
* **Expected Reliable Outcome:** GSAi API error responses abstract away provider-specific jargon or internal details. Messages are standardized.
* **Verification Steps:** Inspect the GSAi API response body for any provider-specific details.

* **ID:** TC_R751_PROVIDERMAP_004
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify consistency in error mapping across different providers for similar underlying issues (e.g., rate limiting from Bedrock vs. Vertex AI).
* **Exposure Point(s):** Error handling logic for all supported providers.
* **Test Method/Action:** Simulate a similar error condition (e.g., rate limit) from Bedrock and then from Vertex AI. Compare the GSAi API's response.
* **Prerequisites:** API is running. Ability to mock similar errors from different providers.
* **Expected Reliable Outcome:** For the same conceptual error (e.g., rate limiting), the GSAi API returns the same HTTP status code and a similarly structured error message, regardless of the originating provider.
* **Verification Steps:** Compare GSAi API responses for similar errors triggered from different providers.

* **ID:** TC_R751_PROVIDERMAP_005
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Verify provider-specific error mapping for streaming responses.
* **Exposure Point(s):** Streaming logic in provider modules, e.g., `app/providers/vertex_ai/vertexai.py:119-121`.
* **Test Method/Action:** Induce a provider error mid-stream (e.g., provider sends an error object or closes connection unexpectedly).
* **Prerequisites:** API is running. Using a streaming request. Ability to mock provider behavior during streaming.
* **Expected Reliable Outcome:** The GSAi API stream terminates cleanly, ideally signaling an error to the client in a standardized way (e.g., last chunk contains error info or an appropriate HTTP status if the error occurs before streaming starts). Generic exceptions are mapped to user-friendly error signals.
* **Verification Steps:** Observe client stream behavior. Check for standardized error indication. Review server logs for provider error mapping in stream context.

---

## Enhanced Test Cases (8 Advanced Error Response Validation Scenarios)

### 3. Database Error Response Handling

* **ID:** TC_R751_DATABASE_ERROR_001
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Validate proper error response handling for SQLAlchemy database connection failures and integrity constraint violations.
* **Exposure Point(s):** app/main.py (SQLAlchemy exception handlers), app/db/session.py (database connection management)
* **Test Method/Action:**
    1. Simulate database connection failure during authentication
    2. Trigger SQLAlchemy IntegrityError during user operations
    3. Test database timeout scenarios during high load
    4. Validate connection pool exhaustion error handling
* **Prerequisites:** Database connectivity control, ability to simulate database failures
* **Expected Reliable Outcome:** Database connection failures return 503 Service Unavailable. Integrity errors return 400 Bad Request with descriptive message. Connection timeout errors provide appropriate retry guidance. No sensitive database information exposed.
* **Verification Steps:**
    1. Verify correct HTTP status codes for different database error types
    2. Validate error message consistency and security
    3. Test error correlation with request IDs for debugging

### 4. Async Error Propagation and Context Management

* **ID:** TC_R751_ASYNC_ERROR_002
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Validate error handling and context preservation in FastAPI async request processing.
* **Exposure Point(s):** FastAPI async request handlers, app/logs/logging_context.py (context management)
* **Test Method/Action:**
    1. Test error propagation through async call chains
    2. Validate context preservation during async exceptions
    3. Test concurrent error handling without cross-contamination
    4. Verify proper async resource cleanup during errors
* **Prerequisites:** Async testing framework, ability to simulate concurrent requests with errors
* **Expected Reliable Outcome:** Async errors propagate correctly with preserved context. Request correlation IDs maintained through error paths. No resource leaks during async error handling. Context isolation between concurrent requests.
* **Verification Steps:**
    1. Verify context data consistency in error logs
    2. Test async resource cleanup completion
    3. Validate error isolation between concurrent requests

### 5. Provider Error Classification and Intelligent Retry Guidance

* **ID:** TC_R751_PROVIDER_CLASSIFICATION_003
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Implement intelligent provider error classification with specific retry guidance and recovery recommendations.
* **Exposure Point(s):** app/providers/exceptions.py (error classification), provider adapter error handling
* **Test Method/Action:**
    1. Classify provider errors by category (transient, permanent, rate limit, configuration)
    2. Test intelligent retry guidance based on error type
    3. Validate provider-specific error code mapping
    4. Test error recovery recommendations for different scenarios
* **Prerequisites:** Provider error simulation, error classification framework
* **Expected Reliable Outcome:** Provider errors classified accurately with appropriate retry guidance. Transient errors suggest retry with backoff. Permanent errors provide configuration guidance. Rate limit errors include retry timing. Security-sensitive errors properly sanitized.
* **Verification Steps:**
    1. Validate error classification accuracy across providers
    2. Test retry guidance appropriateness
    3. Verify error message security and usefulness

### 6. Graceful Error Degradation and Fallback Responses

* **ID:** TC_R751_GRACEFUL_DEGRADATION_004
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Test graceful degradation strategies when primary error handling mechanisms fail.
* **Exposure Point(s):** Error handling fallback mechanisms, emergency response generation
* **Test Method/Action:**
    1. Test error handling when logging systems fail
    2. Validate fallback error responses during system overload
    3. Test error handling when monitoring systems are unavailable
    4. Validate emergency response generation for critical failures
* **Prerequisites:** System component failure simulation, fallback mechanism implementation
* **Expected Reliable Outcome:** Fallback error responses maintain service availability. Emergency responses provide basic error information. System degradation is graceful and predictable. Critical error paths remain functional.
* **Verification Steps:**
    1. Test fallback mechanism activation and effectiveness
    2. Verify emergency response quality and consistency
    3. Validate graceful degradation behavior

### 7. Error Response Security and Information Disclosure Prevention

* **ID:** TC_R751_SECURITY_DISCLOSURE_005
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Validate prevention of sensitive information disclosure in error responses across all error scenarios.
* **Exposure Point(s):** All error handling code paths, stack trace sanitization, internal detail filtering
* **Test Method/Action:**
    1. Test for stack trace leakage in error responses
    2. Validate provider credential sanitization in errors
    3. Test internal system path disclosure prevention
    4. Verify database schema information protection
* **Prerequisites:** Security testing framework, error response analysis tools
* **Expected Reliable Outcome:** No stack traces, internal paths, or credentials exposed in error responses. Error messages provide sufficient debugging information without security risks. Consistent security filtering across all error types.
* **Verification Steps:**
    1. Scan error responses for sensitive information patterns
    2. Verify consistent security filtering across error types
    3. Test error message usefulness without security compromise

### 8. Multi-Step Operation Error Recovery and State Management

* **ID:** TC_R751_MULTISTEP_RECOVERY_006
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Test error handling and recovery for multi-step operations including billing, authentication, and provider interactions.
* **Exposure Point(s):** Multi-step operation coordination, state management during errors, transaction rollback
* **Test Method/Action:**
    1. Test error recovery during multi-step authentication flows
    2. Validate billing queue consistency during operation failures
    3. Test provider interaction rollback on partial failures
    4. Verify state consistency across distributed operations
* **Prerequisites:** Multi-step operation testing framework, state inspection capabilities
* **Expected Reliable Outcome:** Partial failures handled gracefully with proper rollback. State consistency maintained during error recovery. Clear error communication about operation completion status. Recovery guidance for incomplete operations.
* **Verification Steps:**
    1. Verify state consistency after error recovery
    2. Test rollback completeness and accuracy
    3. Validate error communication clarity for multi-step failures

### 9. Error Response Performance and Efficiency

* **ID:** TC_R751_ERROR_PERFORMANCE_007
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Validate error response generation performance and resource efficiency under various error conditions.
* **Exposure Point(s):** Error handling performance, resource usage during error processing
* **Test Method/Action:**
    1. Measure error response generation latency for different error types
    2. Test error handling performance under high error rates
    3. Validate resource efficiency during error processing
    4. Test error handling scalability and overhead
* **Prerequisites:** Performance monitoring, error rate generation capabilities
* **Expected Reliable Outcome:** Error responses generated within acceptable latency (<100ms). Error handling doesn't significantly impact system performance. Resource usage remains bounded during high error rates. Error processing scales efficiently.
* **Verification Steps:**
    1. Measure error response latency across error types
    2. Monitor resource usage during error handling
    3. Test error handling performance under load

### 10. Advanced Error Analytics and Pattern Detection

* **ID:** TC_R751_ERROR_ANALYTICS_008
* **Category Ref:** R751_ERROR_RESPONSE_VALIDATION
* **Description:** Implement advanced error analytics for pattern detection, root cause analysis, and proactive error prevention.
* **Exposure Point(s):** Error analytics framework, pattern detection algorithms, predictive error prevention
* **Test Method/Action:**
    1. Implement error pattern detection and classification
    2. Test root cause analysis automation for common error scenarios
    3. Validate error trend analysis and alerting
    4. Test predictive error prevention based on patterns
* **Prerequisites:** Error analytics infrastructure, pattern detection algorithms, historical error data
* **Expected Reliable Outcome:** Error patterns detected accurately with actionable insights. Root cause analysis provides useful debugging information. Error trends identified early with appropriate alerting. Predictive prevention reduces error occurrence by 20-30%.
* **Verification Steps:**
    1. Validate error pattern detection accuracy
    2. Test root cause analysis effectiveness
    3. Verify predictive prevention impact on error rates

---