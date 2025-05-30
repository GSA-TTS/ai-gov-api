# **Test Cases for API10:2023 \- Unsafe Consumption of APIs (Downstream LLMs)**

## **Introduction**

This document outlines test cases for **API10:2023 \- Unsafe Consumption of APIs** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md". These tests focus on how the GSAi API framework securely interacts with downstream LLM provider APIs (Bedrock, Vertex AI), ensuring it validates their responses, handles their errors gracefully, and doesn't implicitly trust their output.  
**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 1.API10:2023)  
* app/providers/bedrock/bedrock.py (Bedrock interaction logic)  
* app/providers/vertex\_ai/vertexai.py (Vertex AI interaction logic)  
* app/providers/\*/adapter\_to\_core.py (Response transformation logic from provider to core schema)  
* app/main.py (Global error handling)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** API10:2023 \- Unsafe Consumption of APIs  
* **Description:** What specific aspect of downstream API consumption is being tested.  
* **Exposure Point(s):** Code that calls provider SDKs, response parsing/validation logic for provider responses, error handling for provider failures.  
* **Test Method/Action:** Mock downstream LLM provider responses to simulate errors, malformed data, or unexpected content.  
* **Prerequisites:** Valid API key. Ability to mock LLM provider SDK calls.  
* **Expected Secure Outcome:** The API framework robustly handles varied responses from downstream LLMs, validates their structure, manages errors gracefully, and avoids passing potentially harmful or malformed data directly to the client without appropriate processing or error reporting.  
* **Verification Steps:** Check API responses to the client, server logs for error details, and ensure no crashes or security vulnerabilities are introduced due to unsafe consumption.

## **Test Cases**

* **ID:** UCA\_PROVIDER\_MALFORMED\_JSON\_001  
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs  
  * **Description:** Test how the API handles a downstream LLM provider returning a 200 OK status but with a malformed JSON response (e.g., syntactically incorrect JSON).  
  * **Exposure Point(s):** Response parsing in provider implementations, adapter_to_core modules, JSON parsing error handling in provider backends.  
  * **Test Method/Action:**  
    1. Mock the LLM provider's SDK call (e.g., bedrock-runtime.converse, vertexai.GenerativeModel.generate\_content\_async) to return a 200 OK HTTP status but with a response body that is not valid JSON (e.g., {"key": "value") or truncated JSON.  
    2. Make a valid request to /chat/completions or /embeddings that would use the mocked provider.  
  * **Prerequisites:** Valid API key. Mocking capability for provider SDKs.  
  * **Expected Secure Outcome:** The API framework should catch the JSON parsing error (e.g., JSONDecodeError or Pydantic validation error if parsing into a provider-specific schema) and return a 500 Internal Server Error to the client with a generic message and a request\_id. It should not crash or expose the malformed data/error details from the provider to the client.  
  * **Verification Steps:**  
    1. Verify API client receives a 500 status code.  
    2. Verify response body is {"detail": "Internal Server Error", "request\_id": "\<uuid\>"}.  
    3. Check server logs for the actual JSON parsing error and request\_id.  
  * **Code Reference:** Provider backend implementations, adapter_to_core modules, json_500_handler in app/main.py:84-99.  
* **ID:** UCA\_PROVIDER\_SCHEMA\_MISMATCH\_001  
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs  
  * **Description:** Test how the API handles a downstream LLM provider returning a 200 OK with valid JSON, but the JSON structure does not match the expected schema (e.g., missing required fields, wrong data types for fields that the adapter expects).  
  * **Exposure Point(s):** Pydantic model validation in adapter_to_core modules, provider-specific response schemas (e.g., ConverseResponse in app/providers/bedrock/converse_schemas.py), schema transformation logic.  
  * **Test Method/Action:**  
    1. Mock the LLM provider's SDK call to return JSON that is structurally different from what the adapter's Pydantic model expects (e.g., ConverseResponse.output.message.content is an integer instead of a list of text blocks).  
    2. Make a valid request.  
  * **Prerequisites:** Valid API key. Mocking capability.  
  * **Expected Secure Outcome:** The Pydantic validation within the adapter or provider backend should fail. The API framework should catch this validation error and return a 500 Internal Server Error to the client.  
  * **Verification Steps:**  
    1. Verify API client receives a 500 status code.  
    2. Verify generic error response.  
    3. Check server logs for Pydantic validation error details.  
  * **Code Reference:** Pydantic validation in adapter modules, ConverseResponse schema, schema transformation error handling.  
* **ID:** UCA\_PROVIDER\_UNEXPECTED\_ERROR\_CODE\_001  
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs  
  * **Description:** Test how the API handles an unexpected HTTP error code (e.g., 418 I'm a teapot, 507 Insufficient Storage) from a downstream LLM provider that isn't explicitly mapped.  
  * **Exposure Point(s):** Error handling logic in BedRockBackend / VertexBackend for provider SDK exceptions.  
  * **Test Method/Action:** Mock the provider SDK call to raise a ClientError (for BotoCore) or GoogleAPIError (for Vertex) with an unusual HTTP status code.  
  * **Prerequisites:** Valid API key. Mocking capability.  
  * **Expected Secure Outcome:** The API framework should catch the generic provider SDK exception and return a 500 Internal Server Error. It should not expose the unusual status code or raw error directly to the client.  
  * **Verification Steps:**  
    1. Verify API client receives a 500 status code.  
    2. Verify generic error response.  
    3. Check server logs for the original provider error.  
* **ID:** UCA\_PROVIDER\_TIMEOUT\_001  
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs  
  * **Description:** Test how the API handles a timeout when calling a downstream LLM provider.  
  * **Exposure Point(s):** Provider SDK timeout configurations and exception handling in BedRockBackend / VertexBackend.  
  * **Test Method/Action:** Mock the provider SDK call to simulate a connection or read timeout.  
  * **Prerequisites:** Valid API key. Mocking capability.  
  * **Expected Secure Outcome:** The API framework should catch the timeout exception from the SDK and return an appropriate error to the client, ideally a 504 Gateway Timeout or a generic 500\. The API itself should not hang indefinitely.  
  * **Verification Steps:**  
    1. Verify API client receives a 504 or 500 status code.  
    2. Verify response time is reasonable (i.e., API's own timeout logic works if provider SDK timeout is too long).  
    3. Check server logs for timeout error details.  
* **ID:** UCA\_PROVIDER\_HARMFUL\_CONTENT\_001 (Conceptual \- LLM behavior)  
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs  
  * **Description:** Test if the API framework has any mechanisms to detect or sanitize potentially harmful content (e.g., XSS payloads, malicious links) returned by an LLM, if this is within its responsibility.  
  * **Exposure Point(s):** Response transformation in adapter\_to\_core.py modules.  
  * **Test Method/Action:** Mock an LLM provider to return content containing \<script\>alert('XSS')\</script\> or other potentially harmful strings.  
  * **Prerequisites:** Valid API key. Mocking capability.  
  * **Expected Secure Outcome:**  
    * Ideally, the API framework would sanitize such output or use strict Content Security Policy if responses were rendered directly in HTML by a client it controls.  
    * For a JSON API, the output should be correctly JSON-encoded (e.g., \< becomes \\u003c). The responsibility for handling this content then falls to the client consuming the JSON.  
    * The API framework itself should not be vulnerable to XSS if its own management/debug UIs (if any) were to display this data.  
  * **Verification Steps:**  
    1. Inspect the raw JSON response from the API. Verify correct JSON encoding of special characters.  
    2. If the API has a client/UI, ensure the harmful content is not rendered/executed.  
* **ID:** UCA\_PROVIDER\_DATA\_LEAKAGE\_001 (Conceptual \- LLM behavior)  
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs  
  * **Description:** Test if the API framework inadvertently passes through excessive or unintended data fields from a verbose LLM provider response that are not part of the defined GSAi API schema.  
  * **Exposure Point(s):** Response transformation in adapter_to_core modules, Pydantic response models in app/providers/open_ai/schemas.py:192-202 (ChatCompletionResponse), field filtering logic.  
  * **Test Method/Action:** Mock an LLM provider to return a response with extra, non-standard fields alongside the expected data.  
  * **Prerequisites:** Valid API key. Mocking capability.  
  * **Expected Secure Outcome:** The API response to the client should only contain fields defined in its Pydantic response models (e.g., ChatCompletionResponse). Extra fields from the provider should be filtered out by the adapter or Pydantic model validation.  
  * **Verification Steps:**  
    1. Inspect the API response to the client.  
    2. Verify that only documented fields are present and no unexpected provider-specific fields have leaked through.  
  * **Code Reference:** Response schemas in app/providers/open_ai/schemas.py:192-202, adapter transformation logic, field filtering mechanisms.  
* **ID:** UCA\_PROVIDER\_REDIRECT\_HANDLING\_001 (If applicable)  
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs  
  * **Description:** If provider SDKs could follow redirects, test if the API framework handles this securely (e.g., doesn't get redirected to malicious sites or internal resources).  
  * **Exposure Point(s):** Provider SDK configurations.  
  * **Test Method/Action:** Mock a provider to return an HTTP redirect (e.g., 301, 302\) to an arbitrary URL.  
  * **Prerequisites:** Valid API key. Mocking capability.  
  * **Expected Secure Outcome:** Provider SDKs should ideally not follow redirects by default for API calls, or if they do, there should be strict controls. If a redirect is followed and leads to an error or unexpected content, the API framework should handle it gracefully (e.g., 500 error) and not expose the redirect target or content if it's from an untrusted source.  
  * **Verification Steps:**  
    1. Verify API response (likely an error).  
    2. Check server logs for details about redirect handling.  
  * **Code Reference:** Provider SDK configurations, redirect handling in HTTP clients.

* **ID:** UCA\_PROVIDER\_AUTHENTICATION\_FAILURE\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test how the API handles authentication failures when calling downstream LLM providers.
  * **Exposure Point(s):** Provider authentication mechanisms, credential validation, authentication error handling in provider backends.
  * **Test Method/Action:**
    1. Mock provider SDK calls to return authentication errors (401 Unauthorized, 403 Forbidden).
    2. Test with expired or invalid provider credentials.
    3. Simulate credential refresh failures.
    4. Test various authentication error scenarios across different providers.
  * **Prerequisites:** Provider credentials, mocking capability for authentication failures.
  * **Expected Secure Outcome:** Authentication failures should be handled gracefully without exposing credential details. Appropriate error responses should be returned to clients.
  * **Verification Steps:**
    1. Verify appropriate HTTP status codes (500 for internal auth failures).
    2. Check that credential details are not exposed in error responses.
    3. Verify proper error logging without credential exposure.
    4. Test error message consistency across authentication failure types.
  * **Code Reference:** Provider authentication logic, credential handling, authentication error processing.

* **ID:** UCA\_PROVIDER\_QUOTA\_EXHAUSTION\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test handling of provider quota and rate limit exhaustion responses.
  * **Exposure Point(s):** Provider rate limit handling, quota exhaustion responses, error propagation from provider limits.
  * **Test Method/Action:**
    1. Mock provider responses indicating quota exhaustion or rate limiting.
    2. Test various quota-related error codes (429, 503, provider-specific errors).
    3. Simulate burst usage patterns that trigger provider limits.
    4. Test quota exhaustion recovery and retry logic.
  * **Prerequisites:** Understanding of provider rate limiting, mocking capability for quota responses.
  * **Expected Secure Outcome:** Quota exhaustion should be handled gracefully with appropriate client error responses. No infinite retry loops or resource exhaustion.
  * **Verification Steps:**
    1. Verify appropriate error responses to clients (429 or 503).
    2. Check for proper retry logic and backoff mechanisms.
    3. Test system stability under provider quota constraints.
    4. Verify error message clarity for quota-related failures.
  * **Code Reference:** Provider rate limit handling, quota response processing, retry logic implementation.

* **ID:** UCA\_PROVIDER\_CONNECTION\_SECURITY\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test security of connections to downstream LLM providers including TLS validation and certificate handling.
  * **Exposure Point(s):** Provider connection configuration, TLS/SSL settings, certificate validation, secure communication channels.
  * **Test Method/Action:**
    1. Test TLS certificate validation for provider connections.
    2. Simulate invalid or expired provider certificates.
    3. Test connection security settings and cipher suites.
    4. Verify secure communication channel establishment.
  * **Prerequisites:** Understanding of TLS configuration, certificate testing capabilities.
  * **Expected Secure Outcome:** All provider connections use secure protocols with proper certificate validation. Invalid certificates are rejected.
  * **Verification Steps:**
    1. Verify TLS configuration and certificate validation.
    2. Test rejection of invalid or expired certificates.
    3. Check secure cipher suite usage.
    4. Verify no fallback to insecure protocols.
  * **Code Reference:** Provider connection configuration, TLS settings, certificate validation logic.

* **ID:** UCA\_PROVIDER\_RESPONSE\_SIZE\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test handling of unexpectedly large responses from downstream LLM providers.
  * **Exposure Point(s):** Response size limits, memory management during response processing, large response handling.
  * **Test Method/Action:**
    1. Mock provider responses that are extremely large (multiple MB).
    2. Test streaming response handling for large content.
    3. Simulate memory exhaustion scenarios during response processing.
    4. Test response size limits and truncation logic.
  * **Prerequisites:** Ability to generate large mock responses, memory monitoring capabilities.
  * **Expected Secure Outcome:** Large responses should be handled efficiently without memory exhaustion. Appropriate limits should be enforced.
  * **Verification Steps:**
    1. Monitor memory usage during large response processing.
    2. Verify response size limits are enforced.
    3. Test system stability with large provider responses.
    4. Check for proper resource cleanup after large response handling.
  * **Code Reference:** Response processing logic, memory management, size limit enforcement.

* **ID:** UCA\_PROVIDER\_RETRY\_LOGIC\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test retry logic for transient provider failures to ensure it doesn't create security vulnerabilities or resource exhaustion.
  * **Exposure Point(s):** Retry mechanisms, backoff strategies, failure detection, retry limit enforcement.
  * **Test Method/Action:**
    1. Mock transient provider failures (network timeouts, temporary unavailability).
    2. Test retry limits and backoff behavior.
    3. Simulate scenarios that could trigger infinite retry loops.
    4. Test retry logic under concurrent load.
  * **Prerequisites:** Understanding of retry mechanisms, mocking capability for transient failures.
  * **Expected Secure Outcome:** Retry logic should be bounded and not lead to resource exhaustion. Appropriate backoff strategies should be implemented.
  * **Verification Steps:**
    1. Verify retry limits are enforced.
    2. Test backoff strategy implementation.
    3. Check for resource usage during retry scenarios.
    4. Verify no infinite retry loops under any conditions.
  * **Code Reference:** Retry logic implementation, backoff strategies, retry limit configuration.

* **ID:** UCA\_PROVIDER\_CONTENT\_VALIDATION\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test validation of content returned by providers to ensure it meets safety and format requirements.
  * **Exposure Point(s):** Content validation logic, response sanitization, content filtering mechanisms.
  * **Test Method/Action:**
    1. Mock provider responses with potentially unsafe content.
    2. Test content validation for various formats and encodings.
    3. Simulate responses with embedded malicious content.
    4. Test content filtering and sanitization logic.
  * **Prerequisites:** Understanding of content validation requirements, ability to craft test content.
  * **Expected Secure Outcome:** Unsafe content should be detected and handled appropriately. Content validation should prevent security issues.
  * **Verification Steps:**
    1. Verify content validation mechanisms are effective.
    2. Test handling of various unsafe content types.
    3. Check content sanitization and filtering.
    4. Verify no security bypasses in content processing.
  * **Code Reference:** Content validation logic, sanitization mechanisms, content filtering implementation.

* **ID:** UCA\_PROVIDER\_ERROR\_INFORMATION\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test that provider error information is properly sanitized before being exposed to clients or logs.
  * **Exposure Point(s):** Error message processing, provider error sanitization, log content filtering.
  * **Test Method/Action:**
    1. Mock provider errors containing sensitive information.
    2. Test error message sanitization and filtering.
    3. Simulate provider errors with internal system details.
    4. Test error logging and information exposure.
  * **Prerequisites:** Understanding of error handling, ability to mock various error types.
  * **Expected Secure Outcome:** Sensitive information from provider errors should not be exposed to clients. Error logs should be sanitized.
  * **Verification Steps:**
    1. Verify error message sanitization.
    2. Check that sensitive provider information is not exposed.
    3. Test error logging for information leakage.
    4. Verify consistent error handling across providers.
  * **Code Reference:** Error handling logic, message sanitization, logging configuration.

* **ID:** UCA\_PROVIDER\_SESSION\_MANAGEMENT\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test session and connection management with downstream providers to prevent resource leaks or security issues.
  * **Exposure Point(s):** Provider session management, connection pooling, session lifecycle handling.
  * **Test Method/Action:**
    1. Test provider session creation and cleanup.
    2. Simulate connection pool exhaustion scenarios.
    3. Test session timeout and cleanup mechanisms.
    4. Verify proper session isolation between requests.
  * **Prerequisites:** Understanding of session management, connection monitoring capabilities.
  * **Expected Secure Outcome:** Provider sessions should be properly managed without resource leaks. Session isolation should be maintained.
  * **Verification Steps:**
    1. Monitor provider connection and session usage.
    2. Test session cleanup and resource management.
    3. Verify session isolation between concurrent requests.
    4. Check for resource leaks in session handling.
  * **Code Reference:** Session management logic, connection pooling configuration, cleanup mechanisms.

* **ID:** UCA\_PROVIDER\_DEPENDENCY\_VALIDATION\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test validation of provider SDK dependencies and versions to ensure security and compatibility.
  * **Exposure Point(s):** Provider SDK version management, dependency validation, security update handling.
  * **Test Method/Action:**
    1. Test provider SDK version validation.
    2. Simulate usage of outdated or vulnerable SDK versions.
    3. Test dependency conflict resolution.
    4. Verify security update handling for provider SDKs.
  * **Prerequisites:** Understanding of dependency management, SDK version monitoring.
  * **Expected Secure Outcome:** Provider SDKs should be kept up-to-date and validated for security. Vulnerable versions should be detected.
  * **Verification Steps:**
    1. Verify provider SDK version monitoring.
    2. Test detection of vulnerable SDK versions.
    3. Check dependency validation mechanisms.
    4. Verify security update processes for provider dependencies.
  * **Code Reference:** Dependency management configuration, SDK version validation, security update handling.

* **ID:** UCA\_PROVIDER\_CIRCUIT\_BREAKER\_001
  * **Category Ref:** API10:2023 \- Unsafe Consumption of APIs
  * **Description:** Test circuit breaker patterns for provider failures to prevent cascading failures and resource exhaustion.
  * **Exposure Point(s):** Circuit breaker implementation, failure detection, recovery mechanisms.
  * **Test Method/Action:**
    1. Test circuit breaker activation under provider failure conditions.
    2. Simulate sustained provider unavailability.
    3. Test circuit breaker recovery and reset logic.
    4. Verify proper error handling during circuit breaker states.
  * **Prerequisites:** Understanding of circuit breaker patterns, failure simulation capabilities.
  * **Expected Secure Outcome:** Circuit breakers should prevent cascading failures and provide graceful degradation. Recovery should be automatic when appropriate.
  * **Verification Steps:**
    1. Test circuit breaker activation and deactivation.
    2. Verify failure detection and recovery mechanisms.
    3. Check error handling during circuit breaker states.
    4. Test system stability under provider failure conditions.
  * **Code Reference:** Circuit breaker implementation, failure detection logic, recovery mechanisms.