# **Test Cases: Section 7.2 \- Exception Handling & Error Propagation**

This document outlines test cases for ensuring proper error handling, logging, and user-facing error responses throughout the LLM request processing pipeline, without exposing sensitive information. This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_EH\_...)  
* **Category Ref:** (e.g., FV\_EH\_PROVIDER, FV\_EH\_ADAPTER, FV\_EH\_INTERNAL, FV\_EH\_SENSITIVE)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** Custom exception handlers (app/common/exceptions.py, app/providers/exceptions.py), provider adapters, FastAPI error middleware.  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** Ability to mock services/SDKs to raise specific exceptions.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (e.g., "Provider's ValidationException translated to HTTP 400").  
* **Verification Steps:** How to confirm the expected secure outcome.

## **1\. Provider Error Translation & Handling**

### **FV\_EH\_PROVIDER\_BEDROCK\_VALIDATION\_001**

* **Category Ref:** FV\_EH\_PROVIDER  
* **Description:** Test translation of a Bedrock ValidationException to an appropriate API HTTP error.  
* **Exposure Point(s):** Bedrock provider adapter (app/providers/bedrock/bedrock.py), common exception handlers.  
* **Test Method/Action:** Mock the boto3.client("bedrock-runtime").converse() (or invoke\_model) method to raise a botocore.exceptions.ClientError that simulates a ValidationException from Bedrock (e.g., by setting the response\['Error'\]\['Code'\] in the exception object). Make a request to a Bedrock model.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking for Boto3.  
* **Expected Secure Outcome:** API returns an HTTP 400 Bad Request or 422 Unprocessable Entity error. The response body contains a generic, user-friendly error message, not the raw Bedrock exception details.  
* **Verification Steps:**  
  * Assert HTTP status code (400 or 422).  
  * Assert response JSON contains a non-sensitive error message (e.g., "Invalid input parameters for the model.").  
  * Check server logs to confirm the original ValidationException from Bedrock was caught and logged.  
* **Code Reference:** app/providers/bedrock/bedrock.py handles Bedrock client errors, app/providers/exceptions.py defines error types.

### **FV\_EH\_PROVIDER\_BEDROCK\_ACCESSDENIED\_001**

* **Category Ref:** FV\_EH\_PROVIDER  
* **Description:** Test translation of a Bedrock AccessDeniedException.  
* **Exposure Point(s):** Bedrock provider adapter, exception handlers.  
* **Test Method/Action:** Mock Bedrock SDK to raise an AccessDeniedException. Make a request.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking.  
* **Expected Secure Outcome:** API returns an HTTP 403 Forbidden or potentially a 502/503 if it's a general access issue to the Bedrock service/model on behalf of the API. Message should be generic.  
* **Verification Steps:**  
  * Assert HTTP status code (e.g., 403, 502, 503).  
  * Assert generic error message.  
  * Check logs for original Bedrock error.  
* **Code Reference:** Bedrock error handling in app/providers/bedrock/bedrock.py.

### **FV\_EH\_PROVIDER\_BEDROCK\_THROTTLING\_001**

* **Category Ref:** FV\_EH\_PROVIDER  
* **Description:** Test translation of a Bedrock ThrottlingException.  
* **Exposure Point(s):** Bedrock provider adapter, exception handlers.  
* **Test Method/Action:** Mock Bedrock SDK to raise a ThrottlingException. Make a request.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking.  
* **Expected Secure Outcome:** API returns an HTTP 429 Too Many Requests error.  
* **Verification Steps:** Assert HTTP status code is 429\. Assert generic error message.  
* **Code Reference:** Throttling exception handling in Bedrock provider adapter.

### **FV\_EH\_PROVIDER\_VERTEXAI\_INVALID\_ARG\_001**

* **Category Ref:** FV\_EH\_PROVIDER  
* **Description:** Test translation of a Vertex AI google.api\_core.exceptions.InvalidArgument error.  
* **Exposure Point(s):** Vertex AI provider adapter (app/providers/vertex\_ai/vertexai.py), exception handlers.  
* **Test Method/Action:** Mock the Vertex AI SDK method (e.g., GenerativeModel.generate\_content()) to raise google.api\_core.exceptions.InvalidArgument. Make a request to a Vertex AI model.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking for Vertex AI SDK.  
* **Expected Secure Outcome:** API returns an HTTP 400 Bad Request or 422 Unprocessable Entity. Generic error message.  
* **Verification Steps:** Assert HTTP status code. Assert generic error message. Check logs.  
* **Code Reference:** app/providers/vertex_ai/vertexai.py handles Vertex AI client errors.

### **FV\_EH\_PROVIDER\_VERTEXAI\_PERMISSION\_DENIED\_001**

* **Category Ref:** FV\_EH\_PROVIDER  
* **Description:** Test translation of a Vertex AI google.api\_core.exceptions.PermissionDenied error.  
* **Exposure Point(s):** Vertex AI provider adapter, exception handlers.  
* **Test Method/Action:** Mock Vertex AI SDK to raise PermissionDenied. Make a request.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking.  
* **Expected Secure Outcome:** API returns HTTP 403 Forbidden or 502/503. Generic error message.  
* **Verification Steps:** Assert HTTP status code. Assert generic error message. Check logs.  
* **Code Reference:** Vertex AI error handling in app/providers/vertex_ai/vertexai.py.

### **FV\_EH\_PROVIDER\_VERTEXAI\_UNAVAILABLE\_001**

* **Category Ref:** FV\_EH\_PROVIDER  
* **Description:** Test translation of a Vertex AI google.api\_core.exceptions.ServiceUnavailable error.  
* **Exposure Point(s):** Vertex AI provider adapter, exception handlers.  
* **Test Method/Action:** Mock Vertex AI SDK to raise ServiceUnavailable. Make a request.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking.  
* **Expected Secure Outcome:** API returns HTTP 503 Service Unavailable. Generic error message.  
* **Verification Steps:** Assert HTTP status code is 503\. Assert generic error message.  
* **Code Reference:** Service unavailable handling in Vertex AI provider.

## **2\. Adapter Layer Exception Handling**

### **FV\_EH\_ADAPTER\_MALFORMED\_PROVIDER\_RESPONSE\_001**

* **Category Ref:** FV\_EH\_ADAPTER  
* **Description:** Test adapter's error handling if a provider returns an unexpected/malformed response structure that the adapter cannot parse.  
* **Exposure Point(s):** adapter\_to\_core.py for Bedrock/Vertex AI.  
* **Test Method/Action:**  
  1. Mock a provider SDK method (e.g., Bedrock converse()) to return a response with a missing required field or incorrect data type that the adapter expects (e.g., output.message.content is an integer instead of list of content blocks).  
  2. Make a request to the corresponding provider's model.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking.  
* **Expected Secure Outcome:** The adapter catches the parsing error (e.g., KeyError, TypeError, Pydantic ValidationError if parsing into an internal schema). API returns an HTTP 502 Bad Gateway error, indicating an issue with the upstream provider's response.  
* **Verification Steps:**  
  * Assert HTTP status code is 502\.  
  * Assert response contains a generic message like "Error processing response from the upstream service."  
  * Check server logs for details about the parsing error in the adapter.  
* **Code Reference:** Response parsing in app/providers/{bedrock,vertex_ai}/adapter_to_core.py.

### **FV\_EH\_ADAPTER\_UNEXPECTED\_FINISH\_REASON\_001**

* **Category Ref:** FV\_EH\_ADAPTER  
* **Description:** Test adapter behavior if a provider returns a finish\_reason or stopReason not explicitly mapped by the adapter.  
* **Exposure Point(s):** finish\_reason mapping logic in adapter\_to\_core.py.  
* **Test Method/Action:** Mock provider SDK to return a response with a novel or unmapped finish\_reason (e.g., "provider\_specific\_new\_reason").  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking.  
* **Expected Secure Outcome:** The adapter should ideally map unknown reasons to a generic but valid OpenAI finish reason (e.g., "stop" or "unknown"), or handle it gracefully to prevent an error. If it must error, it should be a 502\. A warning should be logged.  
* **Verification Steps:**  
  * Assert HTTP status code (200 or 502).  
  * If 200, check the finish\_reason in the API response. It should be a valid one.  
  * Check server logs for warnings or errors about unmapped finish reasons.  
* **Code Reference:** Finish reason mapping in provider adapter_to_core.py files.

## **3\. Internal API Error Handling & Propagation**

### **FV\_EH\_INTERNAL\_UNHANDLED\_IN\_ROUTE\_001**

* **Category Ref:** FV\_EH\_INTERNAL  
* **Description:** Test FastAPI's default 500 error handling if an unexpected Python exception occurs within a route handler (not a custom API exception).  
* **Exposure Point(s):** FastAPI error middleware.  
* **Test Method/Action:** Modify a route handler (e.g., in /chat/completions) to temporarily raise a generic Python exception (e.g., ZeroDivisionError) before returning a response.  
* **Prerequisites:** Ability to modify route code for testing.  
* **Expected Secure Outcome:** API returns an HTTP 500 Internal Server Error. The response body should be a generic error message (e.g., {"detail":"Internal Server Error"}) and NOT the Python stack trace or exception details.  
* **Verification Steps:**  
  * Assert HTTP status code is 500\.  
  * Assert response JSON is generic (e.g., {"detail":"Internal Server Error"}).  
  * Check server logs for the full Python stack trace of the ZeroDivisionError.  
* **Code Reference:** FastAPI error handling middleware in app/main.py.

### **FV\_EH\_INTERNAL\_CUSTOM\_API\_EXCEPTION\_001**

* **Category Ref:** FV\_EH\_INTERNAL  
* **Description:** Test that a custom API exception (e.g., InputDataError from app/common/exceptions.py) is correctly handled by its registered FastAPI exception handler.  
* **Exposure Point(s):** Custom exception handlers in app/main.py or relevant modules. app/providers/utils.py parse\_data\_uri.  
* **Test Method/Action:** Trigger an InputDataError by sending a malformed data URI in a chat request (as in FV\_INP\_DATA\_URI\_001).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns the status code defined for InputDataError (e.g., 400\) and the error message from the exception.  
* **Verification Steps:**  
  * Assert HTTP status code is 400\.  
  * Assert response JSON contains {"detail": "Invalid data URI format"} (or similar, as defined by the exception).  
* **Code Reference:** Custom exception handlers in app/common/exceptions.py, app/providers/utils.py:parse_data_uri.

### **FV\_EH\_INTERNAL\_STREAMING\_ERROR\_001**

* **Category Ref:** FV\_EH\_INTERNAL  
* **Description:** Test error handling during a streaming response if an error occurs mid-stream (e.g., provider connection drops after some chunks are sent).  
* **Exposure Point(s):** Streaming logic in provider backends, FastAPI streaming response handling.  
* **Test Method/Action:**  
  1. Mock a provider's streaming method (e.g., Bedrock converse\_stream()) to yield a few valid chunks.  
  2. Then, make the mock raise an exception.  
  3. Initiate a streaming /chat/completions request.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking.  
* **Expected Secure Outcome:** The client receives the initial valid SSE chunks. When the error occurs, the stream should terminate. The client might see a broken connection or an incomplete stream. The server should log the error. It's difficult for the server to send a traditional HTTP error status code *after* 200 OK and text/event-stream headers have been sent. The key is graceful termination and logging. Some frameworks might send a final error object within the SSE stream itself, if designed.  
* **Verification Steps:**  
  * Client receives initial chunks.  
  * Stream terminates prematurely (not with \[DONE\]).  
  * Server logs show the mocked exception.  
  * No unhandled exceptions on the server.  
  * (Optional, if implemented) Check if an error object was sent as the last event in the stream.  
* **Code Reference:** Streaming implementation in app/routers/api_v1.py:41-50, provider streaming methods.

## **4\. Sensitive Information Leakage in Errors**

### **FV\_EH\_SENSITIVE\_NO\_STACKTRACE\_IN\_RESPONSE\_001**

* **Category Ref:** FV\_EH\_SENSITIVE  
* **Description:** Ensure that no Python stack traces are ever included in API error responses to the client.  
* **Exposure Point(s):** All error responses (4xx, 5xx).  
* **Test Method/Action:** Trigger various errors (validation errors, internal server errors, provider errors).  
* **Prerequisites:** None specific.  
* **Expected Secure Outcome:** Error response bodies contain user-friendly messages and defined error structures (e.g., {"detail": "..."}), but never raw stack traces or detailed internal exception messages.  
* **Verification Steps:** Inspect the raw JSON response for any error. Assert it does not contain "Traceback (most recent call last):" or similar patterns indicative of a stack trace.  
* **Code Reference:** FastAPI error handling configuration and middleware in app/main.py.

### **FV\_EH\_SENSITIVE\_NO\_PROVIDER\_INTERNAL\_DETAILS\_001**

* **Category Ref:** FV\_EH\_SENSITIVE  
* **Description:** Ensure that internal error details or overly specific error codes from downstream providers (Bedrock, Vertex AI) are not leaked in API responses.  
* **Exposure Point(s):** Error translation logic in adapters and exception handlers.  
* **Test Method/Action:** Mock provider SDKs to return various specific error messages or codes.  
* **Prerequisites:** Mocking.  
* **Expected Secure Outcome:** API error messages are generic (e.g., "Error communicating with upstream service," "Invalid input for model") rather than exposing provider-specifics like "Bedrock model ARN invalid" or a raw Vertex AI gRPC error code.  
* **Verification Steps:** Inspect API error responses. Compare them against the mocked provider error. Ensure abstraction.  
* **Code Reference:** Error translation logic in app/providers/{bedrock,vertex_ai}/ and app/providers/exceptions.py.

### **FV\_EH\_SENSITIVE\_NO\_CONFIG\_DETAILS\_IN\_RESPONSE\_001**

* **Category Ref:** FV\_EH\_SENSITIVE  
* **Description:** Ensure that no configuration details (e.g., file paths, internal URLs, partial API keys/credentials for downstream services) are leaked in error messages.  
* **Exposure Point(s):** All error responses.  
* **Test Method/Action:** Trigger errors related to configuration (e.g., FV\_CFM\_ENV\_MISSING\_VAR\_BEDROCK\_REGION\_001 if it leads to a distinct error path).  
* **Prerequisites:** Trigger config-related errors.  
* **Expected Secure Outcome:** Error messages are generic and do not reveal any part of the API's internal configuration.  
* **Verification Steps:** Inspect error responses for any sensitive keywords or paths.  
* **Code Reference:** Configuration error handling in app/config/settings.py and error response formatting.

## **5\. Additional Error Scenarios**

### **FV\_EH\_RATE\_LIMIT\_PROVIDER\_001**

* **Category Ref:** FV\_EH\_PROVIDER  
* **Description:** Test handling of provider-specific rate limit errors.  
* **Exposure Point(s):** Provider-specific rate limit error handling.  
* **Test Method/Action:** Mock provider SDK to raise rate limit exceptions specific to each provider.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking.  
* **Expected Secure Outcome:** API returns HTTP 429 Too Many Requests with generic rate limit message.  
* **Verification Steps:**  
  * Assert HTTP status code is 429\.  
  * Assert generic rate limit error message.  
  * Verify no provider-specific rate limit details are exposed.  
* **Code Reference:** Rate limit handling in provider adapters.

### **FV\_EH\_TIMEOUT\_PROVIDER\_001**

* **Category Ref:** FV\_EH\_PROVIDER  
* **Description:** Test handling of provider request timeouts.  
* **Exposure Point(s):** Provider SDK timeout handling.  
* **Test Method/Action:** Mock provider SDK to raise timeout exceptions.  
* **Prerequisites:** Valid API Key with models:inference scope. Mocking.  
* **Expected Secure Outcome:** API returns HTTP 504 Gateway Timeout with generic timeout message.  
* **Verification Steps:**  
  * Assert HTTP status code is 504\.  
  * Assert generic timeout error message.  
  * Verify request doesn't hang indefinitely.  
* **Code Reference:** Timeout handling in provider implementations.

### **FV\_EH\_PYDANTIC\_VALIDATION\_ERROR\_001**

* **Category Ref:** FV\_EH\_INTERNAL  
* **Description:** Test FastAPI's handling of Pydantic validation errors with detailed field information.  
* **Exposure Point(s):** Pydantic model validation in request schemas.  
* **Test Method/Action:** Send request with multiple validation errors (missing required fields, wrong types, etc.).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns HTTP 422 with structured validation error details including field paths and error types.  
* **Verification Steps:**  
  * Assert HTTP status code is 422\.  
  * Assert response contains "detail" array with validation errors.  
  * Verify field locations and error messages are present.  
  * Ensure no sensitive information is leaked in validation errors.  
* **Code Reference:** FastAPI automatic Pydantic validation error handling, request schemas in app/providers/open_ai/schemas.py.