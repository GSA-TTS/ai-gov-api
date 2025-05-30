# **Test Cases for API4:2023 \- Unrestricted Resource Consumption**

## **Introduction**

This document outlines test cases for **API4:2023 \- Unrestricted Resource Consumption** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md". These tests aim to verify that the API framework and its interactions with LLMs are protected against abuse that could lead to denial of service or excessive financial costs.  
**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 1.API4:2023)  
* app/providers/open\_ai/schemas.py (fields like max\_tokens, structure of messages and input for embeddings)  
* Test Plan Section 5.9.6 (Rate Limiting & Throttling)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** API4:2023 \- Unrestricted Resource Consumption  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** API endpoints (/chat/completions, /embeddings), parameters controlling resource usage (e.g., max\_tokens, input length, number of messages, batch size for embeddings), lack of rate limiting or quotas.  
* **Test Method/Action:** Send requests designed to consume excessive resources.  
* **Prerequisites:** Valid API key. Understanding of potential limits (API framework, LLM provider).  
* **Expected Secure Outcome:** The API gracefully handles or rejects requests that would lead to excessive resource consumption. Implemented rate limits or quotas are enforced. Clear error messages (e.g., 429 Too Many Requests, 413 Payload Too Large, or provider-specific errors for resource limits) are returned.  
* **Verification Steps:** Monitor API responses (status codes, error messages). Observe server resource utilization (CPU, memory) if possible. Check for enforcement of rate limits/quotas.

## **Test Cases**

* **ID:** URC\_CHAT\_001  
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption  
  * **Description:** Test /chat/completions with a very high max\_tokens value to verify token generation limits.  
  * **Exposure Point(s):** max_tokens parameter in ChatCompletionRequest schema (app/providers/open_ai/schemas.py:141-144), PositiveInt validation, provider token limits.  
  * **Test Method/Action:** Send a request to /chat/completions with max\_tokens set to an extremely large value (e.g., 1,000,000) or a value known to exceed the specific model's output limit.  
  * **Prerequisites:** Valid API Key with models:inference scope.  
  * **Expected Secure Outcome:**  
    1. Pydantic PositiveInt validation accepts the value but provider should enforce its own limits.  
    2. The downstream LLM provider should either cap the generation at its own maximum output limit or return an error. The API should relay this provider behavior gracefully (e.g., a 200 OK with truncated output and appropriate finish\_reason, or a relayed 4xx/5xx error from the provider).  
    3. The API framework itself should not crash or consume excessive memory trying to handle a potentially huge response.  
  * **Verification Steps:**  
    1. Check HTTP status code and response body.  
    2. If successful (200 OK), verify completion\_tokens in usage is within the model's actual limits.  
    3. If error, verify it's an appropriate error code (e.g., 400, 422 from provider, or 500 if provider error is generic) and a clear message.  
  * **Code Reference:** max_tokens field in app/providers/open_ai/schemas.py:141-144, provider response handling in adapter classes.  
* **ID:** URC\_CHAT\_002  
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption  
  * **Description:** Test /chat/completions with an excessively long prompt (many messages or very long content in messages).  
  * **Exposure Point(s):** messages array in ChatCompletionRequest (app/providers/open_ai/schemas.py:110), ChatCompletionMessage content field, web server request size limits.  
  * **Test Method/Action:** Send a request with a messages payload that is extremely large (e.g., total character count approaching server limits, or total token count exceeding a model's context window).  
  * **Prerequisites:** Valid API Key with models:inference scope.  
  * **Expected Secure Outcome:**  
    1. The web server (e.g., Uvicorn) might reject with 413 Payload Too Large if HTTP request size limits are hit.  
    2. FastAPI/Pydantic might reject with 422 if schema has size constraints on strings/lists.  
    3. If passed to the LLM provider, the provider should return an error indicating the context window was exceeded. The API should relay this error (e.g., as a 400 Bad Request or 422).  
    4. The API framework should not crash due to OOM errors.  
  * **Verification Steps:**  
    1. Verify HTTP status code (413, 422, 400, or provider-relayed error).  
    2. Check error message for clarity.  
    3. Monitor API server resources during the test if possible.  
  * **Code Reference:** messages field in app/providers/open_ai/schemas.py:110, ChatCompletionMessage schema definition, FastAPI request size handling.  
* **ID:** URC\_EMBED\_001  
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption  
  * **Description:** Test /embeddings with an extremely long single input string.  
  * **Exposure Point(s):** input field in EmbeddingRequest (app/providers/open_ai/schemas.py:206-264), Union[str, List[str]] type, LLM provider's input token limit for embeddings.  
  * **Test Method/Action:** Send an embedding request with the input field containing a string that is excessively long (e.g., millions of characters or exceeding provider token limits).  
  * **Prerequisites:** Valid API Key with models:embedding scope.  
  * **Expected Secure Outcome:** Similar to URC\_CHAT\_002: 413, 422 (if schema has max\_length), or a provider error (e.g., 400\) relayed by the API. API framework remains stable.  
  * **Verification Steps:**  
    1. Verify HTTP status code and error message.  
    2. Monitor API server resources.  
  * **Code Reference:** EmbeddingRequest input field in app/providers/open_ai/schemas.py:206-264, provider embedding handling.  
* **ID:** URC\_EMBED\_002  
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption  
  * **Description:** Test /embeddings with a very large batch of input strings.  
  * **Exposure Point(s):** input list in EmbeddingRequest (app/providers/open_ai/schemas.py:206-264), List[str] variant of Union type, LLM provider's batch size limits for embeddings.  
  * **Test Method/Action:** Send an embedding request with the input field as a list containing a very large number of strings (e.g., 10,000 strings).  
  * **Prerequisites:** Valid API Key with models:embedding scope.  
  * **Expected Secure Outcome:** Similar to URC\_CHAT\_002: 413, 422 (if schema has max\_items), or a provider error (e.g., "batch size exceeded") relayed by the API. API framework remains stable.  
  * **Verification Steps:**  
    1. Verify HTTP status code and error message.  
    2. Monitor API server resources.  
  * **Code Reference:** EmbeddingRequest input field in app/providers/open_ai/schemas.py:206-264, list handling in embedding adapters.  
* **ID:** URC\_STREAM\_001  
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption  
  * **Description:** Test abuse of streaming requests for /chat/completions to keep connections open indefinitely or consume resources without legitimate use.  
  * **Exposure Point(s):** stream parameter in ChatCompletionRequest (app/providers/open_ai/schemas.py:131-134), SSE connection handling, async generator cleanup.  
  * **Test Method/Action:**  
    1. Initiate a streaming request with stream=true.  
    2. Client reads very slowly from the stream, or not at all after initial connection.  
    3. Client keeps connection open without sending further requests or closing after LLM finishes.  
  * **Prerequisites:** Valid API Key with models:inference scope.  
  * **Expected Secure Outcome:** The API server should have timeouts for idle stream connections. Server resources (connections, memory for stream context) should be reclaimed after timeout or client disconnection. It should not be possible to exhaust server connection pool by opening many idle streams.  
  * **Verification Steps:**  
    1. Observe if idle connections are eventually terminated by the server.  
    2. Attempt to open a large number of concurrent streams and see if the server hits connection limits or becomes unresponsive. (This overlaps with load testing).  
  * **Code Reference:** stream field in app/providers/open_ai/schemas.py:131-134, streaming response handling in provider adapters.  
* **ID:** URC\_RATE\_LIMIT\_001  
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption  
  * **Description:** Verify basic rate limiting functionality if implemented by the API framework itself (beyond provider rate limits).  
  * **Exposure Point(s):** All API endpoints.  
  * **Test Method/Action:** Send a rapid burst of requests to an endpoint exceeding any configured API-level rate limits.  
  * **Prerequisites:** Valid API Key. API framework configured with rate limits (e.g., per IP, per API key). (Note: The current codebase does not show explicit application-level rate limiting; this test assumes it might be added or is handled by an API Gateway in front).  
  * **Expected Secure Outcome:** After exceeding the limit, requests receive a 429 Too Many Requests error, possibly with a Retry-After header.  
  * **Verification Steps:**  
    1. Send N requests within the rate limit window. They should succeed.  
    2. Send N+M requests. The M requests should receive 429 errors.  
* **ID:** URC\_IMAGE\_SIZE\_001 (For multimodal chat)  
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption  
  * **Description:** Test /chat/completions with an extremely large base64 encoded image in a data URI.  
  * **Exposure Point(s):** ImageContentPart.image\_url.url in ChatCompletionRequest, parse\_data\_uri function in app/providers/utils.py:8-22, base64.b64decode operation at line 18.  
  * **Test Method/Action:** Send a request with an image data URI where the base64 encoded data represents a very large image (e.g., \>20MB, which is a common limit for some models, or even larger to test framework limits).  
  * **Prerequisites:** Valid API Key with models:inference scope. A model that supports image input.  
  * **Expected Secure Outcome:**  
    1. The web server might reject with 413 Payload Too Large.  
    2. parse\_data\_uri might fail with InvalidBase64DataError (leading to 400 Bad Request) if decoding the large string consumes too much memory or hits internal Python limits, though it primarily checks format.  
    3. If passed to the LLM provider, the provider should return an error for excessive image size, relayed by the API.  
    4. The API framework should not crash due to OOM.  
  * **Verification Steps:**  
    1. Verify HTTP status code (413, 400, or provider-relayed error).  
    2. Check error message.  
    3. Monitor API server resources.  
  * **Code Reference:** parse_data_uri function in app/providers/utils.py:8-22, base64.b64decode at line 18, InvalidBase64DataError handling.  
* **ID:** URC\_FILE\_SIZE\_001 (For multimodal chat with files)  
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption  
  * **Description:** Test /chat/completions with extremely large base64 encoded file data.  
  * **Exposure Point(s):** FileContentPart.file.file\_data in ChatCompletionRequest. LLM provider's file size limits.  
  * **Test Method/Action:** Send a request with file data URI where base64 encoded data represents a very large file (e.g., \>50MB).  
  * **Prerequisites:** Valid API Key with models:inference scope. A model that supports file input.  
  * **Expected Secure Outcome:** Similar to URC\_IMAGE\_SIZE\_001. Web server might reject (413), Pydantic Base64Bytes validation might hit limits if the string is astronomically large, or provider rejects, relayed by API. API framework remains stable.  
  * **Verification Steps:**  
    1. Verify HTTP status code and error message.  
    2. Monitor API server resources.  
  * **Code Reference:** FileContentPart schema definition, file handling in provider adapters.

* **ID:** URC\_CONCURRENT\_CONNECTIONS\_001
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption
  * **Description:** Test server behavior under excessive concurrent connection attempts to verify connection pooling and limits.
  * **Exposure Point(s):** FastAPI/Uvicorn connection handling, database connection pooling in app/db/session.py:23-32, async session management.
  * **Test Method/Action:** 
    1. Open a large number of concurrent connections (e.g., 1000+ simultaneous requests).
    2. Test both short-lived and long-lived connections.
    3. Mix normal requests with slow/hanging connections.
  * **Prerequisites:** Load testing tools, multiple API keys or single key with high concurrency.
  * **Expected Secure Outcome:** Server should gracefully handle connection limits. New connections should be rejected with appropriate errors (503 Service Unavailable) when limits are reached. Existing connections should remain stable. Database connection pool should not be exhausted.
  * **Verification Steps:**
    1. Monitor server connection count during test.
    2. Verify appropriate HTTP status codes for rejected connections.
    3. Check database connection pool utilization.
    4. Verify server recovery after load reduction.
  * **Code Reference:** Database session factory in app/db/session.py:23-32, FastAPI/Uvicorn connection configuration.

* **ID:** URC\_MEMORY\_EXHAUSTION\_001
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption
  * **Description:** Test protection against memory exhaustion attacks through request payload manipulation.
  * **Exposure Point(s):** JSON parsing, Pydantic model instantiation, large object creation during request processing.
  * **Test Method/Action:**
    1. Send requests with deeply nested JSON objects.
    2. Send requests with very wide JSON objects (many keys).
    3. Send requests with repetitive patterns designed to consume parsing memory.
  * **Prerequisites:** Valid API Key, ability to craft malformed JSON payloads.
  * **Expected Secure Outcome:** Server should reject malformed or excessively complex JSON with appropriate errors. Memory usage should remain bounded. Server should not crash or become unresponsive.
  * **Verification Steps:**
    1. Monitor server memory usage during attack.
    2. Verify appropriate error responses (400 Bad Request for malformed JSON).
    3. Test server responsiveness to normal requests during attack.
    4. Verify server stability after attack completion.
  * **Code Reference:** FastAPI JSON parsing, Pydantic model validation in request schemas.

* **ID:** URC\_PARAMETER\_EXPLOSION\_001
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption
  * **Description:** Test parameter validation limits to prevent processing resource exhaustion.
  * **Exposure Point(s):** Query parameter processing, request validation, ChatCompletionRequest and EmbeddingRequest parameter handling.
  * **Test Method/Action:**
    1. Send requests with extremely large numbers of query parameters.
    2. Send requests with very long parameter names and values.
    3. Test boundary conditions in numeric parameters (very large floats, scientific notation).
  * **Prerequisites:** Valid API Key, ability to craft requests with excessive parameters.
  * **Expected Secure Outcome:** Server should reject requests with excessive parameters or parameter sizes. Parameter processing should be bounded in time and memory.
  * **Verification Steps:**
    1. Verify rejection of requests with excessive parameters.
    2. Test processing time for complex parameter sets.
    3. Monitor server resource usage during parameter processing.
  * **Code Reference:** FastAPI parameter parsing, Pydantic field validation in schemas.

* **ID:** URC\_DATABASE\_EXHAUSTION\_001
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption
  * **Description:** Test protection against database resource exhaustion through query abuse.
  * **Exposure Point(s):** Database queries for authentication, API key validation, user lookups, billing operations.
  * **Test Method/Action:**
    1. Send rapid bursts of requests requiring database lookups.
    2. Test with invalid API keys to trigger authentication queries.
    3. Send requests designed to trigger complex database operations.
  * **Prerequisites:** Multiple API keys, understanding of database operations triggered by API calls.
  * **Expected Secure Outcome:** Database connection pool should not be exhausted. Query performance should remain acceptable. Long-running or expensive queries should be limited or timeout.
  * **Verification Steps:**
    1. Monitor database connection pool utilization.
    2. Measure query response times during load.
    3. Verify database recovery after load reduction.
    4. Check for proper query timeouts and error handling.
  * **Code Reference:** Database operations in app/auth/repositories.py, connection pooling in app/db/session.py:23-32.

* **ID:** URC\_PROVIDER\_RATE\_LIMITING\_001
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption
  * **Description:** Test handling of provider rate limits and quota exhaustion.
  * **Exposure Point(s):** Provider API calls, rate limit responses from external services, quota management.
  * **Test Method/Action:**
    1. Send requests at high frequency to trigger provider rate limits.
    2. Test behavior when provider quotas are exhausted.
    3. Verify proper error propagation from providers.
  * **Prerequisites:** API keys with known rate limits, ability to trigger provider rate limiting.
  * **Expected Secure Outcome:** Provider rate limit errors should be properly handled and not cause server instability. Appropriate error codes (429, 503) should be returned to clients. Server should implement proper backoff strategies.
  * **Verification Steps:**
    1. Verify proper handling of 429 responses from providers.
    2. Test error message clarity for rate limit scenarios.
    3. Monitor server behavior during provider rate limiting.
    4. Verify proper error code propagation to clients.
  * **Code Reference:** Provider error handling in adapter classes, rate limit response processing.

* **ID:** URC\_ASYNC\_TASK\_EXHAUSTION\_001
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption
  * **Description:** Test protection against async task queue exhaustion and resource leaks.
  * **Exposure Point(s):** Async request processing, task queues, concurrent request handling, resource cleanup.
  * **Test Method/Action:**
    1. Send many concurrent requests to saturate async task processing.
    2. Test requests that fail mid-processing to verify cleanup.
    3. Send requests designed to take long processing time.
  * **Prerequisites:** Understanding of async processing patterns, ability to send concurrent requests.
  * **Expected Secure Outcome:** Async task processing should be bounded. Failed tasks should be properly cleaned up. Server should not accumulate resource leaks over time.
  * **Verification Steps:**
    1. Monitor async task queue depth.
    2. Verify proper cleanup of failed or cancelled requests.
    3. Test server stability under sustained concurrent load.
    4. Monitor for resource leaks over extended periods.
  * **Code Reference:** Async request handling patterns, FastAPI background task management.

* **ID:** URC\_RESPONSE\_SIZE\_LIMITS\_001
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption
  * **Description:** Test response size limits to prevent server resource exhaustion during response generation.
  * **Exposure Point(s):** Large response generation, JSON serialization, memory usage during response creation.
  * **Test Method/Action:**
    1. Request operations that might generate very large responses.
    2. Test model responses with maximum token limits.
    3. Test embedding requests that might return large vector arrays.
  * **Prerequisites:** Models capable of generating large responses, understanding of response size patterns.
  * **Expected Secure Outcome:** Server should limit response sizes to reasonable bounds. Memory usage for response generation should be controlled. Large responses should be handled efficiently.
  * **Verification Steps:**
    1. Monitor server memory during large response generation.
    2. Verify response size limits are enforced.
    3. Test JSON serialization performance for large responses.
    4. Verify server stability during large response handling.
  * **Code Reference:** Response generation in provider adapters, JSON serialization handling.

* **ID:** URC\_ERROR\_AMPLIFICATION\_001
  * **Category Ref:** API4:2023 \- Unrestricted Resource Consumption
  * **Description:** Test protection against error amplification attacks where error handling consumes excessive resources.
  * **Exposure Point(s):** Error handling paths, exception processing, logging systems, error response generation.
  * **Test Method/Action:**
    1. Send requests designed to trigger various error conditions rapidly.
    2. Test error scenarios that might consume significant processing time.
    3. Send malformed requests designed to trigger expensive error handling.
  * **Prerequisites:** Understanding of error handling paths, ability to trigger various error conditions.
  * **Expected Secure Outcome:** Error handling should not consume excessive resources. Error response generation should be bounded. Logging should not become a performance bottleneck.
  * **Verification Steps:**
    1. Monitor server performance during error condition stress testing.
    2. Verify error handling efficiency and resource usage.
    3. Test logging system performance under error load.
    4. Verify server recovery after error condition stress.
  * **Code Reference:** Error handlers in app/main.py:57-99, logging middleware in app/logs/middleware.py.