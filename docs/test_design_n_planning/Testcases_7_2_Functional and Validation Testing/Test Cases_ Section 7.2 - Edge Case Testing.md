# **Test Cases: Section 7.2 \- Edge Case Testing**

This document outlines test cases for handling atypical inputs and scenarios, focusing on how the API and downstream LLMs respond. This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_EDGE\_...)  
* **Category Ref:** (e.g., FV\_EDGE\_EMPTY, FV\_EDGE\_UNICODE, FV\_EDGE\_LARGE, FV\_EDGE\_CONCURRENT, FV\_EDGE\_MALFORMED\_SUBTLE, FV\_EDGE\_NETWORK)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** API endpoints, Pydantic validation, adapter logic, provider SDKs.  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (graceful processing or clear error).  
* **Verification Steps:** How to confirm the expected secure outcome.

## **1\. Empty or Null Inputs (Beyond Basic Pydantic Min\_Length)**

These tests assume basic Pydantic validation (like min\_length=1 on a list) might have already been tested in Input Validation. These focus more on how the application/provider handles functionally "empty" data that might still pass initial schema checks if not strictly constrained.

### **FV\_EDGE\_EMPTY\_CHAT\_CONTENT\_001**

* **Category Ref:** FV\_EDGE\_EMPTY  
* **Description:** Test /chat/completions with messages\[0\].content as an empty string "".  
* **Exposure Point(s):** /chat/completions endpoint, adapter logic, LLM provider.  
* **Test Method/Action:** Make a POST request with messages: \[{"role": "user", "content": ""}\].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:**  
  * If Pydantic schema for content has min\_length=1 (or similar constraint for the string itself), expect 422\.  
  * Otherwise (if empty string is schema-valid): API returns 200 OK. The LLM provider receives the empty content. The LLM's response might be a canned "I need more information" or similar. No API error.  
* **Verification Steps:**  
  * If 422: Verify error message.  
  * If 200: Assert HTTP status code. Inspect LLM response for sensible handling of empty input. Check usage for token counts (empty string might still consume some tokens).

### **FV\_EDGE\_EMPTY\_EMBED\_INPUT\_STR\_001**

* **Category Ref:** FV\_EDGE\_EMPTY  
* **Description:** Test /embeddings with input as an empty string "".  
* **Exposure Point(s):** /embeddings endpoint, adapter logic, LLM provider.  
* **Test Method/Action:** Make a POST request with input: "".  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:**  
  * If Pydantic schema for input string has min\_length=1, expect 422\.  
  * Otherwise: API returns 200 OK. Provider might return a specific embedding for an empty string or error. If provider errors, API should translate it gracefully (e.g., 400 or 502).  
* **Verification Steps:**  
  * If 422: Verify error message.  
  * If 200: Inspect data\[0\].embedding.  
  * If provider error translated: Assert appropriate 4xx/5xx code and safe error message.

### **FV\_EDGE\_EMPTY\_EMBED\_INPUT\_LIST\_001**

* **Category Ref:** FV\_EDGE\_EMPTY  
* **Description:** Test /embeddings with input as a list containing an empty string \[""\].  
* **Exposure Point(s):** /embeddings endpoint, adapter logic, LLM provider.  
* **Test Method/Action:** Make a POST request with input: \[""\].  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** Similar to FV\_EDGE\_EMPTY\_EMBED\_INPUT\_STR\_001. Provider processes the empty string in the list.  
* **Verification Steps:** Similar to FV\_EDGE\_EMPTY\_EMBED\_INPUT\_STR\_001.

## **2\. Unicode and Special Characters**

### **FV\_EDGE\_UNICODE\_CHAT\_PROMPT\_001**

* **Category Ref:** FV\_EDGE\_UNICODE  
* **Description:** Test /chat/completions with a prompt containing various Unicode characters (emojis, non-Latin scripts, symbols).  
* **Exposure Point(s):** /chat/completions endpoint, adapters, LLM provider character handling and tokenization.  
* **Test Method/Action:** Make a POST request with messages: \[{"role": "user", "content": "Hello 😊 Привет мир ✓ 你好"}\].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns 200 OK. The LLM processes the Unicode prompt correctly. The response from the LLM is coherent. Token counts in usage are plausible.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Inspect LLM response for correctness and ensure no character encoding issues (e.g., mojibake).  
  * Verify usage.prompt\_tokens seems reasonable (Unicode characters can affect tokenization).

### **FV\_EDGE\_UNICODE\_EMBED\_INPUT\_001**

* **Category Ref:** FV\_EDGE\_UNICODE  
* **Description:** Test /embeddings with input containing various Unicode characters.  
* **Exposure Point(s):** /embeddings endpoint, adapters, LLM provider tokenization for embeddings.  
* **Test Method/Action:** Make a POST request with input: "Embedding this: 😊 Привет ✓ 你好".  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** API returns 200 OK. An embedding vector is returned. usage.prompt\_tokens is plausible.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert data\[0\].embedding is a list of numbers.  
  * Verify usage.prompt\_tokens.

### **FV\_EDGE\_UNICODE\_RTL\_CHAT\_001**

* **Category Ref:** FV\_EDGE\_UNICODE  
* **Description:** Test /chat/completions with Right-to-Left (RTL) text (e.g., Arabic, Hebrew) in the prompt.  
* **Exposure Point(s):** /chat/completions endpoint, text handling in adapters and by LLM.  
* **Test Method/Action:** Make a POST request with messages: \[{"role": "user", "content": "مرحبا بالعالم"}\] (Hello world in Arabic).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns 200 OK. LLM responds appropriately to the RTL prompt. No display or processing errors related to text direction.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Inspect LLM response for coherence.

### **FV\_EDGE\_UNICODE\_CONTROL\_CHARS\_CHAT\_001**

* **Category Ref:** FV\_EDGE\_UNICODE  
* **Description:** Test /chat/completions with a prompt containing control characters (e.g., \\n, \\t, and potentially others like \\r, \\b if not stripped by HTTP server/FastAPI).  
* **Exposure Point(s):** /chat/completions endpoint, FastAPI request parsing, adapter string handling.  
* **Test Method/Action:** Make a POST request with messages: \[{"role": "user", "content": "Line one\\nLine two\\tIndented."}\].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns 200 OK. Control characters like \\n and \\t are generally preserved and interpreted by LLMs. More obscure control characters might be stripped or cause issues; the API should handle them gracefully (not crash).  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Inspect LLM response to see if formatting (newlines, tabs) is respected or how other control chars are handled.  
  * Ensure no API errors.

## **3\. Large Payloads**

### **FV\_EDGE\_LARGE\_CHAT\_PROMPT\_001**

* **Category Ref:** FV\_EDGE\_LARGE  
* **Description:** Test /chat/completions with a very long prompt, approaching but not exceeding the model's context window.  
* **Exposure Point(s):** /chat/completions, FastAPI request size limits, Uvicorn limits, provider SDKs.  
* **Test Method/Action:** Construct a prompt that is, e.g., 90% of the model's context window size. Make a POST request.  
* **Prerequisites:** Valid API Key with models:inference scope. Knowledge of model context window and server request size limits.  
* **Expected Secure Outcome:** API returns 200 OK (or an error from the provider if it still exceeds some internal limit, handled gracefully). No crashes due to memory or request size limits in the API framework itself.  
* **Verification Steps:**  
  * Assert HTTP status code (200 or a handled provider error like 400/413).  
  * If 200, verify response is generated.  
  * Monitor server resources during the test if possible.

### **FV\_EDGE\_LARGE\_CHAT\_NUM\_MESSAGES\_001**

* **Category Ref:** FV\_EDGE\_LARGE  
* **Description:** Test /chat/completions with a very large number of messages in the messages array (but total token count within limits).  
* **Exposure Point(s):** /chat/completions, Pydantic validation, adapter processing of message lists.  
* **Test Method/Action:** Make a POST request with messages containing many (e.g., 100s) short user/assistant messages.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns 200 OK or a specific error if there's a hard limit on the number of messages (distinct from token limits). Processing should not be unduly slow due to message count alone.  
* **Verification Steps:** Assert HTTP status code. Measure response time (see Performance Testing).

### **FV\_EDGE\_LARGE\_EMBED\_INPUT\_BATCH\_001**

* **Category Ref:** FV\_EDGE\_LARGE  
* **Description:** Test /embeddings with a very large batch of texts for embeddings (approaching provider batch limits).  
* **Exposure Point(s):** /embeddings, FastAPI limits, provider batch limits.  
* **Test Method/Action:** Make a POST request with input as a list of many strings (e.g., 1000s, up to provider limit like 2048 for some).  
* **Prerequisites:** Valid API Key with models:embedding scope. Knowledge of provider batch limits.  
* **Expected Secure Outcome:** API returns 200 OK with embeddings for all inputs, or a provider error (e.g. 400/413) if batch limit is exceeded by provider, handled gracefully by API.  
* **Verification Steps:** Assert HTTP status code. If 200, verify len(response.data) matches input batch size.

### **FV\_EDGE\_LARGE\_REQUEST\_SIZE\_LIMIT\_001**

* **Category Ref:** FV\_EDGE\_LARGE  
* **Description:** Test sending a request that exceeds the web server's (e.g., Uvicorn/FastAPI) configured request body size limit.  
* **Exposure Point(s):** Web server request parsing.  
* **Test Method/Action:** Construct an extremely large payload (e.g., many megabytes of text/image data in a chat request) that is known to exceed server limits.  
* **Prerequisites:** Knowledge of server's max request body size.  
* **Expected Secure Outcome:** API (or rather, the web server fronting it) returns an HTTP 413 Payload Too Large error before it hits application logic.  
* **Verification Steps:** Assert HTTP status code is 413\.

## **4\. Concurrent Requests (Focus on Stability)**

These tests are distinct from Agency Isolation concurrency tests; they focus on general API stability under concurrent load from even a single key.

### **FV\_EDGE\_CONCURRENT\_CHAT\_SAME\_KEY\_001**

* **Category Ref:** FV\_EDGE\_CONCURRENT  
* **Description:** Test multiple simultaneous /chat/completions requests from the same API key.  
* **Exposure Point(s):** API framework, provider SDK client handling, auth dependencies, database connection pooling.  
* **Test Method/Action:** Send N (e.g., 10-20) concurrent POST requests to /chat/completions using the same API key.  
* **Prerequisites:** Valid API Key with models:inference scope. Ability to make concurrent requests.  
* **Expected Secure Outcome:** All (or most, if some hit provider rate limits) requests are processed correctly and return 200 OK or a graceful rate limit error (429 from provider, translated). No 500 errors due to race conditions or resource exhaustion in the API.  
* **Verification Steps:**  
  * Monitor HTTP status codes for all responses.  
  * Check for any 5xx errors.  
  * Verify a sample of successful responses for correctness.

### **FV\_EDGE\_CONCURRENT\_EMBED\_SAME\_KEY\_001**

* **Category Ref:** FV\_EDGE\_CONCURRENT  
* **Description:** Test multiple simultaneous /embeddings requests from the same API key.  
* **Exposure Point(s):** As above.  
* **Test Method/Action:** Send N concurrent POST requests to /embeddings.  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** Similar to FV\_EDGE\_CONCURRENT\_CHAT\_SAME\_KEY\_001.  
* **Verification Steps:** Similar to FV\_EDGE\_CONCURRENT\_CHAT\_SAME\_KEY\_001.

## **5\. Subtly Malformed Data (Not Caught by Top-Level Pydantic)**

These are harder to define generically as Pydantic is quite robust. This might involve nested structures where a sub-field is incorrect in a way that only deeper logic or a provider SDK would catch.

### **FV\_EDGE\_MALFORMED\_CHAT\_TOOL\_CALL\_001 (If applicable)**

* **Category Ref:** FV\_EDGE\_MALFORMED\_SUBTLE  
* **Description:** If providing tool call responses, send a structurally valid tool\_calls object in a message, but with semantically incorrect content that Pydantic might not catch (e.g., tool\_call\_id that doesn't match a previous request, or malformed JSON *within* the function.arguments string if it's expected to be JSON).  
* **Exposure Point(s):** /chat/completions when providing tool responses, adapter logic, provider SDK.  
* **Test Method/Action:** Construct a messages array including a role: "tool" message with a tool\_calls object that has subtle semantic issues.  
* **Prerequisites:** Valid API Key with models:inference scope. Model that supports tool use and expects tool responses.  
* **Expected Secure Outcome:** API returns a 400 Bad Request (or similar 4xx) if the provider SDK rejects the semantic issue, or if API's adapter logic catches it. No 500 error.  
* **Verification Steps:** Assert HTTP status code (4xx). Verify error message is informative if possible.  
* **Code Reference:** Tool call handling in provider adapters and OpenAI schema definitions.

### **FV\_EDGE\_MALFORMED\_MESSAGE\_ROLE\_001**

* **Category Ref:** FV\_EDGE\_MALFORMED\_SUBTLE  
* **Description:** Test /chat/completions with invalid message role that passes Pydantic validation but is semantically incorrect.  
* **Exposure Point(s):** /chat/completions message validation, provider SDK.  
* **Test Method/Action:** Send a POST request with messages containing role: "invalid_role".  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns 422 Unprocessable Entity due to role enum validation or 400 Bad Request from provider.  
* **Verification Steps:**  
  * Assert HTTP status code is 400 or 422\.  
  * Assert error message indicates invalid role value.  
* **Code Reference:** Message role validation in app/providers/open_ai/schemas.py.

### **FV\_EDGE\_MALFORMED\_CHOICE\_INDEX\_001**

* **Category Ref:** FV\_EDGE\_MALFORMED\_SUBTLE  
* **Description:** Test /chat/completions with n > 1 but inconsistent choice indexing expectations.  
* **Exposure Point(s):** /chat/completions with multiple choices, response formatting.  
* **Test Method/Action:** Send a POST request with n: 3 and verify choice indexing.  
* **Prerequisites:** Valid API Key with models:inference scope. Model that supports multiple choices.  
* **Expected Secure Outcome:** Response contains exactly 3 choices with sequential indexes 0, 1, 2.  
* **Verification Steps:**  
  * Assert len(response.choices) == 3\.  
  * Assert choice indexes are [0, 1, 2]\.  
  * Verify each choice has valid message content.  
* **Code Reference:** Choice handling in response adapters.

## **6\. Image and Multimodal Edge Cases**

### **FV\_EDGE\_MULTIMODAL\_INVALID\_DATA\_URI\_001**

* **Category Ref:** FV\_EDGE\_MALFORMED\_SUBTLE  
* **Description:** Test /chat/completions with malformed data URI in image content.  
* **Exposure Point(s):** /chat/completions with image content, data URI parsing logic.  
* **Test Method/Action:** Send a POST request with messages containing invalid data URI (e.g., "data:image/jpeg;base64,INVALID_BASE64").  
* **Prerequisites:** Valid API Key with models:inference scope. Model that supports vision.  
* **Expected Secure Outcome:** API returns 400 Bad Request or 422 Unprocessable Entity with clear error message about invalid image data.  
* **Verification Steps:**  
  * Assert HTTP status code is 400 or 422\.  
  * Assert error message indicates image data format issue.  
  * Verify no server crash or resource leak.
* **Code Reference:** Image parsing handled in provider adapters.

### **FV\_EDGE\_MULTIMODAL\_OVERSIZED\_IMAGE\_001**

* **Category Ref:** FV\_EDGE\_LARGE  
* **Description:** Test /chat/completions with an extremely large image that may exceed model or API limits.  
* **Exposure Point(s):** /chat/completions with large image content, provider image size limits.  
* **Test Method/Action:** Send a POST request with an image that is very large (e.g., high resolution, large file size when base64 encoded).  
* **Prerequisites:** Valid API Key with models:inference scope. Knowledge of image size limits.  
* **Expected Secure Outcome:** API handles the large image gracefully - either processes it successfully or returns an appropriate error (413 Payload Too Large, 400 Bad Request) without crashing.  
* **Verification Steps:**  
  * Monitor HTTP status code (200, 400, 413).  
  * If error, verify clear error message about image size.  
  * Monitor server memory usage during test.

### **FV\_EDGE\_MULTIMODAL\_UNSUPPORTED\_FORMAT\_001**

* **Category Ref:** FV\_EDGE\_MALFORMED\_SUBTLE  
* **Description:** Test /chat/completions with unsupported image format in data URI.  
* **Exposure Point(s):** /chat/completions with image content, image format validation.  
* **Test Method/Action:** Send a POST request with an image in unsupported format (e.g., data:image/tiff or data:image/webp if not supported).  
* **Prerequisites:** Valid API Key with models:inference scope. Knowledge of supported image formats.  
* **Expected Secure Outcome:** API returns 400 Bad Request with clear error message about unsupported image format.  
* **Verification Steps:**  
  * Assert HTTP status code is 400\.  
  * Assert error message indicates unsupported image format.  
  * Verify format validation occurs before sending to provider.

## **7\. Parameter Edge Cases**

### **FV\_EDGE\_PARAM\_MAX\_TOKENS\_ZERO\_001**

* **Category Ref:** FV\_EDGE\_MALFORMED\_SUBTLE  
* **Description:** Test /chat/completions with max_tokens set to 0.  
* **Exposure Point(s):** /chat/completions parameter validation.  
* **Test Method/Action:** Send a POST request with max_tokens: 0.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns 422 Unprocessable Entity due to Pydantic PositiveInt validation constraint.  
* **Verification Steps:**  
  * Assert HTTP status code is 422\.  
  * Assert error message indicates max_tokens must be positive.  
* **Code Reference:** app/providers/open_ai/schemas.py defines PositiveInt constraint for max_tokens.

### **FV\_EDGE\_PARAM\_TEMPERATURE\_EXTREME\_001**

* **Category Ref:** FV\_EDGE\_MALFORMED\_SUBTLE  
* **Description:** Test /chat/completions with temperature values at extreme bounds.  
* **Exposure Point(s):** /chat/completions parameter validation and provider handling.  
* **Test Method/Action:** Send POST requests with temperature: 0.0, temperature: 2.0, and temperature: -0.1.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Valid temperature values (0.0, 2.0) are accepted. Invalid values (-0.1) return 422 due to validation constraints.  
* **Verification Steps:**  
  * For valid values: Assert HTTP status code is 200\.  
  * For invalid values: Assert HTTP status code is 422\.  
  * Verify response quality reflects temperature setting.  
* **Code Reference:** Temperature validation constraints in provider schemas.

### **FV\_EDGE\_PARAM\_TOP\_P\_INVALID\_001**

* **Category Ref:** FV\_EDGE\_MALFORMED\_SUBTLE  
* **Description:** Test /chat/completions with top_p values outside valid range [0,1].  
* **Exposure Point(s):** /chat/completions parameter validation.  
* **Test Method/Action:** Send POST requests with top_p: 1.5 and top_p: -0.1.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns 422 Unprocessable Entity for out-of-range values.  
* **Verification Steps:**  
  * Assert HTTP status code is 422\.  
  * Assert error message indicates top_p range constraint.  
* **Code Reference:** Parameter validation in provider schema definitions.

## **8\. Network and Connection Edge Cases (Harder to test reliably without specific setups)**

### **FV\_EDGE\_NETWORK\_CLIENT\_DISCONNECT\_STREAM\_001 (Conceptual)**

* **Category Ref:** FV\_EDGE\_NETWORK  
* **Description:** Test server behavior if a client disconnects during a /chat/completions stream.  
* **Exposure Point(s):** FastAPI/Uvicorn stream handling, provider SDK stream cancellation.  
* **Test Method/Action:** Initiate a stream. Midway, terminate the client connection abruptly.  
* **Prerequisites:** Valid API Key with models:inference scope. Setup to control client connection.  
* **Expected Secure Outcome:** Server-side resources are cleaned up gracefully. No orphaned processes or memory leaks. The LLM provider call should be cancelled if possible. Logs might show client disconnection.  
* **Verification Steps:** Monitor server logs for errors or resource cleanup messages. Check for resource leaks over multiple such tests (long-term).  
* **Code Reference:** app/routers/api_v1.py:43-50 handles streaming responses.

### **FV\_EDGE\_NETWORK\_PROVIDER\_TIMEOUT\_001 (Conceptual)**

* **Category Ref:** FV\_EDGE\_NETWORK  
* **Description:** Test API behavior if a downstream LLM provider times out during a long operation.  
* **Exposure Point(s):** Provider SDK timeout handling, API's error translation.  
* **Test Method/Action:** Mock the provider SDK to simulate a timeout (e.g., hang indefinitely or raise a timeout exception after a delay).  
* **Prerequisites:** Valid API Key with models:inference scope. Ability to mock provider SDK timeouts.  
* **Expected Secure Outcome:** API returns a 504 Gateway Timeout or 503 Service Unavailable error with a clear message. No indefinite hanging of the API request.  
* **Verification Steps:** Assert HTTP status code (504 or 503). Verify response time is capped by API's own timeout settings for downstream calls.  
* **Code Reference:** Provider implementations in app/providers/{bedrock,vertex_ai}/ handle timeouts.