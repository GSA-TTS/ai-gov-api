# **Test Cases: Section 7.2 \- Response Validation**

This document outlines test cases for API Response Structure & Content Validation as per the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_RESP\_...)  
* **Category Ref:** (e.g., FV\_RESP\_STRUCT, FV\_RESP\_CONTENT, FV\_RESP\_STREAM, FV\_RESP\_USAGE)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** API endpoint and its response structure/fields.  
* **Test Method/Action:** How the test is performed (e.g., "Make GET request and validate response schema").  
* **Prerequisites:** Valid API Key, specific request to elicit the target response.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (e.g., "Response matches ChatCompletionResponse schema").  
* **Verification Steps:** How to confirm the expected secure outcome (e.g., "Assert all required fields are present and have correct types").

## **1\. Success Response Validation (200 OK)**

### **FV\_RESP\_MODELS\_LIST\_001**

* **Category Ref:** FV\_RESP\_STRUCT  
* **Description:** Validate the structure of the /models endpoint response.  
* **Exposure Point(s):** /models endpoint response.  
* **Test Method/Action:** Make a GET request to /models.  
* **Prerequisites:** Valid API Key (no specific scope required for /models endpoint based on app/routers/api_v1.py:25-30).  
* **Expected Secure Outcome:** The response is a JSON array of LLMModel objects. Each item adheres to the LLMModel schema (contains id, name, capability).  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert Content-Type is application/json.  
  * Assert the response is a list (JSON array).  
  * For each item in the response list:  
    * Assert id is a non-empty string.  
    * Assert name is a non-empty string.  
    * Assert capability is a string with value "chat" or "embedding".  
* **Code Reference:** app/routers/api_v1.py:25-30 returns List[LLMModel], app/providers/base.py:16-27 defines LLMModel schema.

### **FV\_RESP\_CHAT\_SUCCESS\_001**

* **Category Ref:** FV\_RESP\_STRUCT  
* **Description:** Validate the structure of a successful non-streaming /chat/completions response.  
* **Exposure Point(s):** /chat/completions endpoint response (non-streaming).  
* **Test Method/Action:** Make a POST request to /chat/completions with a valid payload (e.g., simple prompt, stream: false or not present).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The response adheres to the ChatCompletionResponse schema.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert Content-Type is application/json.  
  * Assert object is "chat.completion".  
  * Assert created is an integer (timestamp from datetime serialization).  
  * Assert model is a non-empty string (matches requested model).  
  * Assert choices is a non-empty list.  
  * For each choice in choices:  
    * Assert index is a non-negative integer.  
    * Assert message is an object adhering to ChatCompletionResponseMessage schema:  
      * Assert role is "assistant".  
      * Assert content is a string.  
    * Assert finish\_reason is "stop" (default value) or null.  
  * Assert usage is an object adhering to ChatCompletionUsage schema:  
    * Assert prompt\_tokens is a non-negative integer.  
    * Assert completion\_tokens is a non-negative integer.  
    * Assert total\_tokens is a non-negative integer (sum of prompt and completion).  
* **Code Reference:** app/providers/open_ai/schemas.py:192-199 defines ChatCompletionResponse, lines 181-189 define response message and choice structures.

### **FV\_RESP\_EMBED\_SUCCESS\_001**

* **Category Ref:** FV\_RESP\_STRUCT  
* **Description:** Validate the structure of a successful /embeddings response.  
* **Exposure Point(s):** /embeddings endpoint response.  
* **Test Method/Action:** Make a POST request to /embeddings with valid input (string or list of strings).  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** The response adheres to the EmbeddingResponse schema.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert Content-Type is application/json.  
  * Assert object is "list".  
  * Assert data is a non-empty list.  
  * For each item in data:  
    * Assert object is "embedding".  
    * Assert embedding is a list of numbers (floats).  
    * Assert index is an integer (starts from 0).  
  * Assert model is a non-empty string (matches requested model).  
  * Assert usage is an object adhering to EmbeddingUsage schema:  
    * Assert prompt\_tokens is a non-negative integer.  
    * Assert total\_tokens is a non-negative integer (equal to prompt\_tokens).

## **2\. Error Response Validation**

### **FV\_RESP\_ERROR\_GENERIC\_001**

* **Category Ref:** FV\_RESP\_STRUCT  
* **Description:** Validate the structure of a generic error response (e.g., 4xx, 5xx).  
* **Exposure Point(s):** Any endpoint when an error occurs (e.g., invalid input, auth failure).  
* **Test Method/Action:** Trigger an error (e.g., send invalid JSON to /chat/completions, use an invalid API key).  
* **Prerequisites:** None specific, depends on the error being triggered.  
* **Expected Secure Outcome:** The error response payload contains a standard structure, e.g., {"detail": "Error message"} or {"error": {"message": "Error message", "type": "error\_type", "code": "error\_code"}}. The exact structure should be consistent.  
* **Verification Steps:**  
  * Assert HTTP status code is as expected for the error (e.g., 400, 401, 422, 500).  
  * Assert Content-Type is application/json.  
  * Assert the response body matches the defined error schema (e.g., contains detail or error.message).  
  * Assert the error message is user-friendly and does not expose sensitive internal details.

### **FV\_RESP\_ERROR\_422\_PYDANTIC\_001**

* **Category Ref:** FV\_RESP\_STRUCT  
* **Description:** Validate the structure of a Pydantic validation error (HTTP 422).  
* **Exposure Point(s):** Any endpoint with Pydantic model validation when invalid data is sent.  
* **Test Method/Action:** Send a request with a field of incorrect type to /chat/completions (e.g., model: 123).  
* **Prerequisites:** Valid API Key.  
* **Expected Secure Outcome:** API returns an HTTP 422 error. The response body is a JSON object, typically {"detail": \[...\]} where the detail is a list of objects, each describing a validation error (e.g., loc, msg, type).  
* **Verification Steps:**  
  * Assert HTTP status code is 422\.  
  * Assert Content-Type is application/json.  
  * Assert the response body has a detail key, and its value is a list.  
  * For each error in the detail list, assert it contains loc (list indicating field path), msg (string error message), and type (string error type).

## **3\. Streaming Response Validation (/chat/completions)**

### **FV\_RESP\_STREAM\_FORMAT\_001**

* **Category Ref:** FV\_RESP\_STREAM  
* **Description:** Validate the Server-Sent Events (SSE) format for streaming /chat/completions.  
* **Exposure Point(s):** /chat/completions endpoint response (streaming).  
* **Test Method/Action:** Make a POST request to /chat/completions with stream: true.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Response Content-Type is text/event-stream. Each event is correctly formatted (e.g., data: {...}\\n\\n). The stream terminates with a data: \[DONE\]\\n\\n message.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert Content-Type header is text/event-stream; charset=utf-8 (or similar, charset may vary).  
  * Collect all events. Verify each event starts with data: and ends with \\n\\n.  
  * Verify the last event is data: \[DONE\]\\n\\n.

### **FV\_RESP\_STREAM\_CHUNK\_SCHEMA\_001**

* **Category Ref:** FV\_RESP\_STREAM  
* **Description:** Validate the schema of individual data chunks in a streaming /chat/completions response.  
* **Exposure Point(s):** Data chunks in /chat/completions streaming response.  
* **Test Method/Action:** Make a POST request to /chat/completions with stream: true. Parse each JSON object from the data: lines (excluding \[DONE\]).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Each JSON chunk adheres to the ChatCompletionChunk schema.  
* **Verification Steps:**  
  * For each data chunk (parsed JSON object):  
    * Assert id is a non-empty string (same across chunks for the same completion).  
    * Assert object is "chat.completion.chunk".  
    * Assert created is an integer (timestamp, same across chunks).  
    * Assert model is a non-empty string (matches requested model, same across chunks).  
    * Assert choices is a list (usually one item).  
    * For each choice in choices:  
      * Assert index is an integer.  
      * Assert delta is an object adhering to ChatCompletionChunkDelta schema:  
        * role (string, usually "assistant", typically only in the first chunk).  
        * content (string, the token diff, can be null or empty).  
        * tool\_calls (list of ChunkToolCall, if applicable).  
      * Assert finish\_reason (string or null, typically null until the last content chunk for that choice).  
    * Assert usage is null or an object adhering to CompletionUsage schema (typically present in the last chunk if provider supports it, or in a separate event after \[DONE\] if following some conventions, though OpenAI spec usually has it in the last chunk before \[DONE\] or not at all in stream). *Verify actual implementation based on app/providers/open\_ai/adapter\_to\_core.py and provider behavior.*  
  * The final content-bearing chunk for a choice should have a non-null finish\_reason.

### **FV\_RESP\_STREAM\_TERMINATION\_001**

* **Category Ref:** FV\_RESP\_STREAM  
* **Description:** Ensure the stream terminates correctly with a \[DONE\] message.  
* **Exposure Point(s):** /chat/completions endpoint streaming response termination.  
* **Test Method/Action:** Make a POST request to /chat/completions with stream: true.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The stream ends with a data: \[DONE\]\\n\\n event. No further data events after \[DONE\].  
* **Verification Steps:**  
  * Collect all events.  
  * Assert the very last event received is exactly data: \[DONE\]\\n\\n.

## **4\. Usage Metrics Validation**

### **FV\_RESP\_USAGE\_CHAT\_NONSTREAM\_001**

* **Category Ref:** FV\_RESP\_USAGE  
* **Description:** Validate the accuracy of the usage object in a non-streaming /chat/completions response.  
* **Exposure Point(s):** usage field in /chat/completions non-streaming response.  
* **Test Method/Action:** Make a POST request with a known prompt and observe max\_tokens.  
* **Prerequisites:** Valid API Key with models:inference scope. A way to independently estimate token counts for the given model/prompt (can be approximate).  
* **Expected Secure Outcome:** prompt\_tokens, completion\_tokens, and total\_tokens are accurate or reasonably close to expected values. total\_tokens \= prompt\_tokens \+ completion\_tokens.  
* **Verification Steps:**  
  * Assert usage.prompt\_tokens is a plausible value for the input prompt.  
  * Assert usage.completion\_tokens is a plausible value for the generated content and respects max\_tokens if finish\_reason is 'length'.  
  * Assert usage.total\_tokens \== usage.prompt\_tokens \+ usage.completion\_tokens.

### **FV\_RESP\_USAGE\_EMBED\_001**

* **Category Ref:** FV\_RESP\_USAGE  
* **Description:** Validate the accuracy of the usage object in an /embeddings response.  
* **Exposure Point(s):** usage field in /embeddings response.  
* **Test Method/Action:** Make a POST request with known input text(s).  
* **Prerequisites:** Valid API Key with models:embedding scope. A way to independently estimate token counts for the given model/input.  
* **Expected Secure Outcome:** prompt\_tokens and total\_tokens are accurate. total\_tokens \= prompt\_tokens.  
* **Verification Steps:**  
  * Assert usage.prompt\_tokens is a plausible value for the input text(s).  
  * Assert usage.total\_tokens \== usage.prompt\_tokens.

### **FV\_RESP\_USAGE\_CHAT\_STREAM\_001**

* **Category Ref:** FV\_RESP\_USAGE  
* **Description:** Validate the accuracy of the usage object if present in a streaming /chat/completions response (often in the last chunk or a separate final event for some implementations, though OpenAI standard is less clear here).  
* **Exposure Point(s):** usage field in the final relevant chunk of a /chat/completions streaming response.  
* **Test Method/Action:** Make a POST request with stream: true and a known prompt. Inspect the chunk that contains usage data (if any).  
* **Prerequisites:** Valid API Key with models:inference scope. Provider must support returning usage in stream.  
* **Expected Secure Outcome:** If usage is provided in the stream, it is accurate. total\_tokens \= prompt\_tokens \+ completion\_tokens. (Note: OpenAI's current spec often omits usage from stream chunks, relying on client to sum token lengths from deltas or make a non-streaming call if exact counts are needed from server). *Verify against actual implementation.*  
* **Verification Steps:**  
  * If a chunk contains usage:  
    * Assert usage.prompt\_tokens is plausible.  
    * Assert usage.completion\_tokens is plausible for the full streamed content.  
    * Assert usage.total\_tokens \== usage.prompt\_tokens \+ usage.completion\_tokens.  
  * If not present in stream, this test might be N/A or require alternative verification (e.g. client-side calculation).

## **5\. Response Content Validation (Basic Semantic Checks)**

### **FV\_RESP\_CONTENT\_MODEL\_MATCH\_001**

* **Category Ref:** FV\_RESP\_CONTENT  
* **Description:** Ensure the model ID in the response matches the requested model ID.  
* **Exposure Point(s):** model field in /chat/completions and /embeddings responses.  
* **Test Method/Action:** Make requests to /chat/completions and /embeddings specifying a particular model.  
* **Prerequisites:** Valid API Key.  
* **Expected Secure Outcome:** The model field in the response exactly matches the model ID sent in the request.  
* **Verification Steps:**  
  * For /chat/completions: Assert response.model \== requested\_model\_id.  
  * For /embeddings: Assert response.model \== requested\_model\_id.

### **FV\_RESP\_CONTENT\_CHAT\_ROLE\_001**

* **Category Ref:** FV\_RESP\_CONTENT  
* **Description:** Ensure the role in a chat completion response message is "assistant".  
* **Exposure Point(s):** choices\[0\].message.role in /chat/completions response.  
* **Test Method/Action:** Make a POST request to /chat/completions.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The role field in the response message part of choices is "assistant".  
* **Verification Steps:** Assert response.choices\[0\].message.role \== "assistant".

### **FV\_RESP\_CONTENT\_EMBED\_VECTOR\_001**

* **Category Ref:** FV\_RESP\_CONTENT  
* **Description:** Ensure embedding vectors are lists of floats.  
* **Exposure Point(s):** data\[0\].embedding in /embeddings response.  
* **Test Method/Action:** Make a POST request to /embeddings.  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** The embedding field is a list, and all its elements are numbers (floats). The list should not be empty.  
* **Verification Steps:**  
  * Assert response.data\[0\].embedding is a list.  
  * Assert len(response.data\[0\].embedding) \> 0\.  
  * For each element in response.data\[0\].embedding, assert isinstance(element, float) (or isinstance(element, (int, float)) if integers are possible, though floats are standard).

## **6\. HTTP Headers Validation**

### **FV\_RESP\_HEADERS\_CHAT\_001**

* **Category Ref:** FV\_RESP\_STRUCT  
* **Description:** Validate HTTP headers for non-streaming chat completion responses.  
* **Exposure Point(s):** HTTP response headers from /chat/completions.  
* **Test Method/Action:** Make a POST request to /chat/completions and inspect response headers.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Response includes appropriate HTTP headers (Content-Type, Content-Length, etc.).  
* **Verification Steps:**  
  * Assert Content-Type header is "application/json"  
  * Assert Content-Length header is present and matches response body size  
  * Verify no sensitive information in headers  
* **Code Reference:** FastAPI automatically sets appropriate headers for JSON responses.

### **FV\_RESP\_HEADERS\_STREAM\_001**

* **Category Ref:** FV\_RESP\_STREAM  
* **Description:** Validate HTTP headers for streaming chat completion responses.  
* **Exposure Point(s):** HTTP response headers from /chat/completions with stream: true.  
* **Test Method/Action:** Make a POST request to /chat/completions with stream: true and inspect headers.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Response includes proper streaming headers.  
* **Verification Steps:**  
  * Assert Content-Type header is "text/event-stream"  
  * Assert Cache-Control header is "no-cache"  
  * Assert X-Accel-Buffering header is "no" (if present)  
  * Verify Transfer-Encoding is "chunked" or similar streaming indicator  
* **Code Reference:** app/routers/api_v1.py:46-49 sets streaming response headers.

## **7\. Error Response Content Validation**

### **FV\_RESP\_ERROR\_PROVIDER\_001**

* **Category Ref:** FV\_RESP\_STRUCT  
* **Description:** Validate error response structure when provider returns errors.  
* **Exposure Point(s):** Error handling for provider failures in chat/embeddings.  
* **Test Method/Action:** Trigger a provider error (invalid model parameters, rate limits, etc.).  
* **Prerequisites:** Valid API Key. Ability to trigger provider errors.  
* **Expected Secure Outcome:** API returns structured error response without exposing provider-specific details.  
* **Verification Steps:**  
  * Assert appropriate HTTP status code (400, 429, 502, 503)  
  * Assert response contains user-friendly error message  
  * Assert no sensitive provider information is leaked  
  * Verify error structure matches expected format  
* **Code Reference:** app/routers/api_v1.py:55-59 handles InvalidInput exceptions, app/providers/exceptions.py defines error types.

### **FV\_RESP\_ERROR\_AUTHENTICATION\_001**

* **Category Ref:** FV\_RESP\_STRUCT  
* **Description:** Validate error response for authentication failures.  
* **Exposure Point(s):** Authentication error handling across all endpoints.  
* **Test Method/Action:** Make requests with invalid API keys or missing authentication.  
* **Prerequisites:** Invalid or missing API key.  
* **Expected Secure Outcome:** API returns 401 Unauthorized with appropriate error structure.  
* **Verification Steps:**  
  * Assert HTTP status code is 401  
  * Assert error response contains authentication failure message  
  * Assert no sensitive information about valid API keys is leaked  
* **Code Reference:** app/auth/dependencies.py handles authentication failures.

### **FV\_RESP\_ERROR\_AUTHORIZATION\_001**

* **Category Ref:** FV\_RESP\_STRUCT  
* **Description:** Validate error response for authorization failures (scope mismatches).  
* **Exposure Point(s):** Authorization error handling for scope validation.  
* **Test Method/Action:** Use API key with insufficient scopes for specific endpoints.  
* **Prerequisites:** Valid API key with limited scopes (e.g., missing models:inference for /chat/completions).  
* **Expected Secure Outcome:** API returns 403 Forbidden with clear scope requirement message.  
* **Verification Steps:**  
  * Assert HTTP status code is 403  
  * Assert error response explains required scope  
  * Assert no sensitive scope configuration details are leaked  
* **Code Reference:** app/auth/dependencies.py:48-66 RequiresScope implementation handles authorization failures.

## **8\. Response Consistency Validation**

### **FV\_RESP\_CONSISTENCY\_MODEL\_FIELD\_001**

* **Category Ref:** FV\_RESP\_CONTENT  
* **Description:** Verify model field consistency across all response types.  
* **Exposure Point(s):** model field in chat completion and embedding responses.  
* **Test Method/Action:** Make multiple requests to different endpoints with the same model.  
* **Prerequisites:** Valid API Key with appropriate scopes.  
* **Expected Secure Outcome:** Model field consistently reflects the requested model ID across response types.  
* **Verification Steps:**  
  * Compare model field values across chat and embedding responses  
  * Verify exact string match with requested model ID  
  * Ensure no model ID transformation or aliasing  
* **Code Reference:** Response model definitions ensure consistent model field handling.

### **FV\_RESP\_CONSISTENCY\_USAGE\_CALCULATION\_001**

* **Category Ref:** FV\_RESP\_USAGE  
* **Description:** Verify usage calculation consistency across similar requests.  
* **Exposure Point(s):** usage object in multiple responses with similar inputs.  
* **Test Method/Action:** Make multiple identical requests and compare usage metrics.  
* **Prerequisites:** Valid API Key. Deterministic model behavior (temperature: 0).  
* **Expected Secure Outcome:** Usage metrics should be consistent for identical inputs with deterministic parameters.  
* **Verification Steps:**  
  * Compare prompt_tokens across identical requests  
  * For deterministic responses, verify completion_tokens consistency  
  * Validate total_tokens calculation accuracy  
* **Code Reference:** Provider adapters handle usage metric extraction and calculation.