# **Data for Edge Cases & Negative Testing**

This document outlines the approach to testing the AI API Framework with data representing edge cases and various negative scenarios. This complements standard functional and input validation testing by probing the system's behavior under less common, extreme, or intentionally challenging conditions. This aligns with the main API Test Plan (api\_test\_plan\_ai\_framework\_v1) objective of ensuring reliability and robustness.

## **1\. Understand the Goal**

The primary goal of "Data for Edge Cases & Negative Testing" is to uncover defects, vulnerabilities, or unexpected behaviors that may not be found during standard positive or typical invalid input testing. This involves intentionally stressing the system with inputs and conditions that are at the boundaries of valid ranges, are structurally correct but semantically unusual, or represent foreseeable misuse or complex failure conditions.

**Specific objectives for this AI API Framework include verifying:**

* **Boundary Value Handling:** How the API handles inputs that are at the extreme minimum or maximum of their allowed ranges or lengths (e.g., min/max temperature, top\_p, max\_tokens, dimensions; very long strings for prompts or user IDs; empty but valid lists where allowed by schema). This includes testing the interaction of multiple boundary values set simultaneously.  
* **Handling of Empty, Null, or Semantically Void (but Permitted) Inputs:** How the API and downstream LLMs react to optional fields being explicitly null, or required fields (like lists or strings) being empty if the schema permits (e.g., an empty messages list if not constrained by min\_length, an empty string as a message content or embedding input).  
* **Large Payloads and Data Volumes:**  
  * How the API framework (including web server, FastAPI, Pydantic, and adapters) handles very large request bodies (e.g., numerous messages in a chat sequence, extremely long text for embedding, large base64 encoded images/files approaching or exceeding practical limits).  
  * How it handles requests that might legitimately lead to very large responses from the LLM (e.g., high max\_tokens value).  
  * This tests for resource exhaustion (memory, CPU), timeouts (in API, adapters, or downstream), or incorrect handling/truncation of large data streams.  
* **Special Characters, Encodings, and Internationalization:**  
  * How the API handles inputs containing a wide range of Unicode characters (various scripts, emojis, symbols, combining characters, right-to-left text).  
  * How it processes control characters (e.g., \\n, \\r, \\t, null bytes \\x00, etc.) if they can be embedded in JSON string values.  
  * Behavior with non-standard or mixed character encodings if they somehow bypass initial UTF-8 parsing by the web server.  
* **Semantically Unusual but Structurally Valid Inputs:**  
  * Prompts that are nonsensical, highly repetitive, contradictory, or specifically designed to confuse or elicit unusual/evasive behavior from LLMs.  
  * Requests that utilize all optional parameters simultaneously, with some set to extreme (but valid) values to test complex interactions.  
  * Messages sequences that are structurally valid but logically unconventional (e.g., conversation starting with an assistant message, or multiple system messages).  
* **Concurrency and Resource Contention (Conceptual):**  
  * While full performance/load testing is separate, some negative tests might involve a small burst of concurrent requests with edge-case data to observe immediate error handling or resource contention symptoms (e.g., for last\_used\_at updates on API keys).  
* **Robustness to Unexpected or Degraded Downstream Behavior:**  
  * How the API framework reacts if a downstream LLM provider returns an unexpected (but not necessarily an HTTP error) response format (e.g., missing expected fields in its JSON, empty but successful response, malformed success response).  
  * How it handles provider-specific errors that are not explicitly mapped or anticipated by adapter logic.  
* **Idempotency (Conceptual for current GET/POST):**  
  * For current POST operations (/chat/completions, /embeddings), ensuring that repeated identical POST requests are treated as distinct new interactions and processed independently without unintended side effects from repetition (e.g., each call results in a new billing event, new LLM inference).  
* **Security-Related Edge Cases (Overlap with Security Testing):**  
  * Inputs designed to probe for logical flaws in authorization that go beyond simple scope checks (e.g., if user context was more deeply embedded, trying to exploit it).  
  * Testing for any verbose error messages that might be triggered only by specific edge case inputs, potentially leaking more information than standard errors.

The aim is to ensure the API is resilient, behaves predictably and securely even with unusual or extreme inputs, doesn't crash or hang, doesn't leak data, and handles all foreseeable (even if unlikely) scenarios gracefully with appropriate error reporting.

## **2\. Identify Potential Edge Case Scenarios, Negative Inputs & Expected Outcomes**

This section details types of data and scenarios that constitute edge cases or negative tests for the AI API Framework, based on its current functionality, data schemas, processing logic, and potential failure points.

**Sources for Identification:**

* **API Endpoints & Schemas (app/routers/api\_v1.py, app/providers/open\_ai/schemas.py):**  
  * Field constraints (min/max values for numbers like temperature, top\_p, max\_tokens, dimensions; min\_length/max\_length for strings/lists if defined by Pydantic or implicitly by LLM providers).  
  * Optional fields and their default behaviors when absent or explicitly null.  
  * Structure of nested objects (e.g., messages list, content list within messages, image\_url object, file object).  
  * Literal types and enum constraints.  
* **Data Processing Logic (app/providers/open\_ai/adapter\_to\_core.py, app/providers/utils.py):**  
  * How different ContentPart types (text, image, file) are parsed and converted to the core schema.  
  * Parsing logic in parse\_data\_uri for image data URIs (prefix, supported formats, Base64 decoding).  
* **Provider Adapters (app/providers/\*/adapter\_from\_core.py, app/providers/\*/adapter\_to\_core.py):**  
  * How core schema data is translated for specific backends (Bedrock, Vertex AI). Each backend might have its own specific limitations or behaviors with edge case data (e.g., handling of system prompts, empty messages, max token interpretations).  
* **Configuration (app/config/settings.py):**  
  * Default values for model parameters (though most are None in ChatCompletionRequest schema, implying provider defaults will be used if not set).  
* **External LLM Provider Documentation:** Each LLM (Claude, Llama, Gemini, Cohere) has its own documented limits and behaviors for token counts, input types, special characters, content policies, handling of empty inputs, etc. These inform what might constitute an edge case for a specific provider.  
* **HTTP Specification and Web Server Limits (Uvicorn/FastAPI):** Limits on request size, header size, URL length.

**A. Edge Cases for Request Body Fields (ChatCompletionRequest, EmbeddingRequest)**

1. **Numeric Parameter Boundaries & Extremes:**  
   * **Fields:** temperature, top\_p, n (OpenAI schema, though not directly used by all current adapters), max\_tokens, presence\_penalty, frequency\_penalty, dimensions (for embeddings).  
   * **Scenarios:**  
     * **Min/Max Valid Values:**  
       * temperature: 0.0, temperature: 2.0  
       * top\_p: 0.0, top\_p: 1.0  
       * max\_tokens: 1 (if model supports, some require more for coherent output), max\_tokens: \<provider\_max\_limit\> (e.g., 4096, 8192, etc., depending on model).  
       * presence\_penalty: \-2.0, presence\_penalty: 2.0  
       * frequency\_penalty: \-2.0, frequency\_penalty: 2.0  
       * dimensions (embeddings): Smallest and largest supported by a specific embedding model.  
     * **Zero Values (if not minimum):** max\_tokens: 0 (if schema allows non-positive, but Pydantic PositiveInt for dimensions prevents this there).  
   * **Expected Outcome:** API accepts valid boundary values. Downstream LLM provider processes them. If a boundary value is valid for the schema but problematic for a specific LLM (e.g., max\_tokens=0 might be rejected by the LLM), the error should originate from the LLM provider and be relayed gracefully by the API (likely as a 5xx, or a provider-specific 4xx if the provider signals it as a client error).  
2. **String and List Lengths & Content:**  
   * **Fields:**  
     * model ID string.  
     * messages\[\].content (if string), TextContentPart.text.  
     * EmbeddingRequest.input (if string or list of strings).  
     * stop (string or list of strings).  
     * user identifier string.  
   * **Scenarios:**  
     * **Empty Strings (where schema allows string but might be semantically problematic):**  
       * model: "" (Will fail model validation in app/providers/dependencies.py).  
       * messages\[\].content: "" (for a text part).  
       * EmbeddingRequest.input: "" (single string input).  
       * EmbeddingRequest.input: \[""\] (list with one empty string).  
       * stop: "" or stop: \[""\].  
       * user: "".  
     * **Very Long Strings (approaching/exceeding limits):**  
       * messages\[\].content.text: String near max token limit for a model, or exceeding HTTP request size limits.  
       * EmbeddingRequest.input: Similar, for single string or individual strings in a list.  
       * user: Very long user ID string.  
     * **Empty Lists (where schema allows list but might be semantically problematic):**  
       * messages: \[\] (Pydantic schema for ChatCompletionRequest.messages is Sequence\[ChatCompletionMessage\], which doesn't inherently enforce non-empty unless a validator or min\_length is added. OpenAI spec usually implies at least one message).  
       * EmbeddingRequest.input: \[\] (Similar, List\[str\]).  
       * stop: \[\] (This is valid in OpenAI spec, meaning no custom stop sequences).  
     * **Very Long Lists:**  
       * messages: List with a very large number of message objects (e.g., 1000s, testing adapter performance and provider limits on conversation history length).  
       * EmbeddingRequest.input: List with a very large number of strings to embed (testing batching limits of providers).  
       * stop: List with many stop sequences (e.g., 4, which is OpenAI's limit).  
   * **Expected Outcome:**  
     * **Empty but Structurally Valid:** If the schema allows an empty string/list (e.g., stop: \[\] is valid), the API should process it. The downstream LLM might return an error (e.g., for empty prompt) or a default behavior.  
     * **Pydantic Validation Failure:** If the schema has min\_length or min\_items constraints (e.g., if ChatCompletionRequest.messages were constrained to be non-empty), a 422 error.  
     * **Exceeding Server/Provider Limits:** For very long strings/lists:  
       * HTTP 413 Request Entity Too Large (if Uvicorn/proxy limit is hit before application logic).  
       * HTTP 422 Unprocessable Entity (if Pydantic has explicit max\_length constraints that are hit).  
       * Error from the LLM provider (e.g., "context window exceeded", "input too long", "too many items in batch"), which should be relayed gracefully by the API (e.g., as a 5xx, or a specific 4xx if the provider indicates a client-side error).  
       * The API framework itself should not crash or become unresponsive.  
3. **Content Types and Structures (within ChatCompletionRequest.messages):**  
   * **Message Roles & Order:**  
     * Sequence starting with an assistant message: \[{"role": "assistant", ...}, {"role": "user", ...}\].  
     * Sequence of only system messages: \[{"role": "system", ...}, {"role": "system", ...}\].  
     * Sequence of only assistant messages.  
     * Multiple system messages interspersed: \[{"role": "system", ...}, {"role": "user", ...}, {"role": "system", ...}\].  
     * Message with role: "user" but content structured like an assistant's typical response.  
   * **Content Parts:**  
     * messages\[\].content as a list with only an ImageContentPart, no TextContentPart.  
     * messages\[\].content as a list with only a FileContentPart, no TextContentPart.  
     * messages\[\].content as a list with multiple ImageContentParts (behavior depends on model/adapter).  
     * messages\[\].content as a list with multiple FileContentParts (behavior depends on model/adapter).  
     * messages\[\].content as an empty list: messages: \[{"role": "user", "content": \[\]}\].  
     * TextContentPart.text being an empty string: messages: \[{"role": "user", "content": \[{"type": "text", "text": ""}\]}\].  
   * **ImageContentPart.image\_url.url (Data URI Edge Cases):**  
     * Valid data URI for a 1x1 pixel image (minimal valid image data for each supported format: jpeg, png, gif, webp).  
     * Valid data URI for a very large image (e.g., 10MB, 20MB, testing size limits for base64 decoding by parse\_data\_uri or processing by LLM).  
     * detail field set to "low" or "high" (verify if passed through by adapters and if it has any observable effect if the model supports it).  
   * **FileContentPart.file.file\_data (Base64 PDF Edge Cases):**  
     * Valid base64 for a tiny, minimal valid PDF (e.g., one empty page, or just a few bytes that constitute a "valid" PDF header).  
     * Valid base64 for a very large PDF (e.g., 10MB, 50MB, testing size limits).  
     * Base64 for a password-protected PDF.  
     * Base64 for a corrupted PDF (valid base64, but PDF content is malformed).  
     * Base64 for a PDF with many pages or complex structures.  
   * **Expected Outcome:**  
     * The API should parse all structurally valid combinations according to Pydantic schemas.  
     * Unusual but structurally valid sequences of messages (e.g., starting with assistant) should be passed to the LLM via the adapters. The LLM's behavior or errors will dictate the outcome. The API itself shouldn't error unless an adapter has specific constraints (e.g., Vertex adapter logic for system prompts).  
     * Minimal/maximal valid image/file data should be processed. parse\_data\_uri should handle valid base64.  
     * Very large image/file data might hit:  
       * HTTP 413 from web server.  
       * InputDataError (400) if parse\_data\_uri or openai\_chat\_request\_to\_core has internal size limits or fails on decoding very large base64 strings (memory issues).  
       * Errors from the LLM provider if the data (after decoding) exceeds their limits.  
     * Corrupted or password-protected files (if base64 is valid) would be passed to the LLM; errors should come from the provider.  
4. **Optional Fields and Defaults:**  
   * **Scenarios:**  
     * Send requests with *none* of the optional parameters set for ChatCompletionRequest (no temperature, top\_p, max\_tokens, stream, stop, presence\_penalty, frequency\_penalty, user).  
     * Send requests with *none* of the optional parameters set for EmbeddingRequest (no dimensions, input\_type, user).  
     * Send requests with optional fields explicitly set to null (JSON null). Pydantic treats Optional\[Type\] \= None such that null is accepted and results in the field being None in the model.  
   * **Expected Outcome:**  
     * API should use default values specified in Pydantic schemas (e.g., stream: False, encoding\_format: "float") or allow them to remain None.  
     * Provider adapters should handle None values appropriately, typically meaning the LLM provider's own defaults for those parameters will be used.  
     * Requests should be processed successfully by the downstream LLM.  
5. **Special Characters & Unicode in String Fields:**  
   * **Fields:** All string inputs: model, messages\[\].content.text, ImageContentPart.image\_url.url (the non-base64 parts if somehow manipulated), FileContentPart.file.file\_name (if used), EmbeddingRequest.input, user, stop sequences.  
   * **Scenarios:**  
     * Strings containing a wide variety of Unicode characters: different language scripts (e.g., Chinese, Arabic, Cyrillic, Hindi), emojis, mathematical symbols, musical symbols, combining characters.  
     * Strings containing JSON special characters (e.g., {}\[\]",:) that are correctly escaped within the overall JSON request.  
     * Strings containing URI-unsafe characters if they were part of a model ID (though model IDs are usually restricted).  
     * Strings containing control characters:  
       * Common: \\n (newline), \\r (carriage return), \\t (tab).  
       * Less common/problematic: \\b (backspace), null bytes (\\x00), other ASCII/Unicode control characters (U+0000–U+001F, U+007F–U+009F). JSON strings can technically contain most of these if properly escaped (e.g., \\u0000).  
     * Right-to-left (RTL) text mixed with LTR text.  
     * Extremely long sequences of a single repeating character.  
   * **Expected Outcome:**  
     * API (FastAPI/Uvicorn/Pydantic) should correctly parse valid JSON containing these characters.  
     * parse\_data\_uri should robustly handle the non-base64 parts of the data URI string.  
     * Adapters should correctly pass these strings (as Python strings) to the backend LLMs.  
     * LLMs should handle them according to their capabilities; some control characters might be stripped or interpreted by LLMs, or cause errors if they violate provider content policies.  
     * API responses should correctly JSON-encode any such characters if they are part of the LLM's output.  
     * No crashes or errors due to character encoding/decoding issues within the API framework itself. If a string causes an error in parse\_data\_uri (e.g., invalid base64 due to control chars), an InputDataError (400) is expected.

**B. Negative Scenarios (Beyond Simple Validation Failures)**

1. **Extremely Large Number of Messages/Inputs (Resource Exhaustion Probes):**  
   * **Scenario (Chat):** ChatCompletionRequest.messages with 10,000s of minimal message objects (if request fits within HTTP limits).  
   * **Scenario (Embeddings):** EmbeddingRequest.input as a list with 10,000s of short strings.  
   * **Purpose:** Stress test list processing, memory allocation in Pydantic model creation and adapter layers, and observe how provider batch/token limits are hit and reported.  
   * **Expected Outcome:**  
     * HTTP 413 Request Entity Too Large if web server (Uvicorn/proxy) limit is hit first.  
     * HTTP 422 if Pydantic has max\_items constraints that are violated.  
     * If the request is parsed by the API, an error from the LLM provider (e.g., "too many tokens in history," "batch size limit exceeded") should be relayed gracefully by the API (e.g., as a 5xx, or a specific 4xx if the provider signals it as a client error).  
     * The API framework should not crash, run out of memory (OOM error), or become unresponsive due to the large number of items (assuming individual items are small). Performance degradation is expected but not outright failure of the API service.  
2. **Rapid, Repeated Valid Requests (Probing for Race Conditions / Implicit Rate Limits):**  
   * **Scenario:** Send 5-10 valid requests (e.g., simple chat completions) in very quick succession (e.g., concurrently or within milliseconds) from a single client using the same API key.  
   * **Purpose:** Observe system behavior under a small, sharp burst of load. Check for race conditions in shared resources (e.g., APIKey.last\_used\_at updates, though SQLAlchemy should handle this). See if downstream provider rate limits are hit and how they are reported.  
   * **Expected Outcome:**  
     * Initial requests should succeed.  
     * APIKey.last\_used\_at should reflect the timestamp of one of the recent calls (exact one might be subject to race but should be updated).  
     * If downstream provider rate limits are hit (e.g., tokens per minute), the API should relay the provider's error (often a 429 Too Many Requests, or a generic 5xx if not specifically handled by the adapter) gracefully for the later requests in the burst.  
     * The API itself should remain stable and continue processing other requests if possible.  
3. **Using All Optional Parameters Simultaneously with Extreme (but Valid) Values:**  
   * **Scenario (Chat):** ChatCompletionRequest with temperature: 0.0, top\_p: 0.0 (can be problematic for some models if both are very low, leading to deterministic but potentially poor output or errors), max\_tokens: 1, stop: \["a", "b", "c", "d"\] (max 4 stop sequences), presence\_penalty: 2.0, frequency\_penalty: 2.0, a long user string.  
   * **Purpose:** Test the combined effect of multiple boundary/extreme parameters on the API framework's adapters and the downstream LLMs.  
   * **Expected Outcome:** The request is structurally valid and should be accepted by Pydantic. The behavior then depends heavily on the specific LLM provider and model. The LLM might produce minimal or strange output, or it might error out (e.g., if temperature and top\_p combination is invalid for it, or if max\_tokens: 1 is too restrictive). The API should relay the LLM's response or error correctly and gracefully.  
4. **Image/File Data Edge Cases (Content Integrity/Type Mismatch):**  
   * **ImageContentPart.image\_url.url:**  
     * **Type Mismatch:** Data URI specifies data:image/jpeg;base64,... but the actual base64 data is for a PNG image.  
     * **Corrupted Image Data:** Valid base64 string, but the decoded bytes do not form a valid image of the specified type (e.g., truncated JPEG data).  
   * **FileContentPart.file.file\_data:**  
     * **Password-Protected PDF:** Valid base64 for a PDF that requires a password to open.  
     * **Corrupted PDF Data:** Valid base64, but decoded bytes do not form a valid PDF.  
     * **Non-PDF as PDF:** Valid base64 of a different file type (e.g., a text file) provided as if it's a PDF (current FilePart in core schema has mime\_type="application/pdf" which is a hint, but adapter\_to\_core for OpenAI FileContentPart doesn't use it yet).  
   * **Expected Outcome:**  
     * parse\_data\_uri will succeed if the data URI prefix and Base64 encoding are valid. It does not validate the *content* of the decoded bytes against the declared MIME type.  
     * The (potentially problematic) decoded byte data will be passed to the LLM provider via the appropriate adapter.  
     * The LLM provider is responsible for handling corrupted, password-protected, or type-mismatched content. It may return an error (e.g., "cannot process image/file," "unsupported file format," "file is encrypted").  
     * The API framework should relay any such errors from the provider gracefully (e.g., as a 5xx or a provider-specific 4xx). The API itself should not crash due to the content of the file/image data once it's past base64 decoding.  
5. **Unexpected LLM Provider Responses (Not HTTP Errors, but Malformed Success):**  
   * **Scenario:** Mock a downstream LLM provider to return a 200 OK HTTP status but with a JSON body that is missing required fields expected by the adapter's Pydantic response model (e.g., Bedrock ConverseResponse missing the output key, or Vertex GenerationResponse missing candidates).  
   * **Purpose:** Test the robustness of the provider response adapters (adapter\_to\_core.py for Bedrock/Vertex).  
   * **Expected Outcome:** The adapter's Pydantic model validation for the provider's response should fail. This should ideally be caught within the provider's invoke\_model or embeddings method and result in a 500 Internal Server Error from the API, with a log message indicating a provider response parsing failure. The API should not crash or return a partially processed/malformed response to the client.

**C. Expected Outcomes Summary for Edge Cases & Negative Tests:**

* **Graceful Degradation/Failure:** The API must not crash, hang, leak resources, or enter an inconsistent state when subjected to edge case or negative inputs.  
* **Correct and Secure Error Reporting:** If an input leads to an error (whether caught by the API's validation, custom logic, or relayed from a downstream provider), the HTTP status code and error message must be appropriate, informative to the client for debugging, and **must not leak sensitive internal system details or excessive user input**.  
  * Client-side errors (bad input format, invalid values per schema): 400 Bad Request or 422 Unprocessable Entity.  
  * Resource limits hit (request size, LLM context window/token limits): 413 Request Entity Too Large, 422, or an error from the provider relayed appropriately (e.g., 400 if provider indicates client error, 5xx if provider indicates its own issue or if the API can't interpret).  
  * Server-side or unhandled provider issues: 500 Internal Server Error (with request\_id).  
* **Adherence to Specification for Boundary Values:** For inputs that are at the extreme boundaries of "valid" (e.g., temperature=0.0, max\_tokens=1), the API should process them according to its defined behavior (usually passing them to the LLM provider). The LLM provider's handling of these boundary values will then determine the final outcome.  
* **Security (No Exploitation):** No new vulnerabilities (e.g., Denial of Service through resource exhaustion, data leakage, command execution) should be exploitable by crafting edge case inputs.  
* **Consistent Behavior:** The API should behave consistently when presented with similar types of edge cases across different but comparable fields or inputs.

## **3\. Design Test Cases**

This section details specific test cases based on the identified edge case scenarios and negative inputs. Each test case will include its ID, category reference, scenario reference, description, input vectors, specific test data/payload, prerequisites, request details, expected HTTP status code, key elements of the expected response body, the overall expected behavior in the context of the edge case, and verification points (including server log checks).

**General Test Case Components:**

* **ID:** Unique identifier (e.g., EC\_BODY\_NUM\_001)  
* **Category Ref:** (e.g., EC\_BODY\_NUMERIC, EC\_BODY\_STRING\_LIST, EC\_BODY\_CONTENT, EC\_NEGATIVE\_LOAD, EC\_NEGATIVE\_PROVIDER)  
* **Scenario Ref:** (Points to the specific scenario in Section 2.A or 2.B)  
* **Description:** What specific edge case or negative condition is being tested.  
* **Input Vector(s):** The specific API endpoint and request field(s) being targeted.  
* **Test Data/Payload:** The exact data representing the edge case or negative input.  
* **Prerequisites:** Valid API Key with necessary scopes, specific model configurations assumed (e.g., a chat model, an embedding model, a multimodal model).  
* **Request Details:** HTTP Method, Endpoint, Headers, Full Request Body.  
* **Expected HTTP Status Code:** (e.g., 200, 400, 413, 422, 5xx).  
* **Expected Response Body (for errors):** Key fields (detail, error, message), specific error messages, and structure. For success, key aspects of the valid response.  
* **Expected Behavior (Contextual):** How the API framework and/or the downstream LLM is expected to handle this specific edge case beyond just the HTTP response (e.g., "LLM should use default for temperature", "API should not crash with large payload").  
* **Verification Points:** Check API response, server logs for specific messages or absence of errors/sensitive data, and any indirect effects if applicable.

**A. Edge Cases for Request Body Fields (Category: EC\_BODY)**

**Sub-Category: Numeric Parameter Boundaries & Extremes (EC\_BODY\_NUMERIC)**

* **ID:** EC\_BODY\_NUM\_001  
  * **Scenario Ref:** 2.A.1 (Numeric Parameter Boundaries)  
  * **Description:** Test temperature at minimum valid value (0.0) for /chat/completions.  
  * **Input Vector(s):** ChatCompletionRequest.temperature  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Test"}\], "temperature": 0.0}  
  * **Prerequisites:** Valid API Key (inference scope), configured chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (or success from provider)  
  * **Expected Response Body:** Valid ChatCompletionResponse. Output should be more deterministic.  
  * **Expected Behavior:** API accepts the value. LLM provider processes with temperature 0.0.  
  * **Verification:** Successful response. Observe output for determinism (if possible with multiple identical requests).  
* **ID:** EC\_BODY\_NUM\_002  
  * **Scenario Ref:** 2.A.1  
  * **Description:** Test temperature at maximum valid value (2.0) for /chat/completions.  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Test"}\], "temperature": 2.0}  
  * **Prerequisites:** Valid API Key (inference scope), configured chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK  
  * **Expected Response Body:** Valid ChatCompletionResponse. Output should be highly creative/random.  
  * **Expected Behavior:** API accepts value. LLM processes with temperature 2.0.  
* **ID:** EC\_BODY\_NUM\_003  
  * **Scenario Ref:** 2.A.1  
  * **Description:** Test max\_tokens at a very low valid value (e.g., 1\) for /chat/completions.  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Tell me a long story"}\], "max\_tokens": 1}  
  * **Prerequisites:** Valid API Key (inference scope), configured chat\_model\_id that supports max\_tokens=1.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK  
  * **Expected Response Body:** Valid ChatCompletionResponse. choices\[0\].message.content should be very short (likely one token). finish\_reason might be "length".  
  * **Expected Behavior:** API accepts. LLM truncates output to 1 token.  
* **ID:** EC\_BODY\_NUM\_004  
  * **Scenario Ref:** 2.A.1  
  * **Description:** Test max\_tokens at a very high value (near provider limit, e.g., 4000\) for /chat/completions.  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Write a short poem"}\], "max\_tokens": 4000}  
  * **Prerequisites:** Valid API Key (inference scope), configured chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK  
  * **Expected Response Body:** Valid ChatCompletionResponse. Content length should be respected by the LLM up to its actual limit for the model.  
  * **Expected Behavior:** API accepts. LLM generates up to its configured max or the requested max\_tokens.  
* **ID:** EC\_BODY\_NUM\_005  
  * **Scenario Ref:** 2.A.1  
  * **Description:** Test dimensions for /embeddings at a small valid value supported by the model.  
  * **Input Vector(s):** EmbeddingRequest.dimensions  
  * **Test Data/Payload:** {"model": "\<embedding\_model\_id\_supports\_dimensions\>", "input": "test", "dimensions": 128}  
  * **Prerequisites:** Valid API Key (embedding scope), configured embedding\_model\_id\_supports\_dimensions that allows custom dimensions.  
  * **Request Details:** POST /api/v1/embeddings  
  * **Expected Status Code:** 200 OK  
  * **Expected Response Body:** Valid EmbeddingResponse. Each embedding vector in data should have length 128\.  
  * **Expected Behavior:** API accepts. Provider generates embeddings of specified dimension.

*(Continue for other numeric fields: top\_p, n, presence\_penalty, frequency\_penalty with min/max values)*

**Sub-Category: String and List Lengths & Content (EC\_BODY\_STR\_LIST)**

* **ID:** EC\_BODY\_STR\_LIST\_001  
  * **Scenario Ref:** 2.A.2 (String and List Lengths)  
  * **Description:** ChatCompletionRequest.messages\[\].content.text is an empty string.  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": ""}\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (LLM provider might return an error or a generic response like "How can I help you?").  
  * **Expected Behavior:** API accepts. LLM handles empty content as per its design.  
  * **Verification:** API responds without framework error. Inspect LLM response.  
* **ID:** EC\_BODY\_STR\_LIST\_002  
  * **Scenario Ref:** 2.A.2  
  * **Description:** EmbeddingRequest.input is an empty string.  
  * **Test Data/Payload:** {"model": "\<embedding\_model\_id\>", "input": ""}  
  * **Prerequisites:** Valid API Key (embedding scope), embedding\_model\_id.  
  * **Request Details:** POST /api/v1/embeddings  
  * **Expected Status Code:** Likely an error from the provider (e.g., 4xx or 5xx relayed by API), as embedding an empty string is often invalid.  
  * **Expected Behavior:** API relays provider's error or Pydantic validation error if schema has min\_length=1.  
  * **Verification:** Check for appropriate error code and message.  
* **ID:** EC\_BODY\_STR\_LIST\_003  
  * **Scenario Ref:** 2.A.2  
  * **Description:** ChatCompletionRequest.messages is an empty list (if not constrained by Pydantic min\_length=1).  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 422 (If ChatCompletionRequest.messages Pydantic schema has min\_length=1 or similar constraint). If not, then an error from the LLM provider is expected.  
  * **Expected Behavior:** API rejects if schema violated, otherwise relays provider error.  
* **ID:** EC\_BODY\_STR\_LIST\_004  
  * **Scenario Ref:** 2.A.2  
  * **Description:** ChatCompletionRequest.messages\[\].content.text with very long string (e.g., 50,000 characters).  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "\<very\_long\_string\>"}\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 413 (if Uvicorn/proxy limit hit), or 400/422/5xx (error from LLM provider due to token limit, relayed by API).  
  * **Expected Behavior:** API handles large input gracefully, does not crash. Relays appropriate error.  
  * **Verification:** Check status code and error message. Monitor server resources during test.  
* **ID:** EC\_BODY\_STR\_LIST\_005  
  * **Scenario Ref:** 2.A.2  
  * **Description:** ChatCompletionRequest.messages with a very large number of message objects (e.g., 200 messages).  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[\<200\_message\_objects\>\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 413, or error from LLM provider (token limit for history), relayed by API.  
  * **Expected Behavior:** API handles gracefully.  
  * **Verification:** Check status and error. Monitor server resources.

*(Continue for EmbeddingRequest.input (long string, long list of strings), stop sequences (empty list, max number of sequences, long sequences)).*

**Sub-Category: Content Types and Structures (EC\_BODY\_CONTENT)**

* **ID:** EC\_BODY\_CONTENT\_001  
  * **Scenario Ref:** 2.A.3 (Content Types and Structures)  
  * **Description:** ChatCompletionRequest.messages starts with an assistant message.  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "assistant", "content": "I start."}, {"role": "user", "content": "Okay?"}\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (Most LLMs accept this, though it's unusual). Behavior depends on LLM.  
  * **Expected Behavior:** API accepts. LLM processes.  
  * **Verification:** Successful response.  
* **ID:** EC\_BODY\_CONTENT\_002  
  * **Scenario Ref:** 2.A.3  
  * **Description:** ChatCompletionRequest.messages\[\].content is a list with only an ImageContentPart (no text).  
  * **Test Data/Payload:** {"model": "\<multimodal\_chat\_model\_id\>", "messages": \[{"role": "user", "content": \[{"type": "image\_url", "image\_url": {"url": "\<valid\_image\_data\_uri\>"}}\]}\]}  
  * **Prerequisites:** Valid API Key (inference scope), multimodal\_chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (if model supports image-only prompts).  
  * **Expected Behavior:** API accepts. LLM processes image.  
  * **Verification:** Successful response, content should be about the image.  
* **ID:** EC\_BODY\_CONTENT\_003  
  * **Scenario Ref:** 2.A.3  
  * **Description:** ImageContentPart.image\_url.url with minimal valid 1x1 pixel image (PNG).  
  * **Test Data/Payload:** (Using a tiny valid PNG base64 string)  
  * **Prerequisites:** Valid API Key (inference scope), multimodal\_chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK  
  * **Expected Behavior:** API and LLM process the minimal image.  
  * **Verification:** Successful response.  
* **ID:** EC\_BODY\_CONTENT\_004  
  * **Scenario Ref:** 2.A.3  
  * **Description:** ImageContentPart.image\_url.url with very large image base64 string (e.g., 15MB).  
  * **Test Data/Payload:** (Generate a large base64 image string)  
  * **Prerequisites:** Valid API Key (inference scope), multimodal\_chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 400 (from InputDataError if parse\_data\_uri has limits or fails on huge base64), 413 (HTTP limit), or error from provider relayed by API.  
  * **Expected Behavior:** Graceful error handling.  
  * **Verification:** Check error, server resources.  
* **ID:** EC\_BODY\_CONTENT\_005  
  * **Scenario Ref:** 2.A.3  
  * **Description:** FileContentPart.file.file\_data with minimal valid PDF base64.  
  * **Test Data/Payload:** (Using a tiny valid PDF base64 string)  
  * **Prerequisites:** Valid API Key (inference scope), multimodal\_chat\_model\_id that supports PDF.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK  
  * **Expected Behavior:** API and LLM process minimal PDF.

*(Continue for very large PDF, password-protected PDF, corrupted PDF (valid base64 but bad PDF content)).*

**Sub-Category: Optional Fields and Defaults (EC\_BODY\_OPTIONAL)**

* **ID:** EC\_BODY\_OPTIONAL\_001  
  * **Scenario Ref:** 2.A.4 (Optional Fields and Defaults)  
  * **Description:** ChatCompletionRequest with no optional parameters set.  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Test defaults"}\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK  
  * **Expected Behavior:** API processes. LLM uses its default values for temperature, top\_p, max\_tokens etc.  
  * **Verification:** Successful response.  
* **ID:** EC\_BODY\_OPTIONAL\_002  
  * **Scenario Ref:** 2.A.4  
  * **Description:** ChatCompletionRequest with optional fields explicitly set to null.  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[...\], "temperature": null, "max\_tokens": null}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (Pydantic Optional\[Type\] \= None allows null, treated as absent).  
  * **Expected Behavior:** Same as if fields were not sent; LLM uses defaults.

**Sub-Category: Special Characters & Unicode (EC\_BODY\_UNICODE)**

* **ID:** EC\_BODY\_UNICODE\_001  
  * **Scenario Ref:** 2.A.5 (Special Characters & Unicode)  
  * **Description:** ChatCompletionRequest.messages\[\].content.text with diverse Unicode (emojis, various scripts).  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Hello 😊 你好 Привет saluto مرحبا"}\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK  
  * **Expected Behavior:** API and LLM process Unicode correctly. Response correctly encodes Unicode.  
  * **Verification:** Successful response. Verify content if LLM echoes or uses the Unicode.  
* **ID:** EC\_BODY\_UNICODE\_002  
  * **Scenario Ref:** 2.A.5  
  * **Description:** ChatCompletionRequest.messages\[\].content.text with JSON special characters (properly escaped in request).  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Text with \\"quotes\\" and {brackets} and \[arrays\]"}\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK  
  * **Expected Behavior:** API parses JSON. LLM receives literal string.  
* **ID:** EC\_BODY\_UNICODE\_003  
  * **Scenario Ref:** 2.A.5  
  * **Description:** ChatCompletionRequest.messages\[\].content.text with control characters (newline, tab).  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Line1\\nLine2\\tIndented"}\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK  
  * **Expected Behavior:** API parses. LLM receives string with control characters, handles as per its design.

**B. Negative Scenarios (Beyond Simple Validation Failures) (Category: EC\_NEGATIVE)**

**Sub-Category: Resource Exhaustion Probes (EC\_NEGATIVE\_RESOURCE)**

* **ID:** EC\_NEGATIVE\_RESOURCE\_001  
  * **Scenario Ref:** 2.B.1 (Extremely Large Number of Messages/Inputs)  
  * **Description:** ChatCompletionRequest.messages with a very large number of small message objects (e.g., 5000 messages of {"role":"user", "content":"a"}).  
  * **Test Data/Payload:** Dynamically generate the large messages list.  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 413 (if HTTP limit hit), or error from LLM provider (token limit for history), relayed by API (e.g., 400, 422, or 5xx).  
  * **Expected Behavior:** API handles large input gracefully without crashing. Relays appropriate error.  
  * **Verification:** Check status and error. Monitor API server memory/CPU.

**Sub-Category: Rapid Requests (EC\_NEGATIVE\_RAPID)**

* **ID:** EC\_NEGATIVE\_RAPID\_001  
  * **Scenario Ref:** 2.B.2 (Rapid, Repeated Requests)  
  * **Description:** Send 10 valid ChatCompletionRequests concurrently or in rapid succession.  
  * **Test Data/Payload:** Standard valid chat payload.  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** 10 x POST /api/v1/chat/completions  
  * **Expected Status Code:** Initial requests 200 OK. Later requests might receive 429 or 5xx if downstream provider rate limits are hit.  
  * **Expected Behavior:** API remains stable. Relays provider rate limit errors correctly. APIKey.last\_used\_at is updated.  
  * **Verification:** Observe status codes of all responses. Check API stability. Check last\_used\_at.

**Sub-Category: Combined Extreme Parameters (EC\_NEGATIVE\_COMBINED)**

* **ID:** EC\_NEGATIVE\_COMBINED\_001  
  * **Scenario Ref:** 2.B.3 (Using All Optional Parameters Simultaneously with Extreme Values)  
  * **Description:** ChatCompletionRequest with temperature:0.0, top\_p:0.0, max\_tokens:1, 4 stop sequences.  
  * **Test Data/Payload:** {"model":"\<chat\_model\_id\>", "messages": \[{"role":"user","content":"Generate"}\], "temperature":0.0, "top\_p":0.0, "max\_tokens":1, "stop":\["a","b","c","d"\]}  
  * **Prerequisites:** Valid API Key (inference scope), chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (or error from provider if combination is invalid for it).  
  * **Expected Behavior:** API accepts. LLM behavior specific.  
  * **Verification:** Check response, ensure API doesn't add its own error for this valid combination.

**Sub-Category: Image/File Data Content Edge Cases (EC\_NEGATIVE\_CONTENT)**

* **ID:** EC\_NEGATIVE\_CONTENT\_001  
  * **Scenario Ref:** 2.B.4 (Image/File Data Edge Cases)  
  * **Description:** ImageContentPart.image\_url.url with image/jpeg MIME type but base64 data is for a PNG.  
  * **Test Data/Payload:** (Craft such a data URI)  
  * **Prerequisites:** Valid API Key, multimodal\_chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (if LLM attempts to process) or error from LLM provider (e.g., "cannot decode image"), relayed by API.  
  * **Expected Behavior:** parse\_data\_uri succeeds. Problem is for LLM to handle. API relays outcome.  
* **ID:** EC\_NEGATIVE\_CONTENT\_002  
  * **Scenario Ref:** 2.B.4  
  * **Description:** FileContentPart.file.file\_data with base64 for a password-protected PDF.  
  * **Test Data/Payload:** (Base64 of a password-protected PDF)  
  * **Prerequisites:** Valid API Key, multimodal\_chat\_model\_id that supports PDF.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** Error from LLM provider (e.g., "cannot open encrypted file"), relayed by API (5xx or provider-specific 4xx).  
  * **Expected Behavior:** API relays provider error.

Sub-Category: Unexpected LLM Provider Responses (EC\_NEGATIVE\_PROVIDER)

(These require mocking the LLM provider's client call within the API's backend adapter)

* **ID:** EC\_NEGATIVE\_PROVIDER\_001  
  * **Scenario Ref:** 2.B.5 (Unexpected Downstream Behavior)  
  * **Description:** Mock LLM provider to return 200 OK but with a malformed JSON response (e.g., missing choices in chat).  
  * **Test Data/Payload:** Valid chat request.  
  * **Prerequisites:** Valid API Key. Mock the specific provider's response parsing point (e.g., inside BedRockBackend.invoke\_model before bedrock\_chat\_response\_to\_core).  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 500 Internal Server Error  
  * **Expected Response Body:** {"detail": "Internal Server Error", "request\_id": "\<uuid\>"}  
  * **Expected Behavior:** Adapter fails to parse provider response, leading to a generic 500 from the API.  
  * **Verification:** Check server logs for parsing error details and request\_id.
