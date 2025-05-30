# **Test Cases: Section 7.2 \- LLM-Specific Functional Testing**

This document outlines test cases for unique functional behaviors of LLMs, including token limit handling, streaming response validation (functional aspects beyond basic schema), and model-specific parameter behavior. This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_LLM\_...)  
* **Category Ref:** (e.g., FV\_LLM\_TOKEN, FV\_LLM\_STREAM\_FUNC, FV\_LLM\_PARAM\_BEHAVIOR)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** API interaction with LLM providers, focusing on how LLM characteristics are handled/exposed.  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** Valid API Key, specific model selection.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be.  
* **Verification Steps:** How to confirm the expected secure outcome.

## **1\. Token Limit Handling**

### **FV\_LLM\_TOKEN\_PROMPT\_EXCEEDS\_CTX\_001**

* **Category Ref:** FV\_LLM\_TOKEN  
* **Description:** Test API and LLM behavior when the input prompt's token count exceeds the model's context window.  
* **Exposure Point(s):** /chat/completions endpoint, LLM provider's context window limit.  
* **Test Method/Action:** Construct a prompt that is known to be larger than a specific model's context window (e.g., send 130,000 tokens to a model with a 128k context window). Make a POST request to /chat/completions.  
* **Prerequisites:** Valid API Key with models:inference scope. Knowledge of the target model's context window size.  
* **Expected Secure Outcome:** The API returns a 400 Bad Request (or similar 4xx, like 413 Payload Too Large, or 422 if caught by API validation) error with a clear message indicating the prompt exceeds the context window limit. The error should originate from the API framework or be a gracefully handled error from the provider.  
* **Verification Steps:**  
  * Assert HTTP status code is 400 (or other appropriate 4xx).  
  * Assert response JSON contains an error message like "Input too long", "Prompt exceeds context window limit", or similar.  
  * Ensure no unhandled 500 error.

### **FV\_LLM\_TOKEN\_MAXTOKENS\_RESPECTED\_001**

* **Category Ref:** FV\_LLM\_TOKEN  
* **Description:** Verify the max\_tokens parameter is respected by the LLM, limiting the length of the generated completion.  
* **Exposure Point(s):** /chat/completions endpoint, max\_tokens parameter.  
* **Test Method/Action:** Make a POST request to /chat/completions with a prompt that would normally generate a long response, but set max\_tokens to a small value (e.g., 10).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The API returns a 200 OK. The completion\_tokens in the usage object should be less than or equal to 10\. The finish\_reason in choices should be "length".  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert response.usage.completion\_tokens \<= 10\.  
  * Assert response.choices\[0\].finish\_reason \== "length".  
  * Assert the actual generated content response.choices\[0\].message.content is short (approximately 10 tokens).

### **FV\_LLM\_TOKEN\_MAXTOKENS\_IGNORED\_IF\_LARGER\_001**

* **Category Ref:** FV\_LLM\_TOKEN  
* **Description:** Verify behavior when max\_tokens is set to a value larger than what the model can/will produce for a given prompt before a natural stop.  
* **Exposure Point(s):** /chat/completions endpoint, max\_tokens parameter.  
* **Test Method/Action:** Make a POST request with a prompt that leads to a short natural response (e.g., "What is 2+2?"). Set max\_tokens to a large value (e.g., 1000).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The API returns a 200 OK. The generation stops naturally. completion\_tokens reflects the actual length. finish\_reason is "stop".  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert response.choices\[0\].finish\_reason \== "stop".  
  * Assert response.usage.completion\_tokens is a small number appropriate for the answer.

### **FV\_LLM\_TOKEN\_COUNT\_ACCURACY\_001**

* **Category Ref:** FV\_LLM\_TOKEN  
* **Description:** Basic check for token count accuracy in the usage object (non-streaming).  
* **Exposure Point(s):** usage object in /chat/completions response.  
* **Test Method/Action:** Send a request with a known simple prompt and observe prompt\_tokens, completion\_tokens, and total\_tokens.  
* **Prerequisites:** Valid API Key. A reference tokenizer for the model, if possible, or use very simple inputs.  
* **Expected Secure Outcome:** Token counts are reasonably accurate. total\_tokens \= prompt\_tokens \+ completion\_tokens.  
* **Verification Steps:**  
  * Compare prompt\_tokens to an expected value (e.g., from a local tokenizer or by provider documentation for simple cases).  
  * Compare completion\_tokens to the length of the generated text (rough validation).  
  * Assert total\_tokens \== prompt\_tokens \+ completion\_tokens.

## **2\. Streaming Response Validation (Functional Aspects)**

These tests focus on the functional behavior of streaming, beyond just SSE format and chunk schema.

### **FV\_LLM\_STREAM\_FUNC\_CONTENT\_ORDER\_001**

* **Category Ref:** FV\_LLM\_STREAM\_FUNC  
* **Description:** Verify that streamed content chunks arrive in the correct order and can be concatenated to form the complete message.  
* **Exposure Point(s):** /chat/completions streaming response.  
* **Test Method/Action:** Make a POST request with stream: true for a prompt expected to generate a multi-token response. Concatenate the delta.content from all chunks.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The concatenated content from stream chunks forms a coherent and complete response, matching what a non-streaming call for the same prompt (with temp=0) would produce.  
* **Verification Steps:**  
  * Collect all delta.content strings from the stream.  
  * Concatenate them in the order received.  
  * Optionally, make a non-streaming request with the same prompt and temperature: 0 (if model supports deterministic output).  
  * Compare the concatenated streamed content with the non-streamed content. They should be identical or very similar if temperature \> 0\.  
  * Ensure the reconstructed message is logical and not jumbled.

### **FV\_LLM\_STREAM\_FUNC\_FINISH\_REASON\_LAST\_CHUNK\_001**

* **Category Ref:** FV\_LLM\_STREAM\_FUNC  
* **Description:** In a stream, verify the finish\_reason is non-null in the chunk that completes a choice's generation, and null in preceding chunks for that choice.  
* **Exposure Point(s):** choices\[0\].finish\_reason in stream chunks (StreamResponseChoice.finish_reason).  
* **Test Method/Action:** Make a POST request with stream: true. Inspect finish\_reason in each chunk.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** For a given choice, finish\_reason is null for all chunks until the one that signals the end of content generation for that choice, where it becomes non-null (e.g., "stop", "length").  
* **Verification Steps:**  
  * Iterate through chunks.  
  * For choices\[0\], track finish\_reason. It should be null in initial/intermediate chunks.  
  * Identify the chunk where choices\[0\].finish\_reason becomes non-null. This should correspond to the end of content for that choice. Subsequent chunks for this choice (if any, e.g. empty delta with finish reason) should maintain or not contradict this.  
* **Code Reference:** app/providers/open_ai/schemas.py:318-321 defines StreamResponseChoice with finish_reason field.

### **FV\_LLM\_STREAM\_FUNC\_TOOL\_CALLS\_001**

* **Category Ref:** FV\_LLM\_STREAM\_FUNC  
* **Description:** Verify streaming behavior when the model decides to call tools.  
* **Exposure Point(s):** choices\[0\].delta.tool\_calls and finish\_reason in stream chunks.  
* **Test Method/Action:** Make a POST request with stream: true, a prompt, and tool definitions that are likely to trigger a tool call.  
* **Prerequisites:** Valid API Key with models:inference scope. Model supports tool calling.  
* **Expected Secure Outcome:** Stream chunks correctly build up the tool\_calls structure. The finish\_reason should eventually be "tool\_calls".  
* **Verification Steps:**  
  * Inspect delta.tool\_calls in chunks. It should progressively build the tool call information (id, type, function name, arguments).  
  * The chunk that completes the tool call decision should have finish\_reason: "tool\_calls".  
  * Concatenated/assembled tool call information should be valid.

## **3\. Model-Specific Behavior Validation**

### **FV\_LLM\_PARAM\_TEMP\_0\_DETERMINISM\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Test if temperature: 0 produces deterministic (or near-deterministic) output for a given model.  
* **Exposure Point(s):** /chat/completions endpoint, temperature parameter.  
* **Test Method/Action:** Make multiple (e.g., 3-5) identical POST requests to /chat/completions with the same prompt and temperature: 0\.  
* **Prerequisites:** Valid API Key with models:inference scope. Model that is expected to be deterministic at temp 0\.  
* **Expected Secure Outcome:** The choices\[0\].message.content should be identical (or highly similar, accounting for potential minor non-determinism in some models even at temp 0\) across all responses.  
* **Verification Steps:**  
  * Collect choices\[0\].message.content from each response.  
  * Compare them. They should be the same.

### **FV\_LLM\_PARAM\_TEMP\_HIGH\_VARIABILITY\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Test if a high temperature (e.g., 1.0 or 1.5, depending on model's supported range) produces varied outputs.  
* **Exposure Point(s):** /chat/completions endpoint, temperature parameter.  
* **Test Method/Action:** Make multiple (e.g., 3-5) identical POST requests with the same prompt and a high temperature value.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The choices\[0\].message.content should be different across the responses, showing creativity/randomness.  
* **Verification Steps:**  
  * Collect choices\[0\].message.content from each response.  
  * Compare them. They should be distinct.

### **FV\_LLM\_PARAM\_STOP\_SEQUENCE\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Test if the stop parameter (stop sequences) correctly halts generation when a sequence is encountered.  
* **Exposure Point(s):** /chat/completions endpoint, stop parameter.  
* **Test Method/Action:** Make a POST request with a prompt and a stop sequence that is likely to be generated by the model (e.g., stop: \["\\n"\] for a model generating line-by-line text).  
* **Prerequisites:** Valid API Key with models:inference scope. Model supports stop sequences.  
* **Expected Secure Outcome:** The generation stops when the stop sequence is first encountered. The stop sequence itself should not be part of choices\[0\].message.content. The finish\_reason should be "stop".  
* **Verification Steps:**  
  * Assert response.choices\[0\].finish\_reason \== "stop".  
  * Assert that response.choices\[0\].message.content does not contain the stop sequence.  
  * Verify that the content generated before the stop sequence is present.

### **FV\_LLM\_PARAM\_STOP\_SEQUENCE\_NOT\_FOUND\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Test behavior when a stop sequence is provided but not encountered in the generation (up to max\_tokens).  
* **Exposure Point(s):** /chat/completions endpoint, stop parameter.  
* **Test Method/Action:** Make a POST request with a prompt and a stop sequence that is very unlikely to be generated, and set max\_tokens to a reasonable limit.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Generation continues until max\_tokens is reached or a natural stop occurs. The finish\_reason will be "length" or "stop" (natural), not due to the provided unlikely stop sequence.  
* **Verification Steps:**  
  * Assert response.choices\[0\].finish\_reason is "length" or "stop".  
  * Assert response.choices\[0\].message.content does not prematurely stop due to the unlikely sequence.

### **FV\_LLM\_PARAM\_SYSTEM\_MESSAGE\_EFFECT\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Basic test for the effect of a system message on model behavior (e.g., persona, output format). This is qualitative.  
* **Exposure Point(s):** /chat/completions endpoint, messages with role: "system".  
* **Test Method/Action:**  
  1. Send a request with a user prompt.  
  2. Send another request with the same user prompt but preceded by a system message instructing a specific persona or output style (e.g., "You are a pirate.", "Respond in rhyme.").  
* **Prerequisites:** Valid API Key with models:inference scope. Model that respects system messages.  
* **Expected Secure Outcome:** The response from the second request should reflect the system message's instruction (e.g., pirate-speak, rhyming response), differing from the first response.  
* **Verification Steps:**  
  * Qualitatively compare the content of the two responses. The second response should show influence from the system message. This may require manual review or more sophisticated NLP checks for full automation.

## **4\. Additional Parameter Behavior Tests**

### **FV\_LLM\_PARAM\_TOP\_P\_EFFECT\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Test if top\_p parameter affects output diversity (nucleus sampling).  
* **Exposure Point(s):** /chat/completions endpoint, top\_p parameter.  
* **Test Method/Action:** Make multiple requests with the same prompt but different top\_p values (e.g., 0.1 vs 0.9) and compare output diversity.  
* **Prerequisites:** Valid API Key with models:inference scope. Model that supports top_p parameter.  
* **Expected Secure Outcome:** Lower top_p values (e.g., 0.1) should produce more focused/consistent outputs, while higher values (e.g., 0.9) should allow more diverse/creative responses.  
* **Verification Steps:** Compare response diversity across different top_p settings. Lower values should show less variation in multiple runs.  
* **Code Reference:** app/providers/open_ai/schemas.py:119-124 defines top_p with ge=0, le=1 constraints.

### **FV\_LLM\_PARAM\_PRESENCE\_PENALTY\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Test if presence\_penalty reduces repetition of topics/concepts.  
* **Exposure Point(s):** /chat/completions endpoint, presence\_penalty parameter.  
* **Test Method/Action:** Use a prompt likely to generate repetitive content. Compare responses with presence\_penalty: 0 vs presence\_penalty: 1.0.  
* **Prerequisites:** Valid API Key with models:inference scope. Model that supports presence_penalty.  
* **Expected Secure Outcome:** Higher presence_penalty should reduce repetitive content and encourage discussion of new topics.  
* **Verification Steps:** Analyze content for topic diversity and repetition patterns.  
* **Code Reference:** app/providers/open_ai/schemas.py:146-151 defines presence_penalty with ge=-2.0, le=2.0 constraints.

### **FV\_LLM\_PARAM\_FREQUENCY\_PENALTY\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Test if frequency\_penalty reduces repetition of specific tokens.  
* **Exposure Point(s):** /chat/completions endpoint, frequency\_penalty parameter.  
* **Test Method/Action:** Use a prompt that might generate repetitive phrases. Compare responses with frequency\_penalty: 0 vs frequency\_penalty: 1.0.  
* **Prerequisites:** Valid API Key with models:inference scope. Model that supports frequency_penalty.  
* **Expected Secure Outcome:** Higher frequency_penalty should reduce repetitive token usage and encourage more varied vocabulary.  
* **Verification Steps:** Analyze content for token-level repetition patterns.  
* **Code Reference:** app/providers/open_ai/schemas.py:153-158 defines frequency_penalty with ge=-2.0, le=2.0 constraints.

## **5\. Streaming SSE Format Validation**

### **FV\_LLM\_STREAM\_SSE\_FORMAT\_001**

* **Category Ref:** FV\_LLM\_STREAM\_FUNC  
* **Description:** Verify streaming response follows proper Server-Sent Events (SSE) format.  
* **Exposure Point(s):** /chat/completions streaming response format, Content-Type headers.  
* **Test Method/Action:** Make a POST request with stream: true and validate SSE format compliance.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Response should have Content-Type: text/event-stream, proper data: prefixes, and [DONE] termination.  
* **Verification Steps:**  
  * Assert Content-Type header is "text/event-stream"  
  * Verify each chunk starts with "data: " prefix  
  * Confirm stream ends with "data: [DONE]"  
  * Validate JSON parsing of each data chunk  
* **Code Reference:** app/routers/api_v1.py:43-49 implements StreamingResponse with proper headers.

### **FV\_LLM\_STREAM\_DELTA\_ACCUMULATION\_001**

* **Category Ref:** FV\_LLM\_STREAM\_FUNC  
* **Description:** Verify delta content properly accumulates to form complete message.  
* **Exposure Point(s):** StreamResponseDelta.content accumulation across chunks.  
* **Test Method/Action:** Stream a response and track delta.content accumulation for message reconstruction.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Delta content chunks should combine seamlessly to form coherent complete message.  
* **Verification Steps:**  
  * Collect all delta.content values from stream  
  * Concatenate in order received  
  * Verify resulting message is complete and coherent  
* **Code Reference:** app/providers/open_ai/schemas.py:313-316 defines StreamResponseDelta structure.

## **6\. Error Handling in LLM Interactions**

### **FV\_LLM\_ERROR\_PROVIDER\_FAILURE\_001**

* **Category Ref:** FV\_LLM\_TOKEN  
* **Description:** Test API behavior when LLM provider returns an error (e.g., rate limit, service unavailable).  
* **Exposure Point(s):** Provider error handling in app/routers/api_v1.py:52-59.  
* **Test Method/Action:** Simulate or trigger a provider error (rate limiting, invalid model parameters, etc.).  
* **Prerequisites:** Valid API Key. Ability to trigger provider errors or use invalid provider-specific parameters.  
* **Expected Secure Outcome:** API should return appropriate HTTP status code (400, 429, 502, 503) with user-friendly error message, not expose provider-specific error details.  
* **Verification Steps:** Assert proper HTTP status code and error message format. Verify no sensitive provider information is leaked.  
* **Code Reference:** app/routers/api_v1.py:55-59 handles InvalidInput exceptions, app/providers/exceptions.py defines error types.

### **FV\_LLM\_ERROR\_STREAMING\_INTERRUPTION\_001**

* **Category Ref:** FV\_LLM\_STREAM\_FUNC  
* **Description:** Test streaming response behavior when connection is interrupted or provider stream fails mid-response.  
* **Exposure Point(s):** Streaming response error handling and graceful termination.  
* **Test Method/Action:** Initiate streaming request and simulate connection interruption or provider stream failure.  
* **Prerequisites:** Valid API Key. Ability to simulate network interruptions or provider failures.  
* **Expected Secure Outcome:** API should handle interruptions gracefully, potentially with partial response and appropriate error signaling.  
* **Verification Steps:** Verify partial content is valid, appropriate error handling, no resource leaks.  
* **Code Reference:** app/routers/api_v1.py:42-50 implements streaming response handling.

## **7\. Provider-Specific Model Behavior**

### **FV\_LLM\_PROVIDER\_CONSISTENCY\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Compare parameter behavior consistency across different providers (Bedrock vs Vertex AI).  
* **Exposure Point(s):** Cross-provider parameter handling via adapter layers.  
* **Test Method/Action:** Use identical requests with same parameters across different providers and compare behavior patterns.  
* **Prerequisites:** Valid API Key. Access to models from multiple providers.  
* **Expected Secure Outcome:** Parameters should behave consistently across providers where supported, with clear documentation of any differences.  
* **Verification Steps:** Compare response characteristics (length, style, parameter effects) across providers.  
* **Code Reference:** app/providers/bedrock/adapter_from_core.py and app/providers/vertex_ai/adapter_from_core.py handle parameter translation.

### **FV\_LLM\_MODEL\_CAPABILITIES\_VALIDATION\_001**

* **Category Ref:** FV\_LLM\_PARAM\_BEHAVIOR  
* **Description:** Verify model capabilities match declared capabilities in backend configuration.  
* **Exposure Point(s):** Model capability declarations vs actual functionality.  
* **Test Method/Action:** For each model, test its declared capabilities (chat vs embedding) and verify functionality.  
* **Prerequisites:** Valid API Key. Access to models with different capabilities.  
* **Expected Secure Outcome:** Models should successfully perform operations matching their declared capabilities and fail appropriately for unsupported operations.  
* **Verification Steps:** Test chat models with /chat/completions (should work) and /embeddings (should fail with 422). Test embedding models with /embeddings (should work) and /chat/completions (should fail with 422).  
* **Code Reference:** app/providers/base.py:27 defines capability types, app/providers/dependencies.py:19-20 validates capability matching.