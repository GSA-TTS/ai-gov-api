# **Test Cases: Section 7.2 \- Response Quality Assessment (Basic Functional Checks)**

This document outlines test cases for automated, basic functional checks of LLM response quality. These are not deep semantic evaluations but focus on fundamental correctness and consistency. This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_RQA\_...)  
* **Category Ref:** (e.g., FV\_RQA\_BASIC, FV\_RQA\_FORMAT, FV\_RQA\_DETERMINISM, FV\_RQA\_PROVIDER\_CONSIST)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** LLM-generated content within API responses.  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** Valid API Key, specific prompts and model selection.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (e.g., "LLM response is non-empty").  
* **Verification Steps:** How to confirm the expected secure outcome.

## **1\. Basic Response Evaluation**

### **FV\_RQA\_BASIC\_NON\_EMPTY\_001**

* **Category Ref:** FV\_RQA\_BASIC  
* **Description:** Test that for a simple, well-defined prompt, the LLM returns non-empty content.  
* **Exposure Point(s):** /api/v1/chat/completions response choices\[0\].message.content.  
* **Test Method/Action:** Make a POST request to /api/v1/chat/completions with a simple prompt like "What is the capital of France?".  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** choices\[0\].message.content is not null and not an empty string.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert response.choices\[0\].message.content is not None.  
  * Assert len(response.choices\[0\].message.content.strip()) \> 0\.  
* **Code Reference:** ChatCompletionResponse schema in app/providers/open_ai/schemas.py:192-202, response content field validation.

### **FV\_RQA\_BASIC\_NO\_GIBBERISH\_SIMPLE\_001**

* **Category Ref:** FV\_RQA\_BASIC  
* **Description:** For a very simple factual prompt, check if the response is broadly relevant and not obvious gibberish (this is a loose check).  
* **Exposure Point(s):** /api/v1/chat/completions response choices\[0\].message.content.  
* **Test Method/Action:** Make a POST request to /api/v1/chat/completions with "What is 2+2?".  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Response content contains "4" or "four". It should not be a random string of characters or completely unrelated topic.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert response.choices\[0\].message.content contains the expected answer (e.g., "4").  
  * (Optionally) Check for absence of known error phrases like "I don't know" if the question is trivial for the model.  
* **Code Reference:** Response content validation through ChatCompletionResponseMessage schema in app/providers/open_ai/schemas.py:181-184.

## **2\. Output Variation & Determinism (Functional Check)**

### **FV\_RQA\_DETERMINISM\_TEMP\_0\_REPEAT\_001**

* **Category Ref:** FV\_RQA\_DETERMINISM (Same as FV\_LLM\_PARAM\_TEMP\_0\_DETERMINISM\_001 but framed from RQA perspective)  
* **Description:** Verify that temperature: 0 yields identical (or near-identical) responses for the same prompt, checking functional determinism.  
* **Exposure Point(s):** /api/v1/chat/completions response content, temperature parameter validation and provider behavior.  
* **Test Method/Action:** Make 3-5 identical POST requests with the same prompt and temperature: 0\.  
* **Prerequisites:** Valid API Key with models:inference scope. Model expected to be deterministic at temp 0\.  
* **Expected Secure Outcome:** All responses' choices\[0\].message.content are identical.  
* **Verification Steps:** Collect all response contents and assert they are equal.  
* **Code Reference:** Temperature parameter constraint in app/providers/open_ai/schemas.py:112-117 (ge=0, le=2), provider adaptation in bedrock/adapter_to_core.py and vertex_ai/adapter_to_core.py.

### **FV\_RQA\_DETERMINISM\_SEED\_EFFECT\_001 (Future Implementation)**

* **Category Ref:** FV\_RQA\_DETERMINISM  
* **Description:** Test seed parameter support for reproducible outputs when implemented in the API.  
* **Exposure Point(s):** /api/v1/chat/completions response content, seed parameter (not currently in ChatCompletionRequest schema).  
* **Test Method/Action:**  
  1. Make 2 requests with temperature: 0.7 and seed: 12345\.  
  2. Make 1 request with temperature: 0.7 and seed: 54321\.  
* **Prerequisites:** Valid API Key with models:inference scope. Future seed parameter implementation.  
* **Expected Secure Outcome:**  
  * The two responses from step 1 (same seed) should be identical.  
  * The response from step 2 (different seed) should be different from responses in step 1\.  
* **Verification Steps:** Compare choices\[0\].message.content across the requests as described.  
* **Code Reference:** ChatCompletionRequest schema in app/providers/open_ai/schemas.py:95-164 (seed parameter not currently implemented).  
* **Implementation Note:** Future enhancement - requires adding seed parameter to schema and provider adapters.

## **3\. Format Adherence (Simple Cases)**

### **FV\_RQA\_FORMAT\_LIST\_REQUEST\_001**

* **Category Ref:** FV\_RQA\_FORMAT  
* **Description:** If a prompt explicitly asks for a list (e.g., "List three primary colors"), check if the output loosely resembles a list.  
* **Exposure Point(s):** /api/v1/chat/completions response content.  
* **Test Method/Action:** Make a POST request to /api/v1/chat/completions with prompt: "List three primary colors. Start each color on a new line with a hyphen."  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The response content contains newline characters and hyphens, or other list-like formatting (e.g., numbered items). This is a heuristic check.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Inspect response.choices\[0\].message.content. Check for presence of patterns like \\n- or 1\. ... 2\. ....  
  * Check if known primary colors are mentioned.  
* **Code Reference:** Response content delivery through ChatCompletionResponseMessage.content in app/providers/open_ai/schemas.py:184.

### **FV\_RQA\_FORMAT\_JSON\_REQUEST\_001 (Model-dependent)**

* **Category Ref:** FV\_RQA\_FORMAT  
* **Description:** Test JSON format instruction following capability for models that support structured output.  
* **Exposure Point(s):** /api/v1/chat/completions response content, model-specific capabilities.  
* **Test Method/Action:** Make a POST request to /api/v1/chat/completions with a prompt like: "Provide user details as JSON: name John Doe, age 30."  
* **Prerequisites:** Valid API Key with models:inference scope. Model capable of generating structured JSON (model-dependent).  
* **Expected Secure Outcome:** choices\[0\].message.content is a string that can be successfully parsed as JSON. The JSON structure contains the requested fields.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Attempt to json.loads(response.choices\[0\].message.content). This should not raise an error.  
  * Assert the parsed JSON contains expected keys (e.g., "name", "age") and values.  
* **Code Reference:** Response content schema in app/providers/open_ai/schemas.py:184, no special JSON mode parameter in current schema.  
* **Implementation Note:** JSON mode parameter could be added to ChatCompletionRequest schema if supported by providers.

## **4\. Regression Detection (Functional \- Basic)**

These tests require a baseline of known good responses for specific simple prompts.

### **FV\_RQA\_REGRESSION\_SIMPLE\_FACT\_001**

* **Category Ref:** FV\_RQA\_BASIC (Regression aspect)  
* **Description:** For a very simple, unchanging factual prompt, ensure the model continues to answer it correctly over time/versions.  
* **Exposure Point(s):** /api/v1/chat/completions response content, model consistency over time.  
* **Test Method/Action:** Make a POST request to /api/v1/chat/completions with a fixed prompt like "What is the chemical symbol for water?". Compare response to a known good answer.  
* **Prerequisites:** Valid API Key with models:inference scope. A baseline "golden" response for this prompt/model combination.  
* **Expected Secure Outcome:** The response content contains "H2O".  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert response.choices\[0\].message.content contains "H2O" (or is substantially similar to the golden response, allowing for minor phrasing changes if temp \> 0).  
* **Code Reference:** Model routing through backend_map in app/config/settings.py:16-20, consistent response through provider adapters.

## **5\. Cross-Provider Consistency (Basic Functional Checks, if applicable)**

These tests apply if the same "generic" model ID might be routed to different providers, or if comparing functionally similar models across providers.

### **FV\_RQA\_PROVIDER\_CONSIST\_PARAM\_EFFECT\_001**

* **Category Ref:** FV\_RQA\_PROVIDER\_CONSIST  
* **Description:** For a common parameter like temperature: 0, check if its effect (determinism) is observed similarly across different providers for their respective models.  
* **Exposure Point(s):** /api/v1/chat/completions behavior with different provider backends through backend_map routing.  
* **Test Method/Action:**  
  1. Select a model from Provider A (e.g., Bedrock Claude) and a functionally similar model from Provider B (e.g., Vertex AI Gemini).  
  2. For each model, make 2-3 identical requests with the same simple prompt and temperature: 0\.  
* **Prerequisites:** Valid API Key with models:inference scope. Models configured for different providers in backend_map.  
* **Expected Secure Outcome:** For each provider, the multiple responses for its model should be identical (or near-identical). This tests if the temperature: 0 instruction is passed through and honored functionally.  
* **Verification Steps:**  
  * For Provider A's model: Assert its responses are identical to each other.  
  * For Provider B's model: Assert its responses are identical to each other.  
  * (Note: Responses *between* Provider A and Provider B will likely differ).  
* **Code Reference:** Provider routing in app/config/settings.py:16-20, temperature parameter adaptation in app/providers/bedrock/adapter_to_core.py and app/providers/vertex_ai/adapter_to_core.py.

### **FV\_RQA\_PROVIDER\_CONSIST\_ERROR\_HANDLING\_001**

* **Category Ref:** FV\_RQA\_PROVIDER\_CONSIST  
* **Description:** Test if a common invalid input results in consistent API error responses regardless of provider backend.  
* **Exposure Point(s):** API error handling consistency through FastAPI validation and provider adapter error handling.  
* **Test Method/Action:** Send an identical, clearly invalid request (e.g., invalid temperature value) targeting a model on Provider A, then the same invalid request targeting a model on Provider B.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Both requests should result in the same HTTP status code (e.g., 422\) and similarly structured error message, as Pydantic validation occurs before provider selection.  
* **Verification Steps:**  
  * Assert HTTP status code is identical for both.  
  * Assert error response structure is identical.  
  * If the error is provider-specific (e.g. model not found by provider), this test is more about the *translation* consistency covered in Multi-Provider Validation.  
* **Code Reference:** Pydantic validation in app/providers/open_ai/schemas.py:112-117, provider routing in app/providers/dependencies.py:12-22, error handling in app/routers/api_v1.py:55-59.

## **6\. Response Completeness and Consistency**

### **FV\_RQA\_RESPONSE\_USAGE\_POPULATED\_001**

* **Category Ref:** FV\_RQA\_BASIC  
* **Description:** Verify that response usage information is consistently populated with reasonable token counts.  
* **Exposure Point(s):** /api/v1/chat/completions response usage object.  
* **Test Method/Action:** Make a POST request to /api/v1/chat/completions with a moderate-length prompt.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** Response contains usage object with prompt_tokens, completion_tokens, and total_tokens. Token counts should be positive integers and total_tokens should equal sum of prompt and completion tokens.  
* **Verification Steps:**  
  * Assert response.usage is not None.  
  * Assert response.usage.prompt_tokens > 0.  
  * Assert response.usage.completion_tokens > 0.  
  * Assert response.usage.total_tokens == response.usage.prompt_tokens + response.usage.completion_tokens.  
* **Code Reference:** ChatCompletionUsage schema in app/providers/open_ai/schemas.py:175-179, token count validation.

### **FV\_RQA\_RESPONSE\_FINISH\_REASON\_POPULATED\_001**

* **Category Ref:** FV\_RQA\_BASIC  
* **Description:** Verify that finish_reason is appropriately populated in chat completion responses.  
* **Exposure Point(s):** /api/v1/chat/completions response choices[0].finish_reason.  
* **Test Method/Action:** Make various POST requests: normal completion, completion with low max_tokens limit.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** finish_reason should be populated with appropriate values ("stop" for normal completion, "length" for max_tokens limit reached).  
* **Verification Steps:**  
  * For normal completion: Assert response.choices[0].finish_reason == "stop".  
  * For max_tokens limited completion: Assert response.choices[0].finish_reason == "length".  
* **Code Reference:** ChatCompletionChoice schema with finish_reason in app/providers/open_ai/schemas.py:186-189.

### **FV\_RQA\_MULTIMODAL\_CONTENT\_HANDLING\_001**

* **Category Ref:** FV\_RQA\_FORMAT  
* **Description:** Test that multimodal inputs (text + images) produce appropriate responses when supported by the model.  
* **Exposure Point(s):** /api/v1/chat/completions with multimodal content in messages.  
* **Test Method/Action:** Make a POST request with a message containing both text and image content parts.  
* **Prerequisites:** Valid API Key with models:inference scope. Model that supports multimodal input. Valid base64 image data.  
* **Expected Secure Outcome:** Response should acknowledge both text and image content appropriately, demonstrating the model processed the multimodal input.  
* **Verification Steps:**  
  * Assert HTTP status code is 200.  
  * Verify response content references or describes elements from both text prompt and image.  
  * Ensure response is not generic error about unsupported content.  
* **Code Reference:** ContentPart union and multimodal schemas in app/providers/open_ai/schemas.py:66, ImageContentPart at app/providers/open_ai/schemas.py:59-64.

## **7\. Streaming Response Quality**

### **FV\_RQA\_STREAMING\_CONTENT\_COMPLETENESS\_001**

* **Category Ref:** FV\_RQA\_BASIC (Streaming)  
* **Description:** Verify that streaming responses deliver complete content when assembled from chunks.  
* **Exposure Point(s):** /api/v1/chat/completions with stream=true, Server-Sent Events response.  
* **Test Method/Action:** Make a streaming POST request and collect all delta content from the response chunks.  
* **Prerequisites:** Valid API Key with models:inference scope. SSE parsing capability.  
* **Expected Secure Outcome:** Assembled content from streaming chunks should form a coherent, complete response comparable to non-streaming mode.  
* **Verification Steps:**  
  * Collect all delta.content from streaming chunks.  
  * Concatenate to form full response.  
  * Verify final content is non-empty and coherent.  
  * Compare total token count with what would be expected from non-streaming equivalent.  
* **Code Reference:** Streaming response schemas in app/providers/open_ai/schemas.py:322-334, streaming implementation in app/routers/api_v1.py:41-50.

### **FV\_RQA\_STREAMING\_FINISH\_REASON\_FINAL\_001**

* **Category Ref:** FV\_RQA\_BASIC (Streaming)  
* **Description:** Verify that streaming responses include appropriate finish_reason in the final chunk.  
* **Exposure Point(s):** Final chunk in streaming /api/v1/chat/completions response.  
* **Test Method/Action:** Make a streaming POST request and examine the final chunk for finish_reason.  
* **Prerequisites:** Valid API Key with models:inference scope. SSE parsing capability.  
* **Expected Secure Outcome:** The final chunk should contain finish_reason with appropriate value ("stop", "length", etc.).  
* **Verification Steps:**  
  * Process streaming response until completion.  
  * Verify final chunk contains choices[0].finish_reason.  
  * Assert finish_reason is appropriate for completion type.  
* **Code Reference:** StreamResponseChoice schema in app/providers/open_ai/schemas.py:318-321, finish_reason handling in streaming responses.

## **8\. Error Response Quality**

### **FV\_RQA\_ERROR\_RESPONSE\_INFORMATIVENESS\_001**

* **Category Ref:** FV\_RQA\_BASIC (Error)  
* **Description:** Verify that error responses provide helpful information without exposing sensitive details.  
* **Exposure Point(s):** Error responses from /api/v1/chat/completions for various invalid inputs.  
* **Test Method/Action:** Trigger various errors: invalid temperature, missing required fields, malformed JSON.  
* **Prerequisites:** Ability to send malformed requests.  
* **Expected Secure Outcome:** Error responses should be informative enough for debugging but not expose internal system details or sensitive information.  
* **Verification Steps:**  
  * Verify error messages describe the issue clearly.  
  * Ensure error messages don't expose internal file paths, database details, or sensitive configuration.  
  * Check that Pydantic validation errors are appropriately formatted.  
* **Code Reference:** Error handling in app/routers/api_v1.py:55-59, FastAPI automatic validation error responses.

### **FV\_RQA\_PROVIDER\_ERROR\_TRANSLATION\_QUALITY\_001**

* **Category Ref:** FV\_RQA\_PROVIDER\_CONSIST (Error)  
* **Description:** Verify that provider-specific errors are translated into consistent, user-friendly API responses.  
* **Exposure Point(s):** Provider error handling and translation to consistent API error format.  
* **Test Method/Action:** Trigger provider-specific errors (e.g., model not available, quota exceeded) and verify error response quality.  
* **Prerequisites:** Valid API Key. Ability to trigger provider-specific errors.  
* **Expected Secure Outcome:** Provider errors should be translated into consistent API error format without exposing provider-specific internal details.  
* **Verification Steps:**  
  * Verify error responses follow consistent structure.  
  * Ensure provider-specific details are abstracted appropriately.  
  * Check that error messages are user-friendly and actionable.  
* **Code Reference:** Provider adapter error handling patterns, InvalidInput exception in app/providers/exceptions.py.