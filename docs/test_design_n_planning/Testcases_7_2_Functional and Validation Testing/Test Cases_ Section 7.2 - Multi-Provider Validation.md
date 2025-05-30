# **Test Cases: Section 7.2 \- Multi-Provider Validation**

This document outlines test cases for ensuring correct request translation and response normalization by adapter layers when interacting with different downstream LLM providers (Bedrock, Vertex AI). This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_MPV\_...)  
* **Category Ref:** (e.g., FV\_MPV\_REQ\_TRANSLATE, FV\_MPV\_RESP\_NORM, FV\_MPV\_FEATURE\_PARITY)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** Adapter layers in app/providers/{bedrock|vertex\_ai}/adapter\_\*.py.  
* **Test Method/Action:** How the test is performed (e.g., "Send core schema request, mock provider SDK, verify translated provider request").  
* **Prerequisites:** Valid API Key, model configurations for different providers, ability to mock provider SDKs and inspect calls.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (e.g., "Core ChatMessage correctly translated to Bedrock ConversationMessage format").  
* **Verification Steps:** How to confirm the expected secure outcome (e.g., "Assert fields in mocked provider request match expected translated values").

## **1\. Request Translation (Core Schema to Provider-Specific)**

These tests generally require mocking the downstream provider's SDK to intercept and inspect the request payload just before it's sent to the actual provider.

### **FV\_MPV\_REQ\_CHAT\_MSG\_ROLES\_BEDROCK\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify correct translation of message roles (user, assistant) from core schema to Bedrock's Converse API format.  
* **Exposure Point(s):** app/providers/bedrock/adapter\_from\_core.py (e.g., \_core\_messages\_to\_bedrock\_converse\_messages).  
* **Test Method/Action:**  
  1. Send a /chat/completions request with model configured for Bedrock (e.g., Claude 3.5 Sonnet via Converse API).  
  2. Include messages: \[{"role": "user", "content": "Hello"}, {"role": "assistant", "content": "Hi there\!"}, {"role": "user", "content": "How are you?"}\].  
  3. Mock the boto3.client("bedrock-runtime").converse() method.  
* **Prerequisites:** Valid API Key with models:inference scope. Bedrock model configured. Mocking capability for Boto3.  
* **Expected Secure Outcome:** The messages parameter passed to the mocked bedrock\_runtime.converse() method correctly reflects Bedrock's expected role structure (e.g., alternating user/assistant, or specific role strings like "user", "assistant").  
* **Verification Steps:**  
  * Inspect the messages argument in the mocked converse() call.  
  * Assert that the roles are translated as per Bedrock's requirements (e.g., {"role": "user", "content": \[...\]}).  
  * Assert content is preserved.  
* **Code Reference:** app/providers/bedrock/adapter_from_core.py message translation logic, app/config/settings.py:16-20 backend registration.

### **FV\_MPV\_REQ\_CHAT\_MSG\_ROLES\_VERTEXAI\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify correct translation of message roles (user, assistant, system) from core schema to Vertex AI Gemini API format.  
* **Exposure Point(s):** app/providers/vertex\_ai/adapter\_from\_core.py (e.g., \_core\_messages\_to\_vertex\_contents).  
* **Test Method/Action:**  
  1. Send a /chat/completions request with model configured for Vertex AI (e.g., Gemini).  
  2. Include messages: \[{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Hello"}, {"role": "assistant", "content": "Hi\!"}, {"role": "user", "content": "How are you?"}\].  
  3. Mock the Vertex AI SDK's GenerativeModel.generate\_content() or start\_chat().send\_message() method.  
* **Prerequisites:** Valid API Key with models:inference scope. Vertex AI model configured. Mocking capability for Vertex AI SDK.  
* **Expected Secure Outcome:** The contents and system\_instruction (if applicable) parameters passed to the mocked Vertex AI SDK method correctly reflect Gemini's structure (e.g., Part objects, role mapping).  
* **Verification Steps:**  
  * Inspect the arguments in the mocked Vertex AI call.  
  * Assert system message is correctly placed in system\_instruction (if used directly) or as a specific part of contents.  
  * Assert user/assistant messages are correctly translated to Content objects with appropriate role ("user", "model") and Part objects.  
* **Code Reference:** app/providers/vertex_ai/adapter_from_core.py message translation, app/providers/vertex_ai/vertexai.py Vertex backend implementation.

### **FV\_MPV\_REQ\_CHAT\_PARAMS\_BEDROCK\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify translation of common parameters like temperature, max\_tokens from core schema to Bedrock Converse API format.  
* **Exposure Point(s):** app/providers/bedrock/adapter\_from\_core.py.  
* **Test Method/Action:** Send /chat/completions request to a Bedrock model with temperature: 0.7, max\_tokens: 100\. Mock bedrock\_runtime.converse().  
* **Prerequisites:** Valid API Key with models:inference scope. Bedrock model. Mocking.  
* **Expected Secure Outcome:** The inferenceConfig (or similar) parameter in the mocked converse() call contains correctly mapped values for temperature and maxTokens.  
* **Verification Steps:**  
  * Inspect inferenceConfig in the mocked call.  
  * Assert inferenceConfig.temperature \== 0.7.  
  * Assert inferenceConfig.maxTokens \== 100\.  
  * Verify other parameters if set (e.g. topP, stopSequences).  
* **Code Reference:** Parameter mapping in app/providers/bedrock/adapter_from_core.py, Bedrock inference configuration.

### **FV\_MPV\_REQ\_CHAT\_PARAMS\_VERTEXAI\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify translation of temperature, max\_tokens, top\_p from core schema to Vertex AI Gemini API format.  
* **Exposure Point(s):** app/providers/vertex\_ai/adapter\_from\_core.py.  
* **Test Method/Action:** Send /chat/completions request to a Vertex AI model with temperature: 0.8, max\_tokens: 150, top\_p: 0.9. Mock Vertex AI SDK.  
* **Prerequisites:** Valid API Key with models:inference scope. Vertex AI model. Mocking.  
* **Expected Secure Outcome:** The generation\_config parameter in the mocked Vertex AI call contains correctly mapped values.  
* **Verification Steps:**  
  * Inspect generation\_config in the mocked call.  
  * Assert generation\_config.temperature \== 0.8.  
  * Assert generation\_config.max\_output\_tokens \== 150\.  
  * Assert generation\_config.top\_p \== 0.9.  
* **Code Reference:** Generation config mapping in app/providers/vertex_ai/adapter_from_core.py.

### **FV\_MPV\_REQ\_MULTIMODAL\_IMAGE\_BEDROCK\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify translation of image input (data URI) for a multimodal Bedrock model.  
* **Exposure Point(s):** app/providers/bedrock/adapter\_from\_core.py.  
* **Test Method/Action:** Send /chat/completions request to a multimodal Bedrock model (e.g., Claude 3.5 Sonnet) with a message containing an image data URI. Mock bedrock\_runtime.converse().  
* **Prerequisites:** Valid API Key with models:inference scope. Multimodal Bedrock model. Mocking.  
* **Expected Secure Outcome:** The image data is correctly formatted within the messages\[...\].content list for the Bedrock Converse API (e.g., as a content block with type: "image", source: {type: "base64", media\_type: "image/png", data: "..."}).  
* **Verification Steps:**  
  * Inspect the messages argument in the mocked converse() call.  
  * Find the image content block. Assert its type is "image".  
  * Assert source.type is "base64".  
  * Assert source.media\_type matches the input (e.g., "image/png").  
  * Assert source.data contains the correct base64 decoded image bytes.  
* **Code Reference:** Image content handling in app/providers/bedrock/adapter_from_core.py, data URI parsing in app/providers/utils.py.

### **FV\_MPV\_REQ\_MULTIMODAL\_IMAGE\_VERTEXAI\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify translation of image input (data URI) for a multimodal Vertex AI model (e.g., Gemini).  
* **Exposure Point(s):** app/providers/vertex\_ai/adapter\_from\_core.py.  
* **Test Method/Action:** Send /chat/completions request to a multimodal Vertex AI model with an image data URI. Mock Vertex AI SDK.  
* **Prerequisites:** Valid API Key with models:inference scope. Multimodal Vertex AI model. Mocking.  
* **Expected Secure Outcome:** The image data is correctly formatted within the contents\[...\].parts list for the Vertex AI Gemini API (e.g., as a Part with inline\_data containing mime\_type and data).  
* **Verification Steps:**  
  * Inspect the contents argument in the mocked Vertex AI call.  
  * Find the image part. Assert inline\_data.mime\_type matches.  
  * Assert inline\_data.data contains the correct base64 decoded image bytes.  
* **Code Reference:** Image part handling in app/providers/vertex_ai/adapter_from_core.py.

### **FV\_MPV\_REQ\_EMBED\_INPUT\_BEDROCK\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify translation of input string/list for Bedrock embedding models (e.g., Cohere, Titan).  
* **Exposure Point(s):** app/providers/bedrock/adapter\_from\_core.py.  
* **Test Method/Action:** Send /embeddings request to a Bedrock embedding model with input: "Test text" or input: \["Text 1", "Text 2"\]. Mock bedrock\_runtime.invoke\_model().  
* **Prerequisites:** Valid API Key with models:embedding scope. Bedrock embedding model. Mocking.  
* **Expected Secure Outcome:** The body passed to invoke\_model() is a JSON string matching the specific provider model's input schema (e.g., {"texts": \["..."\], "input\_type": "..."} for Cohere, or {"inputText": "..."} for Titan Text Embeddings G1).  
* **Verification Steps:**  
  * Parse the JSON body from the mocked invoke\_model() call.  
  * Assert fields and values match the target Bedrock model's schema.  
* **Code Reference:** Embedding request mapping in app/providers/bedrock/adapter_from_core.py, embedding schemas.

### **FV\_MPV\_REQ\_EMBED\_INPUT\_VERTEXAI\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify translation of input content/list for Vertex AI embedding models (e.g., text-embedding-gecko).  
* **Exposure Point(s):** app/providers/vertex\_ai/adapter\_from\_core.py.  
* **Test Method/Action:** Send /embeddings request to a Vertex AI embedding model with input: "Test text" or input: \["Text 1", "Text 2"\]. Mock Vertex AI SDK's get\_embeddings() method.  
* **Prerequisites:** Valid API Key with models:embedding scope. Vertex AI embedding model. Mocking.  
* **Expected Secure Outcome:** The instances (or equivalent) parameter passed to the mocked Vertex AI embedding call contains correctly formatted input(s) (e.g., list of objects with content field).  
* **Verification Steps:**  
  * Inspect the instances (or equivalent like content for EmbeddingPredictionClient.embed) in the mocked call.  
  * Assert format matches Vertex AI embedding model requirements.  
* **Code Reference:** Embedding translation in app/providers/vertex_ai/adapter_from_core.py.

## **2\. Response Normalization (Provider-Specific to Core Schema)**

These tests involve mocking the provider SDK to return a specific provider response, then verifying that the API endpoint returns a correctly normalized OpenAI-compatible response.

### **FV\_MPV\_RESP\_CHAT\_CONTENT\_BEDROCK\_001**

* **Category Ref:** FV\_MPV\_RESP\_NORM  
* **Description:** Verify normalization of Bedrock Converse API chat response (content, role, finish reason) to core schema.  
* **Exposure Point(s):** app/providers/bedrock/adapter\_to\_core.py (e.g., \_bedrock\_converse\_response\_to\_core\_chat).  
* **Test Method/Action:**  
  1. Mock bedrock\_runtime.converse() to return a sample Bedrock Converse API response (e.g., with output.message.content, stopReason).  
  2. Make a /chat/completions request to a Bedrock model.  
* **Prerequisites:** Valid API Key with models:inference scope. Bedrock model. Mocking.  
* **Expected Secure Outcome:** The API response matches ChatCompletionResponse schema, with fields like choices\[0\].message.content, choices\[0\].message.role ("assistant"), and choices\[0\].finish\_reason correctly mapped from the Bedrock response.  
* **Verification Steps:**  
  * Assert API response status 200\.  
  * Assert response.choices\[0\].message.content matches the content from the mocked Bedrock response.  
  * Assert response.choices\[0\].message.role \== "assistant".  
  * Assert response.choices\[0\].finish\_reason is correctly mapped (e.g., Bedrock "stop\_sequence" to OpenAI "stop", "max\_tokens" to "length").  
* **Code Reference:** Response normalization in app/providers/bedrock/adapter_to_core.py, ChatCompletionResponse schema in app/providers/open_ai/schemas.py.

### **FV\_MPV\_RESP\_CHAT\_CONTENT\_VERTEXAI\_001**

* **Category Ref:** FV\_MPV\_RESP\_NORM  
* **Description:** Verify normalization of Vertex AI Gemini API chat response (content, role, finish reason) to core schema.  
* **Exposure Point(s):** app/providers/vertex\_ai/adapter\_to\_core.py (e.g., \_vertex\_generate\_content\_response\_to\_core\_chat).  
* **Test Method/Action:** Mock Vertex AI SDK to return a sample Gemini API response (e.g., with candidates\[0\].content.parts\[0\].text, candidates\[0\].finish\_reason). Make a /chat/completions request.  
* **Prerequisites:** Valid API Key with models:inference scope. Vertex AI model. Mocking.  
* **Expected Secure Outcome:** The API response matches ChatCompletionResponse schema, with fields correctly mapped from the Vertex AI response.  
* **Verification Steps:**  
  * Assert API response status 200\.  
  * Assert response.choices\[0\].message.content matches.  
  * Assert response.choices\[0\].message.role \== "assistant".  
  * Assert response.choices\[0\].finish\_reason is correctly mapped (e.g., Vertex "STOP" to OpenAI "stop").  
* **Code Reference:** Response adaptation in app/providers/vertex_ai/adapter_to_core.py.

### **FV\_MPV\_RESP\_CHAT\_USAGE\_BEDROCK\_001**

* **Category Ref:** FV\_MPV\_RESP\_NORM  
* **Description:** Verify normalization of usage/token counts from Bedrock Converse API to core schema's usage object.  
* **Exposure Point(s):** app/providers/bedrock/adapter\_to\_core.py.  
* **Test Method/Action:** Mock bedrock\_runtime.converse() to return a response including usage (e.g., inputTokenCount, outputTokenCount). Make a /chat/completions request.  
* **Prerequisites:** Valid API Key with models:inference scope. Bedrock model. Mocking.  
* **Expected Secure Outcome:** API response's usage object has prompt\_tokens, completion\_tokens, total\_tokens correctly mapped from Bedrock's usage metrics.  
* **Verification Steps:**  
  * Assert response.usage.prompt\_tokens \== mocked\_bedrock\_response.usage.inputTokenCount.  
  * Assert response.usage.completion\_tokens \== mocked\_bedrock\_response.usage.outputTokenCount.  
  * Assert response.usage.total\_tokens is their sum.  
* **Code Reference:** Usage metric mapping in app/providers/bedrock/adapter_to_core.py.

### **FV\_MPV\_RESP\_CHAT\_USAGE\_VERTEXAI\_001**

* **Category Ref:** FV\_MPV\_RESP\_NORM  
* **Description:** Verify normalization of usage/token counts from Vertex AI Gemini API to core schema's usage object.  
* **Exposure Point(s):** app/providers/vertex\_ai/adapter\_to\_core.py.  
* **Test Method/Action:** Mock Vertex AI SDK to return a response including usage\_metadata (e.g., prompt\_token\_count, candidates\_token\_count). Make a /chat/completions request.  
* **Prerequisites:** Valid API Key with models:inference scope. Vertex AI model. Mocking.  
* **Expected Secure Outcome:** API response's usage object correctly reflects Vertex AI token counts.  
* **Verification Steps:**  
  * Assert response.usage.prompt\_tokens \== mocked\_vertex\_response.usage\_metadata.prompt\_token\_count.  
  * Assert response.usage.completion\_tokens \== mocked\_vertex\_response.usage\_metadata.candidates\_token\_count.  
  * Assert response.usage.total\_tokens is their sum.  
* **Code Reference:** Usage metadata handling in app/providers/vertex_ai/adapter_to_core.py.

### **FV\_MPV\_RESP\_EMBED\_VECTOR\_BEDROCK\_001**

* **Category Ref:** FV\_MPV\_RESP\_NORM  
* **Description:** Verify normalization of embedding vectors from a Bedrock embedding model response to core schema.  
* **Exposure Point(s):** app/providers/bedrock/adapter\_to\_core.py.  
* **Test Method/Action:** Mock bedrock\_runtime.invoke\_model() to return a sample Bedrock embedding response (e.g., Cohere {"embeddings": \[\[...\]\]}). Make an /embeddings request.  
* **Prerequisites:** Valid API Key with models:embedding scope. Bedrock embedding model. Mocking.  
* **Expected Secure Outcome:** API response's data\[0\].embedding contains the vector from the mocked Bedrock response.  
* **Verification Steps:**  
  * Assert response.data\[0\].embedding matches the vector in mocked\_bedrock\_response.embeddings\[0\].  
  * Assert response.object \== "list" and response.data\[0\].object \== "embedding".  
* **Code Reference:** Embedding response conversion in app/providers/bedrock/adapter_to_core.py, EmbeddingResponse schema.

### **FV\_MPV\_RESP\_EMBED\_VECTOR\_VERTEXAI\_001**

* **Category Ref:** FV\_MPV\_RESP\_NORM  
* **Description:** Verify normalization of embedding vectors from a Vertex AI embedding model response to core schema.  
* **Exposure Point(s):** app/providers/vertex\_ai/adapter\_to\_core.py.  
* **Test Method/Action:** Mock Vertex AI SDK's get\_embeddings() to return sample embeddings (predictions\[0\].embeddings.values). Make an /embeddings request.  
* **Prerequisites:** Valid API Key with models:embedding scope. Vertex AI embedding model. Mocking.  
* **Expected Secure Outcome:** API response's data\[0\].embedding contains the vector from the mocked Vertex AI response.  
* **Verification Steps:**  
  * Assert response.data\[0\].embedding matches mocked\_vertex\_response.predictions\[0\].embeddings.values.  
* **Code Reference:** Embedding vector extraction in app/providers/vertex_ai/adapter_to_core.py.

### **FV\_MPV\_RESP\_ERROR\_TRANSLATION\_BEDROCK\_001**

* **Category Ref:** FV\_MPV\_RESP\_NORM  
* **Description:** Verify that an error from Bedrock SDK (e.g., model access denied, validation error) is translated into an appropriate HTTP error by the API.  
* **Exposure Point(s):** Error handling in app/providers/bedrock/bedrock.py and its adapter.  
* **Test Method/Action:** Mock Bedrock SDK to raise a specific exception (e.g., botocore.exceptions.ClientError with a specific error code like AccessDeniedException or ValidationException). Make a request.  
* **Prerequisites:** Valid API Key with models:inference scope. Bedrock model. Mocking.  
* **Expected Secure Outcome:** API returns a mapped HTTP error (e.g., 403 for AccessDenied, 400/422 for ValidationException, 502/503 for service errors) with a generic, safe error message.  
* **Verification Steps:**  
  * Assert the HTTP status code is appropriate for the mocked provider error.  
  * Assert the response body contains a user-friendly error message and does not leak Bedrock-specific error details.  
  * Check server logs for the original Bedrock error.  
* **Code Reference:** Error handling in app/providers/bedrock/bedrock.py, app/providers/exceptions.py error definitions.

### **FV\_MPV\_RESP\_ERROR\_TRANSLATION\_VERTEXAI\_001**

* **Category Ref:** FV\_MPV\_RESP\_NORM  
* **Description:** Verify that an error from Vertex AI SDK (e.g., permission denied, invalid argument) is translated into an appropriate HTTP error by the API.  
* **Exposure Point(s):** Error handling in app/providers/vertex\_ai/vertexai.py and its adapter.  
* **Test Method/Action:** Mock Vertex AI SDK to raise a specific exception (e.g., google.api\_core.exceptions.PermissionDenied, google.api\_core.exceptions.InvalidArgument). Make a request.  
* **Prerequisites:** Valid API Key with models:inference scope. Vertex AI model. Mocking.  
* **Expected Secure Outcome:** API returns a mapped HTTP error (e.g., 403, 400/422) with a generic, safe error message.  
* **Verification Steps:**  
  * Assert HTTP status code.  
  * Assert safe error message in response.  
  * Check server logs for original Vertex AI error.  
* **Code Reference:** Error handling in app/providers/vertex_ai/vertexai.py.

## **3\. Feature Parity and Graceful Handling**

### **FV\_MPV\_FEATURE\_UNSUPPORTED\_PARAM\_001**

* **Category Ref:** FV\_MPV\_FEATURE\_PARITY  
* **Description:** Test behavior when a standard OpenAI parameter (e.g., logit\_bias) is sent, but the underlying provider (e.g., Bedrock Claude) does not support it.  
* **Exposure Point(s):** Adapter logic for parameter mapping.  
* **Test Method/Action:** Send a /chat/completions request to a Bedrock Claude model with logit\_bias: {"some\_token\_id": \-100}.  
* **Prerequisites:** Valid API Key with models:inference scope. Bedrock Claude model.  
* **Expected Secure Outcome:** The API should either:  
  1. Ignore the unsupported parameter and process the request successfully (logging a warning).  
  2. Return a 400/422 error indicating the parameter is not supported for this model/provider.  
     The behavior should be consistent and clearly documented.  
* **Verification Steps:**  
  * Observe API response (200 or 4xx).  
  * If 200, verify the LLM response is sensible and not negatively impacted. Check logs for warnings about the ignored parameter.  
  * If 4xx, verify the error message clearly states the parameter is unsupported.  
  * Ensure no 500 error due to unexpected parameter.  
* **Code Reference:** Parameter validation and mapping in adapter_from_core.py files.

### **FV\_MPV\_FEATURE\_STREAM\_CONSISTENCY\_001**

* **Category Ref:** FV\_MPV\_FEATURE\_PARITY  
* **Description:** Compare basic streaming behavior (chunk structure, DONE message) for a simple prompt across different providers (e.g., Bedrock vs. Vertex AI).  
* **Exposure Point(s):** Streaming adapters for Bedrock and Vertex AI.  
* **Test Method/Action:** Send the same simple prompt with stream: true to a Bedrock model and then to a Vertex AI model.  
* **Prerequisites:** Valid API Key with models:inference scope. Models configured for Bedrock and Vertex AI with chat capability.  
* **Expected Secure Outcome:** Both streams should adhere to the SSE format and ChatCompletionChunk schema for their data events. Both should terminate with data: \[DONE\]\\n\\n. (Content will differ, but structure should be consistent with OpenAI spec).  
* **Verification Steps:**  
  * For each provider's stream:  
    * Verify SSE format.  
    * Verify ChatCompletionChunk schema for data events.  
    * Verify \[DONE\] termination.  
  * Note any provider-specific nuances in optional fields (e.g., presence of usage in stream chunks).  
* **Code Reference:** Streaming implementations in app/routers/api_v1.py:41-50, provider streaming adapters.

## **4\. Model Configuration and Routing**

### **FV\_MPV\_MODEL\_SELECTION\_BEDROCK\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify that requests are correctly routed to Bedrock when using a Bedrock model ID.  
* **Exposure Point(s):** Model routing logic in app/providers/dependencies.py:12-22.  
* **Test Method/Action:** Send /chat/completions request with a Bedrock model ID, mock the Bedrock SDK.  
* **Prerequisites:** Valid API Key with models:inference scope. Bedrock model configured in backend_map.  
* **Expected Secure Outcome:** Request is routed to BedRockBackend instance, not VertexBackend.  
* **Verification Steps:**  
  * Verify mocked Bedrock SDK method is called.  
  * Verify Vertex AI SDK method is NOT called.  
  * Verify model capability validation (chat vs embedding).  
* **Code Reference:** Backend dependency injection in app/providers/dependencies.py, backend registration in app/config/settings.py:11-20.

### **FV\_MPV\_MODEL\_SELECTION\_VERTEXAI\_001**

* **Category Ref:** FV\_MPV\_REQ\_TRANSLATE  
* **Description:** Verify that requests are correctly routed to Vertex AI when using a Vertex AI model ID.  
* **Exposure Point(s):** Model routing logic in app/providers/dependencies.py.  
* **Test Method/Action:** Send /chat/completions request with a Vertex AI model ID, mock the Vertex AI SDK.  
* **Prerequisites:** Valid API Key with models:inference scope. Vertex AI model configured in backend_map.  
* **Expected Secure Outcome:** Request is routed to VertexBackend instance, not BedRockBackend.  
* **Verification Steps:**  
  * Verify mocked Vertex AI SDK method is called.  
  * Verify Bedrock SDK method is NOT called.  
  * Verify model capability validation.  
* **Code Reference:** Backend selection logic in app/providers/dependencies.py:15-19.

### **FV\_MPV\_MODEL\_UNSUPPORTED\_001**

* **Category Ref:** FV\_MPV\_FEATURE\_PARITY  
* **Description:** Test behavior when requesting an unsupported/non-existent model ID.  
* **Exposure Point(s):** Model validation in app/providers/dependencies.py.  
* **Test Method/Action:** Send request with model: "non-existent-model-id".  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns HTTP 422 with clear error message about unsupported model.  
* **Verification Steps:**  
  * Assert HTTP status code is 422\.  
  * Assert error message mentions the unsupported model ID.  
  * Verify no provider SDK calls are made.  
* **Code Reference:** Model validation in app/providers/dependencies.py:15-18.

### **FV\_MPV\_MODEL\_CAPABILITY\_MISMATCH\_001**

* **Category Ref:** FV\_MPV\_FEATURE\_PARITY  
* **Description:** Test behavior when using a chat model for embedding endpoint or vice versa.  
* **Exposure Point(s):** Capability validation in app/providers/dependencies.py:19-20.  
* **Test Method/Action:** Send /embeddings request using a chat-only model ID.  
* **Prerequisites:** Valid API Key with models:embedding scope. Chat model configured.  
* **Expected Secure Outcome:** API returns HTTP 422 with clear capability mismatch error.  
* **Verification Steps:**  
  * Assert HTTP status code is 422\.  
  * Assert error message mentions capability mismatch.  
  * Verify no provider SDK calls are made.  
* **Code Reference:** Capability check in app/providers/dependencies.py:19-20, model definitions in provider implementations.