# **Test Cases: Section 7.2 \- Business Logic Validation**

This document outlines test cases for Internal API Logic and Provider Interaction as per the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_BLV\_...)  
* **Category Ref:** (e.g., FV\_BLV\_ROUTE, FV\_BLV\_CAPABILITY, FV\_BLV\_FAILOVER, FV\_BLV\_CONFIG)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** API internal logic, provider routing (app/providers/dependencies.py), model configuration (settings.backend\_map).  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** Valid API Key, specific model configurations in settings.backend\_map.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (e.g., "Request routed to Bedrock for Claude model").  
* **Verification Steps:** How to confirm the expected secure outcome (e.g., "Mock provider SDK to confirm it was called", "Inspect logs for routing information if available").

## **1\. Model Routing Validation**

### **FV\_BLV\_ROUTE\_BEDROCK\_001**

* **Category Ref:** FV\_BLV\_ROUTE  
* **Description:** Verify a request for a model configured for Bedrock (e.g., claude-3-5-sonnet-20240620) is routed to the Bedrock provider.  
* **Exposure Point(s):** get\_model\_config\_validated in app/providers/dependencies.py, settings.backend\_map.  
* **Test Method/Action:** Make a POST request to /chat/completions with model: "claude-3-5-sonnet-20240620" (assuming this ID is mapped to Bedrock in settings.backend\_map).  
* **Prerequisites:**  
  * Valid API Key with models:inference scope (corrected from models:chat).  
  * claude-3-5-sonnet-20240620 (or a similar Bedrock model ID) correctly configured in backend_map via BedRockBackend.models property with "chat" capability.  
  * Ability to mock/intercept calls to the Bedrock SDK or check logs that indicate provider selection.  
* **Expected Secure Outcome:** The request is processed by the BedRockBackend.  
* **Verification Steps:**  
  * If using mocks: Assert that the Bedrock client's converse or converse\_stream method was called.  
  * If checking logs: Verify logs show the request was routed to the Bedrock provider for the specified model.  
  * The API should return a 200 OK (assuming the Bedrock call itself is successful or mocked successfully).

### **FV\_BLV\_ROUTE\_VERTEXAI\_001**

* **Category Ref:** FV\_BLV\_ROUTE  
* **Description:** Verify a request for a model configured for Vertex AI (e.g., gemini-1.5-flash-001) is routed to the Vertex AI provider.  
* **Exposure Point(s):** get\_model\_config\_validated in app/providers/dependencies.py, settings.backend\_map.  
* **Test Method/Action:** Make a POST request to /chat/completions with model: "gemini-1.5-flash-001" (assuming this ID is mapped to Vertex AI).  
* **Prerequisites:**  
  * Valid API Key with models:chat scope.  
  * gemini-1.5-flash-001 (or a similar Vertex AI model ID) correctly configured in settings.backend\_map to use the "vertex\_ai" provider and has "chat" capability.  
  * Ability to mock/intercept calls to the Vertex AI SDK or check logs.  
* **Expected Secure Outcome:** The request is processed by the VertexBackend.  
* **Verification Steps:**  
  * If using mocks: Assert that the appropriate Vertex AI SDK method (e.g., generate\_content or stream\_generate\_content) was called.  
  * If checking logs: Verify logs show the request was routed to Vertex AI.  
  * The API should return a 200 OK.

### **FV\_BLV\_ROUTE\_OPENAI\_001**

* **Category Ref:** FV\_BLV\_ROUTE  
* **Description:** Verify a request for a model configured for OpenAI (e.g., gpt-4o) is routed to the OpenAI provider (if direct OpenAI integration exists and is configured).  
* **Exposure Point(s):** get\_model\_config\_validated in app/providers/dependencies.py, settings.backend\_map.  
* **Test Method/Action:** Make a POST request to /chat/completions with model: "gpt-4o" (assuming this ID is mapped to OpenAI).  
* **Prerequisites:**  
  * Valid API Key with models:chat scope.  
  * gpt-4o (or a similar OpenAI model ID) correctly configured in settings.backend\_map to use the "openai" provider and has "chat" capability.  
  * Ability to mock/intercept calls to the OpenAI SDK or check logs.  
* **Expected Secure Outcome:** The request is processed by the OpenAIBackend (or equivalent).  
* **Verification Steps:**  
  * If using mocks: Assert that the OpenAI SDK's chat.completions.create method was called.  
  * If checking logs: Verify logs show the request was routed to OpenAI.  
  * The API should return a 200 OK.

### **FV\_BLV\_ROUTE\_NONEXISTENT\_MODEL\_001**

* **Category Ref:** FV\_BLV\_CONFIG  
* **Description:** Test with a model ID that is not present in backend_map.  
* **Exposure Point(s):** Backend.__call__ method in app/providers/dependencies.py:12-22.  
* **Test Method/Action:** Make a POST request to /chat/completions with model: "non-existent-model-123".  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error with message "Model 'non-existent-model-123' is not supported by this API." (app/providers/dependencies.py:18).  
* **Verification Steps:** Assert HTTP status code is 422. Assert response JSON contains the exact error message from the Backend dependency.  
* **Code Reference:** app/providers/dependencies.py:15-18 handles missing model lookup in backend_map.

## **2\. Capability Matching Validation**

### **FV\_BLV\_CAPABILITY\_CHAT\_ON\_EMBED\_001**

* **Category Ref:** FV\_BLV\_CAPABILITY  
* **Description:** Attempt to use a chat-only model (e.g., claude-3-5-sonnet-20240620) with the /embeddings endpoint.  
* **Exposure Point(s):** Backend.__call__ capability check in app/providers/dependencies.py:19-20.  
* **Test Method/Action:** Make a POST request to /embeddings with model: "claude-3-5-sonnet-20240620" and valid embedding input.  
* **Prerequisites:**  
  * Valid API Key with models:embedding scope.  
  * claude-3-5-sonnet-20240620 configured in backend_map with "chat" capability but NOT "embedding".  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error with message "This endpoint not does support embedding with the model 'claude-3-5-sonnet-20240620'." (app/providers/dependencies.py:20).  
* **Verification Steps:** Assert HTTP status code is 422. Assert response JSON contains the exact capability mismatch error message.  
* **Code Reference:** app/providers/dependencies.py:19-20 checks model.capability against required capability, app/providers/base.py:27 defines capability as Literal['chat', 'embedding'].

### **FV\_BLV\_CAPABILITY\_EMBED\_ON\_CHAT\_001**

* **Category Ref:** FV\_BLV\_CAPABILITY  
* **Description:** Attempt to use an embedding-only model (e.g., cohere.embed-english-v3.0) with the /chat/completions endpoint.  
* **Exposure Point(s):** get\_model\_config\_validated in app/providers/dependencies.py.  
* **Test Method/Action:** Make a POST request to /chat/completions with model: "cohere.embed-english-v3.0" and a valid chat payload.  
* **Prerequisites:**  
  * Valid API Key with models:chat scope.  
  * cohere.embed-english-v3.0 configured in settings.backend\_map with "embed" capability but NOT "chat".  
* **Expected Secure Outcome:** API returns a 400 Bad Request or 405 Method Not Allowed error with a message indicating the model does not support the 'chat' capability.  
* **Verification Steps:** Assert HTTP status code (400 or 405). Assert response JSON contains an error message about model capability mismatch.

### **FV\_BLV\_CAPABILITY\_MODEL\_MISSING\_CAP\_001**

* **Category Ref:** FV\_BLV\_CONFIG  
* **Description:** Test with a model that is configured in settings.backend\_map but is missing the required capability for the endpoint (e.g., model has "embed" but /chat/completions is called).  
* **Exposure Point(s):** get\_model\_config\_validated logic.  
* **Test Method/Action:** Configure a model in backend\_map with only "other\_capability". Attempt to use it for /chat/completions.  
* **Prerequisites:** Valid API Key. Custom model configuration.  
* **Expected Secure Outcome:** API returns a 400 Bad Request or 405 Method Not Allowed error indicating capability mismatch.  
* **Verification Steps:** Assert HTTP status code and error message.

## **3\. Provider Configuration in backend\_map**

### **FV\_BLV\_CONFIG\_INVALID\_PROVIDER\_NAME\_001**

* **Category Ref:** FV\_BLV\_CONFIG  
* **Description:** Test with a model in settings.backend\_map that specifies an invalid/unknown provider\_name (e.g., "non\_existent\_provider").  
* **Exposure Point(s):** get\_llm\_provider in app/providers/dependencies.py (or similar logic that instantiates providers).  
* **Test Method/Action:** Configure a model in backend\_map with provider\_name: "invalid\_provider\_XYZ". Attempt to use this model via /chat/completions.  
* **Prerequisites:** Valid API Key. Custom model configuration.  
* **Expected Secure Outcome:** API returns a 500 Internal Server Error or a specific configuration error (e.g., 503 Service Unavailable if provider cannot be loaded) with a log message indicating an unknown provider. User-facing error should be generic.  
* **Verification Steps:** Assert HTTP status code (e.g., 500 or 503). Check server logs for an error message about the invalid provider name. Ensure no sensitive configuration details are leaked in the response.

### **FV\_BLV\_CONFIG\_MISSING\_PROVIDER\_DETAILS\_001**

* **Category Ref:** FV\_BLV\_CONFIG  
* **Description:** Test with a model in settings.backend\_map that is missing essential provider-specific details (e.g., aws\_region for Bedrock, project\_id for Vertex AI).  
* **Exposure Point(s):** Provider instantiation logic (e.g., BedRockBackend.\_\_init\_\_, VertexBackend.\_\_init\_\_).  
* **Test Method/Action:** Configure a Bedrock model in backend\_map but omit aws\_region. Attempt to use this model.  
* **Prerequisites:** Valid API Key. Custom model configuration.  
* **Expected Secure Outcome:** API returns a 500 Internal Server Error or 503 Service Unavailable. Logs should indicate missing configuration for the provider. User-facing error should be generic.  
* **Verification Steps:** Assert HTTP status code. Check server logs for errors related to missing provider configuration.

### **FV\_BLV\_CONFIG\_INCORRECT\_PROVIDER\_MODEL\_ID\_001**

* **Category Ref:** FV\_BLV\_CONFIG  
* **Description:** Test with a model in settings.backend\_map where the API's internal model ID is mapped to an incorrect or non-existent provider\_model\_id.  
* **Exposure Point(s):** Provider interaction logic (e.g., when BedRockBackend calls Bedrock with the provider\_model\_id).  
* **Test Method/Action:** Configure a model, e.g., my-chat-model, mapped to Bedrock with provider\_model\_id: "anthropic.claude-non-existent-vX". Attempt to use my-chat-model.  
* **Prerequisites:** Valid API Key. Custom model configuration.  
* **Expected Secure Outcome:** The API should gracefully handle the error from the provider SDK (e.g., model not found by provider). This should be translated into an appropriate API error response (e.g., 404, 400, or 502 Bad Gateway if the provider itself errors out due to this).  
* **Verification Steps:** Assert HTTP status code. Verify the error message indicates a problem with the model at the provider level, without leaking excessive detail.

## **4\. Fallback Logic (If Implemented \- Currently Not Explicit in Risk Analysis for 7.2)**

*(These are placeholders if fallback logic is introduced. The current risk analysis for 7.2 does not detail specific fallback mechanisms other than general provider integration.)*

### **FV\_BLV\_FAILOVER\_PRIMARY\_FAILS\_001 (Placeholder)**

* **Category Ref:** FV\_BLV\_FAILOVER  
* **Description:** Test primary provider failure and successful switch to backup provider.  
* **Exposure Point(s):** Provider interaction and failover logic.  
* **Test Method/Action:** Configure primary and backup providers. Simulate primary provider failure. Make a request.  
* **Prerequisites:** Configured failover. Ability to simulate provider failure.  
* **Expected Secure Outcome:** Request is successfully handled by the backup provider.  
* **Verification Steps:** Mock/verify backup provider was called. Response is successful.

## **5\. Rate Limiting (API-Level Functional Aspect \- If Implemented)**

*(These are placeholders if API-level rate limiting (beyond provider limits) is part of business logic. Test Plan Section 5.9.6 is referenced, but risk analysis for 7.2 doesn't detail this for business logic validation specifically.)*

### **FV\_BLV\_RATELIMIT\_ENFORCED\_001 (Placeholder)**

* **Category Ref:** FV\_BLV\_RATELIMIT  
* **Description:** Verify API-level rate limits are correctly enforced.  
* **Exposure Point(s):** Rate limiting middleware/logic.  
* **Test Method/Action:** Exceed configured rate limits for an API key.  
* **Prerequisites:** API-level rate limiting configured.  
* **Expected Secure Outcome:** API returns 429 Too Many Requests error after limit is breached.  
* **Verification Steps:** Observe responses, confirm 429 status after threshold.

## **6\. Backend Registration and Model Discovery**

### **FV\_BLV\_BACKEND\_REGISTRATION\_001**

* **Category Ref:** FV\_BLV\_CONFIG  
* **Description:** Verify that backend instances are properly registered and their models are discoverable via /models endpoint.  
* **Exposure Point(s):** app/config/settings.py:11-20 backend_instances registration and _backend_map population.  
* **Test Method/Action:** Make a GET request to /models endpoint and verify all registered models are returned.  
* **Prerequisites:** Valid API Key with any scope (no specific scope required for /models).  
* **Expected Secure Outcome:** API returns 200 OK with a list of all models from BedRockBackend.models and VertexBackend.models.  
* **Verification Steps:** Assert HTTP status code is 200. Verify response contains models from all registered backends. Compare with expected model IDs and capabilities.  
* **Code Reference:** app/config/settings.py:16-20 populates _backend_map from backend.models, app/routers/api_v1.py:25-30 implements /models endpoint.

### **FV\_BLV\_BACKEND\_MODEL\_MAPPING\_001**

* **Category Ref:** FV\_BLV\_CONFIG  
* **Description:** Verify that model ID mapping correctly associates each model with its backend instance.  
* **Exposure Point(s):** app/config/settings.py:18-20 backend registration loop creating _backend_map entries.  
* **Test Method/Action:** Iterate through all models from /models endpoint and verify each can be used for its declared capability.  
* **Prerequisites:** Valid API Key with appropriate scopes (models:inference, models:embedding).  
* **Expected Secure Outcome:** Each model works correctly with endpoints matching its capability (chat models with /chat/completions, embedding models with /embeddings).  
* **Verification Steps:** For each model from /models, make requests to appropriate endpoints and verify successful routing to correct backend.  
* **Code Reference:** app/config/settings.py:16-20 backend model registration, app/providers/dependencies.py:15-22 lookup and validation logic.

### **FV\_BLV\_CONCURRENT\_MODEL\_ACCESS\_001**

* **Category Ref:** FV\_BLV\_ROUTE  
* **Description:** Verify that concurrent requests to different models are properly routed to their respective backends.  
* **Exposure Point(s):** Backend dependency injection and model routing under concurrent load.  
* **Test Method/Action:** Make simultaneous requests to Bedrock and Vertex AI models (e.g., claude-3-5-sonnet and gemini-1.5-flash) concurrently.  
* **Prerequisites:** Valid API Keys, models from both Bedrock and Vertex AI configured.  
* **Expected Secure Outcome:** Both requests are processed successfully by their respective backends without interference.  
* **Verification Steps:** Assert both requests return 200 OK. Verify responses come from correct providers (can check via response characteristics or mocking). No request routing errors or provider confusion.  
* **Code Reference:** app/providers/dependencies.py:12-22 Backend dependency injection, app/config/settings.py:16-20 backend_map thread safety.

### **FV\_BLV\_INVALID\_CAPABILITY\_TYPE\_001**

* **Category Ref:** FV\_BLV\_CONFIG  
* **Description:** Test backend behavior when a model has an invalid capability type (not 'chat' or 'embedding').  
* **Exposure Point(s):** LLMModel capability validation and Backend capability checking.  
* **Test Method/Action:** If possible, mock or configure a model with capability: "invalid_capability" and attempt to use it.  
* **Prerequisites:** Ability to modify backend model configuration for testing.  
* **Expected Secure Outcome:** API should handle gracefully - either exclude invalid models from backend_map or return appropriate error when attempting to use.  
* **Verification Steps:** Verify system stability and appropriate error handling for invalid capability values.  
* **Code Reference:** app/providers/base.py:27 defines capability as Literal['chat', 'embedding'], app/providers/dependencies.py:19 capability comparison logic.