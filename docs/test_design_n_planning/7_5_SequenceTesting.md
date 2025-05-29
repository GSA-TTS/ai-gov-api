# API Call Sequence Testing

This document outlines the approach to testing sequences of API calls for the AI API Framework, as referenced in section 7.5 of the [GSAi API Test Plan](https://docs.google.com/document/d/19_nlgUmNBrs9gKL8sIM8BDDABc6LkTqtLYwT7Aflfso/edit?usp=drive_link).

## 1\. Understand the Goal

The primary goal of API Call Sequence Testing is to validate that a series of API calls, when executed in a specific order, achieve an intended workflow or user scenario correctly. This type of testing is crucial for ensuring the integrated functionality of the system beyond individual component checks.

**Specific objectives include verifying:**

* **Stateful Simulation & Context Handling:** While REST APIs are generally stateless, sequences can simulate stateful interactions. For this API, this primarily involves:  
  * Passing conversational history (user and assistant messages) correctly between turns in a chat completion sequence to ensure models maintain context.  
  * Ensuring that system prompts, when provided, are consistently applied across a sequence of chat interactions.  
* **Workflow Integrity & Correctness:**  
  * Validating common user workflows, such as discovering available models and then successfully using a selected model for its intended capability (chat or embedding).  
  * Ensuring that negative workflows (e.g., attempting to use a model for an incompatible capability) are handled correctly with appropriate error responses at the correct step in the sequence.  
* **Data Consistency & Propagation:**  
  * Ensuring that identifiers or data retrieved from one API call (e.g., a model ID from `/models`) can be correctly used as input in a subsequent API call.  
* **Resource Lifecycle & Authorization Consistency (Conceptual & Actual):**  
  * Verifying that an API key's permissions (scopes) are consistently enforced across a sequence of different API calls. For example, a key with only 'chat' scope should succeed on the chat endpoint but fail on the embedding endpoint within the same logical user session.  
  * Ensuring that if a key's status were to change mid-sequence (e.g., hypothetically revoked), subsequent calls would fail appropriately. Note: This is conceptual for this API at this moment, as key creation/revocation is not via API endpoints.   
* **Correct Routing and Backend Interaction:**  
  * Confirming that sequential calls to different models, potentially handled by different backend providers (Bedrock, Vertex AI as per `app/config/settings.py`), are routed correctly without interference or incorrect state carry-over at the API gateway or adapter level.  
* **Billing Event Triggering:**  
  * Indirectly verifying that a sequence of successful, billable API operations correctly triggers the corresponding billing events (as logged by `app/services/billing.py`).

This testing is distinct from testing individual API calls in isolation (which focuses on the input/output of a single request) and instead focuses on the **combined behavior and end-to-end flow** of multiple, ordered interactions.

## 2\. Identify API Call Sequence Scenarios & Expected Outcomes

Based on the current API functionality (endpoints: `GET /api/v1/models`, `POST /api/v1/chat/completions`, `POST /api/v1/embeddings`) and the underlying system design, we can identify several logical sequences to test.

**Sources for Identification:**

* **API Endpoints:** The available operations in `app/routers/api_v1.py`.  
* **Authentication & Authorization Flow:** How API keys and scopes are used across requests (`app/auth/dependencies.py`, `app/auth/schemas.py`).  
* **Model Capabilities & Configuration:** The distinction between 'chat' and 'embedding' models and their mapping to backend providers (`app/config/settings.py`, `app/providers/base.py`, `app/providers/dependencies.py`).  
* **OpenAI API Parity:** The intended behavior of mimicking OpenAI's chat and embedding functionalities, including how conversational history is managed (`docs/adr/001_Open_AI_API.md`, `app/providers/open_ai/schemas.py`).  
* **Core Provider Adapters:** How requests are translated to and from the core schema for different backends (e.g., `app/providers/bedrock/adapter_from_core.py`, `app/providers/vertex_ai/adapter_from_core.py`).

### A. Model Discovery and Usage Sequence (Category: SEQ\_MODEL\_DISCOVERY)

*Purpose: To ensure users can reliably discover models and then use them for their advertised capabilities.*

* **SEQ\_MODEL\_DISCOVERY\_001: Discover and Use Chat Model**  
  * **Sequence:**  
    1. `GET /api/v1/models` (with a valid API key).  
    2. From the response, parse the list of models and identify a specific model ID that has `"capability": "chat"` (e.g., "claude\_3\_5\_sonnet" or "gemini-2.0-flash", assuming these are configured in `settings.backend_map`).  
    3. `POST /api/v1/chat/completions` using the identified chat model ID from step 2 and a simple, valid chat payload.  
  * **Purpose:** To verify that models advertised for "chat" are correctly listed, identifiable, and then usable via the `/chat/completions` endpoint, being routed to the appropriate backend.  
* **SEQ\_MODEL\_DISCOVERY\_002: Discover and Use Embedding Model**  
  * **Sequence:**  
    1. `GET /api/v1/models` (with a valid API key).  
    2. From the response, parse the list and identify a model ID with `"capability": "embedding"` (e.g., "cohere\_english\_v3" or "text-embedding-005", assuming configured).  
    3. `POST /api/v1/embeddings` using the identified embedding model ID from step 2 and a simple, valid embedding payload.  
  * **Purpose:** To verify that models advertised for "embedding" are correctly listed, identifiable, and then usable via the `/embeddings` endpoint, being routed to the appropriate backend.  
* **SEQ\_MODEL\_DISCOVERY\_003: Attempt to Use Chat Model for Embeddings (Negative Sequence)**  
  * **Sequence:**  
    1. `GET /api/v1/models` (with a valid API key).  
    2. From the response, identify a model ID with `"capability": "chat"`.  
    3. `POST /api/v1/embeddings` using the chat model ID identified in step 2 and a valid embedding payload.  
  * **Purpose:** To verify that the API's capability check (in `app/providers/dependencies.py`) correctly rejects using a chat-only model for an embedding task.  
* **SEQ\_MODEL\_DISCOVERY\_004: Attempt to Use Embedding Model for Chat (Negative Sequence)**  
  * **Sequence:**  
    1. `GET /api/v1/models` (with a valid API key).  
    2. From the response, identify a model ID with `"capability": "embedding"`.  
    3. `POST /api/v1/chat/completions` using the embedding model ID identified in step 2 and a valid chat payload.  
  * **Purpose:** To verify that the API's capability check correctly rejects using an embedding-only model for a chat task.

### B. Conversational Chat Sequence (Category: SEQ\_CONVERSATION)

*Purpose: To ensure the API correctly handles conversational context (history, system prompts) across multiple turns, as expected by the OpenAI API parity goal.*

* **SEQ\_CONVERSATION\_001: Basic Multi-Turn Conversation**  
  * **Sequence:**  
    1. `POST /api/v1/chat/completions` with `model: <chat_model_id>` and `messages: [{"role": "user", "content": "Hello, my name is Alex."}]`.  
    2. Extract the assistant's response content (e.g., `response_content_1`) from the previous call.  
    3. `POST /api/v1/chat/completions` with the same `model` and `messages: [{"role": "user", "content": "Hello, my name is Alex."}, {"role": "assistant", "content": "<response_content_1>"}, {"role": "user", "content": "What is my name?"}]`.  
  * **Purpose:** To verify that the API can pass conversational history (user and assistant turns) correctly to the backend model and that the model can utilize this context.  
* **SEQ\_CONVERSATION\_002: Conversation with System Prompt Maintained**  
  * **Sequence:**  
    1. `POST /api/v1/chat/completions` with `model: <chat_model_id>` and `messages: [{"role": "system", "content": "You are a helpful assistant that always responds in rhymes."}, {"role": "user", "content": "What is the weather like today?"}]`.  
    2. Extract the assistant's rhyming response (e.g., `rhyming_response_1`).  
    3. `POST /api/v1/chat/completions` with `model: <chat_model_id>` and `messages: [{"role": "system", "content": "You are a helpful assistant that always responds in rhymes."}, {"role": "user", "content": "What is the weather like today?"}, {"role": "assistant", "content": "<rhyming_response_1>"}, {"role": "user", "content": "What is your name?"}]`.  
  * **Purpose:** To verify that system prompts are correctly passed and maintained by the backend adapters (e.g., `adapter_from_core.py` for Bedrock/Vertex) and influence model behavior across multiple turns in a conversation.  
* **SEQ\_CONVERSATION\_003: Conversation with Image and Follow-up Text**  
  * **Prerequisites:** A chat model that supports image input (e.g., "gemini-2.0-flash" if configured for multimodal). A valid base64 encoded image.  
  * **Sequence:**  
    1. `POST /api/v1/chat/completions` with `model: <multimodal_chat_model_id>` and `messages: [{"role": "user", "content": [{"type": "text", "text": "What is in this image?"}, {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,<valid_base64_image_string>"}}]}]`.  
    2. Extract the assistant's description of the image (e.g., `image_description_1`).  
    3. `POST /api/v1/chat/completions` with the same `model` and `messages: [{"role": "user", "content": [{"type": "text", "text": "What is in this image?"}, {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,<valid_base64_image_string>"}}]}, {"role": "assistant", "content": "<image_description_1>"}, {"role": "user", "content": "Tell me more about the main subject you identified."}]`.  
  * **Purpose:** To verify handling of multimodal inputs in a conversational sequence, ensuring text and image context is passed and used.

### C. API Key Scope Usage Sequence (Category: SEQ\_AUTH\_SCOPE)

*Purpose: To ensure API key scopes are correctly enforced across a sequence of different operations.*

* **SEQ\_AUTH\_SCOPE\_001: Key with Chat Scope \- Chat Success, Embedding Fail**  
  * **Prerequisites:** An API key (`key_chat_only`) with only the `models:inference` scope. A configured chat model and a configured embedding model.  
  * **Sequence:**  
    1. `POST /api/v1/chat/completions` using `key_chat_only` and a valid chat payload.  
    2. `POST /api/v1/embeddings` using the same `key_chat_only` and a valid embedding payload.  
  * **Purpose:** To verify that a key restricted to chat operations succeeds on the chat endpoint but fails on the embedding endpoint.  
* **SEQ\_AUTH\_SCOPE\_002: Key with Embedding Scope \- Embedding Success, Chat Fail**  
  * **Prerequisites:** An API key (`key_embedding_only`) with only the `models:embedding` scope.  
  * **Sequence:**  
    1. `POST /api/v1/embeddings` using `key_embedding_only` and a valid embedding payload.  
    2. `POST /api/v1/chat/completions` using the same `key_embedding_only` and a valid chat payload.  
  * **Purpose:** To verify that a key restricted to embedding operations succeeds on the embedding endpoint but fails on the chat endpoint.  
* **SEQ\_AUTH\_SCOPE\_003: Key with No Specific Model Scopes \- Models List Success, Chat/Embedding Fail**  
  * **Prerequisites:** An API key (`key_no_model_scopes`) with no `models:inference` or `models:embedding` scopes (e.g., it might have `users:read` or be empty, but is otherwise valid, active, and non-expired).  
  * **Sequence:**  
    1. `GET /api/v1/models` using `key_no_model_scopes`.  
    2. `POST /api/v1/chat/completions` using `key_no_model_scopes` and a valid chat payload.  
    3. `POST /api/v1/embeddings` using `key_no_model_scopes` and a valid embedding payload.  
  * **Purpose:** To verify that the `/models` endpoint is accessible with any valid key, but specific operations still require their respective scopes.

### D. Sequential Use of Different Model Providers (Category: SEQ\_PROVIDER\_SWITCH)

*Purpose: To ensure the API correctly routes requests to different backend providers based on the `model_id` and that these interactions are independent.* *(This assumes models from different backends like Bedrock and Vertex are configured in `settings.backend_map` with distinct `id` values, e.g., `claude_3_5_sonnet` for Bedrock and `gemini-2.0-flash` for Vertex).*

* **SEQ\_PROVIDER\_SWITCH\_001: Chat with Bedrock Model then Vertex Model**  
  * **Prerequisites:** A valid API key with `models:inference` scope. Model `model_bedrock_chat` (e.g., "claude\_3\_5\_sonnet") is configured for Bedrock. Model `model_vertex_chat` (e.g., "gemini-2.0-flash") is configured for Vertex AI.  
  * **Sequence:**  
    1. `POST /api/v1/chat/completions` with `model: <model_bedrock_chat>` and a chat payload (e.g., `{"role": "user", "content": "Tell me about Bedrock."}`).  
    2. `POST /api/v1/chat/completions` with `model: <model_vertex_chat>` and a different chat payload (e.g., `{"role": "user", "content": "Tell me about Vertex AI."}`).  
  * **Purpose:** To ensure the API correctly routes to different backend providers based on the model ID and that there's no state interference or misconfiguration at the API gateway/adapter level between these calls.  
* **SEQ\_PROVIDER\_SWITCH\_002: Embedding with Bedrock Model then Vertex Model**  
  * **Prerequisites:** A valid API key with `models:embedding` scope. Model `model_bedrock_embed` (e.g., "cohere\_english\_v3") for Bedrock. Model `model_vertex_embed` (e.g., "text-embedding-005") for Vertex AI.  
  * **Sequence:**  
    1. `POST /api/v1/embeddings` with `model: <model_bedrock_embed>` and an embedding payload.  
    2. `POST /api/v1/embeddings` with `model: <model_vertex_embed>` and a different embedding payload.  
  * **Purpose:** Similar to above, but for embedding models and providers.

### E. Billing Service Interaction Sequence (Indirect Testing) (Category: SEQ\_BILLING)

*Purpose: To indirectly verify that billing events are queued for each successful billable operation in a sequence.*

* **SEQ\_BILLING\_001: Multiple Successful Calls Triggering Billing Events**  
  * **Prerequisites:** Valid API key with `models:inference` and `models:embedding` scopes. Configured chat and embedding models.  
  * **Sequence:**  
    1. `POST /api/v1/chat/completions` with `model: <chat_model_id_1>` and a valid payload.  
    2. `POST /api/v1/embeddings` with `model: <embedding_model_id>` and a valid payload.  
    3. `POST /api/v1/chat/completions` with `model: <chat_model_id_2>` (can be same or different from step 1\) and another valid payload.  
  * **Purpose:** To verify (conceptually, through logging) that each successful API interaction that is intended to be billable results in an event being sent to the billing queue (`app/services/billing.py`).

## 3\. Design Test Cases

This section details the specific test steps for each scenario identified in Section 2\. Each test case will include prerequisites, the sequence of API calls with expected status and key response elements for each step, and the overall expected outcome of the sequence.

* **General Test Case Components:**  
  * **ID:** Unique identifier (e.g., SEQ\_MODEL\_DISCOVERY\_001\_TC01)  
  * **Category Ref:** (e.g., SEQ\_MODEL\_DISCOVERY)  
  * **Scenario Ref:** (e.g., SEQ\_MODEL\_DISCOVERY\_001)  
  * **Description:** What this specific test case sequence verifies.  
  * **Prerequisites:**  
    * API Key(s) with specified scopes, active status, and expiration status.  
    * Specific models configured in `settings.backend_map` (e.g., "claude\_3\_5\_sonnet" as chat, "cohere\_english\_v3" as embedding).  
    * Any other necessary prior state or data (e.g., a valid base64 image string for multimodal tests).  
  * **Steps:**  
    1. **Call 1:**  
       * **Action:** HTTP Method & Endpoint (e.g., `GET /api/v1/models`)  
       * **Headers:** e.g., `{"Authorization": "Bearer <api_key_for_this_test>", "Content-Type": "application/json"}`  
       * **Body:** (if applicable) JSON payload.  
       * **Expected Status:** e.g., 200  
       * **Key Response Assertions:** e.g., "Response body is a list", "List contains model object with id 'claude\_3\_5\_sonnet' and capability 'chat'".  
       * **Data to Capture:** e.g., `chat_model_id = response.json()[<index_of_chat_model>]["id"]`.  
    2. **Call 2:**  
       * **Action:** HTTP Method & Endpoint (using data from Call 1 if needed).  
       * **Headers:** ...  
       * **Body:** ... (potentially using `chat_model_id` captured from Call 1).  
       * **Expected Status:** ...  
       * **Key Response Assertions:** ...  
       * **Data to Capture:** ...  
    3. **(And so on for subsequent calls in the sequence)**  
  * **Overall Expected Outcome for the Sequence:** A summary of what the entire sequence should achieve or demonstrate (e.g., "User successfully discovers a chat model and receives a valid chat completion using it.").  
  * **Verification Points (Beyond individual call assertions):**  
    * Check server logs for specific log messages (e.g., billing events, `request_id` tracing across sequence if applicable).  
    * Check database state changes if the sequence is expected to alter data (not typical for this API's current endpoints, but good to keep in mind for future features).

### A. Model Discovery and Usage Sequence (Category: SEQ\_MODEL\_DISCOVERY)

* **Test Case ID:** SEQ\_MODEL\_DISCOVERY\_001\_TC01  
    
  * **Category Ref:** SEQ\_MODEL\_DISCOVERY  
  * **Scenario Ref:** SEQ\_MODEL\_DISCOVERY\_001: Discover and Use Chat Model  
  * **Description:** Verifies a user can retrieve the list of models, identify a chat-capable model, and successfully get a chat completion from it.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_all_scopes`) with `models:inference` scope.  
    * At least one model with `"capability": "chat"` (e.g., "claude\_3\_5\_sonnet") is configured in `settings.backend_map`. Let this be `expected_chat_model_id`.  
  * **Steps:**  
    1. **Call 1: List Models**  
       * **Action:** `GET /api/v1/models`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>"}`  
       * **Body:** N/A  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Response is a JSON list. At least one object in the list has `"id": "<expected_chat_model_id>"` and `"capability": "chat"`.  
       * **Data to Capture:** `chat_model_id_from_list = <expected_chat_model_id>` (confirm it's present).  
    2. **Call 2: Use Chat Model**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id_from_list>", "messages": [{"role": "user", "content": "Hello test"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Response is a valid ChatCompletionResponse. `response.json()["model"] == "<chat_model_id_from_list>"`. `response.json()["choices"][0]["message"]["content"]` is not empty.  
  * **Overall Expected Outcome:** The sequence completes successfully, demonstrating the ability to discover and use a chat model.  
  * **Verification Points:** Server logs show a billing event for the chat completion.


* **Test Case ID:** SEQ\_MODEL\_DISCOVERY\_002\_TC01  
    
  * **Category Ref:** SEQ\_MODEL\_DISCOVERY  
  * **Scenario Ref:** SEQ\_MODEL\_DISCOVERY\_002: Discover and Use Embedding Model  
  * **Description:** Verifies a user can retrieve the list of models, identify an embedding-capable model, and successfully get embeddings from it.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_all_scopes`) with `models:embedding` scope.  
    * At least one model with `"capability": "embedding"` (e.g., "cohere\_english\_v3") is configured in `settings.backend_map`. Let this be `expected_embedding_model_id`.  
  * **Steps:**  
    1. **Call 1: List Models**  
       * **Action:** `GET /api/v1/models`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>"}`  
       * **Body:** N/A  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Response is a JSON list. At least one object in the list has `"id": "<expected_embedding_model_id>"` and `"capability": "embedding"`.  
       * **Data to Capture:** `embedding_model_id_from_list = <expected_embedding_model_id>` (confirm it's present).  
    2. **Call 2: Use Embedding Model**  
       * **Action:** `POST /api/v1/embeddings`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<embedding_model_id_from_list>", "input": "Test embedding text"}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Response is a valid EmbeddingResponse. `response.json()["model"] == "<embedding_model_id_from_list>"`. `response.json()["data"]` is a list containing at least one embedding object.  
  * **Overall Expected Outcome:** The sequence completes successfully, demonstrating the ability to discover and use an embedding model.  
  * **Verification Points:** Server logs show a billing event for the embedding request.


* **Test Case ID:** SEQ\_MODEL\_DISCOVERY\_003\_TC01  
    
  * **Category Ref:** SEQ\_MODEL\_DISCOVERY  
  * **Scenario Ref:** SEQ\_MODEL\_DISCOVERY\_003: Attempt to Use Chat Model for Embeddings  
  * **Description:** Verifies a 422 error when attempting to use a chat model for an embedding task.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_all_scopes`) with `models:embedding` scope (to ensure the failure is due to capability mismatch, not auth).  
    * A model with `"capability": "chat"` (e.g., "claude\_3\_5\_sonnet") is configured. Let this be `chat_model_id_for_test`.  
  * **Steps:**  
    1. **Call 1: List Models (Optional, can use known chat model ID)**  
       * **Action:** `GET /api/v1/models`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>"}`  
       * **Expected Status:** 200  
       * **Data to Capture:** Confirm `chat_model_id_for_test` is listed with "chat" capability.  
    2. **Call 2: Attempt Embedding with Chat Model**  
       * **Action:** `POST /api/v1/embeddings`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id_for_test>", "input": "Test text"}`  
       * **Expected Status:** 422  
       * **Key Response Assertions:** `response.json()["detail"] == "This endpoint not does support embedding with the model '<chat_model_id_for_test>'."`  
  * **Overall Expected Outcome:** The API correctly prevents misuse of a chat model for embeddings.  
  * **Verification Points:** No billing event should be logged for the failed embedding call.


* **Test Case ID:** SEQ\_MODEL\_DISCOVERY\_004\_TC01  
    
  * **Category Ref:** SEQ\_MODEL\_DISCOVERY  
  * **Scenario Ref:** SEQ\_MODEL\_DISCOVERY\_004: Attempt to Use Embedding Model for Chat  
  * **Description:** Verifies a 422 error when attempting to use an embedding model for a chat task.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_all_scopes`) with `models:inference` scope.  
    * A model with `"capability": "embedding"` (e.g., "cohere\_english\_v3") is configured. Let this be `embedding_model_id_for_test`.  
  * **Steps:**  
    1. **Call 1: List Models (Optional)**  
       * **Action:** `GET /api/v1/models`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>"}`  
       * **Expected Status:** 200  
       * **Data to Capture:** Confirm `embedding_model_id_for_test` is listed with "embedding" capability.  
    2. **Call 2: Attempt Chat with Embedding Model**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<embedding_model_id_for_test>", "messages": [{"role": "user", "content": "Hello"}]}`  
       * **Expected Status:** 422  
       * **Key Response Assertions:** `response.json()["detail"] == "This endpoint not does support chat with the model '<embedding_model_id_for_test>'."`  
  * **Overall Expected Outcome:** The API correctly prevents misuse of an embedding model for chat.  
  * **Verification Points:** No billing event should be logged for the failed chat call.

### B. Conversational Chat Sequence (Category: SEQ\_CONVERSATION)

* **Test Case ID:** SEQ\_CONVERSATION\_001\_TC01  
    
  * **Category Ref:** SEQ\_CONVERSATION  
  * **Scenario Ref:** SEQ\_CONVERSATION\_001: Basic Multi-Turn Conversation  
  * **Description:** Verifies context retention in a simple two-turn user-assistant-user conversation.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_inference`) with `models:inference` scope.  
    * A configured chat model (`chat_model_id`, e.g., "claude\_3\_5\_sonnet").  
  * **Steps:**  
    1. **Call 1: Initial User Message**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_inference>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id>", "messages": [{"role": "user", "content": "Hello, my name is Alex. What is your favorite color?"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid ChatCompletionResponse.  
       * **Data to Capture:** `assistant_response_1 = response.json()["choices"][0]["message"]["content"]`.  
    2. **Call 2: Follow-up User Message with History**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_inference>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id>", "messages": [{"role": "user", "content": "Hello, my name is Alex. What is your favorite color?"}, {"role": "assistant", "content": "<assistant_response_1>"}, {"role": "user", "content": "Remind me, what is my name?"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid ChatCompletionResponse. The content of `response.json()["choices"][0]["message"]["content"]` should ideally contain "Alex".  
  * **Overall Expected Outcome:** The model correctly recalls "Alex" from the conversational history.  
  * **Verification Points:** Billing events logged for both calls.


* **Test Case ID:** SEQ\_CONVERSATION\_002\_TC01  
    
  * **Category Ref:** SEQ\_CONVERSATION  
  * **Scenario Ref:** SEQ\_CONVERSATION\_002: Conversation with System Prompt Maintained  
  * **Description:** Verifies a system prompt's influence is maintained across multiple conversational turns.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_inference`) with `models:inference` scope.  
    * A configured chat model (`chat_model_id`).  
  * **Steps:**  
    1. **Call 1: User Message with System Prompt**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_inference>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id>", "messages": [{"role": "system", "content": "You are a cheerful assistant who loves to talk about cats and ends every sentence with 'meow'."}, {"role": "user", "content": "What is the capital of France?"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Response content should mention Paris, be cheerful, possibly mention cats, and end with "meow.".  
       * **Data to Capture:** `assistant_response_1 = response.json()["choices"][0]["message"]["content"]`.  
    2. **Call 2: Follow-up User Message with History and System Prompt**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_inference>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id>", "messages": [{"role": "system", "content": "You are a cheerful assistant who loves to talk about cats and ends every sentence with 'meow'."}, {"role": "user", "content": "What is the capital of France?"}, {"role": "assistant", "content": "<assistant_response_1>"}, {"role": "user", "content": "Do you like dogs?"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Response content should address dogs (likely negatively given the cat persona), be cheerful, and end with "meow.".  
  * **Overall Expected Outcome:** The system prompt's persona is consistently applied in both responses.  
  * **Verification Points:** Billing events logged for both calls.


* **Test Case ID:** SEQ\_CONVERSATION\_003\_TC01  
    
  * **Category Ref:** SEQ\_CONVERSATION  
  * **Scenario Ref:** SEQ\_CONVERSATION\_003: Conversation with Image and Follow-up Text  
  * **Description:** Verifies handling of multimodal inputs (image then text) in a conversational sequence.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_inference`) with `models:inference` scope.  
    * A configured multimodal chat model (`multimodal_chat_model_id`, e.g., "gemini-2.0-flash").  
    * A `valid_base64_image_string` (e.g., an image of a red apple).  
  * **Steps:**  
    1. **Call 1: User Message with Image and Text**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_inference>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<multimodal_chat_model_id>", "messages": [{"role": "user", "content": [{"type": "text", "text": "Describe this fruit."}, {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,<valid_base64_image_string_of_apple>"}}]}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Response content should describe an apple (e.g., "This is a red apple.").  
       * **Data to Capture:** `assistant_response_1 = response.json()["choices"][0]["message"]["content"]`.  
    2. **Call 2: Follow-up Text Question about the Image Content**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_inference>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<multimodal_chat_model_id>", "messages": [{"role": "user", "content": [{"type": "text", "text": "Describe this fruit."}, {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,<valid_base64_image_string_of_apple>"}}]}, {"role": "assistant", "content": "<assistant_response_1>"}, {"role": "user", "content": "What color did you say it was?"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Response content should mention "red", recalling the information from the image.  
  * **Overall Expected Outcome:** The model correctly processes the image and then answers a follow-up question based on its initial observation, demonstrating multimodal context retention.  
  * **Verification Points:** Billing events logged for both calls.

---

### C. API Key Scope Usage Sequence (Category: SEQ\_AUTH\_SCOPE)

* **Test Case ID:** SEQ\_AUTH\_SCOPE\_001\_TC01  
    
  * **Category Ref:** SEQ\_AUTH\_SCOPE  
  * **Scenario Ref:** SEQ\_AUTH\_SCOPE\_001: Key with Chat Scope \- Chat Success, Embedding Fail  
  * **Description:** Verifies a key with only `models:inference` scope can use chat but not embeddings.  
  * **Prerequisites:**  
    * API Key `key_chat_only` with `scopes=["models:inference"]`, active and not expired.  
    * Configured chat model (`chat_model_id`).  
    * Configured embedding model (`embedding_model_id`).  
  * **Steps:**  
    1. **Call 1: Chat Completion (Expected Success)**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <key_chat_only>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id>", "messages": [{"role": "user", "content": "Test chat"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid chat completion response.  
    2. **Call 2: Embeddings (Expected Fail)**  
       * **Action:** `POST /api/v1/embeddings`  
       * **Headers:** `{"Authorization": "Bearer <key_chat_only>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<embedding_model_id>", "input": "Test embedding"}`  
       * **Expected Status:** 401  
       * **Key Response Assertions:** `response.json()["detail"] == "Not Authorized"`.  
  * **Overall Expected Outcome:** Scope restriction is correctly enforced across the sequence.  
  * **Verification Points:** Billing event for Call 1, no billing event for Call 2\.


* **Test Case ID:** SEQ\_AUTH\_SCOPE\_002\_TC01  
    
  * **Category Ref:** SEQ\_AUTH\_SCOPE  
  * **Scenario Ref:** SEQ\_AUTH\_SCOPE\_002: Key with Embedding Scope \- Embedding Success, Chat Fail  
  * **Description:** Verifies a key with only `models:embedding` scope can use embeddings but not chat.  
  * **Prerequisites:**  
    * API Key `key_embedding_only` with `scopes=["models:embedding"]`, active and not expired.  
  * **Steps:**  
    1. **Call 1: Embeddings (Expected Success)**  
       * **Action:** `POST /api/v1/embeddings`  
       * **Headers:** `{"Authorization": "Bearer <key_embedding_only>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<embedding_model_id>", "input": "Test embedding"}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid embedding response.  
    2. **Call 2: Chat Completion (Expected Fail)**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <key_embedding_only>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id>", "messages": [{"role": "user", "content": "Test chat"}]}`  
       * **Expected Status:** 401  
       * **Key Response Assertions:** `response.json()["detail"] == "Not Authorized"`.  
  * **Overall Expected Outcome:** Scope restriction is correctly enforced.  
  * **Verification Points:** Billing event for Call 1, no billing event for Call 2\.


* **Test Case ID:** SEQ\_AUTH\_SCOPE\_003\_TC01  
    
  * **Category Ref:** SEQ\_AUTH\_SCOPE  
  * **Scenario Ref:** SEQ\_AUTH\_SCOPE\_003: Key with No Specific Model Scopes \- Models List Success, Chat/Embedding Fail  
  * **Description:** Verifies a key with no model-specific scopes can list models but cannot use chat or embedding endpoints.  
  * **Prerequisites:**  
    * API Key `key_no_model_scopes` with `scopes=[]` (or other non-model scopes like `users:read`), active and not expired.  
  * **Steps:**  
    1. **Call 1: List Models (Expected Success)**  
       * **Action:** `GET /api/v1/models`  
       * **Headers:** `{"Authorization": "Bearer <key_no_model_scopes>"}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Response is a valid list of models.  
    2. **Call 2: Chat Completion (Expected Fail)**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <key_no_model_scopes>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id>", "messages": [{"role": "user", "content": "Test chat"}]}`  
       * **Expected Status:** 401  
       * **Key Response Assertions:** `response.json()["detail"] == "Not Authorized"`.  
    3. **Call 3: Embeddings (Expected Fail)**  
       * **Action:** `POST /api/v1/embeddings`  
       * **Headers:** `{"Authorization": "Bearer <key_no_model_scopes>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<embedding_model_id>", "input": "Test embedding"}`  
       * **Expected Status:** 401  
       * **Key Response Assertions:** `response.json()["detail"] == "Not Authorized"`.  
  * **Overall Expected Outcome:** The `/models` endpoint is accessible, but scoped endpoints are correctly restricted.  
  * **Verification Points:** No billing events for Call 2 or Call 3\.

### D. Sequential Use of Different Model Providers (Category: SEQ\_PROVIDER\_SWITCH)

* **Test Case ID:** SEQ\_PROVIDER\_SWITCH\_001\_TC01  
    
  * **Category Ref:** SEQ\_PROVIDER\_SWITCH  
  * **Scenario Ref:** SEQ\_PROVIDER\_SWITCH\_001: Chat with Bedrock Model then Vertex Model  
  * **Description:** Verifies correct routing and independent processing when switching between chat models from different providers.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_inference`) with `models:inference` scope.  
    * Model `model_bedrock_chat` (e.g., "claude\_3\_5\_sonnet") configured for Bedrock.  
    * Model `model_vertex_chat` (e.g., "gemini-2.0-flash") configured for Vertex AI.  
  * **Steps:**  
    1. **Call 1: Chat with Bedrock Model**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_inference>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<model_bedrock_chat>", "messages": [{"role": "user", "content": "Response from Bedrock model?"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid ChatCompletionResponse. `response.json()["model"] == "<model_bedrock_chat>"`.  
       * **Data to Capture:** `response_content_bedrock = response.json()["choices"][0]["message"]["content"]`.  
    2. **Call 2: Chat with Vertex AI Model**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_inference>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<model_vertex_chat>", "messages": [{"role": "user", "content": "Response from Vertex AI model?"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid ChatCompletionResponse. `response.json()["model"] == "<model_vertex_chat>"`. `response.json()["choices"][0]["message"]["content"]` should be different from `response_content_bedrock` and characteristic of the Vertex model.  
  * **Overall Expected Outcome:** Both calls succeed independently, routed to their respective configured backends.  
  * **Verification Points:** Server logs show two billing events, potentially indicating different backend interactions if logging is detailed.


* **Test Case ID:** SEQ\_PROVIDER\_SWITCH\_002\_TC01  
    
  * **Category Ref:** SEQ\_PROVIDER\_SWITCH  
  * **Scenario Ref:** SEQ\_PROVIDER\_SWITCH\_002: Embedding with Bedrock Model then Vertex Model  
  * **Description:** Verifies correct routing and independent processing for embedding models from different providers.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_embedding`) with `models:embedding` scope.  
    * Model `model_bedrock_embed` (e.g., "cohere\_english\_v3") for Bedrock.  
    * Model `model_vertex_embed` (e.g., "text-embedding-005") for Vertex AI.  
  * **Steps:**  
    1. **Call 1: Embedding with Bedrock Model**  
       * **Action:** `POST /api/v1/embeddings`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_embedding>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<model_bedrock_embed>", "input": "Text for Bedrock embedding"}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid EmbeddingResponse. `response.json()["model"] == "<model_bedrock_embed>"`.  
       * **Data to Capture:** `embedding_vector_bedrock = response.json()["data"][0]["embedding"]`.  
    2. **Call 2: Embedding with Vertex AI Model**  
       * **Action:** `POST /api/v1/embeddings`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_embedding>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<model_vertex_embed>", "input": "Text for Vertex AI embedding"}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid EmbeddingResponse. `response.json()["model"] == "<model_vertex_embed>"`. `response.json()["data"][0]["embedding"]` should likely be different from `embedding_vector_bedrock`.  
  * **Overall Expected Outcome:** Both embedding calls succeed independently, routed to their respective backends.  
  * **Verification Points:** Server logs show two billing events.

### E. Billing Service Interaction Sequence (Indirect Testing) (Category: SEQ\_BILLING)

* **Test Case ID:** SEQ\_BILLING\_001\_TC01  
  * **Category Ref:** SEQ\_BILLING  
  * **Scenario Ref:** SEQ\_BILLING\_001: Multiple Successful Calls Triggering Billing Events  
  * **Description:** Indirectly verifies that a sequence of successful, distinct API calls results in corresponding billing events being logged.  
  * **Prerequisites:**  
    * A valid, active, non-expired API key (`valid_api_key_all_scopes`) with `models:inference` and `models:embedding` scopes.  
    * Configured chat model `chat_model_id_1` (e.g., "claude\_3\_5\_sonnet").  
    * Configured embedding model `embedding_model_id` (e.g., "cohere\_english\_v3").  
    * Configured chat model `chat_model_id_2` (e.g., "gemini-2.0-flash", can be different or same as `chat_model_id_1`).  
    * Access to server logs to verify billing messages.  
  * **Steps:**  
    1. **Call 1: Chat Completion 1**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id_1>", "messages": [{"role": "user", "content": "Billing test call 1"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid ChatCompletionResponse.  
       * **Data to Capture:** `usage1 = response.json()["usage"]`.  
    2. **Call 2: Embedding**  
       * **Action:** `POST /api/v1/embeddings`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<embedding_model_id>", "input": "Billing test input 2"}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid EmbeddingResponse.  
       * **Data to Capture:** `usage2 = response.json()["usage"]`.  
    3. **Call 3: Chat Completion 2**  
       * **Action:** `POST /api/v1/chat/completions`  
       * **Headers:** `{"Authorization": "Bearer <valid_api_key_all_scopes>", "Content-Type": "application/json"}`  
       * **Body:** `{"model": "<chat_model_id_2>", "messages": [{"role": "user", "content": "Billing test call 3"}]}`  
       * **Expected Status:** 200  
       * **Key Response Assertions:** Valid ChatCompletionResponse.  
       * **Data to Capture:** `usage3 = response.json()["usage"]`.  
  * **Overall Expected Outcome:** All three API calls succeed.  
  * **Verification Points:**  
    * Server logs (from `app/services/billing.py`'s `billing_worker`) must show three distinct log entries with the message "billing".  
    * The logged `billing_data` for the first call should include details matching `chat_model_id_1` and `usage1`.  
    * The logged `billing_data` for the second call should include details matching `embedding_model_id` and `usage2`.  
    * The logged `billing_data` for the third call should include details matching `chat_model_id_2` and `usage3`.  
    * (If API key/user ID is part of billing data, verify that too).

---
