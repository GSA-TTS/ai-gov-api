# Error Code Validation

This document outlines the steps to effectively test and validate error codes and error handling mechanisms for the GSAi API Framework, as specified in section 7.5 of [GSAi API Test Plan](https://docs.google.com/document/d/19_nlgUmNBrs9gKL8sIM8BDDABc6LkTqtLYwT7Aflfso/edit?usp=drive_link) .

## 1\. Understand the Goal

The primary goal of "Error Code Validation" is to ensure that the API responds with accurate, standardized, and informative HTTP status codes and error messages when various error conditions occur. This helps client applications and developers understand and handle issues gracefully.

## 2\. Identify Error Scenarios & Expected Outcomes

This section aims to comprehensively list all potential error scenarios. Each scenario should define the expected HTTP status code and the structure/content of the error response body.

**Sources for Identification:**

* **API Specification:** The API is based on the OpenAI Chat Completions API and embedding API (refer to `docs/adr/001_Open_AI_API.md`).  
* **Codebase Review (Key Files):**  
  * **Authentication (`app/auth/dependencies.py`):**  
    * **Missing API Key:** If the `Authorization` header is missing or not in `Bearer <token>` format, FastAPI's `HTTPBearer` dependency will likely raise an error.  
    * **Invalid API Key Format (within `credentials.credentials`):** If the token itself is malformed before hashing. (This might be caught by string expectations or length, but the primary check is post-hash).  
    * **Non-existent API Key (Valid format, but hash not in DB):** `APIKeyRepository.get_by_api_key_value` returns `None`.  
    * **Inactive API Key (`api_key.is_active` is `False`)**  
    * **Expired API Key (`api_key.expires_at` is in the past):**  
    * **API Key with Insufficient Scope (`RequiresScope` dependency):** The key is valid, active, and not expired, but lacks the necessary scopes for the endpoint.  
  * **Input Validation (Pydantic Schemas & Routers \- `app/providers/open_ai/schemas.py`, `app/providers/core/chat_schema.py`, `app/providers/core/embed_schema.py`, `app/routers/api_v1.py`):**  
    * **Invalid Request Body Structure (FastAPI's Pydantic Validation)**  
    * **Custom Input Validation (`InputDataError` in `app/routers/api_v1.py`)**  
  * **Provider/Model Validation (`app/providers/dependencies.py`):**  
    * **Requesting an Unsupported `model_id`:** The `model_id` in the request payload is not found in `settings.backend_map`.  
    * **Requesting a Model for an Incompatible Capability:** The requested `model_id` exists, but its `capability` (e.g., "chat") does not match the endpoint's required capability (e.g., "embedding").  
  * **General HTTP Errors (FastAPI defaults or custom handlers):**  
    * **Resource Not Found (Incorrect Endpoint Path):** E.g., `/api/v1/nonexistent_endpoint`.  
    * **Method Not Allowed:** E.g., sending a GET request to `/api/v1/chat/completions` (which is POST only).  
  * **Server-Side Errors & Downstream Issues:**  
    * **Unhandled Exceptions (`app/main.py` generic exception handler):** Any Python exception not caught by more specific handlers during request processing.  
    * **Database Errors (`app/db/session.py`):** If `get_db_session` fails to connect or if SQLAlchemy operations within repositories (`app/auth/repositories.py`, `app/users/repositories.py`) raise exceptions (e.g., connection errors, integrity errors not caught).  
    * **Downstream Provider Errors (e.g., Bedrock, Vertex AI in `app/providers/bedrock/bedrock.py`, `app/providers/vertex_ai/vertexai.py`):**  
    * **Billing Service Errors (`app/services/billing.py`):** If the `billing_queue.put()` operation fails (e.g., queue full, though unlikely with `asyncio.Queue` default).

**Expected Response Body Structure Summary:**

* **400 Bad Request (Custom `InputDataError`):** `{"error": "Bad Request", "message": "<specific_message>", "field": "<optional_field_name>"}` (as per `app/routers/api_v1.py`).  
* **401 Unauthorized (Custom Auth Logic):** `{"detail": "<specific_auth_failure_message>"}` (as per `app/auth/dependencies.py`).  
* **401/403 Unauthorized (FastAPI `HTTPBearer`):** `{"detail": "Not authenticated"}` or `{"detail": "Invalid authentication credentials"}`.  
* **404 Not Found (FastAPI Default):** `{"detail": "Not Found"}`.  
* **405 Method Not Allowed (FastAPI Default):** `{"detail": "Method Not Allowed"}`.  
* **422 Unprocessable Entity (FastAPI Pydantic Validation):** `{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}`.  
* **422 Unprocessable Entity (Custom Provider/Model Validation):** `{"detail": "<specific_model_error_message>"}` (as per `app/providers/dependencies.py`).  
* **500 Internal Server Error (Generic Handler):** `{"detail": "Internal Server Error", "request_id": "<uuid_from_StructlogMiddleware>"}` (as per `app/main.py`).  
* **Key Principle:** Ensure error messages are clear, concise, provide a `request_id` where applicable (especially for 5xx errors), and **do not leak sensitive information** (e.g., raw exception messages, stack traces, internal configurations, database details).

## 3\. Design Test Cases

For each identified error scenario, design specific test cases. Test cases should be categorized based on the type of error they are designed to trigger.

* **Test Case Components (General):**  
  * **ID:** Unique identifier (e.g., ECV\_AUTH\_001).  
  * **Category:** The main error category this test case falls under.  
  * **Description:** What specific error condition is being tested.  
  * **Prerequisites:** Any setup required (e.g., specific API key state like expired, inactive, or with specific scopes).  
  * **Request Details:** Endpoint, HTTP Method, Headers, Request Body, Query Parameters.  
  * **Expected HTTP Status Code:** (e.g., 401, 400, 422, 500).  
  * **Expected Response Body:** Key fields, specific error messages, absence of sensitive information.

**Main Test Case Categories:**

1. ### Authentication and Authorization Error Test Cases (Category: ECV\_AUTH)

   

   * **Description:** These test cases focus on verifying the API's response to various authentication and authorization failures related to API keys. This includes scenarios like missing, malformed, invalid, inactive, expired keys, and keys with insufficient scopes.  
   * **Test Cases:**  
     * **ECV\_AUTH\_001: Missing Authorization Header**  
       * **Description:** Verify API response when the `Authorization` header is completely missing.  
       * **Prerequisites:** API is running.  
       * **Request Details (Example for `/api/v1/models`):**  
         * Endpoint: `/api/v1/models`  
         * Method: GET  
         * Headers: `{}` (No Authorization header)  
         * Body: N/A  
       * **Expected Status Code:** 401 (or 403 depending on FastAPI's `HTTPBearer` strictness, typically 401 if `valid_api_key` is not even reached due to `Depends(security)`)  
       * **Expected Response Body:** `{"detail": "Not authenticated"}`  
     * **ECV\_AUTH\_002: Malformed Authorization Header (No Bearer Scheme)**  
       * **Description:** Verify API response when `Authorization` header is present but doesn't use the "Bearer" scheme.  
       * **Prerequisites:** API is running.  
       * **Request Details (Example for `/api/v1/models`):**  
         * Endpoint: `/api/v1/models`  
         * Method: GET  
         * Headers: `{"Authorization": "InvalidScheme some_token"}`  
         * Body: N/A  
       * **Expected Status Code:** 401 (or 403\)  
       * **Expected Response Body:** `{"detail": "Not authenticated"}` or `{"detail": "Invalid authentication credentials"}`  
     * **ECV\_AUTH\_003: Malformed Authorization Header (Missing Token)**  
       * **Description:** Verify API response when `Authorization` header has "Bearer" but no token.  
       * **Prerequisites:** API is running.  
       * **Request Details (Example for `/api/v1/models`):**  
         * Endpoint: `/api/v1/models`  
         * Method: GET  
         * Headers: `{"Authorization": "Bearer "}`  
         * Body: N/A  
       * **Expected Status Code:** 401 (or 403\)  
       * **Expected Response Body:** `{"detail": "Not authenticated"}` or `{"detail": "Invalid authentication credentials"}`  
     * **ECV\_AUTH\_004: Non-existent API Key**  
       * **Description:** Verify API response when a syntactically valid but non-existent API key is provided.  
       * **Prerequisites:** API is running. The provided key's hash does not exist in the `api_keys` table.  
       * **Request Details (Example for `/api/v1/models`):**  
         * Endpoint: `/api/v1/models`  
         * Method: GET  
         * Headers: `{"Authorization": "Bearer test_prefix_thisKeyDoesNotExistInDB123abc"}`  
         * Body: N/A  
       * **Expected Status Code:** 401  
       * **Expected Response Body:** `{"detail": "Missing or invalid API key"}`  
     * **ECV\_AUTH\_005: Inactive API Key**  
       * **Description:** Verify API response when a valid API key is provided, but its `is_active` flag is `False` in the database.  
       * **Prerequisites:** API is running. An API key exists with `is_active = False`.  
       * **Request Details (Example for `/api/v1/models`):**  
         * Endpoint: `/api/v1/models`  
         * Method: GET  
         * Headers: `{"Authorization": "Bearer <inactive_api_key_string>"}`  
         * Body: N/A  
       * **Expected Status Code:** 401  
       * **Expected Response Body:** `{"detail": "Missing or invalid API key"}`  
     * **ECV\_AUTH\_006: Expired API Key**  
       * **Description:** Verify API response when a valid API key is provided, but its `expires_at` timestamp is in the past.  
       * **Prerequisites:** API is running. An API key exists with `is_active = True` and `expires_at` \< current time.  
       * **Request Details (Example for `/api/v1/models`):**  
         * Endpoint: `/api/v1/models`  
         * Method: GET  
         * Headers: `{"Authorization": "Bearer <expired_api_key_string>"}`  
         * Body: N/A  
       * **Expected Status Code:** 401  
       * **Expected Response Body:** `{"detail": "API key is expired"}`  
     * **ECV\_AUTH\_007: Insufficient Scope for `/api/v1/chat/completions`**  
       * **Description:** Verify API response when a valid, active, non-expired API key is used but lacks the `models:inference` scope.  
       * **Prerequisites:** API is running. An API key exists with scopes that *do not* include `models:inference` (e.g., only `models:embedding` or no scopes).  
       * **Request Details:**  
         * Endpoint: `/api/v1/chat/completions`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <key_without_inference_scope>", "Content-Type": "application/json"}`  
         * Body: `{"model": "claude_3_5_sonnet", "messages": [{"role": "user", "content": "Hello"}]}` (or any valid model from `settings.backend_map` with "chat" capability)  
       * **Expected Status Code:** 401  
       * **Expected Response Body:** `{"detail": "Not Authorized"}`  
     * **ECV\_AUTH\_008: Insufficient Scope for `/api/v1/embeddings`**  
       * **Description:** Verify API response when a valid, active, non-expired API key is used but lacks the `models:embedding` scope.  
       * **Prerequisites:** API is running. An API key exists with scopes that *do not* include `models:embedding` (e.g., only `models:inference` or no scopes).  
       * **Request Details:**  
         * Endpoint: `/api/v1/embeddings`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <key_without_embedding_scope>", "Content-Type": "application/json"}`  
         * Body: `{"model": "cohere_english_v3", "input": "test"}` (or any valid model from `settings.backend_map` with "embedding" capability)  
       * **Expected Status Code:** 401  
       * **Expected Response Body:** `{"detail": "Not Authorized"}`  
     * **ECV\_AUTH\_009: Valid Key with All Necessary Scopes for `/api/v1/chat/completions` (Positive Test)**  
       * **Description:** Verify successful access when a valid key with `models:inference` scope is used.  
       * **Prerequisites:** API is running. An API key exists with `models:inference` scope.  
       * **Request Details:**  
         * Endpoint: `/api/v1/chat/completions`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <key_with_inference_scope>", "Content-Type": "application/json"}`  
         * Body: `{"model": "claude_3_5_sonnet", "messages": [{"role": "user", "content": "Hello"}]}`  
       * **Expected Status Code:** 200 (or other success code depending on model interaction)  
       * **Expected Response Body:** Valid chat completion response.  
     * **ECV\_AUTH\_010: Valid Key with All Necessary Scopes for `/api/v1/embeddings` (Positive Test)**  
       * **Description:** Verify successful access when a valid key with `models:embedding` scope is used.  
       * **Prerequisites:** API is running. An API key exists with `models:embedding` scope.  
       * **Request Details:**  
         * Endpoint: `/api/v1/embeddings`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <key_with_embedding_scope>", "Content-Type": "application/json"}`  
         * Body: `{"model": "cohere_english_v3", "input": "test"}`  
       * **Expected Status Code:** 200 (or other success code)  
       * **Expected Response Body:** Valid embedding response.  
     * **ECV\_AUTH\_011: Valid Key with No Scopes for `/api/v1/chat/completions`**  
       * **Description:** Test if a key with an empty scope list is denied access to a scoped endpoint.  
       * **Prerequisites:** API is running. An API key exists with `scopes = []`.  
       * **Request Details:**  
         * Endpoint: `/api/v1/chat/completions`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <key_with_no_scopes>", "Content-Type": "application/json"}`  
         * Body: `{"model": "claude_3_5_sonnet", "messages": [{"role": "user", "content": "Hello"}]}`  
       * **Expected Status Code:** 401  
       * **Expected Response Body:** `{"detail": "Not Authorized"}`  
     * **ECV\_AUTH\_012: Valid Key with Irrelevant Scopes for `/api/v1/chat/completions`**  
       * **Description:** Test if a key with scopes not matching the required `models:inference` is denied.  
       * **Prerequisites:** API is running. An API key exists with scopes like `["users:read"]`.  
       * **Request Details:**  
         * Endpoint: `/api/v1/chat/completions`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <key_with_irrelevant_scopes>", "Content-Type": "application/json"}`  
         * Body: `{"model": "claude_3_5_sonnet", "messages": [{"role": "user", "content": "Hello"}]}`  
       * **Expected Status Code:** 401  
       * **Expected Response Body:** `{"detail": "Not Authorized"}`  
     * **ECV\_AUTH\_013: Accessing `/api/v1/models` with a key that has no specific scopes (should pass if `valid_api_key` is the only dependency)**  
       * **Description:** The `/models` endpoint only depends on `valid_api_key`, not `RequiresScope`.  
       * **Prerequisites:** API is running. A valid, active, non-expired API key exists, even with an empty scope list.  
       * **Request Details:**  
         * Endpoint: `/api/v1/models`  
         * Method: GET  
         * Headers: `{"Authorization": "Bearer <valid_key_any_scope_or_no_scope>"}`  
       * **Expected Status Code:** 200  
       * **Expected Response Body:** List of models.

   

2. ### Request Input Validation Error Test Cases (Category: ECV\_INPUT)

   

   * **Description:** These test cases aim to validate how the API handles invalid or malformed request payloads. This covers errors detected by FastAPI's Pydantic model validation and custom input validation logic.  
   * **Sub-Category: Pydantic Validation \- `/api/v1/chat/completions`**  
     * **ECV\_INPUT\_CHAT\_001: Missing `model` field**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"messages": [{"role": "user", "content": "Hello"}]}`  
       * Expected Status: 422, Expected Body: `{"detail": [{"loc": ["body", "model"], "msg": "Field required", "type": "missing"}]}` (or similar Pydantic error)  
     * **ECV\_INPUT\_CHAT\_002: Missing `messages` field**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet"}`  
       * Expected Status: 422, Expected Body: `{"detail": [{"loc": ["body", "messages"], "msg": "Field required", "type": "missing"}]}`  
     * **ECV\_INPUT\_CHAT\_003: `messages` as empty list**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": []}`  
       * Expected Status: 422 (Pydantic might require min\_items=1 for `messages` if specified, otherwise this might pass initial validation but fail later)  
     * **ECV\_INPUT\_CHAT\_004: `messages` with invalid role**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [{"role": "invalid_role", "content": "Hello"}]}`  
       * Expected Status: 422, Expected Body: `{"detail": [{"loc": ["body", "messages", 0, "role"], "msg": "Input tag 'invalid_role' found using 'role' does not match any of the expected tags: 'user', 'system', 'assistant'", "type": "literal_error"}]}` (or similar)  
     * **ECV\_INPUT\_CHAT\_005: `messages` item missing `content`**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [{"role": "user"}]}`  
       * Expected Status: 422, Expected Body: `{"detail": [{"loc": ["body", "messages", 0, "content"], "msg": "Field required", "type": "missing"}]}`  
     * **ECV\_INPUT\_CHAT\_006: Invalid `temperature` type**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [...], "temperature": "hot"}`  
       * Expected Status: 422, Expected Body: `{"detail": [{"loc": ["body", "temperature"], "msg": "Input should be a valid number", "type": "float_parsing"}]}`  
     * **ECV\_INPUT\_CHAT\_007: `temperature` out of range (too low)**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [...], "temperature": -1.0}`  
       * Expected Status: 422, Expected Body: `{"detail": [{"loc": ["body", "temperature"], "msg": "Input should be greater than or equal to 0", "type": "greater_than_equal"}]}`  
     * **ECV\_INPUT\_CHAT\_008: `temperature` out of range (too high)**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [...], "temperature": 3.0}`  
       * Expected Status: 422, Expected Body: `{"detail": [{"loc": ["body", "temperature"], "msg": "Input should be less than or equal to 2", "type": "less_than_equal"}]}`  
     * **ECV\_INPUT\_CHAT\_009: Invalid `top_p` type**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [...], "top_p": "one"}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_010: `top_p` out of range**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [...], "top_p": 1.5}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_011: Invalid `max_tokens` type**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [...], "max_tokens": "many"}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_012: Invalid `stream` type**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [...], "stream": "yes"}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_013: Invalid `stop` type (not string or list)**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "claude_3_5_sonnet", "messages": [...], "stop": 123}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_014: Invalid `ImageContentPart` \- missing `image_url`**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": [{"type": "image_url"}]}]}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_015: Invalid `ImageContentPart` \- missing `image_url.url`**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"detail": "auto"}}]}]}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_016: Invalid `ImageContentPart` \- invalid `image_url.detail` enum**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "data:...", "detail": "very_high"}}]}]}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_017: Invalid `FileContentPart` \- missing `file`**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": [{"type": "file"}]}]}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_018: Invalid `FileContentPart` \- missing `file.file_data`**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": [{"type": "file", "file": {}}]}]}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_CHAT\_019: Invalid `FileContentPart` \- `file.file_data` not base64**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": [{"type": "file", "file": {"file_data": "not base64 at all"}}]}]}`  
       * Expected Status: 422 (Pydantic `Base64Bytes` validation)  
   * **Sub-Category: Pydantic Validation \- `/api/v1/embeddings`**  
     * **ECV\_INPUT\_EMBED\_001: Missing `model` field**  
       * Request: `POST /api/v1/embeddings`, Body: `{"input": "test"}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_EMBED\_002: Missing `input` field**  
       * Request: `POST /api/v1/embeddings`, Body: `{"model": "cohere_english_v3"}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_EMBED\_003: `input` as empty string**  
       * Request: `POST /api/v1/embeddings`, Body: `{"model": "cohere_english_v3", "input": ""}`  
       * Expected Status: 422 (Pydantic might require min\_length if specified in schema, or model provider might reject)  
     * **ECV\_INPUT\_EMBED\_004: `input` as empty list**  
       * Request: `POST /api/v1/embeddings`, Body: `{"model": "cohere_english_v3", "input": []}`  
       * Expected Status: 422 (Pydantic might require min\_items if specified)  
     * **ECV\_INPUT\_EMBED\_005: `input` with non-string element in list**  
       * Request: `POST /api/v1/embeddings`, Body: `{"model": "cohere_english_v3", "input": ["text1", 123]}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_EMBED\_006: Invalid `encoding_format` enum**  
       * Request: `POST /api/v1/embeddings`, Body: `{"model": "cohere_english_v3", "input": "test", "encoding_format": "int32"}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_EMBED\_007: Invalid `dimensions` type (not positive int)**  
       * Request: `POST /api/v1/embeddings`, Body: `{"model": "cohere_english_v3", "input": "test", "dimensions": "small"}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_EMBED\_008: `dimensions` as zero or negative**  
       * Request: `POST /api/v1/embeddings`, Body: `{"model": "cohere_english_v3", "input": "test", "dimensions": 0}`  
       * Expected Status: 422  
     * **ECV\_INPUT\_EMBED\_009: Invalid `input_type` enum**  
       * Request: `POST /api/v1/embeddings`, Body: `{"model": "cohere_english_v3", "input": "test", "input_type": "unknown_type"}`  
       * Expected Status: 422  
   * **Sub-Category: Custom Input Validation (`InputDataError` from `app/providers/utils.py`) \- `/api/v1/chat/completions`**  
     * **ECV\_INPUT\_CUSTOM\_001: Invalid Image Data URI format (wrong prefix)**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "http://example.com/image.jpg"}}]}]}`  
       * Expected Status: 400  
       * Expected Body: `{"error": "Bad Request", "message": "Invalid or unsupported image data URI format. Must be data:image/[jpeg|png|gif|webp];base64,..."}`  
     * **ECV\_INPUT\_CUSTOM\_002: Invalid Image Data URI format (unsupported image type)**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "data:image/tiff;base64,..."}}]}]}`  
       * Expected Status: 400  
       * Expected Body: `{"error": "Bad Request", "message": "Invalid or unsupported image data URI format. Must be data:image/[jpeg|png|gif|webp];base64,..."}`  
     * **ECV\_INPUT\_CUSTOM\_003: Invalid Base64 Data in Image URI (malformed base64 string)**  
       * Request: `POST /api/v1/chat/completions`, Body: `{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,!!!not_base64!!!"}}]}]}`  
       * Expected Status: 400  
       * Expected Body: `{"error": "Bad Request", "message": "Invalid Base64 data: <specific_error_from_binascii>"}`

   

3. ### Provider and Model Validation Error Test Cases (Category: ECV\_MODEL)

   

   * **Description:** These test cases check the API's behavior when requests specify unsupported models or attempt to use models for incompatible capabilities. This is primarily handled by the `Backend` dependency in `app/providers/dependencies.py`.  
   * **Test Cases:**  
     * **ECV\_MODEL\_CHAT\_001: Unsupported `model_id` for Chat Completions**  
       * **Description:** Verify API response when an unknown `model_id` is sent to `/api/v1/chat/completions`.  
       * **Prerequisites:** API is running. Valid API Key with `models:inference` scope.  
       * **Request Details:**  
         * Endpoint: `/api/v1/chat/completions`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <valid_key>", "Content-Type": "application/json"}`  
         * Body: `{"model": "non_existent_model_123", "messages": [{"role": "user", "content": "Hello"}]}`  
       * **Expected Status Code:** 422  
       * **Expected Response Body:** `{"detail": "Model 'non_existent_model_123' is not supported by this API."}`  
     * **ECV\_MODEL\_EMBED\_001: Unsupported `model_id` for Embeddings**  
       * **Description:** Verify API response when an unknown `model_id` is sent to `/api/v1/embeddings`.  
       * **Prerequisites:** API is running. Valid API Key with `models:embedding` scope.  
       * **Request Details:**  
         * Endpoint: `/api/v1/embeddings`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <valid_key>", "Content-Type": "application/json"}`  
         * Body: `{"model": "unknown_embedding_model_456", "input": "Test text"}`  
       * **Expected Status Code:** 422  
       * **Expected Response Body:** `{"detail": "Model 'unknown_embedding_model_456' is not supported by this API."}`  
     * **ECV\_MODEL\_CHAT\_002: Incompatible Model Capability for Chat (Using Embedding Model)**  
       * **Description:** Verify API response when a model configured for 'embedding' is used for `/api/v1/chat/completions`.  
       * **Prerequisites:** API is running. Valid API Key with `models:inference` scope. `cohere_english_v3` is configured with 'embedding' capability.  
       * **Request Details:**  
         * Endpoint: `/api/v1/chat/completions`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <valid_key>", "Content-Type": "application/json"}`  
         * Body: `{"model": "cohere_english_v3", "messages": [{"role": "user", "content": "Hello"}]}`  
       * **Expected Status Code:** 422  
       * **Expected Response Body:** `{"detail": "This endpoint not does support chat with the model 'cohere_english_v3'."}`  
     * **ECV\_MODEL\_EMBED\_002: Incompatible Model Capability for Embeddings (Using Chat Model)**  
       * **Description:** Verify API response when a model configured for 'chat' is used for `/api/v1/embeddings`.  
       * **Prerequisites:** API is running. Valid API Key with `models:embedding` scope. `claude_3_5_sonnet` is configured with 'chat' capability.  
       * **Request Details:**  
         * Endpoint: `/api/v1/embeddings`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <valid_key>", "Content-Type": "application/json"}`  
         * Body: `{"model": "claude_3_5_sonnet", "input": "Test text"}`  
       * **Expected Status Code:** 422  
       * **Expected Response Body:** `{"detail": "This endpoint not does support embedding with the model 'claude_3_5_sonnet'."}`  
     * **ECV\_MODEL\_CHAT\_003: Valid Model for Chat Completions (Positive Test)**  
       * **Description:** Verify successful request with a model correctly configured for 'chat'.  
       * **Prerequisites:** API is running. Valid API Key with `models:inference` scope. `claude_3_5_sonnet` is configured with 'chat' capability.  
       * **Request Details:**  
         * Endpoint: `/api/v1/chat/completions`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <valid_key>", "Content-Type": "application/json"}`  
         * Body: `{"model": "claude_3_5_sonnet", "messages": [{"role": "user", "content": "Hello"}]}`  
       * **Expected Status Code:** 200 (or other success from provider)  
       * **Expected Response Body:** Valid chat completion response.  
     * **ECV\_MODEL\_EMBED\_003: Valid Model for Embeddings (Positive Test)**  
       * **Description:** Verify successful request with a model correctly configured for 'embedding'.  
       * **Prerequisites:** API is running. Valid API Key with `models:embedding` scope. `cohere_english_v3` is configured with 'embedding' capability.  
       * **Request Details:**  
         * Endpoint: `/api/v1/embeddings`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <valid_key>", "Content-Type": "application/json"}`  
         * Body: `{"model": "cohere_english_v3", "input": "Test text"}`  
       * **Expected Status Code:** 200 (or other success from provider)  
       * **Expected Response Body:** Valid embedding response.

   

4. ### General HTTP Protocol Error Test Cases (Category: ECV\_HTTP)

   

   * **Description:** These test cases verify the API's adherence to standard HTTP error responses for common issues like trying to access non-existent resources or using incorrect HTTP methods. FastAPI handles these by default.  
   * **Test Cases:**  
     * **ECV\_HTTP\_001: Resource Not Found \- Completely Invalid Path**  
       * **Description:** Verify 404 for a path that doesn't exist under `/api/v1/`.  
       * **Prerequisites:** API is running. Valid API Key (to ensure it's not an auth error).  
       * **Request Details:**  
         * Endpoint: `/api/v1/thispathdoesnotexist`  
         * Method: GET (or any method)  
         * Headers: `{"Authorization": "Bearer <valid_key>"}`  
       * **Expected Status Code:** 404  
       * **Expected Response Body:** `{"detail": "Not Found"}`  
     * **ECV\_HTTP\_002: Resource Not Found \- Invalid Path for Existing Root**  
       * **Description:** Verify 404 for a path under an existing root like `/models/` but with an invalid sub-path, assuming `/models/{model_id}` is not a defined route.  
       * **Prerequisites:** API is running. Valid API Key.  
       * **Request Details:**  
         * Endpoint: `/api/v1/models/someinvalidextension`  
         * Method: GET  
         * Headers: `{"Authorization": "Bearer <valid_key>"}`  
       * **Expected Status Code:** 404  
       * **Expected Response Body:** `{"detail": "Not Found"}`  
     * **ECV\_HTTP\_003: Method Not Allowed for `/api/v1/models` (e.g., POST)**  
       * **Description:** The `/api/v1/models` endpoint is GET only.  
       * **Prerequisites:** API is running. Valid API Key.  
       * **Request Details:**  
         * Endpoint: `/api/v1/models`  
         * Method: POST  
         * Headers: `{"Authorization": "Bearer <valid_key>", "Content-Type": "application/json"}`  
         * Body: `{}`  
       * **Expected Status Code:** 405  
       * **Expected Response Body:** `{"detail": "Method Not Allowed"}`  
     * **ECV\_HTTP\_004: Method Not Allowed for `/api/v1/chat/completions` (e.g., GET)**  
       * **Description:** The `/api/v1/chat/completions` endpoint is POST only.  
       * **Prerequisites:** API is running. Valid API Key.  
       * **Request Details:**  
         * Endpoint: `/api/v1/chat/completions`  
         * Method: GET  
         * Headers: `{"Authorization": "Bearer <valid_key>"}`  
       * **Expected Status Code:** 405  
       * **Expected Response Body:** `{"detail": "Method Not Allowed"}`  
     * **ECV\_HTTP\_005: Method Not Allowed for `/api/v1/embeddings` (e.g., PUT)**  
       * **Description:** The `/api/v1/embeddings` endpoint is POST only.  
       * **Prerequisites:** API is running. Valid API Key.  
       * **Request Details:**  
         * Endpoint: `/api/v1/embeddings`  
         * Method: PUT  
         * Headers: `{"Authorization": "Bearer <valid_key>", "Content-Type": "application/json"}`  
         * Body: `{"model": "cohere_english_v3", "input": "test"}`  
       * **Expected Status Code:** 405  
       * **Expected Response Body:** `{"detail": "Method Not Allowed"}`  
     * **ECV\_HTTP\_006: Accessing Root Path `/` (If not explicitly defined)**  
       * **Description:** Verify behavior when accessing the application root. FastAPI might return 404 if no route is defined for `/`.  
       * **Prerequisites:** API is running.  
       * **Request Details:**  
         * Endpoint: `/`  
         * Method: GET  
       * **Expected Status Code:** 404 (Likely, unless a root endpoint is added)  
       * **Expected Response Body:** `{"detail": "Not Found"}`  
     * **ECV\_HTTP\_007: Accessing `/api/` Path (If not explicitly defined)**  
       * **Description:** Verify behavior when accessing an intermediate path.  
       * **Prerequisites:** API is running.  
       * **Request Details:**  
         * Endpoint: `/api/`  
         * Method: GET  
       * **Expected Status Code:** 404 (Likely)  
       * **Expected Response Body:** `{"detail": "Not Found"}`

   

5. ### Server-Side and Downstream Error Handling Test Cases (Category: ECV\_SERVER)

   

   * **Description:** These test cases evaluate how the API handles unexpected internal errors, issues with its dependencies (like the database), or failures from downstream AI model providers. The focus is on ensuring graceful error reporting and no leakage of sensitive information.  
   * **Test Cases:**  
     * **ECV\_SERVER\_001: Generic Unhandled Exception in Endpoint Logic**  
       * **Description:** Simulate an unexpected Python error within an endpoint after initial validation and auth.  
       * **Prerequisites:** API is running. Valid API Key with appropriate scopes. Requires ability to mock/patch a function called by the endpoint to raise a generic `Exception`.  
       * **Request Details:** Any valid request to an endpoint (e.g., `POST /api/v1/chat/completions`).  
       * **Expected Status Code:** 500  
       * **Expected Response Body:** `{"detail": "Internal Server Error", "request_id": "<uuid>"}`  
       * **Verification:** Check server logs for the original exception traceback and the corresponding `request_id`.  
     * **ECV\_SERVER\_002: Database Connection Failure during API Key Validation**  
       * **Description:** Simulate the database being unavailable when `valid_api_key` dependency tries to connect via `get_db_session` or when `APIKeyRepository` attempts a query.  
       * **Prerequisites:** API is running. Requires ability to make the database temporarily inaccessible to the API (e.g., stop DB service, misconfigure connection string temporarily, mock `async_session` to raise `OperationalError`).  
       * **Request Details:** Any request to a protected endpoint (e.g., `GET /api/v1/models`).  
       * **Expected Status Code:** 500  
       * **Expected Response Body:** `{"detail": "Internal Server Error", "request_id": "<uuid>"}`  
       * **Verification:** Check server logs for database connection error details.  
     * **ECV\_SERVER\_003: Database Operation Failure in Repository**  
       * **Description:** Simulate a SQLAlchemy error (e.g., `IntegrityError`, `DataError`) during a repository operation (e.g., `APIKeyRepository.get_by_api_key_value`).  
       * **Prerequisites:** API is running. Valid API Key. Requires ability to mock a repository method to raise a `SQLAlchemyError`.  
       * **Request Details:** Any request to a protected endpoint.  
       * **Expected Status Code:** 500  
       * **Expected Response Body:** `{"detail": "Internal Server Error", "request_id": "<uuid>"}`  
       * **Verification:** Check server logs for the specific SQLAlchemy error.  
     * **ECV\_SERVER\_004: Downstream Bedrock Provider API Error**  
       * **Description:** Simulate Bedrock's `converse` or `invoke_model` (for embeddings) API returning an error (e.g., 4xx or 5xx from Bedrock, or raising `botocore.exceptions.ClientError`).  
       * **Prerequisites:** API is running. Valid API Key with appropriate scopes. Request targets a Bedrock-backed model. Requires mocking the `aioboto3.Session().client("bedrock-runtime").converse` or `invoke_model` call.  
       * **Request Details:** Valid request to `/api/v1/chat/completions` or `/api/v1/embeddings` using a Bedrock model.  
       * **Expected Status Code:** 500 (as current code doesn't specifically handle these to translate to 502/503)  
       * **Expected Response Body:** `{"detail": "Internal Server Error", "request_id": "<uuid>"}`  
       * **Verification:** Server logs should show the error originating from the Bedrock client call.  
     * **ECV\_SERVER\_005: Downstream Vertex AI Provider API Error**  
       * **Description:** Simulate Vertex AI's `generate_content_async` or `get_embeddings_async` API raising an exception (e.g., `google.api_core.exceptions.GoogleAPIError`).  
       * **Prerequisites:** API is running. Valid API Key with appropriate scopes. Request targets a Vertex AI-backed model. Requires mocking the `GenerativeModel.generate_content_async` or `TextEmbeddingModel.get_embeddings_async` call.  
       * **Request Details:** Valid request to `/api/v1/chat/completions` or `/api/v1/embeddings` using a Vertex AI model.  
       * **Expected Status Code:** 500  
       * **Expected Response Body:** `{"detail": "Internal Server Error", "request_id": "<uuid>"}`  
       * **Verification:** Server logs should show the error originating from the Vertex AI client call.  
     * **ECV\_SERVER\_006: Downstream Bedrock Provider Timeout/Network Issue**  
       * **Description:** Simulate a timeout or network connectivity issue when calling Bedrock.  
       * **Prerequisites:** API is running. Valid API Key. Request targets Bedrock. Mock Bedrock client to raise a timeout or network-related exception.  
       * **Request Details:** Valid request using a Bedrock model.  
       * **Expected Status Code:** 500  
       * **Expected Response Body:** `{"detail": "Internal Server Error", "request_id": "<uuid>"}`  
     * **ECV\_SERVER\_007: Downstream Vertex AI Provider Timeout/Network Issue**  
       * **Description:** Simulate a timeout or network connectivity issue when calling Vertex AI.  
       * **Prerequisites:** API is running. Valid API Key. Request targets Vertex AI. Mock Vertex AI client to raise a timeout or network-related exception.  
       * **Request Details:** Valid request using a Vertex AI model.  
       * **Expected Status Code:** 500  
       * **Expected Response Body:** `{"detail": "Internal Server Error", "request_id": "<uuid>"}`  
     * **ECV\_SERVER\_008: Billing Service Queue Failure (Conceptual)**  
       * **Description:** Simulate a failure during the `billing_queue.put()` operation in `app/services/billing.py` if it were to raise an unhandled exception (e.g., if the queue had a strict size limit and was full, and `put_nowait` was used, or a custom error was raised).  
       * **Prerequisites:** API is running. Valid API Key. Requires mocking `billing_queue.put()` to raise an exception.  
       * **Request Details:** Any successful API call that triggers billing.  
       * **Expected Status Code:** 500 (if the exception is not caught within the endpoint that calls billing)  
       * **Expected Response Body:** `{"detail": "Internal Server Error", "request_id": "<uuid>"}`  
       * **Note:** This is more conceptual as `asyncio.Queue` is unlikely to fail this way by default.  
     * **ECV\_SERVER\_009: Lifespan `engine.dispose()` Failure on Shutdown (Conceptual)**  
       * **Description:** Test error handling if `engine.dispose()` during application shutdown (in `app/main.py` lifespan manager) fails. This is harder to test via HTTP requests but important for graceful shutdown.  
       * **Prerequisites:** Requires instrumenting the shutdown sequence or mocking `engine.dispose()`.  
       * **Expected Behavior:** Application logs the error but attempts to shut down as gracefully as possible. No direct HTTP response to test.  
     * **ECV\_SERVER\_010: Lifespan `drain_billing_queue()` Failure on Shutdown (Conceptual)**  
       * **Description:** Test error handling if `drain_billing_queue()` during application shutdown fails.  
       * **Prerequisites:** Requires instrumenting the shutdown sequence or mocking parts of `drain_billing_queue()`.  
       * **Expected Behavior:** Application logs the error.

## 4\. Set Up Test Environment & Data

* **API Instance:** Deploy the API to a dedicated, stable test environment.  
* **Database:**  
  * Ensure the test PostgreSQL database (as specified in `app/config/settings.py` and `README.md`) is set up.  
  * Use Alembic (`alembic.ini`, `alembic/versions/`) to manage schema and ensure it's up-to-date (`uv run alembic upgrade head`).  
* **API Keys:**  
  * Use `create_admin_user.py` or similar logic to generate valid API keys with different scope combinations (e.g., `models:inference` only, `models:embedding` only, all scopes).  
  * Manually (or via script) insert/update records in the `api_keys` table to create keys that are:  
    * Expired (current `datetime` \> `expires_at`).  
    * Inactive (`is_active = False`).  
  * Keep a list of intentionally invalid key strings (e.g., "totally\_invalid\_key").  
* **Test Data Payloads:**  
  * Craft JSON payloads for `/chat/completions` and `/embeddings` that will trigger Pydantic validation errors (e.g., missing `model` or `messages`/`input`, incorrect data type for `temperature`).  
  * Prepare sample image/file data (as base64 strings) that are malformed or use unsupported formats to test `InputDataError` scenarios (e.g., invalid base64 string, incorrect `data:image/...` prefix).  
* **Tooling:**  
  * **Postman/Insomnia:** For manual exploration and execution of individual test cases.  
  * **Programmatic (Python `requests` \+ `pytest`):** Preferred for automation. Leverage the existing `pytest` setup in the `tests` directory. You can create a new test file like `tests/integration/test_error_handling.py`.  
  * **Mocking Libraries:** `unittest.mock` (standard library) or `pytest-mock` for simulating failures in dependencies (database, downstream providers).

## 5\. Test Results

* tba

### Verify Results & Analyze

* **Status Code:** Compare the actual status code against the expected status code.  
* **Response Body:**  
  * Validate the structure of the JSON response (e.g., does it contain a `detail` key?).  
  * Verify the content of key fields matches the expected error message.  
  * For 500 errors, confirm the presence and format of `request_id`.  
  * Critically, ensure no sensitive operational details (stack traces, database errors, internal paths) are leaked in any error response.  
* **Server Logs:**  
  * After triggering an error, inspect the server-side logs (Structlog output, configured in `app/logs/logging_config.py` and `app/logs/middleware.py`).  
  * Verify that the error was logged with appropriate severity and context (e.g., `request_id`, method, path, client\_ip).  
  * For unhandled exceptions leading to 500 errors, ensure the log contains the stack trace for debugging.

### Document & Report Defects

* Maintain a record of all test executions (test management tools or spreadsheets). Include input, expected output, and actual output.  
* Log any discrepancies (failed assertions in automated tests, or manual mismatches) as defects in your project's bug tracking system.  
* **Defect Report Details:**  
  * Test Case ID that failed.  
  * Clear, concise summary of the issue.  
  * Steps to reproduce the error.  
  * The exact request sent (method, URL, headers, body).  
  * Expected result (status code, specific body content).  
  * Actual result (status code, full actual body).  
  * Relevant server log snippets (especially the log entry with the corresponding `request_id`).
