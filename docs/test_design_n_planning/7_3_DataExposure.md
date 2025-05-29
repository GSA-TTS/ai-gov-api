# Data Exposure Testing

This document outlines the approach to testing for potential data exposure vulnerabilities within the AI API Framework. This aligns with section 7.3 of the [GSAi API Test Plan](https://docs.google.com/document/d/19_nlgUmNBrs9gKL8sIM8BDDABc6LkTqtLYwT7Aflfso/edit?usp=drive_link) , which references NIST SP 800-228 Sec 2.5, REC-API-20 and DoD API Tech Guide Sec 3.3.3.

## 1\. Understand the Goal

The primary goal of Data Exposure Testing is to systematically identify, analyze, and mitigate any instances where sensitive, confidential, or internal data could be unintentionally leaked or exposed through the API's various outputs. This includes API responses (both success and error), error messages, logs, and any other observable behavior or artifact.

**Specific objectives include ensuring:**

* **Principle of Least Privilege for Data in Responses:** API endpoints must only return data fields that are explicitly intended for the client and necessary for the API's function. Superfluous or internal-only data should be stripped before responding. For example, the `/api/v1/models` endpoint should only return public-facing model identifiers and capabilities, not internal ARNs or provider-specific configurations.  
* **No Sensitive Information in Error Messages:** Error messages, regardless of type (client-side 4xx or server-side 5xx), must be carefully crafted to be informative to the client for debugging legitimate issues but must **never** reveal:  
* Internal system details (e.g., file paths, internal IP addresses, library versions).  
* Full stack traces or raw exception messages from the application or its dependencies.  
* Database queries, table names, or specific database error messages.  
* Sensitive configuration parameters (e.g., parts of connection strings, secret keys).  
* Excessive portions of sensitive user input that might have caused the error, especially if the input itself contained PII or other confidential data.  
* **Secure and Purposeful Logging Practices:** Application logs (managed by Structlog via `app/logs/`) are essential for debugging, monitoring, and security auditing. However, they must not become a source of data leakage. This means:  
* Avoid logging sensitive user data such as PII (e.g., full names, email addresses from `User` model if not explicitly needed for that log entry's purpose), full content of LLM prompts or responses (which might contain confidential user information), or raw API keys.  
* If sensitive identifiers (like `user_id` or `request_id`) are logged, ensure access to these logs is strictly controlled and auditable.  
* Configuration secrets (database passwords, provider API keys used by the framework) must never be logged.  
* Log levels (`app/config/settings.py`) should be appropriately configured for different environments (e.g., `INFO` for production, more verbose for `dev` but still cautious about sensitive data).  
* **Protection of Configuration and Credentials:**  
* Sensitive configuration details (e.g., `POSTGRES_CONNECTION`, `BEDROCK_ASSUME_ROLE`, provider-specific ARNs/project IDs defined in `app/config/settings.py`) must not be directly or indirectly exposable through any API endpoint.  
* The application must not inadvertently reveal credentials it uses to connect to downstream services (LLMs, database).  
* **Secure Data Handling in Transit and At Rest (Contextual Considerations):**  
* **In Transit:** While HTTPS setup is a deployment concern, the API design should not include features that might encourage or necessitate insecure data transmission (e.g., returning sensitive tokens in URLs).  
* **At Rest (Database):** The application stores user PII (`app/users/models.py`) and API key information (`app/auth/models.py`). This testing will verify that what the application *intends* to store securely (e.g., hashed API keys) is indeed handled that way by the application logic before it reaches the database. Database-level encryption is a separate infrastructure concern.  
* **No Exposure of Internal Architectural Details:** API responses or errors should not leak information about internal class names, function names, library choices, or specific backend provider details beyond what is explicitly intended (e.g., the public model ID).

The ultimate aim is to protect user privacy, safeguard system secrets (API keys, configuration), prevent attackers from gaining reconnaissance advantages through leaked system information, and maintain compliance with data protection regulations.

## 2\. Identify Potential Data Exposure Points

This section details areas within the AI API Framework where data is processed, returned, or logged, and where potential exposures could occur. For each point, we define the type of data involved, how it's currently handled, and potential exposure risks.

**Sources for Identification:**

* **API Endpoints & Schemas:**  
* `app/routers/api_v1.py`: Defines API routes and their response models.  
* `app/providers/open_ai/schemas.py`: Pydantic models for external-facing request/response bodies (`ChatCompletionRequest`, `ChatCompletionResponse`, `EmbeddingRequest`, `EmbeddingResponse`).  
* `app/providers/core/chat_schema.py` & `app/providers/core/embed_schema.py`: Internal representation schemas.  
* `app/providers/base.py`: `LLMModel` schema for `/models` endpoint.  
* **Error Handling Logic:**  
* `app/main.py`: Global exception handler (`json_500_handler`).  
* `app/routers/api_v1.py`: Specific handling of `InputDataError`.  
* FastAPI's default handlers for Pydantic validation errors (422) and other HTTP errors (404, 405, 415, etc.).  
* **Logging Mechanisms:**  
* `app/logs/middleware.py` (`StructlogMiddleware`): Captures request metadata.  
* `app/logs/logging_config.py`: Configures log format, level, and processors.  
* `app/services/billing.py` (`billing_worker`): Logs billing-related data.  
* Direct logging calls in provider implementations (e.g., `app/providers/bedrock/bedrock.py` logs metrics, `app/providers/vertex_ai/vertexai.py` currently has minimal direct logging).  
* **Configuration Management:**  
* `app/config/settings.py`: Loads settings (including secrets like DB connection strings, provider ARNs/IDs) from environment variables or `.env` file.  
* **Database Models & Repositories:**  
* `app/auth/models.py` (`APIKey`): Stores `hashed_key`, `key_prefix`, `scopes`, `manager_id` (links to `User`), `is_active`, timestamps, `expires_at`, `last_used_at`.  
* `app/users/models.py` (`User`): Stores PII: `id` (UUID), `email`, `name`, `role`.  
* Repositories in `app/auth/repositories.py` and `app/users/repositories.py`: Logic for fetching and returning data (though current API endpoints don't directly expose full User/APIKey objects).  
* **Provider Adapters:**  
* Modules in `app/providers/*/adapter_*.py`: Transform data between core schema and provider-specific schemas. Important to check if any sensitive intermediate data is inadvertently passed through or logged.

### A. API Response Data (Success Cases)

1. **`GET /api/v1/models` Endpoint:**  
* **Data Returned:** List of `LLMModel` objects. Each object contains `name` (str), `id` (str), `capability` (Literal "chat" or "embedding").  
* **Source:** `settings.backend_map` values, filtered to `LLMModel` schema.  
* **Potential Exposure:** Leaking provider-specific internal identifiers (like full ARNs from `BedrockModel.arn` or detailed `VertexModel` configurations) if the `LLMModel` schema in `app/providers/base.py` were to include them or if the mapping in `app/config/settings.py` were incorrect.  
* **Current Implementation Check:** The `LLMModel` schema in `app/providers/base.py` correctly restricts fields to `name`, `id`, `capability`. Provider-specific details from `BedrockModel` or `VertexModel` are not part of this public schema.  
* **Expected Secure Outcome:** Only the non-sensitive fields (`id`, `name`, `capability`) defined in `LLMModel` are returned for each model. No ARNs, project IDs, assumed roles, or other internal configuration details from `BedrockModelsSettings` or `VertexModelsSettings` are exposed.  
2. **`POST /api/v1/chat/completions` Endpoint:**  
* **Data Returned:** `ChatCompletionResponse` object. Key fields: `model` (string, the requested model ID), `choices[].message.content` (string, LLM's generated text), `usage` (token counts).  
* **Source:** Data is transformed from the core schema (`ChatRepsonse`) by `app/providers/open_ai/adapter_from_core.core_chat_response_to_openai`. The `message.content` originates from the downstream LLM provider.  
* **Potential Exposure:**  
  * **LLM Content:** The `message.content` could contain sensitive data if the LLM was prompted with it or if the LLM itself generates it (this is an LLM security concern, the API should just relay).  
  * **Model Identifier:** Returning an internal/sensitive model identifier instead of the public-facing one used in the request.  
  * **Internal Metadata:** Accidentally including internal processing details, user PII (not directly part of this response schema unless the LLM generates it), or system configuration.  
* **Current Implementation Check:** The `model` field in the response is correctly set to the input `model` ID. `message.content` is taken from the core response, which comes from the LLM. The `ChatCompletionResponse` schema is well-defined and doesn't include fields for internal metadata.  
* **Expected Secure Outcome:** The response strictly adheres to the `ChatCompletionResponse` schema. The `model` field is the public ID. `message.content` is the direct output from the LLM. No additional internal metadata, user PII (unless explicitly part of the LLM's response to a prompt), or system details are included.  
3. **`POST /api/v1/embeddings` Endpoint:**  
* **Data Returned:** `EmbeddingResponse` object. Key fields: `model` (string, requested model ID), `data[].embedding` (list of floats), `usage` (token counts).  
* **Source:** Transformed from core schema (`EmbeddingResponse`) by `app/providers/open_ai/adapter_from_core.core_embed_response_to_openai`. Embedding vectors originate from the downstream LLM provider.  
* **Potential Exposure:**  
  * **Model Identifier:** Similar to chat, returning an internal model ID.  
  * **Input Data Reflection:** The original input text used to generate embeddings should not be echoed back in the success response (it's not part of the `EmbeddingResponse` schema).  
* **Current Implementation Check:** The `model` field is the input model ID. The `data` field contains only `embedding` and `index`.  
* **Expected Secure Outcome:** Response strictly adheres to the `EmbeddingResponse` schema. No source text is echoed back. `model` is the public ID.

### B. API Response Data (Error Cases)

1. **Pydantic Validation Errors (422 Unprocessable Entity):**  
* **Data Exposed by FastAPI Default:** `{"detail": [{"loc": ["body", "<field_path>", ...], "msg": "<error_message>", "type": "<error_type>"}]}`. The `msg` or content of `loc` might include parts of the user's invalid input.  
* **Potential Exposure:** If a user submits highly sensitive data in a field that then fails a format/type validation (e.g., a very long string with PII in a field expecting an integer), that data could be partially reflected in the error response.  
* **Expected Secure Outcome:** FastAPI's default behavior of reflecting parts of the input in `loc` and `msg` is generally for debugging by the client. The key is that it must not leak *additional* server-side information or full sensitive inputs if they are very large. The current setup relies on this default. No internal system details should be part of this.  
2. **Custom `InputDataError` (400 Bad Request \- from `app/routers/api_v1.py` handling `app/providers/exceptions.py`):**  
* **Data Exposed:** `{"error": "Bad Request", "message": str(e), "field": e.field_name (optional)}`. `str(e)` is the message from `InvalidImageURLError` or `InvalidBase64DataError`.  
* **Current Implementation Check:** Messages like "Invalid or unsupported image data URI format..." or "Invalid Base64 data: " are static or describe the format error, generally not echoing the full problematic (potentially large/sensitive) input.  
* **Expected Secure Outcome:** Error messages are informative about the format/type error but do not include the full, potentially large or sensitive, invalid input data. The specific base64 error `<reason>` should also be generic and not the full faulty string.  
3. **Authentication/Authorization Errors (401 Unauthorized \- from `app/auth/dependencies.py`):**  
* **Data Exposed:** `{"detail": "<specific_auth_failure_message>"}` (e.g., "Missing or invalid API key", "API key is expired", "Not Authorized").  
* **Expected Secure Outcome:** Messages are informative about the auth failure type without leaking system state (e.g., not saying "API key X found but scope Y missing for user Z"). Current messages are good.  
4. **Model/Provider Validation Errors (422 Unprocessable Entity \- from `app/providers/dependencies.py`):**  
* **Data Exposed:** `{"detail": "Model '{model_id}' is not supported..."}` or `{"detail": "This endpoint not does support {capability}..."}`.  
* **Expected Secure Outcome:** Echoes back the user-provided `model_id` and the relevant `capability`, which is acceptable as it's user input and helps them debug. No internal provider mapping details should be exposed.  
5. **Generic Server Errors (500 Internal Server Error \- from `app/main.py` `json_500_handler`):**  
* **Data Exposed:** `{"detail": "Internal Server Error", "request_id": "<uuid>"}`.  
* **Expected Secure Outcome:** This is the ideal generic response for unhandled server errors. It provides no internal details to the client but gives a `request_id` (from `app/logs/logging_context.py`) for server-side log correlation. Absolutely no stack traces, exception messages, database error details, or configuration values should be part of this client-facing response.

**C. Logging (`app/logs/` and `app/services/billing.py`)**

1. **`StructlogMiddleware` (`app/logs/middleware.py`):**  
* **Data Logged by Default:** `request_id`, `method`, `path`, `query_params` (as dict), `client_ip`, `user_agent`, `status_code`, `duration_ms`. Also, if an exception occurs *and is caught by the middleware's `except Exception:` block* (meaning it's an unhandled one leading to 500), it logs `exc_info=True` which includes the stack trace *in the server logs only*.  
* **Potential Exposure in Logs:**  
  * `query_params`: If sensitive data were ever passed here (not current design).  
  * `client_ip`, `user_agent`: Standard PII/fingerprinting data.  
  * Stack traces for unhandled exceptions (server-side logs only): These are essential for debugging but must be protected.  
* **Current Implementation Check:** Does not log request/response bodies by default. `structlog.processors.format_exc_info` is added for non-dev environments, ensuring stack traces are available in production logs (not sent to client).  
* **Expected Secure Outcome:** Logs essential request metadata. No full request/response bodies. Stack traces for 500 errors are logged server-side only. Query parameters should be reviewed if they ever become sensitive.  
2. **`billing_worker` (`app/services/billing.py`):**  
* **Data Logged:** `logger.info("billing", **billing_data)`. `billing_data` is constructed in the endpoint routers (e.g., `app/routers/api_v1.py`) and would likely contain: `api_key.manager_id` (user's UUID), `api_key.id` (API key's own int ID), `req.model` (model ID string), and token counts from `resp.usage`.  
* **Potential Exposure in Logs:**  
  * `manager_id` (User UUID) and `api_key.id` are internal identifiers.  
  * `req.model` is public.  
  * Token counts are operational data.  
  * Crucially, it does *not* log the content of the prompts or responses.  
* **Expected Secure Outcome:** Billing logs contain necessary identifiers for tracking usage (user UUID, API key ID, model ID) and metrics (token counts). No sensitive prompt/response content. Access to these logs must be strictly controlled.  
3. **Provider-Specific Logging (e.g., in `BedRockBackend`, `VertexBackend`):**  
* `BedRockBackend` (`app/providers/bedrock/bedrock.py`): Logs `response['metrics']` (e.g., `latencyMs`) and `model_id` for chat. For embeddings, logs `latency` (from headers) and `token_count` (from headers), and `modelId`.  
* `VertexBackend` (`app/providers/vertex_ai/vertexai.py`): Currently, no explicit detailed logging of request/response data passed to/from Vertex AI, beyond what the SDK might do.  
* **Potential Exposure in Logs:** If any adapter or backend implementation were modified to log the full `payload` to or `response` from the downstream LLM provider at a high log level (e.g., INFO), this would log potentially sensitive user prompts and LLM generations.  
* **Expected Secure Outcome:** Logs should focus on operational metrics (latency, token counts, model IDs used), error codes from providers, and correlation IDs. Full prompt/response data should only be logged at a DEBUG level (if at all) and be disabled in production, or if logged, subject to strict access controls and retention policies. The current direct logging in `BedRockBackend` appears safe.

### D. Configuration and Secrets (`app/config/settings.py`)

* **Data Handled:** `postgres_connection` (contains database username, password, host, port, dbname), `bedrock_assume_role`, `aws_default_region`, `vertex_project_id`, various Bedrock model ARNs. These are loaded via Pydantic `BaseSettings` from environment variables or a `.env` file.  
* **Potential Exposure:**  
* If the `Settings` object itself or its sensitive attributes were accidentally logged (e.g., `logger.info("settings", settings=get_settings().model_dump())` without redaction).  
* If an API endpoint inadvertently returned parts of the `Settings` object.  
* If default values in the code contained real secrets (not the case here, as they use `Field(default=...)` indicating they must be provided by env).  
* **Current Implementation Check:** Secrets are intended to be loaded from the environment. The application accesses them via `get_settings()`. No current code logs the entire settings object or exposes it via API.  
* **Expected Secure Outcome:** Secrets are not hardcoded. They are loaded from a secure environment configuration. The application does not log these secrets. No API endpoint returns these raw setting values.

### E. Database Storage (`app/auth/models.py`, `app/users/models.py`)

1. **`User` Model:**  
* **Data Stored:** `id` (UUID), `email` (String, PII), `name` (String, PII), `role` (String), `is_active` (Bool), timestamps.  
* **Expected Secure Outcome:** PII is stored. The database itself must be secured (network access, authentication, authorization, encryption at rest). The application should only retrieve/expose this data through authorized API endpoints (currently no endpoints directly expose full `User` objects).  
2. **`APIKey` Model:**  
* **Data Stored:** `id` (Int), `hashed_key` (String), `key_prefix` (String), `manager_id` (ForeignKey to `User`), `scopes` (Array of String), `is_active` (Bool), timestamps, `expires_at`, `last_used_at`.  
* **Current Implementation Check:** `app/auth/utils.py`'s `generate_api_key` creates a raw key and its SHA256 hash. `APIKeyRepository.create` stores the `hashed_key`. `APIKeyRepository.get_by_api_key_value` hashes the provided key before querying. This is correct.  
* **Expected Secure Outcome:** Only cryptographically strong hashes (SHA256) of API keys are stored in the database, not the raw keys.

### F. Data In Transit

* **Client \<-\> API:** HTTP by default with FastAPI/Uvicorn. HTTPS (TLS) is a deployment concern (reverse proxy like Nginx, load balancer).  
* **Expected Secure Outcome:** All production deployments **MUST** be fronted by a TLS-terminating proxy to enforce HTTPS. The API itself does not handle TLS.  
* **API \<-\> Downstream Providers (Bedrock, Vertex AI):** The AWS SDK (`aioboto3`) and Google Cloud SDK (`vertexai`) use HTTPS by default for their API calls.  
* **Expected Secure Outcome:** Communication with LLM providers is encrypted by their SDKs.  
* **API \<-\> Database (PostgreSQL):** The `postgres_connection` string in `app/config/settings.py` can be configured to require SSL/TLS (e.g., `postgresql+asyncpg://user:pass@host/db?ssl=require`).  
* **Expected Secure Outcome:** Database connections should be encrypted, especially if the database is not on `localhost` or within a trusted, isolated network. This is a configuration concern for the connection string.

## 3\. Design Test Cases

This section details specific test cases to probe for potential data exposures based on the points identified above. Each test case will include its ID, category, description, the specific exposure point being tested, the test method, prerequisites, the expected secure outcome, and how to verify it.

**General Test Case Components:**

* **ID:** Unique identifier (e.g., DE\_RESP\_SUCCESS\_001)  
* **Category Ref:** (e.g., DE\_API\_RESPONSE, DE\_ERROR\_MESSAGE, DE\_LOGGING, DE\_CONFIG, DE\_DB\_STORAGE)  
* **Description:** What specific potential data exposure is being tested.  
* **Exposure Point(s):** The API endpoint, log file, error message type, database field, or configuration aspect being examined.  
* **Test Method/Action:** How the test is performed (e.g., "Make GET request to...", "Trigger 500 error and inspect response", "Review server logs after specific API call", "Inspect database record for APIKey").  
* **Prerequisites:** Valid API Key (if needed), specific conditions to trigger an error, specific data to be logged, etc.  
* **Expected Secure Outcome:** A clear statement of what data *should not* be exposed and what *is acceptable* to be present.  
* **Verification Steps:** How to confirm the expected secure outcome (e.g., "Assert response JSON does not contain 'arn'", "Verify error message matches expected generic text", "Confirm logs do not show plaintext API key").

---

### A. API Response Data (Success Cases) \- Category: DE\_API\_RESPONSE\_SUCCESS

* **ID:** DE\_API\_RESPONSE\_SUCCESS\_001  
* **Description:** Verify `/api/v1/models` response does not expose sensitive backend model configuration.  
* **Exposure Point(s):** JSON response of `GET /api/v1/models`.  
* **Test Method/Action:** Make a `GET` request to `/api/v1/models`.  
* **Prerequisites:** Valid API Key.  
* **Expected Secure Outcome:** The response is a list of objects, each containing only "id", "name", and "capability". No AWS ARNs, GCP project IDs, or other provider-specific internal configuration details are present.  
* **Verification Steps:**  
1. Inspect the JSON response.  
2. For each model object, verify only the keys `id`, `name`, `capability` exist.  
3. Verify values do not contain ARNs or other sensitive identifiers from `BedrockModelsSettings` or `VertexModelsSettings` beyond the public `id`.  
* **ID:** DE\_API\_RESPONSE\_SUCCESS\_002  
* **Description:** Verify `/api/v1/chat/completions` response does not expose internal metadata or PII beyond LLM output.  
* **Exposure Point(s):** JSON response of `POST /api/v1/chat/completions`.  
* **Test Method/Action:** Make a successful `POST` request to `/api/v1/chat/completions` with a simple prompt.  
* **Prerequisites:** Valid API Key with `models:inference` scope.  
* **Expected Secure Outcome:** The response adheres strictly to the `ChatCompletionResponse` schema. The `model` field contains the public model ID. `choices[].message.content` contains only the LLM's output. No internal processing details, user PII (unless the LLM was prompted to generate it), or server configuration is included.  
* **Verification Steps:**  
1. Inspect the JSON response.  
2. Verify all top-level keys match the `ChatCompletionResponse` schema (`object`, `created`, `model`, `choices`, `usage`).  
3. Verify `choices[].message` only contains `role` and `content`.  
* **ID:** DE\_API\_RESPONSE\_SUCCESS\_003  
  * **Description:** Verify `/api/v1/embeddings` response does not expose input text or internal metadata.  
  * **Exposure Point(s):** JSON response of `POST /api/v1/embeddings`.  
  * **Test Method/Action:** Make a successful `POST` request to `/api/v1/embeddings`.  
  * **Prerequisites:** Valid API Key with `models:embedding` scope.  
  * **Expected Secure Outcome:** The response adheres strictly to the `EmbeddingResponse` schema. The original input text is not echoed in the response. The `model` field is the public model ID.  
  * **Verification Steps:**  
1. Inspect the JSON response.  
2. Verify all top-level keys match the `EmbeddingResponse` schema (`object`, `data`, `model`, `usage`).  
3. Verify `data[]` objects only contain `embedding` and `index`.

### B. API Response Data (Error Cases) \- Category: DE\_API\_RESPONSE\_ERROR

* **ID:** DE\_API\_RESPONSE\_ERROR\_001  
  * **Description:** Verify Pydantic validation error (422) messages do not expose excessive sensitive input.  
  * **Exposure Point(s):** `detail` field in 422 JSON response.  
  * **Test Method/Action:** Send a request to `/api/v1/chat/completions` with a field containing potentially sensitive but malformed data (e.g., a very long string with PII where an integer is expected for `max_tokens`).  
  * **Prerequisites:** Valid API Key.  
  * **Expected Secure Outcome:** The 422 error message in `detail[].msg` or `detail[].loc` should describe the validation failure but not echo back an unreasonably large or overly sensitive portion of the invalid input. FastAPI's default truncation/representation of invalid values should be verified. No server-side internal details.  
  * **Verification Steps:**  
1. Trigger a 422 error by providing invalid input in a field.  
2. Inspect the `detail` array in the JSON response.  
3. Confirm that if input values are reflected, they are reasonably truncated or summarized and do not constitute a significant data leak.  
4. Confirm no stack traces or internal variable names (beyond Pydantic field paths) are present.  
* **ID:** DE\_API\_RESPONSE\_ERROR\_002  
  * **Description:** Verify custom `InputDataError` (400) messages do not expose the full invalid input.  
  * **Exposure Point(s):** `message` field in 400 JSON response (from `app/routers/api_v1.py`).  
  * **Test Method/Action:** Send a request to `/api/v1/chat/completions` with a malformed `image_url.url` (e.g., invalid Base64 string that is very long and contains mock sensitive data).  
  * **Prerequisites:** Valid API Key.  
  * **Expected Secure Outcome:** The 400 error message (e.g., "Invalid Base64 data: ") should describe the error generically and not include the full, potentially sensitive, malformed Base64 string.  
  * **Verification Steps:**  
1. Trigger an `InputDataError` (e.g., invalid image data URI).  
2. Inspect the `message` field in the JSON response.  
3. Confirm the full invalid input is not echoed.  
* **ID:** DE\_API\_RESPONSE\_ERROR\_003  
  * **Description:** Verify 500 Internal Server Error responses do not leak any internal details.  
  * **Exposure Point(s):** JSON response for 500 errors (from `app/main.py` `json_500_handler`).  
  * **Test Method/Action:** Simulate an unhandled exception in an endpoint (e.g., by mocking a downstream call to raise an unexpected error).  
  * **Prerequisites:** Valid API Key. Ability to mock internal functions to raise an error.  
  * **Expected Secure Outcome:** Response is exactly `{"detail": "Internal Server Error", "request_id": "<uuid>"}`. No stack traces, exception messages, code snippets, database errors, or configuration values are present.  
  * **Verification Steps:**  
1. Trigger a 500 error.  
2. Verify the response status code and body match the expected generic message.  
3. Ensure no other sensitive information is present.

### C. Logging \- Category: DE\_LOGGING

* **ID:** DE\_LOGGING\_001  
  * **Description:** Verify `StructlogMiddleware` does not log full request/response bodies by default.  
  * **Exposure Point(s):** Server logs generated by `app/logs/middleware.py`.  
  * **Test Method/Action:** Make various successful and unsuccessful API calls to all endpoints.  
  * **Prerequisites:** API running with configured logging.  
  * **Expected Secure Outcome:** Logs contain `request_id`, `method`, `path`, `query_params`, `client_ip`, `user_agent`, `status_code`, `duration_ms`. Logs do **not** contain the JSON request body or JSON response body.  
  * **Verification Steps:**  
1. Make API calls.  
2. Inspect server logs (e.g., console output or log files).  
3. Confirm absence of full request/response bodies in standard request/completion log lines.  
* **ID:** DE\_LOGGING\_002  
  * **Description:** Verify `StructlogMiddleware` logs for 500 errors include stack trace server-side only.  
  * **Exposure Point(s):** Server logs for 500 errors.  
  * **Test Method/Action:** Trigger a 500 error.  
  * **Prerequisites:** API running.  
  * **Expected Secure Outcome:** Server logs for the 500 error (identified by `request_id`) should contain the Python stack trace (`exc_info=True` behavior). The client should not receive this stack trace.  
  * **Verification Steps:**  
1. Trigger a 500 error.  
2. Verify client receives generic 500 message.  
3. Inspect server log for the corresponding `request_id` and confirm presence of stack trace.  
* **ID:** DE\_LOGGING\_003  
  * **Description:** Verify billing logs (`app/services/billing.py`) do not log sensitive prompt/response content.  
  * **Exposure Point(s):** Server logs with message "billing".  
  * **Test Method/Action:** Make successful calls to `/chat/completions` and `/embeddings` with varied (potentially mock-sensitive) inputs.  
  * **Prerequisites:** API running.  
  * **Expected Secure Outcome:** Billing logs contain `manager_id` (User UUID), `api_key.id` (APIKey int ID), `model` (ID string), and token counts. They do **not** contain the text from `messages[].content` or `input` fields, nor the LLM's generated `content` or embedding vectors.  
  * **Verification Steps:**  
1. Make API calls.  
2. Inspect server logs for "billing" entries.  
3. Verify the structure of `billing_data` logged and confirm absence of prompt/response content.  
* **ID:** DE\_LOGGING\_004  
  * **Description:** Verify provider interaction logs (e.g., Bedrock metrics) do not log full payloads.  
  * **Exposure Point(s):** Server logs from `app/providers/bedrock/bedrock.py` or `app/providers/vertex_ai/vertexai.py`.  
  * **Test Method/Action:** Make successful calls to models handled by Bedrock and Vertex AI.  
  * **Prerequisites:** API running, models from both providers configured.  
  * **Expected Secure Outcome:** Logs from provider backends should contain metrics (latency, token counts, model ID used), provider-side error codes if any, but not the full request payload sent to the provider or the full response payload received from the provider (unless at a specific DEBUG level not active in production).  
  * **Verification Steps:**  
1. Make API calls to Bedrock and Vertex models.  
2. Inspect server logs for entries related to these provider interactions.  
3. Confirm logged data is limited to metadata and metrics.  
* **ID:** DE\_LOGGING\_005  
  * **Description:** Verify that raw API keys are never logged.  
  * **Exposure Point(s):** All server logs.  
  * **Test Method/Action:** Make API calls with a valid API key. Search all logs.  
  * **Prerequisites:** API running.  
  * **Expected Secure Outcome:** The plaintext API key string (e.g., "test\_prefix\_...") is never present in any log message. Hashed keys or internal API key IDs are acceptable if needed for specific logs.  
  * **Verification Steps:**  
1. Make API calls using a known API key.  
2. Grep/search all server logs for the plaintext API key string. It should not be found.

### D. Configuration and Secrets \- Category: DE\_CONFIG

* **ID:** DE\_CONFIG\_001  
  * **Description:** Verify no API endpoint directly exposes sensitive configuration from `settings.py`.  
  * **Exposure Point(s):** All API endpoint responses.  
  * **Test Method/Action:** Call all available API endpoints with valid inputs.  
  * **Prerequisites:** API running.  
  * **Expected Secure Outcome:** No part of the API response for any endpoint should contain values like `POSTGRES_CONNECTION` string, `BEDROCK_ASSUME_ROLE`, `AWS_DEFAULT_REGION`, `VERTEX_PROJECT_ID`, or provider model ARNs.  
  * **Verification Steps:**  
1. Call each endpoint.  
2. Inspect all fields in the JSON responses.  
3. Confirm absence of any sensitive configuration values.  
* **ID:** DE\_CONFIG\_002  
  * **Description:** Verify sensitive configuration values are not logged during application startup or normal operation (unless at a highly verbose, non-production debug level).  
  * **Exposure Point(s):** Server logs during startup and request processing.  
  * **Test Method/Action:** Start the API. Make some requests. Review all logs.  
  * **Prerequisites:** API configured with real (or realistic mock) secrets in `.env` or environment.  
  * **Expected Secure Outcome:** Logs should not contain plaintext database connection strings, cloud provider secret keys/assume roles, or full model ARNs (unless an ARN is part of a non-sensitive operational log message like "routing to model ARN X").  
  * **Verification Steps:**  
1. Start the application.  
2. Make a few API calls.  
3. Review all generated server logs for any instance of secrets defined in `app/config/settings.py`.

### E. Database Storage \- Category: DE\_DB\_STORAGE

* **ID:** DE\_DB\_STORAGE\_001  
  * **Description:** Verify that only hashed API keys are stored in the database, not plaintext keys.  
  * **Exposure Point(s):** `api_keys.hashed_key` column in the database.  
  * **Test Method/Action:**  
1. Use `create_admin_user.py` to generate a new API key (note the plaintext key).  
2. Inspect the `api_keys` table in the database for the newly created record.  
   * **Prerequisites: Database access. Ability to run create\_admin\_user.py.**  
   * **Expected Secure Outcome: The hashed\_key column contains a SHA256 hash, not the plaintext API key. The key\_prefix is stored as plaintext (as intended).**  
   * **Verification Steps:**  
1. Generate a key, e.g., `test_abc123`.  
2. Manually calculate its SHA256 hash.  
3. Query the DB for the record associated with `key_prefix='test'`.  
4. Compare the stored `hashed_key` with the manually calculated hash. They should match.  
5. Confirm the plaintext key `test_abc123` is NOT in the `hashed_key` column.  
* **ID:** DE\_DB\_STORAGE\_002  
  * **Description:** Verify User PII (email, name) is stored as expected and not inadvertently exposed through non-user-management API calls.  
  * **Exposure Point(s):** `users` table in DB; API responses from `/models`, `/chat/completions`, `/embeddings`.  
  * **Test Method/Action:**  
1. Create a user.  
2. Make API calls to general endpoints using an API key associated with this user.  
3. Inspect API responses.  
   * **Prerequisites: Database access. API running.**  
   * **Expected Secure Outcome: User PII (email, name) is stored in the users table. Responses from /models, /chat/completions, /embeddings do not contain the email or name of the user associated with the API key. (The manager\_id which is a UUID might be logged for billing, which is acceptable if log access is controlled).**  
   * **Verification Steps:**  
1. Confirm PII in `users` table.  
2. Call `/models`, `/chat/completions`, `/embeddings`.  
3. Inspect responses to ensure user's `email` and `name` are not present.

**F. Data In Transit (Considerations for Test Setup & Review)**

* **ID:** DE\_TRANSIT\_001  
    
  * **Description:** Review deployment configuration to ensure HTTPS is enforced for client-API communication in production-like environments.  
  * **Exposure Point(s):** Network traffic between client and API.  
  * **Test Method/Action:** This is primarily a configuration review and test in a staged environment. Attempt to connect via HTTP to a production-like deployment.  
  * **Prerequisites:** Access to deployment configuration or a similarly configured staging environment.  
  * **Expected Secure Outcome:** HTTP requests are redirected to HTTPS, or rejected. HTTPS is enforced with strong TLS configuration.  
  * **Verification Steps:** Use tools like `curl -v http://<api_host>` and `openssl s_client -connect <api_host>:443` to check redirection and TLS details.  
* **ID:** DE\_TRANSIT\_002  
  * **Description:** Confirm (via documentation or code review of SDK usage) that API-to-Downstream (Bedrock, Vertex AI) communication uses HTTPS.  
  * **Exposure Point(s):** Network traffic between API server and LLM providers.  
  * **Test Method/Action:** Code review of `aioboto3` and `vertexai` SDK usage (they use HTTPS by default). Network sniffing in a controlled test environment if deep verification is needed (complex).  
  * **Prerequisites:** N/A for basic check.  
  * **Expected Secure Outcome:** SDKs use HTTPS.  
  * **Verification Steps:** Confirm SDK defaults or explicit HTTPS configuration in provider client setup.


* **ID:** DE\_TRANSIT\_003  
  * **Description:** Review database connection string configuration for SSL/TLS usage.  
  * **Exposure Point(s):** Network traffic between API server and PostgreSQL database.  
  * **Test Method/Action:** Review the `POSTGRES_CONNECTION` string format in `app/config/settings.py` and how it's set in `.env`/environment variables for production-like deployments.  
  * **Prerequisites:** Access to deployment configuration.  
  * **Expected Secure Outcome:** Connection string includes SSL parameters (e.g., `?ssl=require`) when the database is not on localhost or within a secure, isolated network.  
  * **Verification Steps:** Inspect the connection string.
