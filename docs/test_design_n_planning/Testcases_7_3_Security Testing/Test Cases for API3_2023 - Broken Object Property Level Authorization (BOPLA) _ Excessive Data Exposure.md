# **Test Cases for API3:2023 \- Broken Object Property Level Authorization (BOPLA) / Excessive Data Exposure**

## **Introduction**

This document outlines test cases for **API3:2023 \- Broken Object Property Level Authorization (BOPLA)**, which encompasses **Excessive Data Exposure** and **Mass Assignment** vulnerabilities, as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md". These tests aim to verify that the API only exposes intended object properties in responses and only allows modification of properties that users are authorized to change, particularly in the context of LLM interactions and configurations.  
**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 1.API3:2023)  
* docs/test\_design\_n\_planning/archive/DataExposure.md (Sections 2.A, 2.B, 2.C)  
* app/providers/base.py (LLMModel schema)  
* app/providers/open\_ai/schemas.py (ChatCompletionResponse, EmbeddingResponse schemas)  
* app/main.py (json\_500\_handler)  
* app/logs/middleware.py and app/logs/logging\_config.py

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** API3:2023 \- BOPLA / EDE  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** API responses (all endpoints), error messages, logs.  
* **Test Method/Action:** Inspect API responses for unexpected fields. Attempt to update read-only or unauthorized fields.  
* **Prerequisites:** Valid API key. Understanding of expected response schemas.  
* **Expected Secure Outcome:** API responses contain only documented and authorized fields. Attempts to modify unauthorized properties fail or are ignored. No sensitive internal details are exposed in responses, errors, or logs.  
* **Verification Steps:** Validate JSON response schemas. Check for absence of sensitive/internal fields. Verify error messages are generic. Review logs for sensitive data leakage.

## **Test Cases \- Excessive Data Exposure**

* **ID:** EDE\_MODELS\_001  
  * **Category Ref:** API3:2023 \- BOPLA / EDE  
  * **Description:** Verify /api/v1/models response exposes only necessary model fields without sensitive backend configuration.  
  * **Exposure Point(s):** GET /api/v1/models endpoint response, LLMModel schema in app/providers/base.py:16-27.  
  * **Test Method/Action:** Make a GET request to /api/v1/models.  
  * **Prerequisites:** Valid API Key (any scope sufficient for /models endpoint).  
  * **Expected Secure Outcome:** Response returns List[LLMModel] with only "name", "id", and "capability" fields. No internal ARNs, project IDs, backend configurations, or provider-specific identifiers are exposed.  
  * **Verification Steps:**  
    1. Verify HTTP 200 OK response.  
    2. Confirm response is JSON array of model objects.  
    3. For each model, verify only fields: name (str), id (str), capability ("chat" or "embedding").  
    4. Verify no internal identifiers like ARNs or project IDs in any field values.  
  * **Code Reference:** LLMModel schema in app/providers/base.py:16-27, endpoint implementation in app/routers/api_v1.py:25-30.  
* **ID:** EDE\_CHAT\_RESP\_001  
  * **Category Ref:** API3:2023 \- BOPLA / EDE  
  * **Description:** Verify /api/v1/chat/completions response strictly follows ChatCompletionResponse schema without exposing internal metadata.  
  * **Exposure Point(s):** POST /api/v1/chat/completions response, ChatCompletionResponse schema in app/providers/open_ai/schemas.py:192-202.  
  * **Test Method/Action:** Make a successful POST request to /api/v1/chat/completions.  
  * **Prerequisites:** Valid API Key with models:inference scope.  
  * **Expected Secure Outcome:** Response strictly follows ChatCompletionResponse schema with fields: object, created, model, choices, usage. No internal processing details, raw provider responses, or server configuration exposed.  
  * **Verification Steps:**  
    1. Verify HTTP 200 OK response.  
    2. Validate response schema matches ChatCompletionResponse exactly.  
    3. Confirm fields: object="chat.completion", created (timestamp), model (string), choices (array), usage (object).  
    4. Verify choices[0] contains: index, message (role="assistant", content), finish_reason.  
    5. Verify usage contains: prompt_tokens, completion_tokens, total_tokens.  
    6. Confirm no additional internal fields are present.  
  * **Code Reference:** ChatCompletionResponse schema in app/providers/open_ai/schemas.py:192-202, response generation in provider adapters.  
* **ID:** EDE\_EMBED\_RESP\_001  
  * **Category Ref:** API3:2023 \- BOPLA / EDE  
  * **Description:** Verify /api/v1/embeddings response follows EmbeddingResponse schema without exposing input text or internal metadata.  
  * **Exposure Point(s):** POST /api/v1/embeddings response, EmbeddingResponse schema in app/providers/open_ai/schemas.py:294-308.  
  * **Test Method/Action:** Make a successful POST request to /api/v1/embeddings with specific input text.  
  * **Prerequisites:** Valid API Key with models:embedding scope.  
  * **Expected Secure Outcome:** Response follows EmbeddingResponse schema exactly. Original input text is not echoed. No internal processing details exposed.  
  * **Verification Steps:**  
    1. Verify HTTP 200 OK response.  
    2. Validate response schema: object="list", data (array), model (string), usage (object).  
    3. Verify data array contains EmbeddingData objects with: object="embedding", embedding (float array), index.  
    4. Verify usage contains: prompt_tokens, total_tokens.  
    5. Confirm original input text is NOT present anywhere in response.  
    6. Verify no additional internal fields.  
  * **Code Reference:** EmbeddingResponse schema in app/providers/open_ai/schemas.py:294-308, EmbeddingData schema at lines 269-279.  
* **ID:** EDE\_ERROR\_MSG\_001  
  * **Category Ref:** API3:2023 \- BOPLA / EDE  
  * **Description:** Verify error responses do not expose sensitive system details, stack traces, or internal configuration.  
  * **Exposure Point(s):** Error response handling in app/main.py:57-99, FastAPI automatic error responses, provider error handling.  
  * **Test Method/Action:** Trigger various error conditions:  
    1. 422 Pydantic validation (invalid temperature: "string").  
    2. 400 InvalidInput error (malformed image data URI).  
    3. 401 Authentication error (invalid API key).  
    4. 403 Authorization error (wrong scope).  
    5. 500 Internal server error (mock provider failure).  
  * **Prerequisites:** Ability to craft invalid requests and mock internal failures.  
  * **Expected Secure Outcome:** Error responses contain minimal, safe information. 500 errors use generic handler format. No stack traces, file paths, or internal details exposed.  
  * **Verification Steps:**  
    1. Test each error type systematically.  
    2. Verify 500 errors return: {"detail": "Internal Server Error", "request_id": "<uuid>"}.  
    3. Verify 422 errors show field validation details but no internal implementation.  
    4. Verify 400 errors from InvalidInput are appropriately generic.  
    5. Confirm no stack traces, database details, or file paths in any error.  
  * **Code Reference:** Error handlers in app/main.py:57-99, json_500_handler at lines 84-99, InvalidInput handling in app/routers/api_v1.py:55-59.  
* **ID:** EDE\_LOGS\_001  
  * **Category Ref:** API3:2023 \- BOPLA / EDE  
  * **Description:** Verify server logs do not expose sensitive data like prompts, responses, or raw API keys at production log levels.  
  * **Exposure Point(s):** StructlogMiddleware logging in app/logs/middleware.py:11-47, logging configuration in app/logs/logging_config.py:11-48, billing logs in app/services/billing.py:13.  
  * **Test Method/Action:** Make API calls with identifiable sensitive data in prompts and inspect server logs at INFO level.  
  * **Prerequisites:** API running with INFO log level. Access to application logs.  
  * **Expected Secure Outcome:** INFO-level logs contain only metadata (request_id, method, path, status_code, duration_ms, key_id). No prompt content, response content, or raw API keys are logged.  
  * **Verification Steps:**  
    1. Make chat/completion request with identifiable prompt content.  
    2. Review logs for "Request started" and "Request completed" entries.  
    3. Verify logs contain only: request_id, method, path, client_ip, user_agent, status_code, duration_ms, key_id.  
    4. Confirm no prompt/response content is present.  
    5. Confirm raw API keys are never logged (only key_id from request.state).  
    6. Verify billing logs contain metadata only, not content.  
  * **Code Reference:** StructlogMiddleware in app/logs/middleware.py:17-27 (request), 37-44 (completion), key_id logging at line 38, billing logs in app/services/billing.py:13.

## **Test Cases \- Mass Assignment (Less directly applicable to LLM proxy, but consider related concepts)**

The current API primarily proxies requests to LLMs and doesn't involve direct creation or complex modification of rich domain objects by users via the LLM endpoints themselves. API key creation (app/routers/tokens.py) and user creation (app/routers/users.py) are admin-only. However, we can consider "mass assignment" in the context of LLM parameters or future features.

* **ID:** MA\_LLM\_PARAMS\_001  
  * **Category Ref:** API3:2023 \- BOPLA / Mass Assignment  
  * **Description:** Test protection against mass assignment by including undocumented fields in LLM parameter requests.  
  * **Exposure Point(s):** ChatCompletionRequest parsing in app/providers/open_ai/schemas.py:95-164, EmbeddingRequest parsing at lines 206-264.  
  * **Test Method/Action:** Send requests with extra, undocumented fields:  
    1. POST /api/v1/chat/completions with additional fields: {"internal_provider_knob": "value", "debug_mode": true}.  
    2. POST /api/v1/embeddings with extra fields: {"secret_parameter": "test", "admin_override": true}.  
  * **Prerequisites:** Valid API Key with appropriate scopes.  
  * **Expected Secure Outcome:** Pydantic models ignore extra fields due to ConfigDict(extra="ignore") or default behavior. Extra fields are not passed to core logic or providers. Request succeeds based on valid fields only.  
  * **Verification Steps:**  
    1. Send requests with valid + extra fields.  
    2. Verify API returns 200 OK when valid fields are correct.  
    3. Verify response is identical to request without extra fields.  
    4. Confirm extra fields don't affect LLM provider calls.  
    5. Verify no error caused by extra fields presence.  
  * **Code Reference:** Pydantic extra field handling in schemas, ConfigDict settings in app/providers/open_ai/schemas.py model configurations.  
* **ID:** EDE\_STREAM\_RESP\_001
  * **Category Ref:** API3:2023 \- BOPLA / EDE
  * **Description:** Verify streaming chat completion responses do not expose internal metadata or processing details in stream chunks.
  * **Exposure Point(s):** POST /api/v1/chat/completions with stream=true, server-sent events, provider stream handling in adapters.
  * **Test Method/Action:** Make a streaming chat completion request and inspect each SSE chunk for excessive data exposure.
  * **Prerequisites:** Valid API Key with models:inference scope.
  * **Expected Secure Outcome:** Stream chunks contain only: data field with ChatCompletionStreamResponse format, no internal processing details, no provider-specific metadata.
  * **Verification Steps:**
    1. Send POST /api/v1/chat/completions with stream=true.
    2. Parse each "data: {...}" SSE chunk.
    3. Verify chunks follow format: {"object": "chat.completion.chunk", "created": timestamp, "model": string, "choices": [...]}.
    4. Verify choices contain only: index, delta (role/content), finish\_reason.
    5. Confirm no internal timing, provider response metadata, or processing details.
    6. Verify final chunk with "data: [DONE]" format.
  * **Code Reference:** Stream handling in provider adapters, SSE response formatting.

* **ID:** EDE\_CORS\_HEADERS\_001
  * **Category Ref:** API3:2023 \- BOPLA / EDE
  * **Description:** Verify CORS headers and OPTIONS responses do not expose sensitive server configuration.
  * **Exposure Point(s):** CORS middleware configuration, OPTIONS request responses, server headers.
  * **Test Method/Action:** Send OPTIONS requests to API endpoints and inspect response headers.
  * **Prerequisites:** None (OPTIONS requests don't require authentication).
  * **Expected Secure Outcome:** CORS headers reveal minimal information. No internal server details, file paths, or configuration exposed in headers.
  * **Verification Steps:**
    1. Send OPTIONS /api/v1/chat/completions.
    2. Inspect response headers: Access-Control-\*, Allow, Content-Type only.
    3. Verify no Server, X-Powered-By, or custom headers with internal details.
    4. Confirm no file paths, version numbers, or configuration details in headers.
  * **Code Reference:** CORS configuration in FastAPI application setup, middleware headers.

* **ID:** EDE\_HEALTH\_CHECK\_001
  * **Category Ref:** API3:2023 \- BOPLA / EDE
  * **Description:** Verify health check or status endpoints do not expose sensitive system information.
  * **Exposure Point(s):** Root endpoint GET /, any health/status endpoints, system information disclosure.
  * **Test Method/Action:** Query root and potential health endpoints for excessive system information.
  * **Prerequisites:** None (health endpoints typically public).
  * **Expected Secure Outcome:** Health responses contain minimal status information only. No database details, internal IPs, file paths, or system configuration.
  * **Verification Steps:**
    1. GET / and inspect response.
    2. Try common health endpoints: /health, /status, /ping, /.well-known/.
    3. Verify responses contain only basic status ("OK", timestamp).
    4. Confirm no database connection strings, internal URLs, file paths, or system details.
  * **Code Reference:** Root endpoint in app/routers/root.py, health check implementations.

* **ID:** EDE\_VALIDATION\_ERRORS\_001
  * **Category Ref:** API3:2023 \- BOPLA / EDE
  * **Description:** Verify Pydantic validation errors do not expose internal model structure or implementation details.
  * **Exposure Point(s):** 422 Validation Error responses, Pydantic error formatting, FastAPI automatic validation.
  * **Test Method/Action:** Send malformed requests to trigger various Pydantic validation errors.
  * **Prerequisites:** Various invalid request payloads.
  * **Expected Secure Outcome:** Validation errors show field names and constraint violations only. No internal class names, file paths, or implementation details.
  * **Verification Steps:**
    1. Send invalid temperature (string instead of float) to /api/v1/chat/completions.
    2. Send missing required fields to trigger validation.
    3. Send invalid enum values, array types, nested object errors.
    4. Verify error format: {"detail": [{"loc": ["field"], "msg": "constraint", "type": "value\_error"}]}.
    5. Confirm no Python class names, file paths, or internal model structure.
  * **Code Reference:** Pydantic validation in request schemas, FastAPI error handling.

* **ID:** EDE\_PROVIDER\_ERRORS\_001
  * **Category Ref:** API3:2023 \- BOPLA / EDE
  * **Description:** Verify provider errors are sanitized and do not expose backend service details.
  * **Exposure Point(s):** Provider error handling in adapters, backend service error responses, error translation layers.
  * **Test Method/Action:** Trigger provider errors (invalid model, quota exceeded, service unavailable) and inspect error responses.
  * **Prerequisites:** Ability to trigger provider errors (invalid requests, service disruption).
  * **Expected Secure Outcome:** Provider errors are translated to generic API errors. No AWS ARNs, GCP project IDs, Azure resource details, or backend URLs exposed.
  * **Verification Steps:**
    1. Send request with invalid model name to trigger provider error.
    2. Test quota/rate limit exceeded scenarios.
    3. Mock provider service unavailable errors.
    4. Verify errors return generic format: {"detail": "Model not available", "request\_id": "uuid"}.
    5. Confirm no backend service URLs, credentials, or internal identifiers.
  * **Code Reference:** Provider error handling in adapter classes, error translation logic.

* **ID:** EDE\_TIMING\_ATTACKS\_001
  * **Category Ref:** API3:2023 \- BOPLA / EDE
  * **Description:** Verify response timing does not reveal sensitive information about data existence or internal processing.
  * **Exposure Point(s):** Response time variations based on data size, existence checks, database queries.
  * **Test Method/Action:** Measure response times for various scenarios to detect timing-based information disclosure.
  * **Prerequisites:** Ability to make timed requests and statistical analysis.
  * **Expected Secure Outcome:** Response times should not reveal information about data existence, user count, or internal processing complexity.
  * **Verification Steps:**
    1. Time responses for existing vs non-existing resources.
    2. Measure processing time variations for different input sizes.
    3. Test authentication timing for valid vs invalid API keys.
    4. Verify consistent timing patterns don't reveal internal state.
  * **Code Reference:** Database query patterns, authentication logic, response generation timing.

* **ID:** EDE\_METADATA\_HEADERS\_001
  * **Category Ref:** API3:2023 \- BOPLA / EDE
  * **Description:** Verify HTTP response headers do not expose sensitive metadata or internal system information.
  * **Exposure Point(s):** All API response headers, middleware-added headers, server identification headers.
  * **Test Method/Action:** Inspect response headers across all endpoints for sensitive information disclosure.
  * **Prerequisites:** Access to inspect HTTP response headers.
  * **Expected Secure Outcome:** Response headers contain minimal necessary information. No server versions, internal IPs, file paths, or processing details.
  * **Verification Steps:**
    1. Inspect headers from all major endpoints (/models, /chat/completions, /embeddings).
    2. Verify standard headers only: Content-Type, Content-Length, Date.
    3. Confirm no X-Powered-By, Server version, X-Request-ID with sensitive data.
    4. Verify no custom headers exposing internal processing information.
  * **Code Reference:** FastAPI default headers, middleware header configuration.

* **ID:** MA\_MODEL\_CONFIG\_001 (Hypothetical for future features)  
  * **Category Ref:** API3:2023 \- BOPLA / Mass Assignment  
  * **Description:** If a feature allowed users to configure aspects of a model (e.g., a custom system prompt template for an agency, or fine-tuning parameters), test if a user can set properties they are not authorized to modify (e.g., changing the base model for a fine-tune, setting global rate limits).  
  * **Exposure Point(s):** Hypothetical model configuration endpoint.  
  * **Test Method/Action:** Attempt to POST/PUT to such an endpoint with payload including unauthorized properties.  
  * **Prerequisites:** Aforementioned hypothetical feature.  
  * **Expected Secure Outcome:** The API should only allow modification of designated, user-configurable properties. Attempts to set or change restricted properties should be rejected (e.g., 400 or 422 error) or silently ignored if the design prefers that.  
  * **Verification Steps:**  
    1. Verify error response or check that the unauthorized properties were not updated.