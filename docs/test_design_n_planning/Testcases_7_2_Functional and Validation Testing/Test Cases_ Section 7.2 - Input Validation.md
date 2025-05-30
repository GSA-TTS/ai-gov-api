# **Test Cases: Section 7.2 \- Input Validation**

This document outlines test cases for Input Validation as per the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_INP\_...)  
* **Category Ref:** (e.g., FV\_INP\_STD\_PARAM, FV\_INP\_BOUNDARY, FV\_INP\_TYPE, FV\_INP\_DATA\_URI)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** API endpoint, request body field, or query parameter.  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** e.g., Valid API Key with necessary scope.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (typically a 4xx error with a descriptive message).  
* **Verification Steps:** How to confirm the expected secure outcome.

## **1\. Standard Parameter Validation (Chat Completions)**

These tests target the /chat/completions endpoint.

### **FV\_INP\_CHAT\_MODEL\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with an incorrectly formatted model ID (e.g., contains spaces, special characters not allowed by providers).  
* **Exposure Point(s):** /chat/completions endpoint, model field in request body.  
* **Test Method/Action:** Make a POST request to /chat/completions with a payload containing an invalid model ID (e.g., "gpt 3.5 turbo" instead of "gpt-3.5-turbo", or a model ID not in settings.backend\_map).  
* **Prerequisites:** Valid API Key with models:inference scope (corrected from models:chat based on app/auth/schemas.py:MODELS_INFERENCE).  
* **Expected Secure Outcome:** API returns a 400 Bad Request error if the model is not found/configured in backend_map (handled by app/providers/dependencies.py), or processed by provider if format is structurally valid but unsupported.  
* **Verification Steps:** Assert HTTP status code is 400. Assert response JSON contains an error message indicating an invalid or unknown model ID.  
* **Code Reference:** app/providers/dependencies.py handles model validation, app/config/settings.py contains backend_map configuration.

### **FV\_INP\_CHAT\_MODEL\_002**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with model ID as a non-string type (e.g., integer, boolean).  
* **Exposure Point(s):** /chat/completions endpoint, model field in request body.  
* **Test Method/Action:** Make a POST request to /chat/completions with a payload where model is 123 or true.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error with a message indicating the model field must be a string.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for the model field.

### **FV\_INP\_CHAT\_MSG\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with messages array containing an object with an invalid role.  
* **Exposure Point(s):** /chat/completions endpoint, messages.role field in request body.  
* **Test Method/Action:** Make a POST request to /chat/completions with messages: \[{"role": "invalid\_role", "content": "Hello"}\].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error with a message indicating the invalid role. (Valid roles: "system", "user", "assistant", "tool").  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the error for the role field (e.g., not a valid Literal).

### **FV\_INP\_CHAT\_MSG\_002**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with messages array containing an object missing the content field (for roles that require it).  
* **Exposure Point(s):** /chat/completions endpoint, messages objects in request body.  
* **Test Method/Action:** Make a POST request to /chat/completions with messages: \[{"role": "user"}\].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error with a message indicating content is a required field for the user role.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the missing content field.

### **FV\_INP\_CHAT\_MSG\_003**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with messages array containing an object with content of an incorrect type (e.g., integer instead of string or list for multi-modal).  
* **Exposure Point(s):** /chat/completions endpoint, messages.content field.  
* **Test Method/Action:** Make a POST request to /chat/completions with messages: \[{"role": "user", "content": 123}\].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error with a message indicating content type is invalid.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for content.

### **FV\_INP\_CHAT\_MSG\_004**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with messages array not being a list.  
* **Exposure Point(s):** /chat/completions endpoint, messages field.  
* **Test Method/Action:** Make a POST request to /chat/completions with messages: {"role": "user", "content": "Hello"}.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error with a message indicating messages must be a list.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for messages.

### **FV\_INP\_CHAT\_TEMP\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with temperature parameter having an invalid type (e.g., string).  
* **Exposure Point(s):** /chat/completions endpoint, temperature field in request body.  
* **Test Method/Action:** Make a POST request with temperature: "high".  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for temperature.

### **FV\_INP\_CHAT\_MAXTOK\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with max\_tokens parameter having an invalid type (e.g., float).  
* **Exposure Point(s):** /chat/completions endpoint, max\_tokens field in request body.  
* **Test Method/Action:** Make a POST request with max\_tokens: 100.5.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for max\_tokens.

### **FV\_INP\_CHAT\_STREAM\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with stream parameter having an invalid type (e.g., string "true").  
* **Exposure Point(s):** /chat/completions endpoint, stream field in request body.  
* **Test Method/Action:** Make a POST request with stream: "true".  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for stream.

### **FV\_INP\_CHAT\_TOPP\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with top\_p parameter having an invalid type (e.g., string).  
* **Exposure Point(s):** /chat/completions endpoint, top\_p field in request body.  
* **Test Method/Action:** Make a POST request with top\_p: "high".  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for top\_p.

## **2\. Standard Parameter Validation (Embeddings)**

These tests target the /embeddings endpoint.

### **FV\_INP\_EMBED\_MODEL\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with an incorrectly formatted model ID for embeddings.  
* **Exposure Point(s):** /embeddings endpoint, model field in request body.  
* **Test Method/Action:** Make a POST request to /embeddings with an invalid model ID (e.g., "text embedding ada" or a model ID not configured for embeddings).  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** API returns a 422 or 400/404 error with a clear message.  
* **Verification Steps:** Assert HTTP status code (422, 400, or 404). Assert response JSON indicates an invalid or unknown model ID for embeddings.

### **FV\_INP\_EMBED\_INPUT\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with input field having an invalid type (e.g., integer, object). Valid types are string or list of strings.  
* **Exposure Point(s):** /embeddings endpoint, input field in request body.  
* **Test Method/Action:** Make a POST request to /embeddings with input: 12345\.  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for input.

### **FV\_INP\_EMBED\_INPUT\_002**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with input as a list containing non-string elements.  
* **Exposure Point(s):** /embeddings endpoint, input field in request body.  
* **Test Method/Action:** Make a POST request to /embeddings with input: \["text1", 123, "text2"\].  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for elements within the input list.

### **FV\_INP\_EMBED\_DIMS\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with dimensions field having an invalid type (e.g., string) if the model supports it.  
* **Exposure Point(s):** /embeddings endpoint, dimensions field in request body.  
* **Test Method/Action:** Make a POST request to /embeddings with dimensions: "small" (assuming a model that accepts dimensions as an integer).  
* **Prerequisites:** Valid API Key with models:embedding scope; Model selected supports dimensions parameter.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for dimensions.

## **3\. Boundary Value Validation (Chat Completions)**

### **FV\_INP\_CHAT\_MSG\_BOUNDARY\_001**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with messages array being empty (if not allowed by Pydantic min\_length=1 or similar constraint).  
* **Exposure Point(s):** /chat/completions endpoint, messages field.  
* **Test Method/Action:** Make a POST request with messages: \[\].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error if messages cannot be empty.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON indicates messages list constraint violation.

### **FV\_INP\_CHAT\_MSG\_BOUNDARY\_002**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with messages array containing a message with empty content string.  
* **Exposure Point(s):** /chat/completions endpoint, messages.content field.  
* **Test Method/Action:** Make a POST request with messages: \[{"role": "user", "content": ""}\].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API processes the request (empty content might be valid for some models/scenarios) or returns a 4xx error if specific model/provider disallows empty content string and the API framework enforces this. (This might be more of a provider behavior test, but good to check API's reaction). If Pydantic schema min\_length=1 for content, then 422\.  
* **Verification Steps:** Observe API response. If 422, verify error message. If 200, verify LLM response is sensible for empty content.

### **FV\_INP\_CHAT\_MAXTOK\_BOUNDARY\_001**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with max\_tokens set to 0\.  
* **Exposure Point(s):** /chat/completions endpoint, max\_tokens field.  
* **Test Method/Action:** Make a POST request with max\_tokens: 0\.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error because max_tokens is defined as PositiveInt (gt=0) in app/providers/open_ai/schemas.py:141.  
* **Verification Steps:** Assert HTTP status code is 422. Assert response JSON details the validation error for max_tokens (value must be greater than 0).  
* **Code Reference:** app/providers/open_ai/schemas.py:141 defines max_tokens as PositiveInt.

### **FV\_INP\_CHAT\_MAXTOK\_BOUNDARY\_002**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with max\_tokens set to 1\.  
* **Exposure Point(s):** /chat/completions endpoint, max\_tokens field.  
* **Test Method/Action:** Make a POST request with max\_tokens: 1\.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 200 OK with a completion of 1 token.  
* **Verification Steps:** Assert HTTP status code is 200\. Assert usage.completion\_tokens is 1 (or consistent with model behavior for 1 token) and choices\[0\].message.content contains a single token. finish\_reason is likely 'length'.

### **FV\_INP\_CHAT\_MAXTOK\_BOUNDARY\_003**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with max\_tokens set to a very large value (e.g., larger than model's context window or typical output).  
* **Exposure Point(s):** /chat/completions endpoint, max\_tokens field.  
* **Test Method/Action:** Make a POST request with max\_tokens: 100000\.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 200 OK. The provider will cap max\_tokens at its maximum allowed, or the model's context limit for generation. finish\_reason might be 'length' if capped by this large value, or 'stop' if generation finishes naturally sooner.  
* **Verification Steps:** Assert HTTP status code is 200\. Inspect usage.completion\_tokens to see actual tokens generated (should be \<= provider's limit).

### **FV\_INP\_CHAT\_TEMP\_BOUNDARY\_001**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with temperature set to 0.0.  
* **Exposure Point(s):** /chat/completions endpoint, temperature field.  
* **Test Method/Action:** Make a POST request with temperature: 0.0.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 200 OK. Response should be (near) deterministic for repeated identical requests.  
* **Verification Steps:** Assert HTTP status code is 200\. Make multiple identical requests and verify content is highly similar or identical.

### **FV\_INP\_CHAT\_TEMP\_BOUNDARY\_002**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with temperature set to 2.0 (max typical value).  
* **Exposure Point(s):** /chat/completions endpoint, temperature field.  
* **Test Method/Action:** Make a POST request with temperature: 2.0.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 200 OK. Response should be highly variable/creative.  
* **Verification Steps:** Assert HTTP status code is 200\. Make multiple identical requests and verify content is diverse.

### **FV\_INP\_CHAT\_TEMP\_BOUNDARY\_003**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with temperature outside valid range (e.g., \-0.5 or 2.1).  
* **Exposure Point(s):** /chat/completions endpoint, temperature field.  
* **Test Method/Action:** Make a POST request with temperature: 2.1 (exceeds maximum) or temperature: -0.5 (below minimum).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error due to Field constraints ge=0, le=2 in app/providers/open_ai/schemas.py:112-117.  
* **Verification Steps:** Assert HTTP status code is 422. Assert error message indicates value must be between 0 and 2.  
* **Code Reference:** app/providers/open_ai/schemas.py:112-117 defines temperature with ge=0, le=2 constraints.

## **4\. Boundary Value Validation (Embeddings)**

### **FV\_INP\_EMBED\_INPUT\_BOUNDARY\_001**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with input as an empty string.  
* **Exposure Point(s):** /embeddings endpoint, input field.  
* **Test Method/Action:** Make a POST request with input: "".  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity if Pydantic schema has min\_length=1 for input string. Otherwise, provider might error or return a specific embedding for empty string.  
* **Verification Steps:** Assert HTTP status code (e.g., 422 or 200). If 200, inspect embedding.

### **FV\_INP\_EMBED\_INPUT\_BOUNDARY\_002**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with input as a list containing an empty string \[""\].  
* **Exposure Point(s):** /embeddings endpoint, input field.  
* **Test Method/Action:** Make a POST request with input: \[""\].  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** Similar to above, depends on schema/provider handling of empty strings within a list.  
* **Verification Steps:** Assert HTTP status code. If 200, inspect embedding.

### **FV\_INP\_EMBED\_INPUT\_BOUNDARY\_003**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with input as an empty list \[\].  
* **Exposure Point(s):** /embeddings endpoint, input field.  
* **Test Method/Action:** Make a POST request with input: \[\].  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error if input list has min\_length=1 constraint. Otherwise, provider dependent.  
* **Verification Steps:** Assert HTTP status code is 422 or observe provider behavior.

### **FV\_INP\_EMBED\_INPUT\_BOUNDARY\_004**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with input as an extremely long string (approaching provider token limits for embeddings).  
* **Exposure Point(s):** /embeddings endpoint, input field.  
* **Test Method/Action:** Make a POST request with input: "long string..." (e.g., 10,000 characters).  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** API returns 200 OK with embedding, or a provider error (e.g., 400\) if input exceeds limits, which should be translated by the API.  
* **Verification Steps:** Assert HTTP status code. If 200, verify embedding. If 4xx, verify error message.

### **FV\_INP\_EMBED\_INPUT\_BOUNDARY\_005**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with input as a list with a very large number of strings (e.g., 2049 if provider limit is 2048).  
* **Exposure Point(s):** /embeddings endpoint, input field.  
* **Test Method/Action:** Make a POST request with input: \["text1", "text2", ..., "text2049"\].  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** API returns 4xx error (e.g. 400 Bad Request or 413 Payload Too Large, depending on how provider limit is enforced/translated) if batch size limit is exceeded. Pydantic might have max\_length on list.  
* **Verification Steps:** Assert HTTP status code and error message.

## **5\. Type Validation (General \- Pydantic handled)**

These are generic tests applicable to many fields. Pydantic handles most of these. The goal is to confirm Pydantic's 422 responses are correctly generated and informative.

### **FV\_INP\_TYPE\_001**

* **Category Ref:** FV\_INP\_TYPE  
* **Description:** Test sending an integer where a string is expected for a common field (e.g., model in chat/embeddings, or messages\[0\].content).  
* **Exposure Point(s):** Various string fields across /chat/completions, /embeddings.  
* **Test Method/Action:** Make a request with model: 123 or messages: \[{"role":"user", "content": 123}\].  
* **Prerequisites:** Valid API Key.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for the specific field.

### **FV\_INP\_TYPE\_002**

* **Category Ref:** FV\_INP\_TYPE  
* **Description:** Test sending a string where a number (int/float) is expected (e.g., temperature, max\_tokens).  
* **Exposure Point(s):** Numeric fields like temperature, max\_tokens in /chat/completions.  
* **Test Method/Action:** Make a request with temperature: "high" or max\_tokens: "one hundred".  
* **Prerequisites:** Valid API Key.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for the specific field.

### **FV\_INP\_TYPE\_003**

* **Category Ref:** FV\_INP\_TYPE  
* **Description:** Test sending a string where a boolean is expected (e.g., stream).  
* **Exposure Point(s):** Boolean fields like stream in /chat/completions.  
* **Test Method/Action:** Make a request with stream: "false".  
* **Prerequisites:** Valid API Key.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for stream.

### **FV\_INP\_TYPE\_004**

* **Category Ref:** FV\_INP\_TYPE  
* **Description:** Test sending an object where a list is expected (e.g., messages in chat, input if it's a list for embeddings).  
* **Exposure Point(s):** List fields like messages or input (list variant).  
* **Test Method/Action:** Make a request with messages: {"role":"user", "content":"hi"}.  
* **Prerequisites:** Valid API Key.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error.  
* **Verification Steps:** Assert HTTP status code is 422\. Assert response JSON details the type error for the specific field.

## **6\. Data URI Validation (Chat Completions \- Multi-modal)**

These tests target the parse\_data\_uri utility via the /chat/completions endpoint when image data is provided. This assumes messages.content can be a list of content parts, one of which is an image URL as a data URI.

### **FV\_INP\_DATA\_URI\_001**

* **Category Ref:** FV\_INP\_DATA\_URI  
* **Description:** Test with a malformed data URI (e.g., missing 'data:', incorrect media type prefix).  
* **Exposure Point(s):** /chat/completions endpoint, messages.content\[type=image\_url\].image\_url.url field.  
* **Test Method/Action:** Make a POST request with content part: {"type": "image\_url", "image\_url": {"url": "datamissing:image/png;base64,..."}}.  
* **Prerequisites:** Valid API Key with models:inference scope; Model supports image input.  
* **Expected Secure Outcome:** API returns a 400 Bad Request error with message "Invalid or unsupported image data URI format. Must be data:image/[jpeg|png|gif|webp];base64,..." (from InvalidImageURLError in app/providers/utils.py:12).  
* **Verification Steps:** Assert HTTP status code is 400. Assert response JSON contains the expected error message.  
* **Code Reference:** app/providers/utils.py:8-22 implements parse_data_uri validation, app/routers/api_v1.py:55-59 handles InvalidInput exceptions with 400 status.

### **FV\_INP\_DATA\_URI\_002**

* **Category Ref:** FV\_INP\_DATA\_URI  
* **Description:** Test with a data URI having an unsupported media type (e.g., image/unsupported).  
* **Exposure Point(s):** /chat/completions endpoint, messages.content\[type=image\_url\].image\_url.url field.  
* **Test Method/Action:** Make a POST request with content part: {"type": "image\_url", "image\_url": {"url": "data:image/unsupported;base64,..."}}.  
* **Prerequisites:** Valid API Key with models:chat scope; Model supports image input.  
* **Expected Secure Outcome:** API returns a 400 Bad Request error with a message like "Unsupported media type" (from InputDataError).  
* **Verification Steps:** Assert HTTP status code is 400\. Assert response JSON contains the expected error message.

### **FV\_INP\_DATA\_URI\_003**

* **Category Ref:** FV\_INP\_DATA\_URI  
* **Description:** Test with a data URI that is not base64 encoded when it claims to be.  
* **Exposure Point(s):** /chat/completions endpoint, messages.content\[type=image\_url\].image\_url.url field.  
* **Test Method/Action:** Make a POST request with content part: {"type": "image\_url", "image\_url": {"url": "data:image/png;base64,thisisnotbase64\!\!\!"}}.  
* **Prerequisites:** Valid API Key with models:chat scope; Model supports image input.  
* **Expected Secure Outcome:** API returns a 400 Bad Request error with a message indicating invalid base64 data (from InputDataError due to binascii.Error).  
* **Verification Steps:** Assert HTTP status code is 400\. Assert response JSON contains the expected error message.

### **FV\_INP\_DATA\_URI\_004**

* **Category Ref:** FV\_INP\_DATA\_URI  
* **Description:** Test with a valid data URI (correct format, supported media type, valid base64).  
* **Exposure Point(s):** /chat/completions endpoint, messages.content\[type=image\_url\].image\_url.url field.  
* **Test Method/Action:** Make a POST request with a small, valid base64 encoded PNG or JPEG data URI.  
* **Prerequisites:** Valid API Key with models:chat scope; Model supports image input.  
* **Expected Secure Outcome:** API returns 200 OK and the request is processed by the LLM.  
* **Verification Steps:** Assert HTTP status code is 200\. Verify the LLM response (if possible, that it acknowledges an image).

## **7\. Schema Evolution (Forward Compatibility)**

### **FV\_INP\_SCHEMA\_EVOL\_001**

* **Category Ref:** FV\_INP\_SCHEMA\_EVOL  
* **Description:** Test sending an unknown/extra field in the request body for /chat/completions.  
* **Exposure Point(s):** /chat/completions endpoint, request body.  
* **Test Method/Action:** Make a POST request to /chat/completions with a valid payload plus an extra field like "unknown\_parameter": "some\_value".  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns 200 OK, ignoring the unknown field (default Pydantic behavior if not configured to error). The request is processed successfully based on known fields.  
* **Verification Steps:** Assert HTTP status code is 200\. Verify the response is as expected for the valid parts of the payload. Confirm no error related to the unknown field.

### **FV\_INP\_SCHEMA\_EVOL\_002**

* **Category Ref:** FV\_INP\_SCHEMA\_EVOL  
* **Description:** Test sending an unknown/extra field in the request body for /embeddings.  
* **Exposure Point(s):** /embeddings endpoint, request body.  
* **Test Method/Action:** Make a POST request to /embeddings with a valid payload plus an extra field like "unknown\_parameter": "some\_value".  
* **Prerequisites:** Valid API Key with models:embedding scope.  
* **Expected Secure Outcome:** API returns 200 OK, ignoring the unknown field. The request is processed successfully.  
* **Verification Steps:** Assert HTTP status code is 200\. Verify the response is as expected for the valid parts of the payload.

## **8\. Additional Parameter Validation Tests**

### **FV\_INP\_CHAT\_TOPP\_BOUNDARY\_001**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with top\_p outside valid range (0-1).  
* **Exposure Point(s):** /chat/completions endpoint, top\_p field.  
* **Test Method/Action:** Make a POST request with top\_p: 1.5 (exceeds maximum) or top\_p: -0.1 (below minimum).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error due to Field constraints ge=0, le=1 in app/providers/open_ai/schemas.py:119-124.  
* **Verification Steps:** Assert HTTP status code is 422. Assert error message indicates value must be between 0 and 1.  
* **Code Reference:** app/providers/open_ai/schemas.py:119-124 defines top_p with ge=0, le=1 constraints.

### **FV\_INP\_CHAT\_PENALTY\_BOUNDARY\_001**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with presence_penalty outside valid range (-2.0 to 2.0).  
* **Exposure Point(s):** /chat/completions endpoint, presence\_penalty field.  
* **Test Method/Action:** Make a POST request with presence\_penalty: 2.5 (exceeds maximum) or presence\_penalty: -2.5 (below minimum).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error due to Field constraints ge=-2.0, le=2.0 in app/providers/open_ai/schemas.py:146-151.  
* **Verification Steps:** Assert HTTP status code is 422. Assert error message indicates value must be between -2.0 and 2.0.  
* **Code Reference:** app/providers/open_ai/schemas.py:146-151 defines presence_penalty constraints.

### **FV\_INP\_CHAT\_PENALTY\_BOUNDARY\_002**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with frequency_penalty outside valid range (-2.0 to 2.0).  
* **Exposure Point(s):** /chat/completions endpoint, frequency\_penalty field.  
* **Test Method/Action:** Make a POST request with frequency\_penalty: 3.0 (exceeds maximum) or frequency\_penalty: -3.0 (below minimum).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error due to Field constraints ge=-2.0, le=2.0 in app/providers/open_ai/schemas.py:153-158.  
* **Verification Steps:** Assert HTTP status code is 422. Assert error message indicates value must be between -2.0 and 2.0.  
* **Code Reference:** app/providers/open_ai/schemas.py:153-158 defines frequency_penalty constraints.

### **FV\_INP\_EMBED\_DIMS\_BOUNDARY\_001**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with dimensions set to 0 or negative value.  
* **Exposure Point(s):** /embeddings endpoint, dimensions field.  
* **Test Method/Action:** Make a POST request with dimensions: 0 or dimensions: -1.  
* **Prerequisites:** Valid API Key with models:embedding scope; Model that supports dimensions parameter.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error because dimensions is defined as PositiveInt (gt=0) in app/providers/open_ai/schemas.py:229.  
* **Verification Steps:** Assert HTTP status code is 422. Assert response JSON details the validation error for dimensions.  
* **Code Reference:** app/providers/open_ai/schemas.py:229 defines dimensions as PositiveInt.

## **9\. Content Validation Tests**

### **FV\_INP\_CHAT\_CONTENT\_MULTIMODAL\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with invalid multimodal content structure (mixed text and non-text in content array).  
* **Exposure Point(s):** /chat/completions endpoint, messages.content field when it's a list.  
* **Test Method/Action:** Make a POST request with messages: [{"role": "user", "content": [{"type": "text", "text": "Hello"}, {"type": "invalid_type", "data": "something"}]}].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error due to invalid ContentPart discriminator.  
* **Verification Steps:** Assert HTTP status code is 422. Assert error message indicates invalid content part type.  
* **Code Reference:** app/providers/open_ai/schemas.py:66 defines ContentPart Union with specific types.

### **FV\_INP\_CHAT\_CONTENT\_EMPTY\_TEXT\_001**

* **Category Ref:** FV\_INP\_BOUNDARY  
* **Description:** Test with empty text in TextContentPart.  
* **Exposure Point(s):** /chat/completions endpoint, TextContentPart.text field.  
* **Test Method/Action:** Make a POST request with content: [{"type": "text", "text": ""}].  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error because TextContentPart.text uses non_empty_string with min_length=1 constraint (app/providers/open_ai/schemas.py:23-26, 51).  
* **Verification Steps:** Assert HTTP status code is 422. Assert error message indicates text field cannot be empty.  
* **Code Reference:** app/providers/open_ai/schemas.py:23-26 defines non_empty_string, line 51 uses it for TextContentPart.text.

## **10\. Messages Array Validation**

### **FV\_INP\_CHAT\_MSG\_SEQUENCE\_001**

* **Category Ref:** FV\_INP\_STD\_PARAM  
* **Description:** Test with messages as None instead of a sequence.  
* **Exposure Point(s):** /chat/completions endpoint, messages field.  
* **Test Method/Action:** Make a POST request with messages: null.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** API returns a 422 Unprocessable Entity error because messages is a required field (app/providers/open_ai/schemas.py:110).  
* **Verification Steps:** Assert HTTP status code is 422. Assert error message indicates messages field is required.  
* **Code Reference:** app/providers/open_ai/schemas.py:110 defines messages as required Sequence.