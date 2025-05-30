# **Test Cases: Section 7.2 \- Pre-runtime Protection Verification**

This document outlines test cases for OpenAPI Schema Conformance, ensuring the live API's behavior matches the statically defined OpenAPI specification (/openapi.json). This is a form of contract testing. This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_PRP\_...)  
* **Category Ref:** (e.g., FV\_PRP\_SCHEMA\_MATCH, FV\_PRP\_PARAM, FV\_PRP\_RESPONSE\_FIELD)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** Live API endpoints vs. /openapi.json specification.  
* **Test Method/Action:** How the test is performed (e.g., "Use Schemathesis to test endpoint against OpenAPI spec").  
* **Prerequisites:** Live API deployment, accessible /openapi.json. Tooling like Schemathesis or custom scripts.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (e.g., "API behavior fully conforms to the OpenAPI specification").  
* **Verification Steps:** How to confirm the expected secure outcome (e.g., "Schemathesis reports no discrepancies").

## **1\. OpenAPI Schema Conformance Testing (General)**

This typically involves using a tool like Schemathesis that consumes the OpenAPI spec and automatically generates and runs tests against the live API.

### **FV\_PRP\_SCHEMATHESIS\_FULL\_RUN\_001**

* **Category Ref:** FV\_PRP\_SCHEMA\_MATCH  
* **Description:** Perform a full API conformance test using Schemathesis against the /openapi.json specification.  
* **Exposure Point(s):** All API endpoints defined in /openapi.json.  
* **Test Method/Action:**  
  1. Fetch the /openapi.json from the live API.  
  2. Run Schemathesis (or a similar tool) against all defined endpoints, using the fetched schema.  
  3. Configure Schemathesis to perform various checks (data types, formats, required fields, enum values, etc.) for both requests and responses.  
* **Prerequisites:**  
  * Live API deployment.  
  * Valid API Key(s) with models:inference scope that Schemathesis can use for authenticated endpoints.  
  * Schemathesis (or equivalent tool) installed and configured.  
* **Expected Secure Outcome:** Schemathesis run completes and reports no discrepancies or failures between the API's behavior and the OpenAPI specification. All requests that should be valid are accepted, and all responses match their defined schemas.  
* **Verification Steps:**  
  * Review the Schemathesis report.  
  * Confirm there are no errors related to:  
    * Request parameter validation (e.g., tool sending valid data according to spec, but API rejecting it).  
    * Response schema validation (e.g., API returning data that doesn't match the response schema in the spec \- missing fields, wrong types, incorrect enum values).  
    * Status code mismatches (e.g., spec says 200, API returns 201).  
* **Code Reference:** FastAPI automatic OpenAPI generation in app/main.py:45, Pydantic schema definitions in app/providers/open_ai/schemas.py.

### **FV\_PRP\_OPENAPI\_ACCESSIBILITY\_001**

* **Category Ref:** FV\_PRP\_SCHEMA\_MATCH  
* **Description:** Verify that the /openapi.json endpoint is accessible and returns valid OpenAPI 3.x specification.  
* **Exposure Point(s):** /openapi.json endpoint.  
* **Test Method/Action:** Make a GET request to /openapi.json and validate the response structure.  
* **Prerequisites:** Live API deployment.  
* **Expected Secure Outcome:** Endpoint returns 200 OK with valid OpenAPI 3.x JSON specification.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Verify Content-Type is application/json.  
  * Validate OpenAPI structure (openapi version, info, paths, components).  
  * Ensure all API endpoints are documented in the specification.  
* **Code Reference:** FastAPI automatic OpenAPI generation, endpoint routing in app/main.py:107-122.

## **2\. Specific Discrepancy Checks (Manual or Scripted if not fully covered by tools)**

These tests are examples of what might be checked if automated tools don't cover all nuances or if specific areas of concern are identified.

### **FV\_PRP\_PARAM\_CHAT\_MAXTOKENS\_001**

* **Category Ref:** FV\_PRP\_PARAM  
* **Description:** Verify if a request parameter defined in OpenAPI for /chat/completions (e.g., max\_tokens) is actually honored by the backend.  
* **Exposure Point(s):** /chat/completions endpoint, max\_tokens parameter handling vs. its OpenAPI definition.  
* **Test Method/Action:**  
  1. Check /openapi.json for the definition of max\_tokens (e.g., type, constraints).  
  2. Send a valid request to /chat/completions with max\_tokens set to a small value (e.g., 5).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The API respects the max\_tokens parameter, and the response usage.completion\_tokens is less than or equal to 5, with finish\_reason likely being 'length'. The behavior aligns with the OpenAPI spec's implication that this parameter controls output length.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert response.usage.completion\_tokens \<= 5\.  
  * Assert response.choices\[0\].finish\_reason \== 'length'.  
  * Ensure no error occurs due to the parameter itself being unrecognized (which Schemathesis should also catch).  
* **Code Reference:** PositiveInt constraint for max_tokens in app/providers/open_ai/schemas.py:8, ChatCompletionRequest schema definition.

### **FV\_PRP\_RESP\_FIELD\_CHAT\_USAGE\_001**

* **Category Ref:** FV\_PRP\_RESPONSE\_FIELD  
* **Description:** Verify if a response field defined in OpenAPI for /chat/completions (e.g., usage.completion\_tokens) is always present and has the correct type in actual responses.  
* **Exposure Point(s):** /chat/completions response, usage.completion\_tokens field vs. its OpenAPI definition.  
* **Test Method/Action:** Make a valid POST request to /chat/completions.  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** The response contains the usage object, and within it, completion\_tokens is present and is an integer, as defined in the OpenAPI spec.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Assert response.usage is an object.  
  * Assert response.usage.completion\_tokens exists.  
  * Assert isinstance(response.usage.completion\_tokens, int).  
* **Code Reference:** ChatCompletionUsage schema with NonNegativeInt constraints, response schemas in app/providers/open_ai/schemas.py.

### **FV\_PRP\_ENUM\_CHAT\_FINISHREASON\_001**

* **Category Ref:** FV\_PRP\_RESPONSE\_FIELD  
* **Description:** Verify that the finish\_reason field in /chat/completions responses only contains values specified in the OpenAPI enum for that field.  
* **Exposure Point(s):** /chat/completions response, choices\[0\].finish\_reason field vs. its OpenAPI enum definition.  
* **Test Method/Action:**  
  1. Identify the allowed enum values for finish\_reason from /openapi.json.  
  2. Make various valid POST requests to /chat/completions designed to elicit different finish reasons (e.g., natural stop, length, tool\_calls).  
* **Prerequisites:** Valid API Key with models:inference scope.  
* **Expected Secure Outcome:** All observed finish\_reason values in responses are members of the enum defined in the OpenAPI specification.  
* **Verification Steps:**  
  * For each response:  
    * Assert response.choices\[0\].finish\_reason is one of the allowed enum values from the spec (e.g., "stop", "length", "tool\_calls", "content\_filter").  
* **Code Reference:** Finish reason enum definitions in response schemas, Literal type constraints in Pydantic models.

### **FV\_PRP\_ENDPOINT\_MODELS\_AVAILABILITY\_001**

* **Category Ref:** FV\_PRP\_SCHEMA\_MATCH  
* **Description:** Ensure the /models endpoint is available and its basic structure matches the OpenAPI spec.  
* **Exposure Point(s):** /models endpoint.  
* **Test Method/Action:** Make a GET request to /models.  
* **Prerequisites:** Valid API Key (no specific scope required for /models endpoint).  
* **Expected Secure Outcome:** The endpoint returns a 200 OK and the response structure (e.g., a list of model objects) matches the OpenAPI definition.  
* **Verification Steps:**  
  * Assert HTTP status code is 200\.  
  * Perform structural validation against the LLMModel schema or equivalent in OpenAPI (as covered by Schemathesis or FV\_RESP\_MODELS\_LIST\_001). This test emphasizes that the endpoint itself behaves as specified at a high level.  
* **Code Reference:** /models endpoint in app/routers/api_v1.py:25-30, LLMModel schema in app/providers/base.py.

### **FV\_PRP\_RESP\_STATUS\_CODE\_AUTH\_001**

* **Category Ref:** FV\_PRP\_SCHEMA\_MATCH  
* **Description:** Verify that an unauthenticated request to a protected endpoint returns a 401 status code as (presumably) defined in the OpenAPI specification for security schemes.  
* **Exposure Point(s):** Any protected endpoint (e.g., /chat/completions).  
* **Test Method/Action:** Make a POST request to /chat/completions without an API key or with an invalid one.  
* **Prerequisites:** None.  
* **Expected Secure Outcome:** API returns an HTTP 401 Unauthorized status code. The OpenAPI specification should indicate this for endpoints requiring authentication.  
* **Verification Steps:**  
  * Assert HTTP status code is 401\.  
  * Check if the OpenAPI spec for the endpoint and its security requirements imply a 401 response for failed authentication.  
* **Code Reference:** Authentication dependencies in app/auth/dependencies.py, security scheme configuration in FastAPI.

### **FV\_PRP\_PARAM\_VALIDATION\_CONSTRAINT\_001**

* **Category Ref:** FV\_PRP\_PARAM  
* **Description:** Verify that parameter constraints defined in Pydantic schemas are properly reflected in OpenAPI and enforced by the API.  
* **Exposure Point(s):** Request parameter validation across endpoints.  
* **Test Method/Action:** Send requests with parameters that violate defined constraints (e.g., negative temperature, empty strings where min_length=1).  
* **Prerequisites:** Valid API Key with appropriate scopes.  
* **Expected Secure Outcome:** API returns 422 Unprocessable Entity with detailed validation errors matching the constraints defined in the OpenAPI specification.  
* **Verification Steps:**  
  * Test various constraint violations (min/max values, string length, format validation).  
  * Verify error responses match FastAPI's standard validation error format.  
  * Ensure error details correspond to the specific constraint violations.  
* **Code Reference:** Pydantic constraints in app/providers/open_ai/schemas.py:23-26 (non_empty_string), PositiveInt and NonNegativeInt usage.

## **3\. Schema Evolution and Versioning**

### **FV\_PRP\_SCHEMA\_VERSION\_CONSISTENCY\_001**

* **Category Ref:** FV\_PRP\_SCHEMA\_MATCH  
* **Description:** Verify that the OpenAPI specification version and API version information are consistent and properly documented.  
* **Exposure Point(s):** OpenAPI info object, API versioning in endpoints.  
* **Test Method/Action:** Examine /openapi.json for version information and compare with actual API behavior.  
* **Prerequisites:** Live API deployment.  
* **Expected Secure Outcome:** OpenAPI specification contains accurate version information that matches the deployed API version.  
* **Verification Steps:**  
  * Verify openapi field indicates correct OpenAPI specification version (3.x).  
  * Check info.version field reflects current API version.  
  * Ensure API endpoint paths include correct version prefix (/api/v1).  
  * Validate that deprecated endpoints are properly marked if applicable.  
* **Code Reference:** FastAPI app configuration in app/main.py:45, router prefixes in app/main.py:107-110.

### **FV\_PRP\_SCHEMA\_COMPLETENESS\_001**

* **Category Ref:** FV\_PRP\_SCHEMA\_MATCH  
* **Description:** Verify that all API endpoints are documented in the OpenAPI specification and no undocumented endpoints exist.  
* **Exposure Point(s):** All API routes vs. OpenAPI paths.  
* **Test Method/Action:** Compare actual API routes with those documented in /openapi.json.  
* **Prerequisites:** Live API deployment. Access to route introspection.  
* **Expected Secure Outcome:** All accessible API endpoints are documented in the OpenAPI specification. No hidden or undocumented endpoints exist.  
* **Verification Steps:**  
  * Extract all paths from /openapi.json.  
  * Test accessibility of documented endpoints.  
  * Verify no additional endpoints are accessible beyond those documented.  
  * Check that include_in_schema=False routes are properly excluded.  
* **Code Reference:** Router inclusion in app/main.py:101-122, include_in_schema configuration for non-public endpoints.

## **4\. Response Format Validation**

### **FV\_PRP\_RESPONSE\_CONTENT\_TYPE\_001**

* **Category Ref:** FV\_PRP\_RESPONSE\_FIELD  
* **Description:** Verify that API responses have the correct Content-Type headers as specified in the OpenAPI specification.  
* **Exposure Point(s):** HTTP response headers across all endpoints.  
* **Test Method/Action:** Make requests to various endpoints and verify Content-Type headers.  
* **Prerequisites:** Valid API Key with appropriate scopes.  
* **Expected Secure Outcome:** All responses have appropriate Content-Type headers (application/json for JSON responses, text/event-stream for streaming).  
* **Verification Steps:**  
  * Verify JSON endpoints return Content-Type: application/json.  
  * Verify streaming endpoints return Content-Type: text/event-stream.  
  * Check that error responses also have correct Content-Type.  
* **Code Reference:** FastAPI automatic header handling, streaming response configuration in app/routers/api_v1.py:43-49.

### **FV\_PRP\_ERROR\_RESPONSE\_FORMAT\_001**

* **Category Ref:** FV\_PRP\_RESPONSE\_FIELD  
* **Description:** Verify that error responses follow the format specified in the OpenAPI specification.  
* **Exposure Point(s):** Error response schemas across all endpoints.  
* **Test Method/Action:** Trigger various error conditions and verify response format consistency.  
* **Prerequisites:** Ability to trigger different error conditions.  
* **Expected Secure Outcome:** All error responses follow a consistent format as documented in the OpenAPI specification.  
* **Verification Steps:**  
  * Test 400, 401, 403, 422, 500 error responses.  
  * Verify error response structure (e.g., {"detail": "error message"}).  
  * Ensure error messages are user-friendly and don't leak sensitive information.  
  * Check that validation errors include field-specific details.  
* **Code Reference:** Error handling in app/main.py:57-99, exception handlers and response formatting.

### **FV\_PRP\_MULTIMODAL\_SCHEMA\_VALIDATION\_001**

* **Category Ref:** FV\_PRP\_PARAM  
* **Description:** Verify that multimodal content (images, files) parameter schemas are correctly defined and validated.  
* **Exposure Point(s):** Multimodal content schemas in chat completion requests.  
* **Test Method/Action:** Send chat completion requests with various multimodal content types and verify schema compliance.  
* **Prerequisites:** Valid API Key with models:inference scope. Multimodal model support.  
* **Expected Secure Outcome:** Multimodal content is properly validated according to schema definitions. Invalid formats are rejected appropriately.  
* **Verification Steps:**  
  * Test valid image data URIs are accepted.  
  * Test invalid image formats are rejected with 422.  
  * Verify file content schema validation.  
  * Check that content type validation works correctly.  
* **Code Reference:** ImageUrl and FileContent schemas in app/providers/open_ai/schemas.py:27-44, data URI validation logic.