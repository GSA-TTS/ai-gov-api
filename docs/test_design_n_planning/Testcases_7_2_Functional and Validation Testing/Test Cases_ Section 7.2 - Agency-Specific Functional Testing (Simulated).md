# **Test Cases: Section 7.2 \- Agency-Specific Functional Testing (Simulated)**

This document outlines test cases for verifying API key scoping, usage tracking, and quota enforcement related to agencies (simulated via manager\_id or similar constructs). This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_AGY\_...)  
* **Category Ref:** (e.g., FV\_AGY\_SCOPE, FV\_AGY\_USAGE, FV\_AGY\_QUOTA, FV\_AGY\_ISOLATION)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** Authentication (app/auth/dependencies.py), billing service (app/services/billing.py), API key model (app/auth/models.py).  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** Valid API Keys with specific scopes/manager\_ids, database setup, potentially mock billing queue.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be.  
* **Verification Steps:** How to confirm the expected secure outcome.

## **1\. API Key Scoping (Functional)**

### **FV\_AGY\_SCOPE\_CHAT\_ALLOWED\_001**

* **Category Ref:** FV\_AGY\_SCOPE  
* **Description:** Verify an API key with models:inference scope can access /chat/completions.  
* **Exposure Point(s):** RequiresScope([Scope.MODELS_INFERENCE]) dependency in app/auth/dependencies.py on /chat/completions route.  
* **Test Method/Action:** Create an API key with scopes=\["models:inference"\]. Make a POST request to /chat/completions using this key.  
* **Prerequisites:** Database access to create the API key with specific scopes.  
* **Expected Secure Outcome:** API returns 200 OK (assuming valid payload and model).  
* **Verification Steps:** Assert HTTP status code is 200\.

### **FV\_AGY\_SCOPE\_CHAT\_DENIED\_001**

* **Category Ref:** FV\_AGY\_SCOPE  
* **Description:** Verify an API key without models:inference scope (e.g., only models:embedding) is denied access to /chat/completions.  
* **Exposure Point(s):** RequiresScope([Scope.MODELS_INFERENCE]) dependency on /chat/completions.  
* **Test Method/Action:** Create an API key with scopes=\["models:embedding"\]. Make a POST request to /chat/completions.  
* **Prerequisites:** Database access.  
* **Expected Secure Outcome:** API returns 403 Forbidden error.  
* **Verification Steps:** Assert HTTP status code is 403\. Assert error message indicates insufficient scope/permissions.

### **FV\_AGY\_SCOPE\_EMBED\_ALLOWED\_001**

* **Category Ref:** FV\_AGY\_SCOPE  
* **Description:** Verify an API key with models:embedding scope can access /embeddings.  
* **Exposure Point(s):** requires\_scope dependency on /embeddings.  
* **Test Method/Action:** Create an API key with scopes=\["models:embedding"\]. Make a POST request to /embeddings.  
* **Prerequisites:** Database access.  
* **Expected Secure Outcome:** API returns 200 OK.  
* **Verification Steps:** Assert HTTP status code is 200\.

### **FV\_AGY\_SCOPE\_EMBED\_DENIED\_001**

* **Category Ref:** FV\_AGY\_SCOPE  
* **Description:** Verify an API key without models:embedding scope is denied access to /embeddings.  
* **Exposure Point(s):** requires\_scope dependency on /embeddings.  
* **Test Method/Action:** Create an API key with scopes=\["models:chat", "models:read"\]. Make a POST request to /embeddings.  
* **Prerequisites:** Database access.  
* **Expected Secure Outcome:** API returns 403 Forbidden error.  
* **Verification Steps:** Assert HTTP status code is 403\. Assert error message indicates insufficient scope.

### **FV\_AGY\_SCOPE\_MODELS\_ALLOWED\_001**

* **Category Ref:** FV\_AGY\_SCOPE  
* **Description:** Verify any valid API key can access /models (no specific scope required).  
* **Exposure Point(s):** valid_api_key dependency on /models endpoint in app/routers/api_v1.py:28.  
* **Test Method/Action:** Create an API key with any valid scope (e.g., models:inference or models:embedding). Make a GET request to /models.  
* **Prerequisites:** Database access.  
* **Expected Secure Outcome:** API returns 200 OK.  
* **Verification Steps:** Assert HTTP status code is 200\.  
* **Code Reference:** app/routers/api_v1.py:25-30 shows /models endpoint requires valid_api_key but no specific scope.

### **FV\_AGY\_SCOPE\_MODELS\_NO\_AUTH\_DENIED\_001**

* **Category Ref:** FV\_AGY\_SCOPE  
* **Description:** Verify that requests without valid authentication are denied access to /models.  
* **Exposure Point(s):** valid_api_key dependency on /models.  
* **Test Method/Action:** Make a GET request to /models without Authorization header or with invalid API key.  
* **Prerequisites:** None.  
* **Expected Secure Outcome:** API returns 401 Unauthorized error.  
* **Verification Steps:** Assert HTTP status code is 401\.  
* **Code Reference:** app/auth/dependencies.py handles authentication failures.

*(Note: If model-specific permissions per API key/agency are implemented in get\_model\_config\_validated, further tests would be needed here.)*

## **2\. Usage Tracking Attribution (Functional)**

**Note:** Usage tracking and billing are designed but not yet fully implemented in the current codebase. These tests are prepared for future implementation.

### **FV\_AGY\_USAGE\_CHAT\_ATTRIBUTION\_001 (Future Implementation)**

* **Category Ref:** FV\_AGY\_USAGE  
* **Description:** Verify token usage from /chat/completions is correctly attributed to the API key's id and manager\_id.  
* **Exposure Point(s):** Future usage collection in /chat/completions route, billing_worker in app/services/billing.py:10-14.  
* **Test Method/Action:**  
  1. Create an API key with a specific id (e.g., "key-agency-A") and manager\_id (e.g., "agency-A-manager").  
  2. Mock the billing queue (billing_queue.put()).  
  3. Make a successful POST request to /chat/completions using this key.  
* **Prerequisites:** Database access. Implementation of usage tracking in routers. Mockable billing queue.  
* **Expected Secure Outcome:** An item is put onto the billing queue. This item contains the correct api\_key\_id ("key-agency-A"), manager\_id ("agency-A-manager"), prompt\_tokens, completion\_tokens, total\_tokens, model\_id, and endpoint.  
* **Verification Steps:**  
  * Inspect the item passed to the mocked billing_queue.put().  
  * Assert item contains correct API key ID and manager_id.  
  * Assert token counts are present and plausible.  
  * Assert model_id matches the requested model.  
* **Code Reference:** app/services/billing.py:7-14 defines billing infrastructure, usage collection needs to be implemented in routers.  
* **Implementation Status:** 🔧 Requires Setup - billing integration not yet implemented in API routes.

### **FV\_AGY\_USAGE\_EMBED\_ATTRIBUTION\_001**

* **Category Ref:** FV\_AGY\_USAGE  
* **Description:** Verify token usage from /embeddings is correctly attributed.  
* **Exposure Point(s):** Usage collection in /embeddings route, billing\_worker.  
* **Test Method/Action:** Similar to FV\_AGY\_USAGE\_CHAT\_ATTRIBUTION\_001, but make a request to /embeddings.  
* **Prerequisites:** Database access. Mockable billing queue.  
* **Expected Secure Outcome:** Billing queue item contains correct api\_key\_id, manager\_id, prompt\_tokens, total\_tokens (where completion\_tokens would be 0), model\_id, and endpoint ("/v1/embeddings").  
* **Verification Steps:** Inspect mocked queue item and assert fields.

### **FV\_AGY\_USAGE\_MULTIMODAL\_TOKENS\_001**

* **Category Ref:** FV\_AGY\_USAGE  
* **Description:** Verify token counting for multimodal inputs (e.g., images in chat) is correctly captured for billing.  
* **Exposure Point(s):** Usage collection, provider adapters' token calculation for images.  
* **Test Method/Action:** Make a /chat/completions request with image input to a multimodal model. Mock billing queue.  
* **Prerequisites:** Database access. Mockable billing queue. Multimodal model.  
* **Expected Secure Outcome:** The prompt\_tokens in the billing item reflect the combined cost of text and image(s).  
* **Verification Steps:** Inspect prompt\_tokens in the billing item. It should be higher than a text-only request and plausible for the image content based on provider pricing/tokenization rules. (Exact validation might require provider-specific tokenizers or known values).

### **FV\_AGY\_USAGE\_STREAMING\_ATTRIBUTION\_001**

* **Category Ref:** FV\_AGY\_USAGE  
* **Description:** Verify usage from a streaming /chat/completions request is correctly attributed (assuming usage is reported at the end or can be calculated).  
* **Exposure Point(s):** Usage collection for streaming responses.  
* **Test Method/Action:** Make a streaming /chat/completions request. Mock billing queue.  
* **Prerequisites:** Database access. Mockable billing queue.  
* **Expected Secure Outcome:** A billing item is generated with correct api\_key\_id, manager\_id, and token counts reflecting the full streamed response.  
* **Verification Steps:** Inspect mocked queue item. Token counts should correspond to the complete generated stream.

## **3\. Quota Enforcement (Functional \- If Implemented)**

*(These tests depend on the specific implementation of quota logic, e.g., in billing\_worker or a separate service. The risk analysis mentions it under Agency-Specific testing.)*

### **FV\_AGY\_QUOTA\_ENFORCED\_REQUEST\_COUNT\_001 (Placeholder)**

* **Category Ref:** FV\_AGY\_QUOTA  
* **Description:** Verify request count quota enforcement for an API key/agency.  
* **Exposure Point(s):** Quota enforcement logic.  
* **Test Method/Action:**  
  1. Set a low request count quota for an API key/manager\_id (e.g., 5 requests).  
  2. Make N requests (e.g., 5 successful, then the 6th).  
* **Prerequisites:** Quota system implemented and configurable.  
* **Expected Secure Outcome:** The first 5 requests succeed. The 6th request (and subsequent) returns a 429 Too Many Requests (or similar quota exceeded error) until the quota resets.  
* **Verification Steps:** Observe HTTP status codes for requests.

### **FV\_AGY\_QUOTA\_ENFORCED\_TOKEN\_COUNT\_001 (Placeholder)**

* **Category Ref:** FV\_AGY\_QUOTA  
* **Description:** Verify token count quota enforcement.  
* **Exposure Point(s):** Quota enforcement logic.  
* **Test Method/Action:**  
  1. Set a low token quota (e.g., 1000 tokens).  
  2. Make requests that consume tokens, approaching and then exceeding the quota.  
* **Prerequisites:** Quota system.  
* **Expected Secure Outcome:** Requests succeed until token usage exceeds quota. Subsequent requests that would exceed quota are rejected with 429\.  
* **Verification Steps:** Track token usage. Observe HTTP status codes.

### **FV\_AGY\_QUOTA\_RESET\_001 (Placeholder)**

* **Category Ref:** FV\_AGY\_QUOTA  
* **Description:** Verify quota resets after the defined period.  
* **Exposure Point(s):** Quota reset mechanism.  
* **Test Method/Action:** Exceed quota. Wait for reset period. Make another request.  
* **Prerequisites:** Quota system with timed reset.  
* **Expected Secure Outcome:** Request after reset period succeeds (assuming it's within the new quota).  
* **Verification Steps:** Observe HTTP status code.

## **4\. User Management and API Key Lifecycle (Functional)**

### **FV\_AGY\_USER\_KEY\_CREATION\_001**

* **Category Ref:** FV\_AGY\_SCOPE  
* **Description:** Verify that creating a new user and an API key for them with specific scopes functions correctly.  
* **Exposure Point(s):** User creation endpoint (if any via API, or script create\_admin\_user.py), API key generation logic.  
* **Test Method/Action:**  
  1. Create a new user (e.g. with manager\_id="new\_agency").  
  2. Generate an API key for this user with scopes=\["models:chat"\].  
  3. Attempt to use this key for /chat/completions.  
* **Prerequisites:** Mechanism to create users and API keys.  
* **Expected Secure Outcome:** The newly created API key works for the /chat/completions endpoint and is associated with the correct user/agency.  
* **Verification Steps:**  
  * Assert /chat/completions request is 200 OK.  
  * If billing is mocked, verify the manager\_id in the billing record is "new\_agency".

### **FV\_AGY\_KEY\_REVOCATION\_001**

* **Category Ref:** FV\_AGY\_SCOPE  
* **Description:** Verify that a revoked/deleted API key can no longer access LLM services.  
* **Exposure Point(s):** API key validation in get\_current\_active\_user\_with\_api\_key.  
* **Test Method/Action:**  
  1. Create and use an API key successfully.  
  2. Revoke/delete the API key from the database (or mark as inactive).  
  3. Attempt to use the same key again.  
* **Prerequisites:** Database access to manage API key status.  
* **Expected Secure Outcome:** The request made with the revoked/deleted key fails with a 401 Unauthorized or 403 Forbidden error.  
* **Verification Steps:** Assert HTTP status code is 401 or 403\.

### **FV\_AGY\_KEY\_EXPIRATION\_001 (If Implemented)**

* **Category Ref:** FV\_AGY\_SCOPE  
* **Description:** Verify that an expired API key can no longer access LLM services.  
* **Exposure Point(s):** API key validation, checking expires\_at field.  
* **Test Method/Action:**  
  1. Create an API key with an expiration date in the past.  
  2. Attempt to use this key.  
* **Prerequisites:** API key model supports expires\_at.  
* **Expected Secure Outcome:** Request fails with 401 Unauthorized or 403 Forbidden.  
* **Verification Steps:** Assert HTTP status code.

## **5\. Multi-Tenant Isolation (Functional Spot Checks)**

These tests aim to ensure that concurrent requests from different agencies do not interfere with each other's context, model configurations, or billing.

### **FV\_AGY\_ISOLATION\_CONCURRENT\_REQUESTS\_001**

* **Category Ref:** FV\_AGY\_ISOLATION  
* **Description:** Test concurrent requests from two different API keys (different manager\_ids) to ensure correct attribution and no cross-contamination.  
* **Exposure Point(s):** Request context handling, billing attribution, provider client instantiation.  
* **Test Method/Action:**  
  1. Create API Key A for Agency1 and API Key B for Agency2.  
  2. Mock the billing queue.  
  3. Simultaneously (or in rapid succession) send a /chat/completions request using Key A and another using Key B, each for a different model if possible, or with slightly different prompts.  
* **Prerequisites:** Database access. Mockable billing queue. Ability to make concurrent requests.  
* **Expected Secure Outcome:**  
  * Both requests complete successfully (200 OK).  
  * Two distinct items are put on the billing queue.  
  * Billing item 1 is correctly attributed to Key A / Agency1 and its respective model/prompt.  
  * Billing item 2 is correctly attributed to Key B / Agency2 and its respective model/prompt.  
  * Responses received are appropriate for their respective prompts.  
* **Verification Steps:**  
  * Inspect the items in the mocked billing queue; verify correct and distinct api\_key\_id, manager\_id, and request details for each.  
  * Verify responses are correct for each initial request.  
  * Check logs for any signs of context bleeding or misattribution (if detailed logging is available).

### **FV\_AGY\_ISOLATION\_PROVIDER\_CLIENTS\_001**

* **Category Ref:** FV\_AGY\_ISOLATION  
* **Description:** Verify that provider clients (e.g., Boto3 client for Bedrock) are instantiated or used in a way that maintains isolation if agency-specific configurations (e.g., different AWS roles/regions per agency, if ever supported) were to be used. (Current implementation seems to use global clients, so this tests that global client usage doesn't cause issues with concurrent, differently attributed requests).  
* **Exposure Point(s):** Provider client instantiation and usage in app/providers/{bedrock|vertex\_ai}.  
* **Test Method/Action:** Similar to FV\_AGY\_ISOLATION\_CONCURRENT\_REQUESTS\_001, make concurrent requests from different "agencies" (API keys with different manager\_id).  
* **Prerequisites:** As above.  
* **Expected Secure Outcome:** Requests are processed correctly without interference, even if a shared provider client instance is used internally, as long as the calls to the provider SDKs correctly pass distinct parameters derived from each request (e.g. model ID, prompt).  
* **Verification Steps:**  
  * Successful completion of both requests.  
  * Correct billing attribution.  
  * No errors indicating misconfigured or crossed provider sessions (unlikely with current global client model unless state is improperly managed within the client wrapper).