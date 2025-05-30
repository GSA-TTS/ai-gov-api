# **Test Cases: Section 7.2 \- Configuration Management & Backend Mapping**

This document outlines test cases for ensuring the integrity of provider configuration, model mapping in settings.backend\_map, and environment-specific settings. This is based on the "Risk Surface Analysis for Test Plan Section 7.2: Functional and Validation Testing".  
**General Test Case Components Reminder:**

* **ID:** Unique identifier (e.g., FV\_CFM\_...)  
* **Category Ref:** (e.g., FV\_CFM\_BACKEND\_MAP, FV\_CFM\_ENV, FV\_CFM\_DEPENDENCY)  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** app/config/settings.py (especially backend\_map), environment variables, pyproject.toml.  
* **Test Method/Action:** How the test is performed.  
* **Prerequisites:** Ability to modify configuration files/environment variables for testing.  
* **Expected Secure Outcome:** A clear statement of what the outcome should be (e.g., "API uses correct provider based on backend\_map").  
* **Verification Steps:** How to confirm the expected secure outcome.

## **1\. settings.backend\_map Validation**

### **FV\_CFM\_BACKEND\_MAP\_VALID\_ROUTE\_001**

* **Category Ref:** FV\_CFM\_BACKEND\_MAP  
* **Description:** Verify that a correctly configured model in backend\_map routes to the specified provider with correct details. (Similar to FV\_BLV\_ROUTE\_\* but focused on config integrity).  
* **Exposure Point(s):** settings.backend\_map, app/providers/dependencies.py.  
* **Test Method/Action:**  
  1. Ensure a model (e.g., "test-bedrock-chat") is in backend\_map pointing to "bedrock", with valid provider\_model\_id, aws\_region, and "chat" capability.  
  2. Make a /chat/completions request with model: "test-bedrock-chat".  
  3. Mock the Bedrock SDK.  
* **Prerequisites:** Valid API Key with models:inference scope. Control over settings.backend\_map. Mocking.  
* **Expected Secure Outcome:** The request is routed to Bedrock, and the call to Bedrock SDK uses the provider\_model\_id and other parameters (like region) specified in backend\_map.  
* **Verification Steps:**  
  * Assert the Bedrock client was initialized with the correct region from backend\_map.  
  * Assert the modelId parameter in the Bedrock SDK call matches provider\_model\_id from backend\_map.  
  * Request succeeds (200 OK from API).  
* **Code Reference:** Backend registration in app/config/settings.py:11-20, backend dependency injection in app/providers/dependencies.py:12-22.

### **FV\_CFM\_BACKEND\_MAP\_INVALID\_ARN\_001 (Example for Bedrock)**

* **Category Ref:** FV\_CFM\_BACKEND\_MAP  
* **Description:** Test with an invalid provider\_model\_id (e.g., malformed ARN or non-existent model ARN for Bedrock) in backend\_map.  
* **Exposure Point(s):** settings.backend\_map, Bedrock provider interaction.  
* **Test Method/Action:** Configure a model in backend\_map with an invalid provider\_model\_id for Bedrock. Attempt to use this model.  
* **Prerequisites:** Valid API Key with models:inference scope. Control over settings.backend\_map.  
* **Expected Secure Outcome:** The API gracefully handles the error from the Bedrock SDK (e.g., model not found, validation exception). Returns an appropriate API error (e.g., 400, 404, 502\) without leaking sensitive details.  
* **Verification Steps:**  
  * Assert HTTP status code (4xx or 502).  
  * Verify error message is user-friendly.  
  * Check server logs for the specific Bedrock error.  
* **Code Reference:** Error handling in app/providers/bedrock/bedrock.py, backend_map configuration in app/config/settings.py.

### **FV\_CFM\_BACKEND\_MAP\_INVALID\_PROJECT\_ID\_001 (Example for Vertex AI)**

* **Category Ref:** FV\_CFM\_BACKEND\_MAP  
* **Description:** Test with an invalid project\_id in backend\_map for a Vertex AI model.  
* **Exposure Point(s):** settings.backend\_map, Vertex AI provider initialization/interaction.  
* **Test Method/Action:** Configure a model in backend\_map with an incorrect project\_id for Vertex AI. Attempt to use this model.  
* **Prerequisites:** Valid API Key with models:inference scope. Control over settings.backend\_map.  
* **Expected Secure Outcome:** API gracefully handles the error from Vertex AI SDK (e.g., project not found, permission denied). Returns an appropriate API error.  
* **Verification Steps:** Assert HTTP status code and safe error message. Check logs.  
* **Code Reference:** Vertex AI backend implementation in app/providers/vertex_ai/vertexai.py, error handling patterns.

### **FV\_CFM\_BACKEND\_MAP\_CAP\_MISMATCH\_STARTUP\_001**

* **Category Ref:** FV\_CFM\_BACKEND\_MAP  
* **Description:** Check if any validation occurs at startup or during model loading if a model is configured in backend\_map with capabilities that are inherently incompatible with its provider\_model\_id type (e.g. an embedding model ID given "chat" capability). (This might be hard to detect automatically at startup without calling providers).  
* **Exposure Point(s):** settings.backend\_map parsing, get\_model\_config\_validated.  
* **Test Method/Action:** Configure backend\_map with an embedding provider\_model\_id but assign it only capabilities: \["chat"\]. Call /chat/completions with this model.  
* **Prerequisites:** Control over settings.backend\_map.  
* **Expected Secure Outcome:** get\_model\_config\_validated should prevent this misuse, returning a 400/405 error as tested in FV\_BLV\_CAPABILITY\_\*. This test confirms the config itself doesn't cause an unhandled startup error if such validation isn't present at startup. The primary check is runtime.  
* **Verification Steps:** API returns 400/405 when the model is used, as per capability checks. Ensure no startup crashes due to this config.  
* **Code Reference:** Capability validation in app/providers/dependencies.py:19-20, model capability definitions in provider backends.

### **FV\_CFM\_BACKEND\_MAP\_UNKNOWN\_PROVIDER\_001**

* **Category Ref:** FV\_CFM\_BACKEND\_MAP  
* **Description:** Test with a model in backend\_map configured with an unknown provider\_name.  
* **Exposure Point(s):** settings.backend\_map, app/providers/dependencies.py (provider loading).  
* **Test Method/Action:** Configure a model with provider\_name: "mythical\_provider". Attempt to use this model.  
* **Prerequisites:** Control over settings.backend\_map.  
* **Expected Secure Outcome:** API returns a 500 Internal Server Error or 503 Service Unavailable. Logs should indicate failure to load/find the specified provider.  
* **Verification Steps:** Assert HTTP status code. Check server logs for "Unknown provider" or similar error.  
* **Code Reference:** Provider registration logic in app/config/settings.py:11-14, backend_instances list validation.

## **2\. Environment-Specific Configuration Issues**

### **FV\_CFM\_ENV\_MISSING\_VAR\_BEDROCK\_REGION\_001**

* **Category Ref:** FV\_CFM\_ENV  
* **Description:** Test behavior if an essential environment variable for a provider is missing (e.g., AWS\_REGION if Bedrock client relies on it and it's not hardcoded or defaulted safely in settings).  
* **Exposure Point(s):** Bedrock client initialization, environment variable loading in settings.py.  
* **Test Method/Action:** Unset AWS\_REGION (or ensure it's not available to the app). Configure a Bedrock model in backend\_map that *doesn't* explicitly set aws\_region (if the code allows aws\_region to be optional in backend\_map and fall back to env var). Attempt to use a Bedrock model.  
* **Prerequisites:** Control over environment variables.  
* **Expected Secure Outcome:** If the region is critical and not found, the Bedrock client fails to initialize or make calls. API should return a 500/503 error. Logs indicate missing region.  
* **Verification Steps:** Assert HTTP status code. Check logs for errors about missing AWS region.  
* **Code Reference:** AWS configuration in app/config/settings.py:36 (aws_default_region), Bedrock client initialization.

### **FV\_CFM\_ENV\_MISSING\_VAR\_VERTEX\_CREDS\_001 (Conceptual)**

* **Category Ref:** FV\_CFM\_ENV  
* **Description:** Test behavior if Vertex AI credentials (e.g., GOOGLE\_APPLICATION\_CREDENTIALS env var pointing to a service account key) are missing or invalid.  
* **Exposure Point(s):** Vertex AI client initialization.  
* **Test Method/Action:** Unset GOOGLE\_APPLICATION\_CREDENTIALS or point it to a non-existent/invalid file. Attempt to use a Vertex AI model.  
* **Prerequisites:** Control over environment variables.  
* **Expected Secure Outcome:** Vertex AI client fails to authenticate. API returns a 500/503 error. Logs indicate authentication failure.  
* **Verification Steps:** Assert HTTP status code. Check logs for Vertex AI authentication errors.  
* **Code Reference:** Google credentials configuration in app/config/settings.py:34 (google_application_credentials), Vertex AI client setup.

### **FV\_CFM\_ENV\_SETTINGS\_OVERRIDE\_001**

* **Category Ref:** FV\_CFM\_ENV  
* **Description:** Verify that environment variables correctly override default settings in settings.py where designed (e.g., LOG\_LEVEL, DATABASE\_URL).  
* **Exposure Point(s):** settings.py logic for loading environment variables.  
* **Test Method/Action:**  
  1. Set LOG\_LEVEL=DEBUG via environment variable. Start the API. Check if logs are produced at DEBUG level.  
  2. Set a specific DATABASE\_URL via environment variable. Check if the API attempts to connect to this database (may require observing connection attempts or specific db interactions).  
* **Prerequisites:** Control over environment variables.  
* **Expected Secure Outcome:** The application behavior reflects the settings provided by environment variables, overriding any defaults in the code.  
* **Verification Steps:**  
  * For LOG\_LEVEL: Observe log output verbosity.  
  * For DATABASE\_URL: If API starts and connects, it used the env var. If it fails to connect to an intentionally wrong env var URL, this also confirms usage.  
* **Code Reference:** Environment variable handling in app/config/settings.py:23-31, Pydantic BaseSettings configuration.

### **FV\_CFM\_ENV\_DATABASE\_CONNECTION\_001**

* **Category Ref:** FV\_CFM\_ENV  
* **Description:** Test database connection configuration and error handling when database parameters are invalid.  
* **Exposure Point(s):** Database connection settings, app/config/settings.py postgres_connection property.  
* **Test Method/Action:** Set invalid database configuration (wrong host, port, credentials) via environment variables and attempt to start the API.  
* **Prerequisites:** Control over database environment variables.  
* **Expected Secure Outcome:** API should fail to start gracefully with clear error message about database connection failure.  
* **Verification Steps:**  
  * Verify API startup fails appropriately.  
  * Check logs for database connection errors.  
  * Ensure no sensitive database credentials are leaked in error messages.  
* **Code Reference:** Database configuration in app/config/settings.py:27-32, postgres_connection property at lines 40-45.

## **3\. Dynamic Configuration Changes (If Supported \- Not typical for settings.py)**

*(The current settings.py model usually loads config at startup. If a dynamic config reloading mechanism were added, these tests would apply. For now, these are conceptual.)*

### **FV\_CFM\_DYNCONF\_RELOAD\_VALID\_001 (Conceptual)**

* **Category Ref:** FV\_CFM\_ENV (Dynamic)  
* **Description:** Test if dynamic configuration updates (e.g., to backend\_map via an admin API or signal) are correctly applied without restart.  
* **Exposure Point(s):** Dynamic configuration reloading mechanism.  
* **Test Method/Action:** If dynamic reload is supported:  
  1. API is running.  
  2. Update backend\_map (e.g., change provider\_model\_id for a model).  
  3. Trigger config reload.  
  4. Make a request to the modified model.  
* **Prerequisites:** Dynamic config reload mechanism.  
* **Expected Secure Outcome:** The request uses the new configuration.  
* **Verification Steps:** Mock provider SDK and verify the call reflects the updated config.  
* **Code Reference:** Settings caching with @lru_cache() in app/config/settings.py:49-50, potential for cache invalidation.

## **4\. Dependency Validation (pyproject.toml)**

### **FV\_CFM\_DEPENDENCY\_PROVIDER\_SDK\_MISSING\_001 (Conceptual \- Environment Setup)**

* **Category Ref:** FV\_CFM\_DEPENDENCY  
* **Description:** Test API behavior if a required provider SDK is not installed in the environment (e.g., boto3 or google-cloud-aiplatform missing).  
* **Exposure Point(s):** Provider module imports (app/providers/{bedrock|vertex\_ai}).  
* **Test Method/Action:** Create a Python environment without, for example, boto3. Try to run the API and make a request to a Bedrock model.  
* **Prerequisites:** Control over Python environment setup.  
* **Expected Secure Outcome:** The API fails to start cleanly if the import is at module level and critical, or a request to the specific provider fails with a 500/503 error if import is deferred/conditional. Logs should show ImportError.  
* **Verification Steps:** Observe API startup logs or request response. Check logs for ImportError.  
* **Code Reference:** Provider imports in app/config/settings.py:7-8, provider module dependencies.

### **FV\_CFM\_DEPENDENCY\_SDK\_VERSION\_INCOMPAT\_001 (Conceptual \- Hard to Test Systematically)**

* **Category Ref:** FV\_CFM\_DEPENDENCY  
* **Description:** Test for issues if an installed provider SDK version is incompatible with the API's adapter code (e.g., due to breaking changes in SDK).  
* **Exposure Point(s):** Adapter code using SDK features.  
* **Test Method/Action:** Manually install an older or much newer (potentially unreleased) version of a provider SDK. Make requests using that provider.  
* **Prerequisites:** Control over Python environment.  
* **Expected Secure Outcome:** Ideally, pyproject.toml specifies compatible versions, preventing this. If an incompatible version is forced, API requests to that provider may fail with errors like AttributeError or TypeError when calling SDK methods. These should result in 500/503 errors.  
* **Verification Steps:** Observe API responses and logs for SDK-related errors.  
* **Code Reference:** Dependency specifications in pyproject.toml, provider SDK usage in adapter implementations.

## **5\. Settings Validation and Integrity**

### **FV\_CFM\_SETTINGS\_VALIDATION\_REQUIRED\_FIELDS\_001**

* **Category Ref:** FV\_CFM\_ENV  
* **Description:** Test behavior when required configuration fields are missing from environment variables.  
* **Exposure Point(s):** Pydantic Field validation in app/config/settings.py.  
* **Test Method/Action:** Start API with missing required environment variables (e.g., env, log_level, db_user, etc.).  
* **Prerequisites:** Control over environment variables.  
* **Expected Secure Outcome:** API should fail to start with clear validation error indicating which required fields are missing.  
* **Verification Steps:**  
  * Verify API startup fails.  
  * Check that error message lists missing required fields.  
  * Ensure no default values are used for critical security-related settings.  
* **Code Reference:** Required field definitions in app/config/settings.py:24-36, Pydantic Field(default=...) usage.

### **FV\_CFM\_SETTINGS\_TYPE\_VALIDATION\_001**

* **Category Ref:** FV\_CFM\_ENV  
* **Description:** Test Pydantic type validation for configuration fields.  
* **Exposure Point(s):** Type annotations in Settings class.  
* **Test Method/Action:** Set environment variables with incorrect types (e.g., non-boolean for database_echo, non-integer for db_port).  
* **Prerequisites:** Control over environment variables.  
* **Expected Secure Outcome:** API should fail to start with clear type validation error.  
* **Verification Steps:**  
  * Verify API startup fails appropriately.  
  * Check that error messages indicate type mismatch.  
  * Verify no type coercion occurs for security-sensitive fields.  
* **Code Reference:** Type annotations in app/config/settings.py Settings class, Pydantic type validation.

### **FV\_CFM\_BACKEND\_MAP\_INITIALIZATION\_001**

* **Category Ref:** FV\_CFM\_BACKEND\_MAP  
* **Description:** Verify that backend_map is correctly populated during application startup.  
* **Exposure Point(s):** Backend map initialization in app/config/settings.py.  
* **Test Method/Action:** Start API and verify that backend_map contains expected provider-model mappings.  
* **Prerequisites:** Standard provider configuration.  
* **Expected Secure Outcome:** backend_map should contain all models from all registered backend instances with correct provider-model associations.  
* **Verification Steps:**  
  * Verify backend_map is not empty.  
  * Check that all provider backends are represented.  
  * Verify model IDs are unique across providers.  
  * Ensure model capabilities are correctly assigned.  
* **Code Reference:** Backend map construction in app/config/settings.py:16-20, backend registration logic.

### **FV\_CFM\_SETTINGS\_CACHE\_CONSISTENCY\_001**

* **Category Ref:** FV\_CFM\_ENV  
* **Description:** Test that settings caching with @lru_cache() maintains consistency throughout application lifecycle.  
* **Exposure Point(s):** get_settings() function caching in app/config/settings.py.  
* **Test Method/Action:** Make multiple calls to get_settings() and verify same instance is returned. Test across different request contexts.  
* **Prerequisites:** Running API instance.  
* **Expected Secure Outcome:** get_settings() should return the same Settings instance for all calls, ensuring configuration consistency.  
* **Verification Steps:**  
  * Verify object identity consistency across multiple get_settings() calls.  
  * Test settings consistency across different API request contexts.  
  * Ensure no configuration drift during application runtime.  
* **Code Reference:** Settings caching implementation in app/config/settings.py:49-50, @lru_cache() decorator usage.