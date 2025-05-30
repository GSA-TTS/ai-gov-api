# **Test Cases for API9:2023 \- Improper Inventory Management**

## **Introduction**

This document outlines test cases for **API9:2023 \- Improper Inventory Management** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md". These tests focus on ensuring that the API's exposed endpoints, versions, and supported models are accurately documented, managed, and that no "shadow" or deprecated/unmaintained LLM-interacting endpoints exist.  
**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 1.API9:2023)  
* app/main.py (router inclusions)  
* app/routers/api\_v1.py (defined v1 endpoints)  
* app/config/settings.py (especially backend\_map for model inventory)  
* API documentation (e.g., /openapi.json, docs/adr/001\_Open\_AI\_API.md)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** API9:2023 \- Improper Inventory Management  
* **Description:** What specific aspect of inventory management is being tested.  
* **Exposure Point(s):** API documentation, /api/v1/models endpoint, actual routable API paths, model configuration.  
* **Test Method/Action:** Compare documented inventory with actual exposed services; probe for undocumented or deprecated endpoints/models.  
* **Prerequisites:** Access to API documentation, list of expected production endpoints and models.  
* **Expected Secure Outcome:** The API's exposed surface (endpoints, models) matches its documentation and intended inventory. No "shadow" APIs or outdated/vulnerable components are accessible. Clear versioning and deprecation strategy (if applicable).  
* **Verification Steps:** Compare live API behavior with documentation. Scan for common non-production paths.

## **Test Cases**

* **ID:** IIM\_DOC\_ACCURACY\_001  
  * **Category Ref:** API9:2023 \- Improper Inventory Management  
  * **Description:** Verify that all endpoints listed in the OpenAPI specification (/openapi.json) are implemented and behave as documented regarding basic path and method.  
  * **Exposure Point(s):** /openapi.json, live API endpoints, router registrations in app/main.py:101-122.  
  * **Test Method/Action:**  
    1. Fetch and parse /openapi.json.  
    2. For each path and method combination in the spec, send a basic valid request (with auth).  
  * **Prerequisites:** API running. Valid API key.  
  * **Expected Secure Outcome:** All documented endpoints respond (not with 404). Implemented methods match the spec (e.g., a documented GET endpoint doesn't only accept POST).  
  * **Verification Steps:**  
    1. Iterate through paths in /openapi.json.  
    2. Confirm each path/method returns an expected status code (e.g., 200 for valid GET, 422/400 for POST without full valid body but path exists, not 404).  
  * **Code Reference:** Router registrations in app/main.py:101-122, endpoint implementations in router files.  
* **ID:** IIM\_SHADOW\_ENDPOINTS\_001  
  * **Category Ref:** API9:2023 \- Improper Inventory Management  
  * **Description:** Probe for common non-production or debug endpoints that might be inadvertently exposed and interact with LLMs.  
  * **Exposure Point(s):** Potential undocumented API paths.  
  * **Test Method/Action:** Attempt requests to common development/debug paths, e.g.:  
    * /api/v1/debug/chat  
    * /api/v1/test/embeddings  
    * /api/v1/internal/llm\_status  
    * Endpoints with suffixes like \_dev, \_test, \_beta.  
  * **Prerequisites:** API running. Valid API key (to bypass initial auth rejection).  
  * **Expected Secure Outcome:** All such non-documented, non-production endpoints should return 404 Not Found or 401/403 if they exist but have specific admin protection not covered by the test key. They should not provide access to LLM functionalities.  
  * **Verification Steps:**  
    1. Verify HTTP status code is 404 (ideally) or 401/403.  
    2. Ensure no unexpected LLM interaction occurs.  
* **ID:** IIM\_MODEL\_INVENTORY\_001  
  * **Category Ref:** API9:2023 \- Improper Inventory Management  
  * **Description:** Verify the /api/v1/models list is accurate and matches the configured backend\_map in app/config/settings.py.  
  * **Exposure Point(s):** /api/v1/models endpoint (app/routers/api_v1.py:25-30), settings.backend_map configuration, model enumeration logic.  
  * **Test Method/Action:**  
    1. Make a GET request to /api/v1/models.  
    2. Compare the returned list of model IDs and capabilities with the models defined in settings.backend\_map.  
  * **Prerequisites:** Valid API key. Access to the application's configuration (or a known list of expected models).  
  * **Expected Secure Outcome:** The /models list accurately reflects only the intentionally exposed and configured models. No deprecated or internal-only models are listed.  
  * **Verification Steps:**  
    1. Fetch /models response.  
    2. Compare with settings.backend\_map (model IDs and capabilities should match).  
    3. Ensure no unexpected models appear.  
  * **Code Reference:** Models endpoint in app/routers/api_v1.py:25-30, backend_map configuration in app/config/settings.py.  
* **ID:** IIM\_MODEL\_UNDECLARED\_ACCESS\_001  
  * **Category Ref:** API9:2023 \- Improper Inventory Management  
  * **Description:** Attempt to use an LLM model ID in /chat/completions or /embeddings that is *not* listed in /api/v1/models but might be known to exist at the provider level (if such a scenario is possible due to configuration drift).  
  * **Exposure Point(s):** /chat/completions, /embeddings endpoints, get_model_config_validated in app/providers/dependencies.py, model validation logic.  
  * **Test Method/Action:** Try to use a valid model ID for a provider (e.g., a new Bedrock model ARN) that is not yet added to settings.backend\_map.  
  * **Prerequisites:** Valid API key. Knowledge of a provider model ID not in backend\_map.  
  * **Expected Secure Outcome:** Request should fail with a 422 Unprocessable Entity error stating "Model '\<model\_id\>' is not supported by this API." (as per get\_model\_config\_validated).  
  * **Verification Steps:**  
    1. Verify HTTP status code is 422\.  
    2. Verify error message.  
  * **Code Reference:** Model validation in app/providers/dependencies.py, get_model_config_validated function, backend_map lookup logic.  
* **ID:** IIM\_VERSIONING\_001  
  * **Category Ref:** API9:2023 \- Improper Inventory Management  
  * **Description:** Check if older, unmaintained API versions (e.g., a hypothetical /api/v0/) are accessible.  
  * **Exposure Point(s):** API routing.  
  * **Test Method/Action:** Attempt requests to plausible older version paths (e.g., /api/v0/chat/completions, /api/v0.9/models).  
  * **Prerequisites:** API running.  
  * **Expected Secure Outcome:** Requests to undefined or deprecated API versions should result in 404 Not Found. Only explicitly supported versions (currently /api/v1/) should be active.  
  * **Verification Steps:** Verify HTTP status code is 404 for non-v1 paths.  
* **ID:** IIM\_DOCS\_HOSTING\_001  
  * **Category Ref:** API9:2023 \- Improper Inventory Management  
  * **Description:** Verify if API documentation endpoints (/openapi.json, /docs, /redoc) are appropriately protected if they contain sensitive information or if public exposure is not desired.  
  * **Exposure Point(s):** FastAPI's default documentation UIs.  
  * **Test Method/Action:** Attempt to access /openapi.json, /docs, /redoc without authentication, and with different levels of authenticated users (if auth is applied to them).  
  * **Prerequisites:** API running.  
  * **Expected Secure Outcome:** These endpoints should either be publicly accessible (if intended and spec contains no sensitive details like example internal hostnames) or protected by authentication/authorization matching the API's general access policy. The current app/main.py does not show explicit protection for these.  
  * **Verification Steps:**  
    1. Access documentation endpoints.  
    2. Verify if access control is applied as per policy.  
    3. Review content of /openapi.json for any inadvertently exposed sensitive defaults or internal descriptions.  
  * **Code Reference:** FastAPI automatic documentation generation, OpenAPI schema exposure.

* **ID:** IIM\_ENDPOINT\_DEPRECATION\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Test for proper handling of deprecated endpoints and ensure no deprecated functionality remains accessible.
  * **Exposure Point(s):** API versioning strategy, deprecated endpoint handling, legacy endpoint exposure.
  * **Test Method/Action:**
    1. Test access to hypothetical deprecated endpoints (e.g., /api/v0/, legacy paths).
    2. Verify deprecated endpoints return appropriate responses.
    3. Check for proper deprecation warnings in responses.
    4. Test sunset headers and deprecation notices.
  * **Prerequisites:** Understanding of API evolution and deprecation strategy.
  * **Expected Secure Outcome:** Deprecated endpoints either return 404 Not Found or include proper deprecation warnings. No security vulnerabilities in legacy code paths.
  * **Verification Steps:**
    1. Verify deprecated endpoints are inaccessible or properly marked.
    2. Check for appropriate HTTP status codes and headers.
    3. Test that deprecated functionality doesn't bypass current security controls.
    4. Verify deprecation timeline adherence.
  * **Code Reference:** API versioning implementation, endpoint lifecycle management.

* **ID:** IIM\_ADMIN\_ENDPOINT\_INVENTORY\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Verify administrative endpoints are properly inventoried and secured with appropriate access controls.
  * **Exposure Point(s):** Admin endpoints (/users, /tokens), administrative functionality exposure, include_in_schema settings.
  * **Test Method/Action:**
    1. Enumerate all administrative endpoints from router configurations.
    2. Test access controls on administrative functionality.
    3. Verify admin endpoints are not exposed in public documentation.
    4. Check for proper authentication and authorization on admin endpoints.
  * **Prerequisites:** Understanding of administrative functionality, admin credentials.
  * **Expected Secure Outcome:** Administrative endpoints are properly secured, documented internally, and not exposed to unauthorized users.
  * **Verification Steps:**
    1. Verify admin endpoints require proper authentication.
    2. Check that admin endpoints are excluded from public documentation.
    3. Test authorization levels for different admin operations.
    4. Verify proper audit logging for administrative actions.
  * **Code Reference:** Admin routers in app/main.py:113-122, include_in_schema=False settings, admin authentication requirements.

* **ID:** IIM\_PROVIDER\_MODEL\_SYNC\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Test synchronization between configured models and actual provider model availability.
  * **Exposure Point(s):** Provider model configurations, backend_map consistency, model availability validation.
  * **Test Method/Action:**
    1. Compare configured models with actual provider model availability.
    2. Test for models that are configured but unavailable at provider.
    3. Verify error handling for unavailable models.
    4. Check for model configuration drift detection.
  * **Prerequisites:** Access to provider model catalogs, configuration validation capabilities.
  * **Expected Secure Outcome:** Configured models are available and functional. Unavailable models are properly handled with clear error messages.
  * **Verification Steps:**
    1. Test all configured models for actual availability.
    2. Verify error handling for unavailable models.
    3. Check model capability consistency between configuration and reality.
    4. Test model health checking and monitoring.
  * **Code Reference:** Provider model configurations, backend_map validation, model availability checks.

* **ID:** IIM\_API\_SURFACE\_ENUMERATION\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Comprehensive enumeration of API surface to identify all accessible endpoints and ensure they match inventory.
  * **Exposure Point(s):** All API endpoints, router configurations, URL patterns, HTTP methods.
  * **Test Method/Action:**
    1. Systematically enumerate all accessible API paths and methods.
    2. Compare discovered endpoints with documented inventory.
    3. Test for hidden or undocumented endpoints.
    4. Verify HTTP method support matches specifications.
  * **Prerequisites:** API scanning tools, comprehensive endpoint discovery capabilities.
  * **Expected Secure Outcome:** All discovered endpoints are documented and intentional. No shadow or forgotten endpoints exist.
  * **Verification Steps:**
    1. Perform comprehensive API surface scanning.
    2. Compare discovered endpoints with official documentation.
    3. Test each discovered endpoint for proper functionality.
    4. Verify no unintended endpoints are accessible.
  * **Code Reference:** All router configurations, endpoint definitions, URL pattern matching.

* **ID:** IIM\_CONFIGURATION\_DRIFT\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Test for configuration drift between documented models/endpoints and actual runtime configuration.
  * **Exposure Point(s):** Runtime configuration vs documented configuration, environment-specific variations.
  * **Test Method/Action:**
    1. Compare runtime configuration with documented/expected configuration.
    2. Test for environment-specific model availability differences.
    3. Verify configuration consistency across deployment environments.
    4. Check for unauthorized configuration modifications.
  * **Prerequisites:** Access to configuration baselines, multiple environment configurations.
  * **Expected Secure Outcome:** Runtime configuration matches documented/approved configuration. No unauthorized drift has occurred.
  * **Verification Steps:**
    1. Compare actual vs expected configuration.
    2. Test configuration consistency across environments.
    3. Verify configuration change tracking and approval.
    4. Check for unauthorized configuration modifications.
  * **Code Reference:** Configuration loading and validation, environment-specific settings.

* **ID:** IIM\_MODEL\_CAPABILITY\_VALIDATION\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Validate that model capabilities (chat vs embedding) are accurately represented and enforced.
  * **Exposure Point(s):** Model capability declarations, endpoint routing based on capabilities, capability validation.
  * **Test Method/Action:**
    1. Test each model's declared capabilities against actual functionality.
    2. Verify that chat models cannot be used for embeddings and vice versa.
    3. Test capability validation in endpoint routing.
    4. Check for proper error handling when capabilities are mismatched.
  * **Prerequisites:** Understanding of model capabilities, access to all configured models.
  * **Expected Secure Outcome:** Model capabilities are accurately represented and properly enforced. Cross-capability usage is prevented.
  * **Verification Steps:**
    1. Test each model with its declared capability type.
    2. Attempt to use models with incorrect capability types.
    3. Verify proper error responses for capability mismatches.
    4. Check capability consistency in documentation and implementation.
  * **Code Reference:** Model capability validation, endpoint routing logic, capability-based access controls.

* **ID:** IIM\_HEALTH\_CHECK\_INVENTORY\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Verify health check and monitoring endpoints are properly inventoried and secured.
  * **Exposure Point(s):** Health check endpoints, monitoring interfaces, status reporting functionality.
  * **Test Method/Action:**
    1. Identify and test all health check and monitoring endpoints.
    2. Verify health check endpoint security and information disclosure.
    3. Test health check functionality for all configured models/providers.
    4. Check for proper health check authentication and authorization.
  * **Prerequisites:** Understanding of health check implementation, monitoring system architecture.
  * **Expected Secure Outcome:** Health checks provide necessary operational information without exposing sensitive details.
  * **Verification Steps:**
    1. Test all health check endpoints for functionality.
    2. Verify health check security and information limits.
    3. Check health check coverage for all system components.
    4. Test health check authentication requirements.
  * **Code Reference:** Health check implementations, monitoring endpoint configurations.

* **ID:** IIM\_THIRD\_PARTY\_INTEGRATION\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Inventory and validate all third-party integrations and external dependencies.
  * **Exposure Point(s):** Provider integrations, external service dependencies, third-party API connections.
  * **Test Method/Action:**
    1. Inventory all third-party integrations and external dependencies.
    2. Verify third-party service versions and compatibility.
    3. Test third-party integration security and authentication.
    4. Check for unauthorized or undocumented third-party connections.
  * **Prerequisites:** Understanding of system architecture, third-party integration documentation.
  * **Expected Secure Outcome:** All third-party integrations are documented, authorized, and properly secured.
  * **Verification Steps:**
    1. Document all third-party integrations and dependencies.
    2. Verify third-party service security and authentication.
    3. Test third-party integration functionality and error handling.
    4. Check for proper vendor risk management.
  * **Code Reference:** Provider integrations, external service configurations, third-party authentication.

* **ID:** IIM\_FEATURE\_FLAG\_INVENTORY\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Test feature flag and configuration-based functionality inventory and management.
  * **Exposure Point(s):** Feature flags, conditional functionality, environment-based feature availability.
  * **Test Method/Action:**
    1. Identify and test all feature flags and conditional functionality.
    2. Verify feature flag security and access controls.
    3. Test feature flag consistency across environments.
    4. Check for proper feature flag documentation and management.
  * **Prerequisites:** Understanding of feature flag implementation, configuration management systems.
  * **Expected Secure Outcome:** Feature flags are properly managed, documented, and secured. No unauthorized feature exposure occurs.
  * **Verification Steps:**
    1. Inventory all feature flags and conditional features.
    2. Test feature flag functionality and access controls.
    3. Verify feature flag consistency and documentation.
    4. Check for proper feature flag lifecycle management.
  * **Code Reference:** Feature flag implementations, conditional functionality configurations.

* **ID:** IIM\_SCHEMA\_VERSION\_CONSISTENCY\_001
  * **Category Ref:** API9:2023 \- Improper Inventory Management
  * **Description:** Verify API schema versions are consistent and properly managed across all endpoints.
  * **Exposure Point(s):** OpenAPI schema versions, endpoint schema consistency, versioning strategy implementation.
  * **Test Method/Action:**
    1. Verify schema version consistency across all endpoints.
    2. Test schema validation for all endpoint requests and responses.
    3. Check for schema version conflicts or inconsistencies.
    4. Verify proper schema evolution and backward compatibility.
  * **Prerequisites:** Understanding of API schema management, versioning strategies.
  * **Expected Secure Outcome:** Schema versions are consistent, properly managed, and evolution is controlled.
  * **Verification Steps:**
    1. Test schema consistency across all endpoints.
    2. Verify schema version management and evolution.
    3. Check schema validation and error handling.
    4. Test backward compatibility and breaking change management.
  * **Code Reference:** Schema definitions, versioning implementation, validation logic.