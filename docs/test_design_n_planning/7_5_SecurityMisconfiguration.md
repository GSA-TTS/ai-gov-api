# **Security Misconfiguration Testing**

This document outlines the approach to testing for security misconfigurations within the AI API Framework. This aligns with section 7.3 of the main API Test Plan (api\_test\_plan\_ai\_framework\_v1), which covers OWASP API Security Top 10 (especially API7:2023 \- Server Side Request Forgery, which can be exacerbated by misconfigurations, and API8:2023 \- Security Misconfiguration).

## **1\. Understand the Goal**

The primary goal of Security Misconfiguration Testing is to proactively identify, analyze, and validate that the AI API Framework, its underlying components (application server, database, cloud services), and its deployment environment are configured securely. This means adhering to security best practices, internal security policies, and relevant regulatory requirements to minimize the attack surface and prevent vulnerabilities that could be exploited.

**Specific objectives for this AI API Framework include verifying:**

* **Secure Application Framework Configuration (FastAPI/Uvicorn):**  
  * **Production Hardening:** Ensure debugging features (e.g., FastAPI debug=True, Uvicorn \--reload) are unequivocally disabled in production and production-like environments to prevent exposure of sensitive diagnostic information.  
  * **Strict Error Handling:** Verify that global and specific error handlers are configured not to reveal internal system details (stack traces, raw exception messages, configuration values) to the client, aligning with Data Exposure Testing but focusing on the configuration that prevents such leaks.  
  * **Robust Request Processing:** Confirm that HTTP methods, routing, and request parsing mechanisms are strict and do not permit unexpected interpretations or bypasses.  
* **Secure Middleware Configuration:**  
  * **CORS (CORSMiddleware in app/main.py):** Ensure Cross-Origin Resource Sharing policies are configured with the principle of least privilege, restricting allow\_origins, allow\_methods, allow\_headers, and allow\_credentials to only known and trusted entities, especially in production. Avoid overly permissive wildcards ("\*") where sensitive data or state-changing operations are involved.  
  * **Logging (StructlogMiddleware in app/logs/middleware.py):** Verify that logging is configured to capture essential auditable events and diagnostic information without logging sensitive data (PII, API keys, full request/response payloads containing sensitive content). Ensure log levels (app/logs/logging\_config.py) are appropriate for each environment (e.g., INFO or WARNING for production, DEBUG only for development with caution).  
* **Secure Authentication and Authorization Mechanisms:**  
  * **Strict Enforcement:** Confirm that authentication (HTTPBearer, valid\_api\_key in app/auth/dependencies.py) is consistently and correctly enforced on all protected API endpoints without exception.  
  * **Correct Scope Implementation:** Ensure scope checks (RequiresScope in app/auth/dependencies.py) are accurately applied to endpoints, function as intended, and cannot be easily bypassed.  
  * **Absence of Default/Weak Credentials:** Verify there are no hardcoded, default, guessable, or easily enumerable credentials for API access or any administrative functions. (Note: create\_admin\_user.py generates random keys, which is good).  
* **Secure Secrets Management (app/config/settings.py):**  
  * **Externalized Secrets:** Confirm that all sensitive configurations (database connection strings, cloud provider API keys/role ARNs, application-specific secrets) are loaded securely from environment variables or protected .env files, and are **never** hardcoded in the codebase.  
  * **.env File Security:** Ensure the .env file is not web-accessible, has restrictive file system permissions, and is robustly excluded from version control (e.g., via .gitignore).  
* **Secure Dependency Management (Process Verification):**  
  * Acknowledge that a critical misconfiguration is the use of outdated or vulnerable third-party libraries (pyproject.toml). Testing involves verifying that processes are in place for regular dependency scanning, vulnerability assessment, and timely patching.  
* **Appropriate HTTP Security Headers:**  
  * Check for the presence and correct configuration of essential security-related HTTP response headers designed to protect against common web vulnerabilities (e.g., Strict-Transport-Security (HSTS), X-Content-Type-Options: nosniff, X-Frame-Options: DENY or SAMEORIGIN, Content-Security-Policy (CSP), Referrer-Policy). While often managed by a reverse proxy in production, the application should not interfere with or undermine these.  
* **Secure Database Configuration & Access:**  
  * **Least Privilege Access:** Ensure the application connects to the database (app/db/session.py) using credentials that have the minimum necessary permissions for its runtime operations (e.g., CRUD on specific tables, not administrative rights).  
  * **Connection String Security:** The database connection string itself must be protected as a secret.  
  * **Secure Database Server Configuration:** (External to app code but relevant) The database server itself should be hardened (e.g., limited network exposure, strong admin credentials, regular patching).  
* **Minimization of Attack Surface (Unnecessary Features/Endpoints):**  
  * Verify that no unnecessary services, ports, or debug/test/sample endpoints are enabled or accessible in production environments.  
  * Ensure that default routes or features of the framework (FastAPI, Uvicorn) or libraries that are not explicitly needed and could pose a security risk are disabled.  
* **Secure Cloud Provider Configuration (Bedrock, Vertex AI):**  
  * **Least Privilege IAM:** Ensure the application uses secure methods to authenticate with cloud providers (e.g., IAM roles like BEDROCK\_ASSUME\_ROLE, or service accounts for Vertex AI, as configured in app/providers/) and that these identities have permissions strictly limited to the necessary actions on specific resources (e.g., invoking only specific LLM models).  
  * **Secure SDK Configuration:** Verify that SDKs (aioboto3, vertexai) are used with secure defaults and configurations (e.g., region specification, retry mechanisms that don't leak info).

This testing aims to reduce the overall attack surface by ensuring the system is hardened through correct and secure configurations at all relevant layers.

## **2\. Identify Potential Misconfiguration Points & Expected Secure Configurations/Outcomes**

This section details areas within the AI API Framework and its typical deployment context where security misconfigurations could occur. For each point, it defines the potential misconfiguration, its impact, relevant code references (if applicable), and the expected secure state or behavior.

**Sources for Identification:**

* **Application Code:** app/main.py, app/config/settings.py, app/auth/, app/logs/, app/db/, app/providers/, app/routers/.  
* **Deployment Scripts & Infrastructure as Code (IaC) (if available):** Dockerfiles, server setup scripts, cloud formation templates, etc.  
* **Web Server Configuration (Uvicorn defaults, or reverse proxy like Nginx/Traefik):** How Uvicorn is run, proxy configurations.  
* **Database Server Configuration:** PostgreSQL settings.  
* **Cloud Provider IAM Policies and Service Configurations:** AWS IAM policies for Bedrock, GCP IAM for Vertex AI.  
* **Dependency Manifests:** pyproject.toml.  
* **Security Best Practices & Checklists:** OWASP, NIST, CIS Benchmarks.

**A. Application Framework (FastAPI/Uvicorn) Misconfigurations:**

1. **Debug Mode in Production:**  
   * **Misconfiguration:** FastAPI application initialized with debug=True (e.g., FastAPI(debug=True, ...)). Uvicorn run with \--reload or \--debug flags in a production environment.  
   * **Potential Impact:** Exposure of detailed error pages containing stack traces, local variables, and other sensitive internal debugging information to clients upon unhandled exceptions. This provides attackers with valuable reconnaissance data.  
   * **Code Reference:** app/main.py initializes app \= FastAPI(lifespan=lifespan). The debug parameter defaults to False. The README.md command uv run fastapi dev implies development mode, which often includes reload. Production startup scripts must explicitly avoid these flags.  
   * **Expected Secure Configuration/Outcome:** In production environments, FastAPI(debug=False, ...) (or default). Uvicorn must be run without \--reload or \--debug. All unhandled errors must be caught by the generic 500 error handler in app/main.py (json\_500\_handler), which returns a non-revealing JSON response.  
2. **Verbose Error Messages (Beyond Debug Mode):**  
   * **Misconfiguration:** Custom exception handlers or default framework error responses revealing excessive detail (e.g., raw exception messages, parts of problematic code, full SQL queries, internal variable names/values).  
   * **Potential Impact:** Information leakage aiding attackers in understanding system internals or crafting further attacks.  
   * **Code Reference:**  
     * app/main.py json\_500\_handler: Returns {"detail": "Internal Server Error", "request\_id": "..."}. This is good.  
     * FastAPI's default 422 Pydantic error handler: Returns {"detail": \[{"loc": ..., "msg": ..., "type": ...}\]}. The msg and loc can reflect user input, which is generally acceptable for client debugging but should be reviewed if input can be extremely sensitive and large.  
     * Custom InputDataError handler in app/routers/api\_v1.py: Returns {"error": "Bad Request", "message": str(e), "field": e.field\_name}. The messages in app/providers/exceptions.py (e.g., InvalidImageURLError) are static or describe format errors, which is good.  
   * **Expected Secure Configuration/Outcome:** Client-facing error messages are generic where appropriate (especially for 5xx errors), provide a request\_id for correlation, and do not leak internal system details. For 4xx errors, messages should help legitimate users correct input without over-exposing validation logic or reflecting excessive sensitive input.

**B. Middleware Misconfigurations:**

1. **CORS Policy Too Permissive (app/main.py CORSMiddleware):**  
   * **Misconfiguration:**  
     * allow\_origins=\["\*"\] in production.  
     * allow\_credentials=True combined with allow\_origins=\["\*"\] or a list of non-specific origins.  
     * allow\_methods=\["\*"\] or allow\_headers=\["\*"\] if not all methods/headers are truly needed.  
   * **Potential Impact:** Allows any website to make requests to the API. If allow\_credentials=True is also permissive, it can enable cross-origin attacks that exploit user sessions (though less relevant for Bearer token auth if tokens aren't sent automatically by browsers for cross-origin requests without specific JS). Can facilitate data exfiltration by malicious sites if the API returns sensitive data and the user is authenticated.  
   * **Current Implementation Check:** app/main.py has origins \= \["[http://localhost](http://localhost/)", "[http://localhost:8080](http://localhost:8080/)", "\*"\]. The "\*" is dangerous for production. allow\_credentials=True is set.  
   * **Expected Secure Configuration/Outcome:** In production, allow\_origins must be an explicit list of trusted frontend domains that need to interact with the API. If allow\_credentials=True is necessary, it must only be used with specific, trusted origins (never "\*") . allow\_methods should be restricted to GET, POST (and OPTIONS for preflight). allow\_headers should list only necessary headers (e.g., Content-Type, Authorization, any custom headers).  
2. **Logging Misconfiguration (app/logs/logging\_config.py, app/logs/middleware.py):**  
   * **Misconfiguration:**  
     * LOG\_LEVEL (from app/config/settings.py) set to DEBUG or more verbose in production.  
     * StructlogMiddleware or other logging points configured to log full request/response bodies, sensitive headers (like raw Authorization token), or other PII/sensitive data by default at INFO level.  
     * structlog.dev.ConsoleRenderer(colors=True) used in production (JSON is preferred for machine parsing).  
   * **Potential Impact:** Leakage of sensitive data (PII, user prompts, LLM responses, API keys if mishandled) into logs, increasing risk if logs are compromised or have broad access. Excessive log volume impacting performance and storage.  
   * **Current Implementation Check:** LOG\_LEVEL is configurable. StructlogMiddleware logs request metadata (path, method, IP, user-agent, status, duration, request\_id) but not bodies. format\_exc\_info is used for non-dev environments (good for server-side stack traces). ConsoleRenderer is used for dev, JSONRenderer for non-dev (good).  
   * **Expected Secure Configuration/Outcome:** LOG\_LEVEL in production should be INFO or WARNING. Logging should not capture full sensitive payloads at these levels. Any sensitive identifiers logged (like user\_id from APIKey.manager\_id in billing) must be acknowledged and log access strictly controlled.

**C. Authentication and Authorization Misconfigurations:**

1. **Endpoints Missing Authentication/Authorization (app/routers/api\_v1.py):**  
   * **Misconfiguration:** An endpoint that processes data or performs actions (not purely public static info) lacks the Depends(valid\_api\_key) or an appropriate Depends(RequiresScope(\[...\])) dependency.  
   * **Potential Impact:** Unauthorized access to API functionalities or data.  
   * **Current Implementation Check:** All defined endpoints (/models, /chat/completions, /embeddings) in app/routers/api\_v1.py correctly use Depends(valid\_api\_key) or Depends(RequiresScope(...)).  
   * **Expected Secure Configuration/Outcome:** All non-public endpoints are protected. New endpoints must have appropriate auth dependencies added.  
2. **Default, Weak, or Hardcoded API Keys:**  
   * **Misconfiguration:** System ships with known default API keys, allows users to create very short/guessable keys, or developers hardcode keys for testing and forget to remove them.  
   * **Potential Impact:** Trivial unauthorized access.  
   * **Current Implementation Check:** app/auth/utils.py generate\_api\_key uses secrets.token\_urlsafe (good for randomness) and SHA256 hashing. create\_admin\_user.py uses this utility. No evidence of hardcoded or default keys in the application logic.  
   * **Expected Secure Configuration/Outcome:** API keys remain cryptographically strong, randomly generated, and their hashes are stored. No hardcoded or default keys exist in the codebase or default configurations.  
3. **Incorrect Scope Definitions or Enforcement (app/auth/schemas.py, app/auth/dependencies.py, app/routers/api\_v1.py):**  
   * **Misconfiguration:**  
     * Scope enum in app/auth/schemas.py missing necessary granular scopes or having overly broad ones.  
     * RequiresScope dependency in app/routers/api\_v1.py applied with incorrect or insufficient scopes for an endpoint's functionality (e.g., an endpoint modifying data only checks for a read scope).  
     * Logical flaws in RequiresScope.\_\_call\_\_ that might allow bypass (current implementation self.scopes.issubset(set(api\_key.scopes)) seems correct for "all required scopes must be present").  
   * **Potential Impact:** Privilege escalation or users being unable to access functionalities they are entitled to.  
   * **Expected Secure Configuration/Outcome:** Scopes are granular and correctly defined. Endpoints are decorated with the precise set of scopes required for their operation, adhering to the principle of least privilege. Scope enforcement logic is sound.

**D. Secrets Management (app/config/settings.py, .env file, deployment environment):**

1. **Hardcoded Secrets in Codebase:**  
   * **Misconfiguration:** Any secret (DB passwords, cloud credentials, application-specific secret keys) directly embedded in Python files or other code files.  
   * **Potential Impact:** High risk of secret exposure if the codebase is leaked, accessed by unauthorized internal personnel, or through version control history.  
   * **Current Implementation Check:** app/config/settings.py uses Pydantic BaseSettings to load secrets from environment variables or a .env file (e.g., postgres\_connection: str \= Field(default=...) where ... means it must be provided). This is the correct approach.  
   * **Expected Secure Configuration/Outcome:** Zero secrets hardcoded in the application codebase. All secrets are loaded exclusively from the environment or secure configuration management systems at runtime.  
2. **Insecure .env File Handling:**  
   * **Misconfiguration:**  
     * .env file containing production secrets committed to version control (e.g., Git).  
     * .env file on the server having overly permissive file system permissions (e.g., world-readable).  
     * .env file being inadvertently served if the web server root is misconfigured.  
   * **Potential Impact:** Direct exposure of all secrets contained within the .env file.  
   * **Expected Secure Configuration/Outcome:** The .env file (if used, especially for development) **MUST** be included in .gitignore. In production, secrets should ideally be injected as environment variables via the deployment platform, not from a file on disk. If a .env file is used in production, its file permissions must be strictly limited to the application user. The web server must be configured never to serve dotfiles.  
3. **Secrets Exposed in Logs or Error Messages (Overlap with Data Exposure):**  
   * **Misconfiguration:** Application code or logging configuration that causes any part of the Settings object (especially fields containing secrets like postgres\_connection, BEDROCK\_ASSUME\_ROLE, etc.) to be logged or included in error responses.  
   * **Potential Impact:** Secrets written to logs or exposed to clients.  
   * **Expected Secure Configuration/Outcome:** Strict avoidance of logging raw Settings objects or their sensitive attributes. Error handling should not reflect configuration values.

**E. Dependency Management (Process Misconfiguration \- pyproject.toml):**

1. **Outdated or Vulnerable Dependencies:**  
   * **Misconfiguration:** Failure to regularly update direct and transitive dependencies. Using libraries with known, unpatched security vulnerabilities.  
   * **Potential Impact:** The API framework inherits vulnerabilities from its dependencies, potentially leading to various exploits (RCE, data breaches, DoS).  
   * **Expected Secure Configuration/Outcome:** A documented process and tooling (e.g., uv pip list \--outdated, pip-audit, GitHub Dependabot, Snyk, or similar) are used to regularly scan dependencies for known vulnerabilities and to plan for timely updates and patching.

**F. HTTP Security Headers (Deployment Context / Reverse Proxy):**

1. **Missing or Weak Key Security Headers:**  
   * **Misconfiguration:** Production deployment lacks or has weakly configured Strict-Transport-Security (HSTS), X-Content-Type-Options: nosniff, X-Frame-Options: DENY (or SAMEORIGIN), Content-Security-Policy (CSP), Referrer-Policy, Permissions-Policy.  
   * **Potential Impact:** Increased susceptibility to Man-in-the-Middle (MITM) attacks (no HSTS), MIME-type confusion attacks, clickjacking, cross-site scripting (if CSP is weak or missing), information leakage via referrers.  
   * **Current Implementation Check:** FastAPI/app/main.py does not add these by default. These are typically managed by a reverse proxy (e.g., Nginx, Traefik) or an API gateway in production.  
   * **Expected Secure Configuration/Outcome:** For production deployments, these headers **MUST** be correctly configured and served, usually by the web server or reverse proxy fronting the FastAPI application. The application itself should not send headers that conflict with or weaken these policies.

**G. Database Configuration & Access (app/db/session.py, POSTGRES\_CONNECTION):**

1. **Overly Permissive Database User Privileges:**  
   * **Misconfiguration:** The database user account specified in the POSTGRES\_CONNECTION string has excessive privileges (e.g., superuser, DDL rights like CREATE TABLE, DROP TABLE) when only DML operations (SELECT, INSERT, UPDATE, DELETE on specific application tables) are required for runtime.  
   * **Potential Impact:** If the API server or application logic is compromised, an attacker could leverage these excessive database privileges to cause greater damage (e.g., drop tables, access other databases, modify schema).  
   * **Expected Secure Configuration/Outcome:** The application's runtime database user connects with the principle of least privilege. A separate, more privileged user might be used for Alembic migrations (alembic.ini can specify a different URL or the migration script can assume higher privileges if run manually by an admin).  
2. **Database Exposed Publicly or Insecure Network Configuration:**  
   * **Misconfiguration:** The PostgreSQL server is directly accessible from the public internet without a firewall, or within an overly permissive internal network segment. Default PostgreSQL port (5432, though your setup uses 5433 for Docker mapping) exposed unnecessarily.  
   * **Potential Impact:** Direct brute-force attacks, exploitation of database vulnerabilities, unauthorized data access.  
   * **Expected Secure Configuration/Outcome:** The database server is firewalled and ideally only accessible from the application server(s) over a private network or via localhost if on the same machine. Network connections to the database should be encrypted if not on a trusted, isolated network.

**H. Unnecessary Features/Endpoints/Methods (app/routers/api\_v1.py, FastAPI defaults):**

1. **Unused HTTP Methods Enabled on Endpoints:**  
   * **Misconfiguration:** FastAPI routes might inadvertently allow or not explicitly restrict HTTP methods beyond those intended (e.g., if a generic route handler was used, though @router.get, @[router.post](http://router.post/) are specific). Standard REST practice is for unused methods to result in a 405\.  
   * **Potential Impact:** Increases the attack surface. Methods like TRACE could potentially be used for information leakage in some contexts (though less common with modern browsers/proxies).  
   * **Current Implementation Check:** FastAPI routes are defined with specific methods (@router.get, @[router.post](http://router.post/)). Unspecified methods on these paths correctly result in a 405 Method Not Allowed.  
   * **Expected Secure Configuration/Outcome:** Only explicitly defined and necessary HTTP methods are enabled and functional for each route. All other methods return 405\.  
2. **Debug/Test/Sample Endpoints Exposed in Production:**  
   * **Misconfiguration:** Leaving development-specific, diagnostic, or sample API endpoints (which might have weaker security or expose internal data) active and accessible in production environments.  
   * **Potential Impact:** Information leakage, unauthorized actions, increased attack surface.  
   * **Current Implementation Check:** No obvious debug-specific endpoints are defined in app/routers/api\_v1.py.  
   * **Expected Secure Configuration/Outcome:** All API endpoints exposed in production are intended for production use, are fully secured, and have undergone security review. Any development/debug endpoints are conditionally compiled out or disabled based on an environment setting (e.g., ENV \!= "dev").

**I. Cloud Provider Security (AWS IAM for Bedrock, GCP IAM for Vertex AI):**

1. **Overly Permissive IAM Roles/Policies for LLM Access:**  
   * **Misconfiguration:** The IAM role specified by BEDROCK\_ASSUME\_ROLE (for AWS Bedrock) or the service account used by Application Default Credentials (for Google Vertex AI) has permissions beyond what's strictly necessary for the application to function (e.g., bedrock:\* on all resources, or broad GCP project roles).  
   * **Potential Impact:** If the API server is compromised, an attacker could potentially abuse these excessive cloud permissions to access other cloud services, manipulate resources, or exfiltrate data beyond the scope of the LLM interactions.  
   * **Code Reference:** BedRockBackend in app/providers/bedrock/bedrock.py uses bedrock\_assume\_role and aws\_default\_region. VertexBackend in app/providers/vertex\_ai/vertexai.py uses vertex\_project\_id and relies on the environment's Application Default Credentials.  
   * **Expected Secure Configuration/Outcome:**  
     * For Bedrock: The IAM role should have a trust policy allowing the application's compute identity to assume it. Its permissions policy should grant bedrock:InvokeModel action only on the specific model ARNs listed in BEDROCK\_MODELS\_\_\*\_ARN settings.  
     * For Vertex AI: The service account used by ADC should have a role like "Vertex AI User" or a custom role granting only aiplatform.endpoints.predict (or similar for generative models) on the specific Vertex AI models/endpoints being used.  
     * Principle of least privilege is strictly applied to cloud resource access.

## **3\. Design Test Cases**

This section details specific test cases to verify the security configurations identified above. Many of these will involve reviewing configurations and observing behavior rather than just sending specific API requests.

**General Test Case Components:**

* **ID:** Unique identifier (e.g., SM\_APP\_001)  
* **Category Ref:** (e.g., A: Application Framework, B: Middleware, etc. from Section 2\)  
* **Misconfiguration Point Ref:** (e.g., A.1 Debug Mode, B.1 CORS Policy)  
* **Description:** What specific misconfiguration is being tested for.  
* **Test Method/Action:** How the test is performed (e.g., "Review production startup scripts/command", "Send OPTIONS request with specific Origin header", "Inspect HTTP response headers", "Review IAM policy document in AWS/GCP console", "Execute uv pip check or pip-audit").  
* **Tools (if applicable):** curl, browser developer tools, AWS/GCP console or CLI, uv, security scanning tools, text editors for config review.  
* **Prerequisites/Environment:** Access to deployment environment (production or production-like staging), configuration files, source code, cloud consoles. Valid API key for some checks.  
* **Expected Secure Configuration/Outcome:** A clear statement of the secure state or behavior (e.g., "Debug mode is False", "CORS allow\_origins lists specific trusted domains", "IAM role only has bedrock:InvokeModel on specific model ARNs").  
* **Verification Steps:** How to confirm the expected secure outcome (e.g., "Verify Uvicorn startup command does not include \--reload", "Observe Access-Control-Allow-Origin header in response", "Check IAM policy JSON").

**A. Application Framework (FastAPI/Uvicorn) Misconfigurations (Category Ref: A)**

* **ID:** SM\_APP\_001  
  * **Misconfiguration Point Ref:** A.1 Debug Mode in Production  
  * **Description:** Verify FastAPI debug mode is disabled and Uvicorn is not run with \--reload or \--debug in production.  
  * **Test Method/Action:** Review production deployment scripts and running process arguments. Intentionally trigger an unhandled exception in a non-production (but similarly configured) environment where debug *might* be on, and then in production.  
  * **Tools:** Process inspection tools (e.g., ps aux | grep uvicorn), deployment configuration files.  
  * **Prerequisites:** Access to production/staging deployment environment.  
  * **Expected Secure Configuration/Outcome:** FastAPI debug parameter is False (default). Uvicorn production startup command does not include \--reload or \--debug. Unhandled exceptions in production result in the generic 500 JSON response from app/main.py, not a FastAPI debug page.  
  * **Verification Steps:**  
    1. Inspect the command used to start Uvicorn in production.  
    2. Review app/main.py to confirm FastAPI() is not called with debug=True.  
    3. (Carefully, in a safe manner) If possible, simulate or trigger a novel unhandled exception in a production-like environment and verify the client receives the generic 500 JSON response, not a debug page.  
* **ID:** SM\_APP\_002  
  * **Misconfiguration Point Ref:** A.2 Verbose Error Messages  
  * **Description:** Verify that error responses (4xx, 5xx) do not leak sensitive internal details.  
  * **Test Method/Action:** Trigger various error types (Pydantic 422, custom 400, auth 401, generic 500\) by sending malformed requests or simulating internal failures (using mocks if testing non-prod).  
  * **Tools:** API client (curl, Postman), mocking libraries.  
  * **Prerequisites:** Running API.  
  * **Expected Secure Configuration/Outcome:**  
    1. 500 errors: Return {"detail": "Internal Server Error", "request\_id": "\<uuid\>"}.  
    2. 4xx errors: Return structured JSON with informative but non-sensitive messages (e.g., Pydantic error details are about input fields; custom error messages are static or describe format issues).  
    3. No stack traces, raw exception messages, SQL queries, or config values in any client-facing error response.  
  * **Verification Steps:**  
    1. Execute test cases from "7.5 Error Code Validation Test" that trigger different error types.  
    2. Inspect all fields of the JSON error responses.  
    3. Confirm absence of stack traces, sensitive exception messages, or internal system details.

**B. Middleware Misconfigurations (Category Ref: B)**

* **ID:** SM\_MID\_CORS\_001  
  * **Misconfiguration Point Ref:** B.1 CORS Policy Too Permissive  
  * **Description:** Verify CORS allow\_origins is not "\*" in production and allow\_credentials=True is used cautiously.  
  * **Test Method/Action:** Review app/main.py CORSMiddleware setup. Send OPTIONS preflight requests and actual requests from an untrusted origin (e.g., using curl with a fake Origin header or a simple HTML page served from a different domain) to a production-like environment.  
  * **Tools:** curl, browser developer tools.  
  * **Prerequisites:** Production-like deployment.  
  * **Expected Secure Configuration/Outcome:** For production, origins in app/main.py should not contain "\*". If allow\_credentials=True, allow\_origins must be a list of specific, trusted domains. Access-Control-Allow-Origin response header should reflect a specific trusted origin or vary based on the request's trusted origin, not "\*".  
  * **Verification Steps:**  
    1. Inspect app/main.py CORSMiddleware parameters.  
    2. Send an OPTIONS request with Origin: [https://untrusted.com](https://untrusted.com/). Check response headers.  
    3. Send a GET/POST request with Origin: [https://untrusted.com](https://untrusted.com/). Check response headers.  
    4. If allow\_credentials=True, ensure Access-Control-Allow-Origin is never "\*" in the response.  
* **ID:** SM\_MID\_LOG\_001  
  * **Misconfiguration Point Ref:** B.2 Logging Misconfiguration  
  * **Description:** Verify production LOG\_LEVEL is INFO or higher, and sensitive data is not in standard logs.  
  * **Test Method/Action:** Review app/config/settings.py for LOG\_LEVEL in production. Send requests with potentially sensitive data in prompts or user fields.  
  * **Tools:** Log inspection tools.  
  * **Prerequisites:** Production-like deployment with logging configured.  
  * **Expected Secure Configuration/Outcome:** LOG\_LEVEL is INFO or WARNING. Logs (Structlog, billing) do not contain full request/response bodies, sensitive prompt content, or raw API keys at this level. JSONRenderer is used for non-dev.  
  * **Verification Steps:**  
    1. Check the effective LOG\_LEVEL in the production environment.  
    2. Make API calls with mock sensitive data in prompts.  
    3. Inspect server logs to confirm that full prompts/payloads are not logged at INFO/WARNING level.  
    4. Confirm log format is JSON in non-dev environments.

**C. Authentication and Authorization Misconfigurations (Category Ref: C)**

* **ID:** SM\_AUTH\_001  
  * **Misconfiguration Point Ref:** C.1 Endpoints Missing Authentication/Authorization  
  * **Description:** Review all defined API endpoints to ensure appropriate auth dependencies are applied.  
  * **Test Method/Action:** Code review of app/routers/api\_v1.py. Attempt to access each endpoint without any Authorization header.  
  * **Tools:** API client, source code editor.  
  * **Prerequisites:** List of all API endpoints.  
  * **Expected Secure Configuration/Outcome:** All endpoints (except potentially a public health check if one existed) have Depends(valid\_api\_key) or Depends(RequiresScope(...)). Requests without valid auth to these endpoints fail with 401/403.  
  * **Verification Steps:**  
    1. For each endpoint in api\_v1.py, verify the presence of auth dependencies.  
    2. Send requests to each endpoint without the Authorization header. Expect 401/403.  
* **ID:** SM\_AUTH\_002  
  * **Misconfiguration Point Ref:** C.3 Incorrect Scope Definitions or Enforcement  
  * **Description:** Review scope definitions and their application to endpoints.  
  * **Test Method/Action:** Code review of app/auth/schemas.py (Scope enum) and app/routers/api\_v1.py (RequiresScope usage). Execute test cases from ECV\_AUTH category (e.g., ECV\_AUTH\_007, ECV\_AUTH\_008) that test scope enforcement.  
  * **Tools:** Source code editor, API client.  
  * **Prerequisites:** Understanding of intended access control for each endpoint.  
  * **Expected Secure Configuration/Outcome:** Scope enum is accurate and granular. RequiresScope uses the correct scopes for each endpoint's functionality, adhering to least privilege.  
  * **Verification Steps:**  
    1. Review scope definitions against functional requirements.  
    2. Review RequiresScope decorators on all protected routes.  
    3. Confirm that tests for insufficient scope (e.g., using an embedding-only key for chat) pass (i.e., correctly result in 401).

**D. Secrets Management (Category Ref: D)**

* **ID:** SM\_SEC\_001  
  * **Misconfiguration Point Ref:** D.1 Hardcoded Secrets in Code  
  * **Description:** Scan codebase for any hardcoded secrets.  
  * **Test Method/Action:** Automated static analysis (SAST tools if available) and manual code review, searching for common secret patterns (passwords, API keys, connection strings) outside of app/config/settings.py's environment loading.  
  * **Tools:** SAST tools (e.g., Bandit for Python, truffleHog), grep, code editor.  
  * **Prerequisites:** Access to source code.  
  * **Expected Secure Configuration/Outcome:** No hardcoded secrets in .py files or other version-controlled files. All secrets loaded via app/config/settings.py from the environment.  
  * **Verification Steps:** Perform search for keywords like "password", "secret", "key", "token", "arn:", "postgresql://", etc., in the codebase. Review settings.py to ensure all sensitive fields use Field(default=...) or are loaded from env.  
* **ID:** SM\_SEC\_002  
  * **Misconfiguration Point Ref:** D.2 Insecure .env File Handling  
  * **Description:** Verify .env is in .gitignore and check typical server deployment for .env file permissions and web accessibility.  
  * **Test Method/Action:** Check .gitignore. In a deployed environment, check file permissions of .env (if used) and attempt to access it via HTTP if web server root is misconfigured.  
  * **Tools:** Git client, shell access to server, web browser/curl.  
  * **Prerequisites:** Access to repository, deployed environment.  
  * **Expected Secure Configuration/Outcome:** .env is in .gitignore. On server, .env (if present) has restrictive permissions (e.g., readable only by application user). .env is not served by the web server.  
  * **Verification Steps:**  
    1. Confirm .env entry in .gitignore.  
    2. If .env is used in deployment, SSH to server and check ls \-l .env.  
    3. Attempt http://\<api\_host\>/.env \- expect 404 or 403\.

**E. Dependency Management (Category Ref: E)**

* **ID:** SM\_DEP\_001  
  * **Misconfiguration Point Ref:** E.1 Outdated or Vulnerable Dependencies  
  * **Description:** Check for known vulnerabilities in installed dependencies.  
  * **Test Method/Action:** Run a dependency vulnerability scanner against pyproject.toml or the installed packages in the virtual environment.  
  * **Tools:** uv pip list \--outdated (for outdated, not directly for vulnerabilities), pip-audit, Snyk, GitHub Dependabot alerts.  
  * **Prerequisites:** Project dependencies defined in pyproject.toml.  
  * **Expected Secure Configuration/Outcome:** No known high or critical severity vulnerabilities in dependencies. A process exists for regular review and patching.  
  * **Verification Steps:**  
    1. Execute uv run pip-audit (or similar tool).  
    2. Review reported vulnerabilities and compare against project's policy for patching.

F. HTTP Security Headers (Category Ref: F)

(Primarily for review of reverse proxy / load balancer configuration in a production-like environment)

* **ID:** SM\_HTTP\_HDR\_001  
  * **Misconfiguration Point Ref:** F.1 Missing Key Security Headers  
  * **Description:** Check for presence of HSTS, X-Content-Type-Options, X-Frame-Options, CSP.  
  * **Test Method/Action:** Make requests to the API in a production-like environment and inspect response headers.  
  * **Tools:** curl \-I, browser developer tools.  
  * **Prerequisites:** Production-like deployment with reverse proxy/gateway.  
  * **Expected Secure Configuration/Outcome:**  
    * Strict-Transport-Security header present with appropriate max-age and includeSubDomains.  
    * X-Content-Type-Options: nosniff present.  
    * X-Frame-Options: DENY or SAMEORIGIN present.  
    * Content-Security-Policy present with a restrictive policy.  
    * (Others like Referrer-Policy, Permissions-Policy as appropriate).  
  * **Verification Steps:** Inspect response headers for several API endpoints.

**G. Database Configuration & Access (Category Ref: G)**

* **ID:** SM\_DB\_001  
  * **Misconfiguration Point Ref:** G.1 Overly Permissive Database User  
  * **Description:** Review privileges of the database user defined in POSTGRES\_CONNECTION.  
  * **Test Method/Action:** Inspect database user grants in PostgreSQL.  
  * **Tools:** PostgreSQL client (e.g., psql), database admin tools.  
  * **Prerequisites:** Access to database with admin rights to check other users' grants. Knowledge of the application's runtime DB user.  
  * **Expected Secure Configuration/Outcome:** The application's runtime DB user has only necessary DML privileges (SELECT, INSERT, UPDATE, DELETE) on the application's tables (users, api\_keys, alembic\_version), and USAGE on sequences. No DDL, superuser, or access to other databases.  
  * **Verification Steps:** Connect to PostgreSQL as an admin and inspect grants for the application user (e.g., using \\du \<app\_user\> and \\dp \<schema\>.\*).

**H. Unnecessary Features/Endpoints/Methods (Category Ref: H)**

* **ID:** SM\_UNNEC\_001  
  * **Misconfiguration Point Ref:** H.2 Debug Endpoints in Production  
  * **Description:** Scan for any known debug or test endpoints in FastAPI routes not protected by environment checks.  
  * **Test Method/Action:** Code review of all router files. Attempt to access common debug paths (e.g., /debug, /test, /status if not intended for public use).  
  * **Tools:** Source code editor, API client.  
  * **Prerequisites:** List of all defined routes.  
  * **Expected Secure Configuration/Outcome:** No undocumented or debug-specific endpoints are accessible in production. Any such routes should be conditionally registered based on settings.ENV \!= "dev".  
  * **Verification Steps:** Review router files. Attempt to access potential debug paths.

**I. Cloud Provider Security (Category Ref: I)**

* **ID:** SM\_CLOUD\_001  
  * **Misconfiguration Point Ref:** I.1 Overly Permissive IAM Roles/Policies  
  * **Description:** Review IAM policies associated with BEDROCK\_ASSUME\_ROLE (AWS) and the service account used by ADC for Vertex AI (GCP).  
  * **Test Method/Action:** Inspect IAM policies in the AWS and GCP consoles or via CLI.  
  * **Tools:** AWS Management Console/CLI, GCP Cloud Console/gcloud CLI.  
  * **Prerequisites:** Access to the relevant AWS/GCP accounts with permissions to view IAM policies. Knowledge of the specific role ARN and service account email.  
  * **Expected Secure Configuration/Outcome:**  
    1. AWS IAM Role: Permissions policy grants bedrock:InvokeModel only for the specific model ARNs listed in settings.py. Trust policy correctly configured for the application's compute identity.  
    2. GCP Service Account: Has a role like "Vertex AI User" or a custom role granting only necessary permissions (e.g., aiplatform.endpoints.predict) on the specific Vertex AI models/endpoints being used. No overly broad project-level permissions like "Editor" or "Owner".  
  * **Verification Steps:**  
    1. In AWS console, find the IAM role for Bedrock. Review its attached permissions policies and trust relationships.  
    2. In GCP console, find the service account used by ADC (or specified). Review its IAM roles and permissions at project/service level.
