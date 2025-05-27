# AI API Framework - Integration Tests

## 1. Introduction & Purpose
This directory `./tests/integration/`) contains integration tests for the AI API Framework. These tests are designed to verify the interactions between different components of the application, ensuring they work together as expected.

Unlike unit tests (found in `./tests/unit`), which focus on isolated parts, integration tests here will typically:
* Make actual HTTP requests to a running instance of the FastAPI application.
* Interact with a real (though typically test-specific) PostgreSQL database.
* Verify the end-to-end flow for API endpoints, including request parsing, authentication, authorization, business logic execution in providers, and response generation.
* Test error handling across components (e.g., how the API responds to auth failures, input validation errors, or simulated downstream provider issues).
* Validate API call sequences and workflows.

The primary objectives of these integration tests are:
* **Functional Correctness of Endpoints:** Ensure each API endpoint behaves as specified when integrated with other services like the database and authentication modules.
* **AuthN/AuthZ Integration:** Verify that authentication (API key validation) and authorization (scope checking) work correctly at the HTTP interface level.
* **Data Validation and Error Handling:** Confirm that input validation (Pydantic, custom) and error responses (4xx, 5xx) are correctly handled and generated through the full request-response cycle.
* **Database Interaction:** Ensure that operations requiring database access (primarily for API key retrieval and validation) function correctly.
* **Provider Interaction (Mocked/Live):** Test the API's interaction with backend LLM providers (either mocked versions for predictable testing or live instances for true end-to-end checks if configured). The tests are designed to primarily use mocked providers controlled by the `USE_MOCK_PROVIDERS` environment variable.
* **API Call Sequences:** Validate that a series of API calls correctly execute workflows and manage context or state implicitly passed between calls.

These tests use `pytest` as the test runner and the `requests` library to make HTTP calls. They also leverage `pytest-asyncio` for asynchronous operations and `unittest.mock` (or `pytest-mock`) for patching and simulating specific conditions.

## 2. Test Structure
The integration tests are organized into files based on the category of functionality or error conditions they target:
* **`conftest.py`**: Contains shared Pytest fixtures used across multiple integration test files. This includes fixtures for setting up test users, API keys with various permissions in the database, generating valid HTTP headers, and providing sample request payloads.
* **`test_auth_errors.py`**: Focuses on testing authentication and authorization mechanisms, including various scenarios of invalid, expired, or insufficient-scope API keys.
* **`test_input_validation_errors.py`**: Tests how the API handles invalid or malformed request payloads, covering Pydantic schema validation and custom input validation logic (e.g., for image data URIs).
* **`test_model_validation_errors.py`**: Verifies error handling when unsupported model IDs are requested or when models are used for incompatible capabilities (e.g., a chat model for an embedding task).
* **`test_http_protocol_errors.py`**: Checks for correct standard HTTP error responses like 404 (Not Found) for invalid paths and 405 (Method Not Allowed) for incorrect HTTP methods on existing endpoints.
* **`test_server_errors.py`**: Focuses on the API's resilience and error reporting when encountering internal server errors or simulated failures from downstream dependencies (like database or LLM providers). This heavily uses mocking.
* _(Additional files would be created for other test categories like API Call Sequences, Data Exposure, etc., following a similar pattern)._

## 3. Prerequisites & Setup
Before running the integration tests, ensure the following prerequisites are met:
1.  **Complete Project Setup:** The main project setup (as outlined in the root `README.md` or `setup_macos.sh` script) must be completed. This includes:
    * Python virtual environment created and dependencies installed via `pip install -r requirements.txt`.
    * Docker installed and running.
    * PostgreSQL (pgvector) Docker container (`pgvector_postgres_aigovapi`) running and accessible.
    * Database schema migrations applied via `python -m alembic upgrade head`.

2.  **`.env` File Configuration:**
    * An `.env` file must be present in the project root, configured by the `setup_macos.sh` script or manually.
    * **`POSTGRES_CONNECTION`**: Must point to the test database (e.g., `postgresql+asyncpg://postgres:postgres@localhost:5433/postgres`).
    * **`USE_MOCK_PROVIDERS`**:
        * Set to `true` (default for most tests) to use the mock LLM provider backends (`app/providers/mocks.py`). This makes tests faster, more predictable, and avoids costs. The mock providers are designed to support the behaviors needed for these integration tests.
         _Set to_ `false` _if you intend to test against live AWS Bedrock and GCP Vertex AI services (requires_ `BEDROCK_ASSUME_ROLE`_,_ `AWS_DEFAULT_REGION`_,_ `VERTEX_PROJECT_ID`_, and model ARNs to be correctly configured in the_ `.env` _file, and your environment must be authenticated to AWS/GCP)._ **Caution:** Testing against live services will incur costs and may be less reliable due to external factors.
    * Other necessary environment variables (like cloud provider ARNs/IDs) should be present, even if using mock providers, as the application settings (`app/config/settings.py`) might expect them for initial validation. The `setup_macos.sh` script handles making these optional if mocks are used.

3.  **SSL Certificate Configuration (for corporate proxies/Zscaler):**
    * If you're behind a corporate proxy or using Zscaler, ensure your SSL certificate is properly configured.
    * Source the certificate environment variables before running tests: `source ./setup_ssl_certs.sh` 
    * This sets the necessary `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` environment variables that allow Python to make HTTPS requests through your corporate proxy.

4.  **Running Application (Optional but Recommended for some test approaches):**
    * While some integration tests using FastAPI's `TestClient` can run against an in-memory instance of the app, these integration tests are designed to use the `requests` library, which requires the FastAPI application to be running as a separate process.
    * Start the application using: `python -m fastapi dev` (while in the virtual environment)
    * If you're behind a corporate proxy, remember to source the SSL certificates first.

5.  **Test Database State:**
    * The tests in `tests/integration/conftest.py` are designed to create necessary users and API keys in the database.
    * It's recommended to run these tests against a dedicated test database that can be reset or cleaned up if needed. The current fixtures create unique users per module/session to minimize interference but do not perform automated cleanup after tests.

## 4. Understanding Key Fixtures (`tests/integration/conftest.py`)
The `conftest.py` file provides several important fixtures:
* **`BASE_URL`**: The base URL for the running API (defaults to `http://127.0.0.1:8000/api/v1`).
* **`test_user`**: Creates a sample user in the database.
* **API Key Fixtures**:
    * `valid_api_key_all_scopes`: A key with both `models:inference` and `models:embedding` scopes.
    * `valid_api_key_inference_only`: A key with only `models:inference` scope.
    * `valid_api_key_embedding_only`: A key with only `models:embedding` scope.
    * `valid_api_key_no_scopes`: A key with no scopes.
    * `inactive_api_key`: An API key that is marked as inactive.
    * `expired_api_key`: An API key whose `expires_at` date is in the past.
* **`valid_headers`**: Provides a dictionary with `Authorization` (using `valid_api_key_all_scopes`) and `Content-Type` headers.
* **Payload Fixtures**:
    * `minimal_chat_payload`: A basic valid payload for `/chat/completions`.
    * `minimal_embedding_payload`: A basic valid payload for `/embeddings`.
* **Model ID Fixtures**:
    * `configured_chat_model_id`: Provides a model ID expected to be configured for chat (e.g., "claude_3_5_sonnet").
    * `configured_embedding_model_id`: Provides a model ID expected to be configured for embeddings (e.g., "cohere_english_v3").
* **Data Fixtures**:
    * `valid_image_data_uri`: A valid Base64 encoded data URI for a tiny image.
    * `valid_file_data_base64`: A valid Base64 encoded string representing minimal PDF-like data.

These fixtures help create consistent test preconditions and reduce boilerplate in test files.

## 5. Running the Tests
1.  **Ensure Prerequisites are Met:** Verify all setup steps from Section 3 are complete.

2.  **Activate the Virtual Environment:**
    ```bash
    source .venv/bin/activate
    ```
    Your command prompt should change to indicate that the virtual environment is active.

3.  **Configure SSL Certificates (if using a corporate proxy/Zscaler):**
    ```bash
    source ./setup_ssl_certs.sh
    ```

4.  **Start the API Application (in one terminal):**
    Open a terminal, navigate to the project root, and run:
    ```bash
    # First activate the virtual environment
    source .venv/bin/activate
    
    # If behind a corporate proxy, source the SSL certificates
    source ./setup_ssl_certs.sh
    
    # Start the application
    python -m fastapi dev
    ```
    Keep this terminal running.

5.  **Run Pytest (in another terminal):**
    Open another terminal, navigate to the project root.
    ```bash
    # Activate the virtual environment
    source .venv/bin/activate
    
    # If behind a corporate proxy, source the SSL certificates
    source ./setup_ssl_certs.sh
    ```
    
    Then run the tests:
    * To run all integration tests:
        ```bash
        python -m pytest tests/integration/
        ```
        
    * To run a specific test file:
        ```bash
        python -m pytest tests/integration/test_auth_errors.py
        ```
        
    * To run a specific test case by name (using `-k` flag):
        ```bash
        python -m pytest tests/integration/test_auth_errors.py -k test_ecv_auth_006_expired_api_key
        ```
        
    * For more verbose output:
        ```bash
        python -m pytest -vv tests/integration/
        ```

**Important Considerations:**
* **Virtual Environment:** Always ensure you have activated the virtual environment (`.venv`) before running either the tests or the application. The tests need access to all the dependencies installed in the virtual environment.
* **Mock vs. Live Providers:** The behavior of tests interacting with LLM providers will depend on the `USE_MOCK_PROVIDERS` setting in your `.env` file. When set to `true`, the mock backends from `app/providers/mocks.py` will be used. When `false`, tests will attempt to call actual AWS Bedrock or GCP Vertex AI services.
* **Database Operations:** Many tests (especially in `test_auth_errors.py`) interact with the database via the API to set up and verify API key states. Ensure your `POSTGRES_CONNECTION` in `.env` is correctly pointing to your test database.
* **Environment Variables:** `pytest` will automatically make variables from your `.env` file available to the application when it's started by `TestClient` or when tests make requests to an externally running instance.
* **SSL Certificates for Corporate Proxies:** If you're working behind Zscaler or another corporate proxy, always remember to source the SSL certificate configuration before running tests or starting the application to avoid SSL verification errors.

By following these instructions, you should be able to effectively run and understand the integration tests for the AI API Framework.