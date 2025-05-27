# Data Anonymization/Masking Testing

This document outlines the approach to testing data anonymization and masking features and requirements within the AI API Framework. This aligns with the broader data privacy and compliance objectives mentioned in the [GSAi API Test Plan](https://docs.google.com/document/d/19_nlgUmNBrs9gKL8sIM8BDDABc6LkTqtLYwT7Aflfso/edit?usp=drive_link)  and specifically addresses section 7.9 of the Test Data Management Strategy (DoD API Tech Guide Sec 6.2.2) regarding the use of anonymized/masked production-derived data for testing.

## 1\. Understand the Goal

The primary goal of Data Anonymization/Masking Testing for the AI API Framework is to ensure that processes and (if any future) features related to the de-identification of sensitive data are effective, secure, and compliant. This is critical for protecting individual privacy and adhering to data protection regulations when handling data that could contain Personally Identifiable Information (PII), Protected Health Information (PHI), Controlled Unclassified Information (CUI), or other sensitive details.

**Specific objectives for this AI API Framework include verifying:**

* **Effectiveness of Anonymization/Masking Techniques (Primarily for Test Data Processes):**  
  * If production-derived data is ever used to create test datasets, the anonymization/masking techniques applied (e.g., redaction, substitution, generalization, synthetic data generation) must effectively remove or obscure direct and indirect identifiers to a level where the risk of re-identifying individuals is minimized to an acceptable threshold according to relevant standards.  
  * For any *future* API features that might offer anonymization, these techniques would need to be directly tested for their de-identification efficacy.  
* **Data Utility Post-Anonymization (for Test Data):**  
  * When anonymized/masked data is used for testing (e.g., performance, functional, security), the de-identification process should aim to preserve the data's structural integrity and representative characteristics enough for it to be useful for its intended testing purpose. This often involves a trade-off between privacy protection and data utility.  
* **No Leakage or Reversal of Anonymization:**  
  * Confirm that original, unmasked sensitive data is not inadvertently exposed through any part of the system (API responses, logs, error messages, side channels) *after* an anonymization/masking process has been applied (e.g., to test data).  
  * Ensure that the API framework itself does not contain functionalities that could inadvertently de-anonymize or allow trivial reversal of pre-anonymized inputs it receives.  
* **Compliance with Policies and Regulations:**  
  * Ensure that any handling of data requiring anonymization or masking (especially in the creation and use of test datasets) adheres to internal data governance policies and external regulatory requirements (e.g., HIPAA, GDPR, CCPA, specific DoD mandates for CUI).  
* **Secure Handling of De-identification Processes (Future Consideration):**  
  * If the API were to perform de-identification as a service, the process itself would need to be secure. This includes protecting any keys, patterns, or algorithms used for de-identification.

Current Scope and Focus for AI API Framework:

The existing codebase for the AI API Framework (app/) primarily functions as a proxy for LLM services, managing authentication and routing requests. It does not currently offer explicit built-in features for data anonymization or masking as a service to its clients.

Therefore, for the current version of the API, this testing will primarily focus on:

1. **Test Data Management Policies and Practices (Procedural Verification):**  
   * Verifying the API framework's behavior when interacting with *test data that is presumed to have been anonymized/masked* according to the guidelines in the main API Test Plan (Section 7.9). This involves ensuring the API processes such data without issues and doesn't inadvertently expose placeholders or reveal patterns that could weaken the anonymization.  
   * This is less about testing an API feature and more about testing the API's compatibility with secure test data practices.  
2. **Secure Handling of Potentially Sensitive Data in Logs and Errors (Overlap with Data Exposure Testing):**  
   * Re-evaluating logging (app/logs/, app/services/billing.py) and error message generation (app/main.py, app/routers/api\_v1.py) from the perspective of data minimization. The goal is to ensure that if a client *were* to send sensitive data (which they should secure themselves), the API framework doesn't unnecessarily persist or expose this data in logs or error details in a way that would create a secondary risk pool.  
3. **Non-Interference with Pre-Anonymized Data:**  
   * Ensuring the API faithfully transmits data that might have been anonymized by the client (e.g., prompts containing \[NAME\] placeholders) to the backend LLMs without altering or misinterpreting these anonymization markers.  
4. **Conceptual Preparedness for Future Anonymization Features:**  
   * Laying the groundwork for how future features involving more direct data handling, user content storage, or explicit anonymization-as-a-service capabilities would be tested.

## 2\. Identify Potential Data Requiring Anonymization/Masking & Expected Outcomes

This section details types of data handled by the system that are or could be sensitive. The focus is on where anonymization/masking would be relevant, primarily in the context of generating or using data for non-production environments (e.g., test datasets) or ensuring the API handles potentially sensitive pass-through data securely in its logs and error messages.

**Sources for Identification:**

* **Database Models (app/users/models.py, app/auth/models.py):**  
  * User model: email (PII), name (PII).  
  * APIKey model: manager\_id (links to User PII), key\_prefix (could be an indirect identifier if prefixes are unique per user/department).  
* **API Request/Response Payloads (app/providers/open\_ai/schemas.py):**  
  * ChatCompletionRequest.messages\[\].content: User prompts can contain arbitrary text, including PII, CUI, or sensitive operational data.  
  * ChatCompletionRequest.user: Optional user identifier provided by the client, could be PII.  
  * EmbeddingRequest.input: Text to be embedded can be sensitive.  
  * EmbeddingRequest.user: Optional user identifier.  
  * ChatCompletionResponse.choices\[\].message.content: LLM-generated content could inadvertently reflect or generate PII if prompted with it or based on its training data.  
* **Logging (app/logs/middleware.py, app/services/billing.py):**  
  * client\_ip, user\_agent (PII/fingerprinting).  
  * billing\_data logs manager\_id (User UUID).  
* **Configuration (app/config/settings.py):** While not user data, some configuration details are sensitive and must not be included in test datasets if they mimic production configurations.

### A. Data Categories Potentially Requiring Anonymization/Masking:

1. **User Personally Identifiable Information (PII) from User Model:**  
   * **Fields:** email, name.  
   * **Context of Anonymization:** Primarily relevant if creating test datasets derived from (hypothetical) production user data for non-production environments (e.g., staging, performance testing). The API itself doesn't currently expose this data directly via its endpoints.  
   * **Anonymization/Masking Techniques (Examples for Test Data Creation):**  
     * email: Replace with synthetic, non-real emails (e.g., user\<N\>@testdomain.example), hash (if linkage is needed for test scenarios but direct exposure is to be avoided), or mask parts (e.g., u\*\*\*\<N\>@testdomain.example).  
     * name: Replace with synthetic names from a pre-defined list of non-real names, or use generic placeholders (e.g., "Test User ", "Anonymous Participant").  
   * **Expected Secure Outcome for Test Data:** Any test dataset containing user-like structures derived from production must not contain actual user emails or names. The anonymization should be irreversible to the original PII with reasonable effort. The API, when interacting with such test data (e.g., an API key linked to a test user with a synthetic email), should function correctly.  
2. **User-Provided Content in Prompts/Inputs (Passed Through by API):**  
   * **Fields:** ChatCompletionRequest.messages\[\].content (text parts), EmbeddingRequest.input.  
   * **Context of Anonymization:**  
     * **Test Data Creation:** If example prompts/inputs are taken from production logs or actual user submissions to create realistic test scenarios (e.g., for testing specific LLM behaviors, performance with typical payload sizes, or adapter logic), this content *must* be anonymized.  
     * **API Logging/Error Handling:** The API itself receives this data. While it doesn't anonymize it, it must not log it insecurely or expose it excessively in error messages.  
   * **Sensitivity:** Can contain any type of sensitive data (PII, PHI, CUI, financial data, proprietary business information).  
   * **Anonymization/Masking Techniques (Examples for Test Data Creation):**  
     * **Redaction:** Complete removal of identified sensitive keywords, phrases, or patterns (e.g., SSNs, credit card numbers).  
     * **Replacement/Substitution:** Replacing specific entities (names, addresses, phone numbers, dates of birth, specific project codes) with consistent but generic placeholders (e.g., \[PERSON\_NAME\], \[STREET\_ADDRESS\], \[PHONE\_NUMBER\], \[PROJECT\_X\]).  
     * **Generalization:** Reducing the specificity of data (e.g., "Patient John Smith, born Jan 15, 1983, residing at 123 Main St, Anytown" becomes "A male patient in their early 40s residing in \[STATE\]").  
     * **Synthetic Data Generation:** Creating entirely new, realistic-looking prompts that mimic the structure, length, and type of real prompts but contain no actual sensitive data. This is often the safest approach for test data.  
   * **Expected Secure Outcome:**  
     * **For Test Data:** Test prompts/inputs used in non-production environments must not contain actual sensitive information. If derived from production, they must be effectively de-identified to prevent re-identification or inference of sensitive details.  
     * **For API Handling:** The API should treat this pass-through content as opaque data. It should not log the full content of prompts/inputs at standard operational log levels (e.g., INFO). If any part of this input is reflected in an error message (e.g., a Pydantic error for a sub-field of content), only the minimal necessary part should be shown, and never large chunks of potentially sensitive text.  
3. **LLM-Generated Content (Passed Through by API):**  
   * **Fields:** ChatCompletionResponse.choices\[\].message.content.  
   * **Context of Anonymization:**  
     * **Test Data/Assertion Creation:** If LLM responses are captured and stored (e.g., to create baseline data for regression tests, or for manual review of LLM behavior during testing).  
     * **API Logging/Error Handling:** Similar to user prompts, the API should not log full LLM responses insecurely.  
   * **Sensitivity:** LLMs can sometimes hallucinate data that resembles PII or repeat sensitive information if they were inadvertently trained on it or specifically prompted in a way that elicits it (even if the input prompt was anonymized).  
   * **Anonymization/Masking Techniques (Examples for Stored Test Outputs):** Similar to user-provided content, potentially using NLP-based PII detection tools to scan and mask/redact sensitive entities in LLM outputs before storing them for broader test/dev use or analysis.  
   * **Expected Secure Outcome:**  
     * **For Stored Test Outputs:** LLM responses captured for testing purposes should be reviewed, and any inadvertently generated sensitive data should be masked or redacted.  
     * **For API Handling:** The API should treat this pass-through content as opaque. It should not log the full content of LLM responses at standard operational log levels.  
4. **User Identifiers in Logs and Billing Data:**  
   * **Fields:** client\_ip, user\_agent (in general request logs from StructlogMiddleware), manager\_id (User UUID in billing logs from app/services/billing.py).  
   * **Context of Anonymization:** These are logged for operational, security auditing, and billing purposes. The primary concern for anonymization arises if these logs are:  
     * Used to create derived datasets for wider analysis or public release.  
     * Shared with third parties or internal teams with less stringent access controls than production log systems.  
     * Retained for very long periods where the risk of re-identification might increase or regulatory requirements for de-identification apply.  
   * **Anonymization/Masking Techniques (Examples for Log Export/Analysis):**  
     * client\_ip: Truncation (e.g., 192.168.1.0), generalization to a network block, replacement with synthetic IPs, or complete removal if not essential for the specific analysis.  
     * user\_agent: Truncation, generalization (e.g., "Chrome Browser" instead of full string), or removal.  
     * manager\_id (User UUID): If direct linkage to specific users is not needed for the analysis, replace with a temporary/session-based synthetic ID, apply hashing with a salt (if only unlinkability to original UUID is needed but consistency within the dataset is desired), or use k-anonymity/differential privacy techniques if creating statistical datasets.  
   * **Current Implementation Check:** The API logs these identifiers.  
   * **Expected Secure Outcome:**  
     * For standard operational logging with strict access controls (as should be the case for production logs), these identifiers are generally acceptable and necessary.  
     * **Crucially, if logs are exported, shared, or used to create test/analytical datasets, these fields MUST be considered for anonymization/masking** to prevent re-identification of users or their activity patterns. Raw operational logs themselves should not be treated as anonymized data without explicit processing.  
5. **API Key Information (Indirect Identifiers):**  
   * **Fields:** APIKey.key\_prefix (stored in DB), APIKey.manager\_id (links to User).  
   * **Context of Anonymization:** If test data includes examples of API key metadata or if test API keys are created based on patterns from production.  
   * **Anonymization/Masking Techniques (Examples for Test Data Creation):**  
     * Use entirely synthetic key\_prefix values for test keys that do not mirror any production prefixing schemes that could reveal organizational structure or user types.  
     * When creating test APIKey records, link them to test User records with synthetic/anonymized PII (as per point A.1).  
   * **Expected Secure Outcome:** Test data involving API keys, and the generation of test API keys, should not allow tracing back to real users or reveal sensitive organizational structures through prefixes or linked user data.

### B. Scenarios Where Anonymization/Masking is Critical (Primarily Process-Oriented for Current API):

1. **Creation of Test Datasets from Production Data (Hypothetical for this API, but a general best practice):**  
   * **Scenario:** If a decision is ever made to use a subset of production data (e.g., user accounts, API usage patterns, sample prompts) to create more realistic test data for non-production environments.  
   * **Expected Outcome:** A formal, documented, and validated anonymization/masking process **MUST** be applied *before* such data enters any non-production environment. This process must effectively de-identify all PII, CUI, and other sensitive content to an agreed-upon risk level. The effectiveness of this process should be verifiable.  
2. **Sharing of Logs for External Analysis or Debugging:**  
   * **Scenario:** If operational or billing logs need to be shared with external vendors, consultants, or even internal teams who do not have a "need-to-know" for the raw sensitive identifiers or content.  
   * **Expected Outcome:** Logs **MUST** be scrubbed/anonymized before sharing. This includes redacting/masking PII (IPs, user agents, user UUIDs if they can be correlated back to individuals without proper authorization), and any snippets of sensitive prompt/response content that might have been logged (ideally, full prompts/responses are not in easily shareable logs anyway).  
3. **Development and Testing of Future Analytics Features:**  
   * **Scenario:** If future development includes features for analyzing API usage trends, popular models, query patterns, etc., and this involves processing historical request data or billing logs.  
   * **Expected Outcome:** Such analytics should be designed to operate on anonymized, pseudonymized, or aggregated data to prevent the exposure or inference of individual user activity or the content of their sensitive queries.

### C. What Typically Does NOT Require Anonymization/Masking by *This Specific API Itself* (but responsibility lies elsewhere):

* **Content passed *through* the API to LLMs by clients:** The API framework currently acts as a proxy. It is generally the client application's responsibility to ensure that any data *it sends* to this API (and thus to the downstream LLMs) is already appropriately anonymized or cleared for that purpose if it contains sensitive information. This API is not expected to automatically anonymize arbitrary user prompts unless this becomes an explicit, advertised feature.  
* **Content received *from* LLMs and passed back to clients:** Similarly, the API relays the LLM's response. If the LLM generates sensitive data (e.g., by hallucination or if prompted inappropriately), the client application consuming this API's response is responsible for handling that generated content appropriately, which might include its own filtering or masking.  
* **API Keys (Raw Secrets):** These are secrets to be protected, not data to be anonymized. The API correctly protects them by storing only their hashes.

## 3\. Design Test Cases

Given that the current API framework does not offer anonymization/masking as a feature, the test cases in this section will primarily focus on:

* **TDH\_ANON (Test Data Handling):** Verifying the API's behavior when interacting with inputs that *simulate* pre-anonymized data (e.g., data containing placeholders like \[NAME\]).  
* **LEM\_ANON (Logging and Error Message Anonymity):** Ensuring that the API's logging and error reporting mechanisms do not inadvertently leak sensitive parts of user inputs, especially those that *would have been* PII or sensitive content. This heavily overlaps with Data Exposure Testing but is viewed here through the lens of "what if this input *was* sensitive PII?".  
* **NID\_ANON (Non-Interference with Pre-Anonymized Data):** Ensuring the API doesn't break or misinterpret common anonymization markers in pass-through data.

**General Test Case Components:**

* **ID:** Unique identifier (e.g., TDH\_ANON\_001)  
* **Category Ref:** (TDH\_ANON, LEM\_ANON, NID\_ANON)  
* **Description:** What specific aspect related to (the absence of or interaction with) anonymized data is being tested.  
* **Input Vector(s):** The specific API endpoint and request field(s) being targeted.  
* **Test Data/Payload:** Example input, including placeholders or simulated sensitive data.  
* **Prerequisites:** Valid API Key with necessary scopes.  
* **Request Details:** HTTP Method, Endpoint, Headers, Full Request Body.  
* **Expected HTTP Status Code & Response Body:** (e.g., 200 OK, or error codes if the structure is invalid).  
* **Expected Behavior (Anonymization Context):** How the API should treat the potentially sensitive/anonymized parts of the input, especially concerning logging and error reporting. No de-anonymization.  
* **Verification Points:** Inspect API responses, server logs, and error messages for any leakage of original "sensitive" mock data or misinterpretation of anonymization placeholders.

### A. Test Data Handling Verification (Category: TDH\_ANON)

Purpose: To ensure the API correctly processes inputs that simulate pre-anonymized data, without error or attempting to de-anonymize them.

* **ID:** TDH\_ANON\_001  
  * **Description:** API processes chat requests with synthetic/placeholder PII in the optional user field.  
  * **Input Vector(s):** ChatCompletionRequest.user  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Hello"}\], "user": "user\_XYZ123\_test@synthetic.domain"}  
  * **Prerequisites:** Valid API Key with models:inference scope. Configured chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (or success from provider)  
  * **Expected Behavior (Anonymization Context):** The user field is passed through to the backend or logged as is. The API does not attempt to resolve "user\_XYZ123\_test@synthetic.domain" or treat it differently than any other string identifier.  
  * **Verification Points:** Successful API response. Server logs (if user field is logged) show the synthetic identifier correctly.  
* **ID:** TDH\_ANON\_002  
  * **Description:** API processes chat requests with prompt content containing common PII placeholders (e.g., \[NAME\], \[ADDRESS\]).  
  * **Input Vector(s):** ChatCompletionRequest.messages\[\].content (text part)  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Please help user \[NAME\] located at \[ADDRESS\] with issue \[ISSUE\_ID\]."}\]}  
  * **Prerequisites:** Valid API Key with models:inference scope. Configured chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (or success from provider)  
  * **Expected Behavior (Anonymization Context):** The placeholders \[NAME\], \[ADDRESS\], \[ISSUE\_ID\] are passed through literally to the backend LLM. The API does not attempt to interpret or replace them.  
  * **Verification Points:** Successful API response (LLM might respond based on the placeholders). Server logs (if prompts were logged at a debug level) would show the placeholders. No error due to the placeholders.  
* **ID:** TDH\_ANON\_003  
  * **Description:** API processes embedding requests with input text containing common PII placeholders.  
  * **Input Vector(s):** EmbeddingRequest.input  
  * **Test Data/Payload:** {"model": "\<embedding\_model\_id\>", "input": "User \[USER\_EMAIL\] reported a problem with transaction \[TRANSACTION\_ID\]."}  
  * **Prerequisites:** Valid API Key with models:embedding scope. Configured embedding\_model\_id.  
  * **Request Details:** POST /api/v1/embeddings  
  * **Expected Status Code:** 200 OK (or success from provider)  
  * **Expected Behavior (Anonymization Context):** The placeholders are treated as part of the literal string to be embedded.  
  * **Verification Points:** Successful API response with embeddings.

### B. Logging and Error Message Verification (Category: LEM\_ANON)

Purpose: To verify that API logs and error messages do not unnecessarily expose sensitive parts of user inputs, especially those that would constitute PII or sensitive content if not already anonymized by the client.

* **ID:** LEM\_ANON\_001  
  * **Description:** Verify that if a user submits a chat prompt containing mock PII (e.g., "My SSN is SYNTHETIC\_SSN\_12345"), this specific mock PII is not logged at INFO level by StructlogMiddleware or the billing service.  
  * **Input Vector(s):** ChatCompletionRequest.messages\[\].content  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "My SSN is SYNTHETIC\_SSN\_12345, please process."}\]}  
  * **Prerequisites:** Valid API Key. Configured chat\_model\_id. Access to server logs.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (or success from provider)  
  * **Expected Behavior (Anonymization Context):** Standard operational logs (request start/end, billing) should not contain "SYNTHETIC\_SSN\_12345".  
  * **Verification Points:** Inspect StructlogMiddleware logs and billing\_worker logs. Confirm the absence of the specific mock PII string from the prompt content. (Note: This relies on current behavior of not logging full bodies/prompts at INFO).  
* **ID:** LEM\_ANON\_002  
  * **Description:** Verify that if a request field intended for a non-sensitive value (e.g., temperature) is accidentally populated with mock PII and causes a Pydantic 422 error, the reflected PII in the error message's msg or loc is handled as per FastAPI defaults (typically showing the problematic value, which needs to be understood).  
  * **Input Vector(s):** ChatCompletionRequest.temperature  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[...\], "temperature": "sensitive\_user\_data\_string\_instead\_of\_float"}  
  * **Prerequisites:** Valid API Key.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 422  
  * **Expected Behavior (Anonymization Context):** The error message detail\[\].msg will likely state that a float was expected and reflect "sensitive\_user\_data\_string\_instead\_of\_float". This is default Pydantic/FastAPI behavior. The test verifies no *additional* unrelated data is leaked.  
  * **Verification Points:** Inspect the 422 response. Confirm only the problematic field's value is reflected as per FastAPI's standard error reporting, and no other sensitive data from other parts of the request or system is leaked.  
* **ID:** LEM\_ANON\_003  
  * **Description:** Verify that if a malformed image data URI containing mock sensitive data in the base64 portion causes a custom 400 InputDataError, the error message does not echo the full mock sensitive base64 string.  
  * **Input Vector(s):** ImageContentPart.image\_url.url  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": \[{"type": "image\_url", "image\_url": {"url": "data:image/jpeg;base64,THIS\_IS\_MOCK\_SENSITIVE\_AND\_VERY\_LONG\_AND\_INVALID\_B64\!\!\!\!"}}\]}\]}  
  * **Prerequisites:** Valid API Key.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 400  
  * **Expected Behavior (Anonymization Context):** The error message (e.g., "Invalid Base64 data: ") should indicate the type of error but not include the full "THIS\_IS\_MOCK\_SENSITIVE\_AND\_VERY\_LONG\_AND\_INVALID\_B64\!\!\!\!" string.  
  * **Verification Points:** Inspect the 400 response message.  
* **ID:** LEM\_ANON\_004  
  * **Description:** Verify that 500 error responses, triggered while processing a request containing mock PII, do not leak any part of that mock PII.  
  * **Input Vector(s):** Any field that could contain mock PII.  
  * **Test Data/Payload:** A valid request structure but designed to trigger a 500 error (e.g., by mocking a downstream service to fail) where the input contains mock PII like {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "Process for \[MOCK\_USER\_ID\]"}\]}.  
  * **Prerequisites:** Valid API Key. Ability to mock an internal component to force a 500 error.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 500  
  * **Expected Behavior (Anonymization Context):** The response body is exactly {"detail": "Internal Server Error", "request\_id": "\<uuid\>"}. No part of "\[MOCK\_USER\_ID\]" or other input is present.  
  * **Verification Points:** Inspect the 500 response body.

### C. Non-Interference with Pre-Anonymized Data (Category: NID\_ANON)

Purpose: To ensure the API correctly passes through data that has common anonymization markers without altering or misinterpreting them.

* **ID:** NID\_ANON\_001  
  * **Description:** Send an embedding request where the input text contains common anonymization markers like \[NAME\], \[LOCATION\], \[ORGANIZATION\].  
  * **Input Vector(s):** EmbeddingRequest.input  
  * **Test Data/Payload:** {"model": "\<embedding\_model\_id\>", "input": "User \[NAME\] from \[LOCATION\] works for \[ORGANIZATION\]."}  
  * **Prerequisites:** Valid API Key with models:embedding scope. Configured embedding\_model\_id.  
  * **Request Details:** POST /api/v1/embeddings  
  * **Expected Status Code:** 200 OK (or success from provider)  
  * **Expected Behavior (Anonymization Context):** The API and its adapters treat \[NAME\], \[LOCATION\], \[ORGANIZATION\] as literal parts of the string to be embedded. They are not removed, replaced, or cause errors.  
  * **Verification Points:** Successful API response with embeddings. (Optionally, if possible to inspect what was sent to the provider via debug logs or mocks, verify the placeholders were intact).  
* **ID:** NID\_ANON\_002  
  * **Description:** Send a chat request with conversational history where user/assistant messages contain anonymization placeholders.  
  * **Input Vector(s):** ChatCompletionRequest.messages\[\].content  
  * **Test Data/Payload:** {"model": "\<chat\_model\_id\>", "messages": \[{"role": "user", "content": "My user ID is \[USER\_001\]."}, {"role": "assistant", "content": "Okay, \[USER\_001\], how can I help?"}, {"role": "user", "content": "What was the ID I just gave you?"}\]}  
  * **Prerequisites:** Valid API Key with models:inference scope. Configured chat\_model\_id.  
  * **Request Details:** POST /api/v1/chat/completions  
  * **Expected Status Code:** 200 OK (or success from provider)  
  * **Expected Behavior (Anonymization Context):** The API and its adapters pass the history with placeholders correctly. The LLM should ideally respond with "\[USER\_001\]".  
  * **Verification Points:** Successful API response. The LLM's response should reflect understanding of the placeholder as part of the context.
