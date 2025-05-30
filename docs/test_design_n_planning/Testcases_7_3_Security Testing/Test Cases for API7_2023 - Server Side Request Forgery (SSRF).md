# **Test Cases for API7:2023 \- Server Side Request Forgery (SSRF)**

## **Introduction**

This document outlines test cases for **API7:2023 \- Server Side Request Forgery (SSRF)** as identified in the "Risk Surface Analysis for Test Plan Section 7.3.md". These tests aim to verify that the API does not fetch resources from arbitrary user-supplied URLs, especially for LLM interactions.  
**References:**

* docs/test\_design\_n\_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Section 1.API7:2023)  
* app/providers/utils.py (specifically parse\_data\_uri)  
* app/providers/open\_ai/schemas.py (specifically ImageContentPart.image\_url.url)

## **General Test Case Components Template**

* **ID:** Unique identifier  
* **Category Ref:** API7:2023 \- SSRF  
* **Description:** What specific feature/vulnerability is being tested.  
* **Exposure Point(s):** Any API input field that accepts a URL from which the server might fetch content (e.g., image URLs for multimodal LLMs).  
* **Test Method/Action:** Provide URLs pointing to internal services, loopback addresses, or cloud metadata endpoints.  
* **Prerequisites:** Valid API key. An endpoint that processes URLs.  
* **Expected Secure Outcome:** The API either strictly validates URLs against an allowlist, only processes specific URI schemes (like data:), or rejects attempts to access internal/restricted resources. Direct SSRF should be prevented.  
* **Verification Steps:** Check API responses for errors or unexpected content. Monitor server logs for outbound requests to unintended destinations.

## **Test Cases**

* **ID:** SSRF\_IMAGE\_URL\_001  
  * **Category Ref:** API7:2023 \- SSRF  
  * **Description:** Attempt SSRF by providing an internal IP address in ImageContentPart.image\_url.url.  
  * **Exposure Point(s):** ImageContentPart.image\_url.url field in /api/v1/chat/completions, parse_data_uri function in app/providers/utils.py:8-22, regex validation at line 10.  
  * **Test Method/Action:** Send a chat completion request with an image\_url.url like:  
    * http://127.0.0.1/someinternalresource  
    * http://10.0.0.1/sensitive-data  
    * http://169.254.169.254/latest/meta-data/  
  * **Prerequisites:** Valid API key with models:inference scope. A model that notionally supports image URLs (though parse\_data\_uri will intercept first).  
  * **Expected Secure Outcome:** The request should be rejected by parse\_data\_uri because it expects a data:image/...;base64,... scheme. An InvalidImageURLError should be raised, leading to a 400 Bad Request from the API. The API server should not attempt to make an HTTP request to the internal IP.  
  * **Verification Steps:**  
    1. Verify HTTP status code is 400\.  
    2. Verify error message indicates "Invalid or unsupported image data URI format."  
    3. (If possible) Monitor network traffic from the API server to ensure no outbound request was made to the specified internal IP.  
  * **Code Reference:** parse_data_uri function in app/providers/utils.py:8-22, regex pattern validation at line 10, InvalidImageURLError at line 12.  
* **ID:** SSRF\_IMAGE\_URL\_002  
  * **Category Ref:** API7:2023 \- SSRF  
  * **Description:** Attempt SSRF by providing a file:/// URI in ImageContentPart.image\_url.url.  
  * **Exposure Point(s):** ImageContentPart.image\_url.url, parse_data_uri function in app/providers/utils.py:8-22, file:// scheme rejection.  
  * **Test Method/Action:** Send a chat completion request with an image\_url.url like file:///etc/passwd.  
  * **Prerequisites:** Valid API key.  
  * **Expected Secure Outcome:** Request rejected by parse\_data\_uri with InvalidImageURLError (400 Bad Request). The API server should not attempt to read local files.  
  * **Verification Steps:**  
    1. Verify HTTP status code is 400\.  
    2. Verify error message.  
  * **Code Reference:** URL scheme validation in app/providers/utils.py:10, InvalidImageURLError handling.  
* **ID:** SSRF\_IMAGE\_URL\_003  
  * **Category Ref:** API7:2023 \- SSRF  
  * **Description:** Attempt SSRF using DNS rebinding or other obfuscation techniques for the URL, if the API were to accept HTTP(S) URLs for images. (This tests the robustness of parse\_data\_uri's scheme check).  
  * **Exposure Point(s):** ImageContentPart.image\_url.url, parse_data_uri regex validation in app/providers/utils.py:10, scheme checking robustness.  
  * **Test Method/Action:** Send a chat completion request with an image\_url.url like http://attacker-controlled-dns.com/image.jpg where the DNS might resolve to an internal IP.  
  * **Prerequisites:** Valid API key.  
  * **Expected Secure Outcome:** Request rejected by parse\_data\_uri (400 Bad Request) because the scheme is http:// not data:.  
  * **Verification Steps:**  
    1. Verify HTTP status code is 400\.  
    2. Verify error message.  
  * **Code Reference:** Regex pattern validation in app/providers/utils.py:10, scheme requirement enforcement.  
* **ID:** SSRF\_FUTURE\_FEATURE\_001 (Hypothetical)  
  * **Category Ref:** API7:2023 \- SSRF  
  * **Description:** If a future feature allows providing HTTP(S) URLs for document processing or RAG context for LLMs, test this feature for SSRF vulnerabilities.  
  * **Exposure Point(s):** Hypothetical new input field accepting external URLs.  
  * **Test Method/Action:** Provide various internal, loopback, and cloud metadata URLs to this hypothetical feature.  
  * **Prerequisites:** Aforementioned hypothetical feature.  
  * **Expected Secure Outcome:** The feature must implement strict SSRF mitigations:  
    * URL validation against an allowlist of domains/IPs.  
    * Disallowing requests to private/internal IP ranges.  
    * Proper handling of redirects.  
    * Connection timeouts.  
    * Response size limits.  
  * **Verification Steps:** Verify requests to disallowed URLs are blocked with appropriate errors. No internal network scanning or data exfiltration is possible.

* **ID:** SSRF\_PROVIDER\_ENDPOINTS\_001
  * **Category Ref:** API7:2023 \- SSRF
  * **Description:** Test potential SSRF through provider endpoint configurations or model selection that might trigger server-side requests.
  * **Exposure Point(s):** Provider backend configurations, model endpoint URLs, provider adapter implementations.
  * **Test Method/Action:**
    1. Test model names that might be interpreted as URLs or contain URL-like patterns.
    2. Attempt to manipulate provider selection to target internal services.
    3. Test for any provider configuration that accepts external URLs.
  * **Prerequisites:** Valid API key, understanding of provider backend architecture.
  * **Expected Secure Outcome:** Provider configurations should be hardcoded or strictly validated. Model selection should not allow arbitrary URL targeting.
  * **Verification Steps:**
    1. Verify model selection is restricted to predefined options.
    2. Check that provider endpoints are not user-controllable.
    3. Monitor for any unexpected outbound requests during provider switching.
  * **Code Reference:** Provider backend configuration, model selection logic, provider adapters.

* **ID:** SSRF\_BASE64\_BYPASS\_001
  * **Category Ref:** API7:2023 \- SSRF
  * **Description:** Test potential SSRF bypass through malformed or manipulated base64 data URIs that might be processed differently.
  * **Exposure Point(s):** Base64 decoding in parse_data_uri function (app/providers/utils.py:18), data URI parsing edge cases.
  * **Test Method/Action:**
    1. Send data URIs with embedded URL redirects in base64 content.
    2. Test malformed base64 that might trigger alternative processing paths.
    3. Send data URIs with multiple schemes or encoding layers.
    4. Test for parser confusion with mixed schemes like data:http://...
  * **Prerequisites:** Valid API key, understanding of base64 encoding and data URI formats.
  * **Expected Secure Outcome:** All malformed or potentially dangerous data URIs should be rejected with InvalidBase64DataError or InvalidImageURLError.
  * **Verification Steps:**
    1. Verify all malformed data URIs are rejected.
    2. Check that base64 decoding doesn't trigger alternative URL processing.
    3. Verify no outbound requests are made during base64 processing.
    4. Test error handling for various malformed inputs.
  * **Code Reference:** base64.b64decode in app/providers/utils.py:18, InvalidBase64DataError handling at line 20.

* **ID:** SSRF\_REDIRECT\_CHAIN\_001
  * **Category Ref:** API7:2023 \- SSRF
  * **Description:** Test potential SSRF through HTTP redirect chains if the API were to support external URL fetching in future features.
  * **Exposure Point(s):** Hypothetical future HTTP client implementations, redirect handling logic.
  * **Test Method/Action:**
    1. Test URLs that redirect to internal IP addresses.
    2. Test redirect chains that eventually target internal services.
    3. Test for redirect limit enforcement.
    4. Test for proper redirect validation and filtering.
  * **Prerequisites:** Hypothetical future feature supporting external URLs.
  * **Expected Secure Outcome:** Any HTTP client implementation must validate redirect targets and prevent internal IP access through redirects.
  * **Verification Steps:**
    1. Verify redirect targets are validated against allowlists.
    2. Check that internal IPs are blocked even through redirects.
    3. Test redirect limit enforcement.
    4. Verify no internal network access through redirect chains.
  * **Code Reference:** Future HTTP client implementations, redirect handling logic.

* **ID:** SSRF\_PROTOCOL\_CONFUSION\_001
  * **Category Ref:** API7:2023 \- SSRF
  * **Description:** Test for protocol confusion attacks where different URI schemes might be interpreted differently by various components.
  * **Exposure Point(s):** URI parsing and validation logic, protocol handling in various components.
  * **Test Method/Action:**
    1. Test mixed protocol schemes like data:file://...
    2. Test protocol confusion with URL encoding.
    3. Test for case sensitivity in protocol handling.
    4. Test unicode or punycode in protocol specifications.
  * **Prerequisites:** Valid API key, understanding of URI parsing edge cases.
  * **Expected Secure Outcome:** URI parsing should be consistent and secure across all components. Protocol confusion should not bypass security controls.
  * **Verification Steps:**
    1. Verify consistent protocol parsing across components.
    2. Check that protocol confusion doesn't bypass validation.
    3. Test URL encoding and unicode handling in protocols.
    4. Verify no unintended protocol interpretation.
  * **Code Reference:** URI parsing logic, protocol validation in app/providers/utils.py.

* **ID:** SSRF\_CLOUD\_METADATA\_001
  * **Category Ref:** API7:2023 \- SSRF
  * **Description:** Test specific cloud metadata service access attempts that are common SSRF targets.
  * **Exposure Point(s):** Any potential external URL processing, cloud metadata endpoint access.
  * **Test Method/Action:**
    1. Test AWS metadata service: http://169.254.169.254/latest/meta-data/
    2. Test GCP metadata service: http://metadata.google.internal/computeMetadata/v1/
    3. Test Azure metadata service: http://169.254.169.254/metadata/instance
    4. Test other cloud provider metadata endpoints.
  * **Prerequisites:** Understanding of cloud metadata services, potential for external URL processing.
  * **Expected Secure Outcome:** All cloud metadata service access should be blocked. No cloud instance metadata should be accessible.
  * **Verification Steps:**
    1. Verify all metadata service URLs are blocked.
    2. Check for any cloud provider metadata exposure.
    3. Test blocking effectiveness across different cloud environments.
    4. Verify no credential or instance information leakage.
  * **Code Reference:** URL validation logic, internal IP range filtering.

* **ID:** SSRF\_PORT\_SCANNING\_001
  * **Category Ref:** API7:2023 \- SSRF
  * **Description:** Test potential for internal port scanning through SSRF if external URL processing were supported.
  * **Exposure Point(s):** Hypothetical external URL processing, internal network access, port enumeration.
  * **Test Method/Action:**
    1. Test requests to various internal IP addresses with different ports.
    2. Attempt to enumerate internal services through port scanning.
    3. Test for timeout differences that might reveal open ports.
    4. Test for error message differences that reveal port status.
  * **Prerequisites:** Hypothetical external URL processing capability.
  * **Expected Secure Outcome:** Internal port scanning should be prevented. No information about internal network topology should be revealed.
  * **Verification Steps:**
    1. Verify no internal port scanning is possible.
    2. Check that timeout patterns don't reveal port status.
    3. Test error message consistency regardless of target port.
    4. Verify no internal network information disclosure.
  * **Code Reference:** Network access controls, timeout handling, error message standardization.

* **ID:** SSRF\_DNS\_REBINDING\_001
  * **Category Ref:** API7:2023 \- SSRF
  * **Description:** Test protection against DNS rebinding attacks that could bypass IP-based filtering.
  * **Exposure Point(s):** DNS resolution handling, IP address validation, hostname to IP mapping.
  * **Test Method/Action:**
    1. Test hostnames that resolve to internal IP addresses.
    2. Test DNS rebinding with time-of-check vs time-of-use attacks.
    3. Test for proper DNS resolution validation.
    4. Test hostname allowlisting vs IP-based filtering.
  * **Prerequisites:** Control over DNS resolution or test domain, understanding of DNS rebinding.
  * **Expected Secure Outcome:** DNS rebinding attacks should be prevented through proper hostname and IP validation. DNS resolution should be secure.
  * **Verification Steps:**
    1. Verify hostnames resolving to internal IPs are blocked.
    2. Check for consistent hostname to IP validation.
    3. Test DNS rebinding protection mechanisms.
    4. Verify no internal network access through DNS manipulation.
  * **Code Reference:** DNS resolution handling, hostname validation, IP address filtering.

* **ID:** SSRF\_WEBHOOK\_SIMULATION\_001
  * **Category Ref:** API7:2023 \- SSRF
  * **Description:** Test potential SSRF through simulated webhook or callback mechanisms if such features exist or are planned.
  * **Exposure Point(s):** Hypothetical webhook endpoints, callback URL processing, notification systems.
  * **Test Method/Action:**
    1. Test webhook URLs pointing to internal services.
    2. Attempt to use webhooks for internal network reconnaissance.
    3. Test callback URL validation and filtering.
    4. Test for webhook payload manipulation.
  * **Prerequisites:** Hypothetical webhook or callback functionality.
  * **Expected Secure Outcome:** Webhook URLs should be strictly validated and filtered. No internal network access through webhooks should be possible.
  * **Verification Steps:**
    1. Verify webhook URL validation and allowlisting.
    2. Check that internal URLs are blocked in webhook configurations.
    3. Test webhook payload security and validation.
    4. Verify no internal network access through webhook mechanisms.
  * **Code Reference:** Webhook handling logic, URL validation, callback processing.

* **ID:** SSRF\_TIME\_BASED\_DETECTION\_001
  * **Category Ref:** API7:2023 \- SSRF
  * **Description:** Test for time-based SSRF detection through response timing analysis.
  * **Exposure Point(s):** Response timing patterns, timeout handling, network latency analysis.
  * **Test Method/Action:**
    1. Test response times for various internal vs external targets.
    2. Analyze timing patterns that might reveal internal network structure.
    3. Test for consistent timeout handling across different targets.
    4. Monitor for timing-based information disclosure.
  * **Prerequisites:** Ability to measure response times, understanding of timing attack vectors.
  * **Expected Secure Outcome:** Response timing should not reveal information about internal network accessibility or structure.
  * **Verification Steps:**
    1. Verify consistent response timing regardless of target.
    2. Check that timeouts don't reveal internal network information.
    3. Test timing consistency across different network conditions.
    4. Verify no timing-based information disclosure.
  * **Code Reference:** Timeout configuration, response timing handling, network access patterns.

Note on Current Implementation:  
The current implementation for image inputs via ImageContentPart.image\_url.url is robust against SSRF because app/providers/utils.py\#parse\_data\_uri explicitly requires the data:image/(jpeg|png|gif|webp);base64,... scheme. Any other scheme, including http://, https://, or file:///, will cause parse\_data\_uri to raise an InvalidImageURLError, which results in a 400 Bad Request from the API. This effectively prevents SSRF through this vector. Tests above confirm this behavior and extend coverage to potential future SSRF vectors.