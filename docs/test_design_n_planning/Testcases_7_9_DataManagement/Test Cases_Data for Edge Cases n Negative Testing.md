# Test Cases for Data for Edge Cases & Negative Testing (Test Data Management Strategy)

This document outlines test cases for the **Comprehensiveness and Accuracy of Edge Case/Negative Test Data** risk surface, as detailed in the "Risk Surface Analysis for Test Plan Section 7.9: Test Data Management Strategy." This focuses on ensuring the API is robustly tested with data that pushes boundaries or is intentionally invalid.

**Test Cases Summary: 17 (Original: 9, Enhanced: +8)**

**Referenced Code Components/Processes:**
* Edge Case Test Implementation: `tests/integration/7_9_DataPrivacyTesting.py:100-279` (edge cases but limited boundary testing)
* Core Edge Testing: `tests/integration/7_2_EdgeCaseTesting.py:40-302` (boundary values, Unicode, large data)
* Validation Schemas: `app/providers/open_ai/schemas.py` (Pydantic request validation)
* Custom Validation: `app/providers/utils.py` (parse_data_uri for image data handling)
* Error Handling: `app/routers/api_v1.py:55-59` (InvalidInput exceptions), `app/main.py` (global error handlers)
* Security Test Data: `tests/integration/7_3_2_LLM_PromptInjection.py` (prompt injection scenarios)
* Unicode Testing: `tests/integration/7_9_DataPrivacyTesting.py:265-290` (limited scope Unicode testing)

## General Test Case Components

* **ID:** Unique identifier (e.g., TDM\_EDGE\_EMPTY\_PROMPT\_001)
* **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA
* **Description:** What specific edge case or negative data scenario is being tested.
* **Exposure Point(s):** API request parameters, request body fields, specific validation logic.
* **Test Method/Action:** Send API requests with the specified edge case or negative test data.
* **Prerequisites:** Valid API key, understanding of expected behavior for the specific edge case.
* **Expected Secure Outcome:** The API handles the edge case/negative data gracefully, either by processing it correctly if it's a valid edge case, or by returning a clear and appropriate error message (4xx series) if it's invalid. No crashes, security vulnerabilities, or unhandled exceptions.
* **Verification Steps:** Inspect API response (status code, body). Check server logs for errors.

---

### Test Cases for Comprehensiveness and Accuracy of Edge Case/Negative Test Data

#### Empty/Null/Boundary Inputs

* **ID:** TDM\_EDGE\_EMPTY\_PROMPT\_001
    * **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA
    * **Description:** Test with an empty string for a chat prompt.
    * **Exposure Point(s):** `messages[].content` in `/api/v1/chat/completions`.
    * **Test Method/Action:** Send a chat request where `messages[0].content` is `""`.
    * **Prerequisites:** Valid API key.
    * **Expected Secure Outcome:** API should handle this gracefully. Provider might return a specific response (e.g., "I need more input") or a validation error if empty prompts are disallowed by provider policy. API framework should relay this.
    * **Verification Steps:** Check API response. (Current tests in `7_2_EdgeCaseTesting.py::test_empty_message_content` expect 200, 400, or 422).

* **ID:** TDM\_EDGE\_NULL\_OPTIONAL\_PARAM\_002
    * **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA
    * **Description:** Test setting optional LLM parameters (e.g., `temperature`, `max_tokens`) explicitly to `null`.
    * **Exposure Point(s):** Optional fields in `ChatCompletionRequest`.
    * **Test Method/Action:** Send a chat request with `temperature: null` and `max_tokens: null`.
    * **Prerequisites:** Valid API key.
    * **Expected Secure Outcome:** Request is processed successfully. `null` values for optional parameters should be treated as if the parameters were not provided, falling back to provider defaults.
    * **Verification Steps:** Verify 200 OK response. Behavior should be similar to omitting these parameters.

* **ID:** TDM\_EDGE\_MAX\_TOKENS\_BOUNDARY\_003
    * **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA
    * **Description:** Test with `max_tokens` at boundary values (e.g., 1, and a very large value like 100,000).
    * **Exposure Point(s):** `max_tokens` in `ChatCompletionRequest`.
    * **Test Method/Action:**
        1.  Send chat request with `max_tokens: 1`.
        2.  Send chat request with `max_tokens: 100000`.
    * **Prerequisites:** Valid API key.
    * **Expected Secure Outcome:**
        1.  `max_tokens: 1` should result in a 1-token completion.
        2.  `max_tokens: 100000` should be capped by the model/provider's actual limit, or result in a validation error if it exceeds a Pydantic/API-defined upper bound.
    * **Verification Steps:** Check response content length, `finish_reason`, and `usage` object. (Partially covered by `7_2_EdgeCaseTesting.py`).

#### Special Characters/Formats

* **ID:** TDM\_EDGE\_UNICODE\_COMPLEX\_004
    * **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA
    * **Description:** Test prompts with complex Unicode (e.g., mixed scripts, emojis, control characters if not stripped by client/HTTP layer).
    * **Exposure Point(s):** `messages[].content`, `input` for embeddings.
    * **Test Method/Action:** Send requests with prompts/inputs containing diverse and potentially problematic Unicode sequences (e.g., zero-width spaces, BiDi control characters, unassigned code points).
    * **Prerequisites:** Valid API key.
    * **Expected Secure Outcome:** API processes the input without crashing. Provider handles Unicode as per its capabilities. Response correctly encodes any Unicode. (Current `7_2_EdgeCaseTesting.py::test_special_unicode_characters` covers some of this).
    * **Verification Steps:** Check API response for errors or malformed output.

* **ID:** TDM\_EDGE\_MALFORMED\_DATA\_URI\_005
    * **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA
    * **Description:** Test with malformed image data URIs (invalid base64, unsupported image type declared, missing data part) beyond basic `parse_data_uri` checks.
    * **Exposure Point(s):** `ImageContentPart.image_url.url`.
    * **Test Method/Action:** Send chat requests with image data URIs having subtle structural issues or very large (but valid base64) data parts that might stress `parse_data_uri`.
    * **Prerequisites:** Valid API key for multimodal model.
    * **Expected Secure Outcome:** `parse_data_uri` should robustly reject invalid formats with `InputDataError` (400). For extremely large valid base64, it might hit memory limits during decoding, which should also result in a graceful error, not a crash.
    * **Verification Steps:** Verify 400 error for malformed URIs. Monitor server resources for large data URIs.

#### Invalid LLM Parameter Combinations (Semantic, not just type)

* **ID:** TDM\_EDGE\_LLMPARAM\_CONFLICT\_006
    * **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA
    * **Description:** Test with potentially conflicting or unusual LLM parameter combinations (e.g., `temperature: 0.0` and `top_p: 0.1` if provider disallows).
    * **Exposure Point(s):** LLM parameters in `ChatCompletionRequest`.
    * **Test Method/Action:** Send chat request with specific combinations that might be problematic for some LLMs.
    * **Prerequisites:** Valid API key. Knowledge of provider-specific parameter constraints.
    * **Expected Secure Outcome:** API passes valid parameters to provider. Provider either handles the combination or returns an error, which API relays gracefully.
    * **Verification Steps:** Check API response (200 or 4xx/5xx from provider). (Current `7_2_EdgeCaseTesting.py::test_conflicting_parameters` exists but fails with 500, indicating a need for better API error handling for this).

#### Security-Related Negative Data

* **ID:** TDM\_EDGE\_PROMPT\_INJECTION\_VARIETY\_007
    * **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA (Security Focus)
    * **Description:** Expand the variety of prompt injection payloads beyond basic attempts.
    * **Exposure Point(s):** `messages[].content`.
    * **Test Method/Action:** Use a curated list of diverse prompt injection techniques (e.g., from OWASP LLM Top 10, recent research papers) including those involving markdown, XML-like structures, or complex role-play scenarios.
    * **Prerequisites:** Valid API key. (Partially covered by `7_3_2_LLM_PromptInjection.py`).
    * **Expected Secure Outcome:** API framework transmits prompts correctly. LLM provider's defenses are primary. API relays provider's response/refusal.
    * **Verification Steps:** Analyze LLM responses for successful injection.

* **ID:** TDM\_EDGE\_DATA\_REPO\_STATUS\_008
    * **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA
    * **Description:** Assess the current state of a centralized negative test data repository. (Identified gap: "Missing Negative Test Data Repository").
    * **Exposure Point(s):** Test data management processes.
    * **Test Method/Action:** Review current test suites to see if negative test data is ad-hoc or systematically managed.
    * **Prerequisites:** N/A.
    * **Expected Secure Outcome:** (Assessment) Recommendation for creating and maintaining a repository of invalid inputs, malformed requests, boundary conditions, and security-focused negative test data.
    * **Verification Steps:** Document findings.

* **ID:** TDM\_EDGE\_BOUNDARY\_VALUE\_SYSTEMATIC\_009
    * **Category Ref:** TDM\_EDGE\_NEGATIVE\_DATA
    * **Description:** Ensure systematic boundary value analysis and testing for all key numeric and string length parameters. (Identified gap: "No Systematic Boundary Testing").
    * **Exposure Point(s):** All relevant API request parameters.
    * **Test Method/Action:** For each numeric parameter (e.g., `max_tokens`, `temperature`, `dimensions`), test values like min-1, min, min+1, nominal, max-1, max, max+1. For string/list lengths, test empty, 1, nominal, max_allowed, max_allowed+1.
    * **Prerequisites:** Knowledge of valid ranges and limits for all parameters.
    * **Expected Secure Outcome:** API correctly validates inputs against defined boundaries, returning 422 for out-of-bound values and processing valid boundary values correctly.
    * **Verification Steps:** Execute boundary tests for all key parameters. Verify responses.

---

## Enhanced Test Cases: Advanced Edge Case and Negative Testing Strategies

### 1. AI-Powered Adversarial Test Data Generation

* **ID:** TDM_EDGE_AI_ADVERSARIAL_010
    * **Category Ref:** TDM_EDGE_NEGATIVE_DATA
    * **Description:** Test AI-powered generation of adversarial test data designed to discover unknown edge cases and vulnerabilities through systematic exploration.
    * **Exposure Point(s):** AI-generated adversarial inputs, automated vulnerability discovery, intelligent fuzzing, adaptive attack generation.
    * **Test Method/Action:**
        1. Deploy AI models trained to generate adversarial inputs for API testing
        2. Test automated discovery of edge cases through intelligent fuzzing techniques
        3. Validate adaptive attack generation that learns from API responses
        4. Test generation of semantically meaningful but problematic inputs
        5. Validate discovery of novel injection patterns and bypass techniques
    * **Prerequisites:** AI-powered testing infrastructure, adversarial generation models, intelligent fuzzing frameworks, semantic analysis capabilities.
    * **Expected Secure Outcome:** AI-generated adversarial inputs discover 40%+ more edge cases than traditional methods. Novel vulnerabilities identified through systematic exploration. Attack generation adapts to API defenses.
    * **Verification Steps:** Measure edge case discovery rate, validate novel vulnerability detection, test adaptive generation effectiveness.

### 2. Multi-Modal Edge Case Testing

* **ID:** TDM_EDGE_MULTIMODAL_011
    * **Category Ref:** TDM_EDGE_NEGATIVE_DATA
    * **Description:** Test comprehensive edge cases across multiple input modalities including text, images, audio, and structured data combinations.
    * **Exposure Point(s):** Multi-modal input validation, cross-modal consistency checking, format conversion edge cases, content analysis boundaries.
    * **Test Method/Action:**
        1. Test edge cases with corrupted or malformed multi-modal inputs
        2. Validate handling of extremely large files and format edge cases
        3. Test cross-modal consistency validation and conflict detection
        4. Validate processing of adversarial examples designed to fool multi-modal models
        5. Test boundary conditions for content analysis and safety filtering
    * **Prerequisites:** Multi-modal processing capabilities, format validation tools, adversarial example generation, content analysis systems.
    * **Expected Secure Outcome:** Robust handling of multi-modal edge cases with graceful degradation. Cross-modal consistency maintained under stress. Adversarial examples detected and handled safely.
    * **Verification Steps:** Test multi-modal edge case handling, validate cross-modal consistency, verify adversarial example detection.

### 3. Real-Time Adaptive Edge Case Discovery

* **ID:** TDM_EDGE_ADAPTIVE_DISCOVERY_012
    * **Category Ref:** TDM_EDGE_NEGATIVE_DATA
    * **Description:** Test real-time adaptive discovery and generation of edge cases based on system behavior and emerging attack patterns.
    * **Exposure Point(s):** Real-time pattern analysis, adaptive test generation, behavior-based edge case discovery, dynamic threat modeling.
    * **Test Method/Action:**
        1. Deploy real-time monitoring of API behavior to identify potential edge cases
        2. Test adaptive generation of test cases based on observed system responses
        3. Validate discovery of edge cases through behavior pattern analysis
        4. Test integration with threat intelligence for emerging attack patterns
        5. Validate continuous learning and improvement of edge case detection
    * **Prerequisites:** Real-time monitoring infrastructure, adaptive generation algorithms, pattern analysis capabilities, threat intelligence integration.
    * **Expected Secure Outcome:** Real-time discovery of new edge cases within minutes of system changes. Adaptive generation improves coverage by 50%+ over static approaches. Threat intelligence integration enhances relevance.
    * **Verification Steps:** Measure real-time discovery speed, validate adaptive improvement, test threat intelligence integration effectiveness.

### 4. Context-Aware Negative Testing

* **ID:** TDM_EDGE_CONTEXT_AWARE_013
    * **Category Ref:** TDM_EDGE_NEGATIVE_DATA
    * **Description:** Test context-aware negative testing that considers business domain, user context, and application-specific edge cases.
    * **Exposure Point(s):** Context modeling systems, domain-specific edge cases, user behavior patterns, application-specific vulnerabilities.
    * **Test Method/Action:**
        1. Generate domain-specific edge cases relevant to government, healthcare, finance contexts
        2. Test user context-aware negative scenarios based on access levels and roles
        3. Validate application-specific edge cases related to LLM usage patterns
        4. Test temporal and geographic context influences on edge case relevance
        5. Validate context-aware prioritization of edge case testing
    * **Prerequisites:** Domain expertise, context modeling frameworks, user behavior analysis, application-specific risk assessment.
    * **Expected Secure Outcome:** Context-aware edge cases achieve higher relevance and defect detection rates. Domain-specific scenarios properly tested. User context influences properly modeled.
    * **Verification Steps:** Validate domain-specific relevance, test user context modeling accuracy, measure application-specific coverage.

### 5. Quantum-Resistant Edge Case Testing

* **ID:** TDM_EDGE_QUANTUM_RESISTANT_014
    * **Category Ref:** TDM_EDGE_NEGATIVE_DATA
    * **Description:** Test edge cases related to quantum-resistant cryptography and post-quantum security scenarios for future-proofing.
    * **Exposure Point(s):** Quantum-resistant algorithms, post-quantum cryptography, quantum computing attack simulations, cryptographic agility testing.
    * **Test Method/Action:**
        1. Test edge cases with quantum-resistant cryptographic algorithms
        2. Validate handling of large key sizes and computational complexity
        3. Test simulation of quantum computing attacks on current cryptography
        4. Validate cryptographic agility and algorithm migration scenarios
        5. Test performance edge cases with post-quantum cryptographic operations
    * **Prerequisites:** Quantum-resistant cryptography implementation, quantum attack simulation capabilities, cryptographic agility frameworks.
    * **Expected Secure Outcome:** System handles quantum-resistant algorithms without edge case failures. Quantum attack simulations validate security posture. Cryptographic agility enables smooth transitions.
    * **Verification Steps:** Test quantum-resistant algorithm handling, validate attack simulation accuracy, verify cryptographic agility effectiveness.

### 6. Distributed Edge Case Coordination

* **ID:** TDM_EDGE_DISTRIBUTED_015
    * **Category Ref:** TDM_EDGE_NEGATIVE_DATA
    * **Description:** Test edge cases that emerge from distributed system coordination including network partitions, consensus failures, and distributed state inconsistencies.
    * **Exposure Point(s):** Distributed system coordination, network partition handling, consensus algorithm edge cases, distributed state management.
    * **Test Method/Action:**
        1. Test edge cases with network partitions and partial connectivity
        2. Validate handling of consensus algorithm failures and split-brain scenarios
        3. Test distributed state inconsistency detection and resolution
        4. Validate edge cases in distributed transaction processing
        5. Test coordination failures during system scaling and load balancing
    * **Prerequisites:** Distributed system infrastructure, network simulation capabilities, consensus algorithm testing, distributed transaction support.
    * **Expected Secure Outcome:** Distributed edge cases handled gracefully with proper failover. Consensus failures detected and resolved automatically. State consistency maintained under all edge conditions.
    * **Verification Steps:** Test distributed coordination under edge conditions, validate consensus failure handling, verify state consistency maintenance.

### 7. Privacy-Preserving Edge Case Testing

* **ID:** TDM_EDGE_PRIVACY_PRESERVING_016
    * **Category Ref:** TDM_EDGE_NEGATIVE_DATA
    * **Description:** Test edge cases while preserving privacy through differential privacy, homomorphic encryption, and secure multi-party computation.
    * **Exposure Point(s):** Privacy-preserving computation, differential privacy edge cases, homomorphic encryption boundaries, secure computation limits.
    * **Test Method/Action:**
        1. Test edge cases with differential privacy noise injection and privacy budget exhaustion
        2. Validate homomorphic encryption computation limits and precision edge cases
        3. Test secure multi-party computation failures and coordination edge cases
        4. Validate privacy-preserving aggregation edge cases and accuracy boundaries
        5. Test edge cases in federated learning and distributed privacy preservation
    * **Prerequisites:** Privacy-preserving computation infrastructure, differential privacy frameworks, homomorphic encryption capabilities, secure computation protocols.
    * **Expected Secure Outcome:** Privacy-preserving edge cases handled without privacy leakage. Computation limits respected with graceful degradation. Accuracy maintained within acceptable bounds.
    * **Verification Steps:** Validate privacy preservation under edge conditions, test computation limit handling, verify accuracy maintenance.

### 8. Evolutionary Edge Case Testing

* **ID:** TDM_EDGE_EVOLUTIONARY_017
    * **Category Ref:** TDM_EDGE_NEGATIVE_DATA
    * **Description:** Test evolutionary approaches to edge case discovery using genetic algorithms and evolutionary computation for systematic exploration.
    * **Exposure Point(s):** Genetic programming frameworks, evolutionary algorithms, fitness function optimization, population-based search.
    * **Test Method/Action:**
        1. Deploy genetic algorithms to evolve edge case test inputs over multiple generations
        2. Test fitness function optimization for maximizing edge case discovery
        3. Validate population diversity maintenance for comprehensive exploration
        4. Test crossover and mutation strategies for generating novel edge cases
        5. Validate convergence detection and exploration-exploitation balance
    * **Prerequisites:** Genetic programming infrastructure, evolutionary computation frameworks, fitness evaluation systems, population management tools.
    * **Expected Secure Outcome:** Evolutionary approaches discover complex edge cases missed by traditional methods. Population diversity ensures comprehensive exploration. Convergence achieves optimal edge case coverage.
    * **Verification Steps:** Measure evolutionary discovery effectiveness, validate population diversity maintenance, test convergence optimization.

---