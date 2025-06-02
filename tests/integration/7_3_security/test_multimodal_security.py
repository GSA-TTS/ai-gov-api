# Section 7.3 - Multi-Modal Content Security Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Multi-Modal Content Security.md

import pytest
import httpx
import asyncio
import base64
import zipfile
import io
from typing import Dict, Any, List
from pathlib import Path

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures
from fixtures.multimodal_fixtures import MultiModalFixtures
from utils.security_validators import SecurityValidator


class TestMultiModalSecurity:
    """Comprehensive multi-modal content security tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_filename_security_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str],
                                       multimodal_fixtures: MultiModalFixtures,
                                       make_request):
        """MULTIMODAL_FILENAME_001: File name security validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test malicious file names
        malicious_filenames = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "../../../../etc/shadow",
            "file|rm -rf /",
            "file$(rm -rf /)",
            "file`rm -rf /`",
            "file; rm -rf /",
            "file && rm -rf /",
            "CON.txt",  # Windows reserved name
            "PRN.jpg",  # Windows reserved name
            "file\x00.txt",  # Null byte injection
            "file\n.txt",  # Newline injection
            "file\r.txt",  # Carriage return injection
            "../../../../proc/self/environ",
            "file\\x2e\\x2e/etc/passwd",
            ".htaccess",
            "web.config"
        ]
        
        for filename in malicious_filenames:
            # Create a simple image for testing
            image_data = multimodal_fixtures.create_test_image()
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": f"Analyze this image file: {filename}"
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{image_base64}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should either reject the request or sanitize the filename
            if response.status_code == 200:
                response_data = response.json()
                response_text = str(response_data).lower()
                
                # Verify no path traversal or command injection occurred
                assert "../" not in response_text
                assert "etc/passwd" not in response_text
                assert "rm -rf" not in response_text
                
            else:
                # Rejection is also acceptable security behavior
                assert response.status_code in [400, 422], \
                    f"Malicious filename should be rejected: {filename}"
        
        logger.info("MULTIMODAL_FILENAME_001: File name security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_file_content_validation_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             multimodal_fixtures: MultiModalFixtures,
                                             make_request):
        """MULTIMODAL_CONTENT_001: File content validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test malicious file content patterns
        malicious_contents = [
            # Script injection
            b"<script>alert('xss')</script>",
            # PHP injection
            b"<?php system($_GET['cmd']); ?>",
            # SQL injection
            b"'; DROP TABLE users; --",
            # Command injection
            b"$(rm -rf /)",
            # HTML injection
            b"<iframe src='javascript:alert(1)'></iframe>",
        ]
        
        for content in malicious_contents:
            # Embed malicious content in image metadata or create malicious "image"
            malicious_data = multimodal_fixtures.create_test_image_with_metadata(content)
            image_base64 = base64.b64encode(malicious_data).decode('utf-8')
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "Analyze this image"
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{image_base64}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            if response.status_code == 200:
                response_data = response.json()
                response_text = str(response_data)
                
                # Verify malicious content is not executed or reflected
                assert "<script>" not in response_text
                assert "<?php" not in response_text
                assert "DROP TABLE" not in response_text
                assert "$(rm" not in response_text
                
            else:
                # Content rejection is acceptable
                assert response.status_code in [400, 422], \
                    "Malicious content should be rejected or sanitized"
        
        logger.info("MULTIMODAL_CONTENT_001: File content validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_zip_bomb_protection_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         multimodal_fixtures: MultiModalFixtures,
                                         make_request):
        """MULTIMODAL_ZIPBOMB_001: Zip bomb protection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Create a zip bomb (small compressed, large uncompressed)
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Create a large file that compresses well
            large_content = b"A" * (10 * 1024 * 1024)  # 10MB of 'A's
            zf.writestr("large_file.txt", large_content)
        
        zip_data = zip_buffer.getvalue()
        zip_base64 = base64.b64encode(zip_data).decode('utf-8')
        
        # Test uploading zip bomb as "image"
        request = {
            "model": config.get_chat_model(0),
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Analyze this compressed image"
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:application/zip;base64,{zip_base64}"
                            }
                        }
                    ]
                }
            ],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request, track_cost=False
        )
        
        # Should reject zip files or handle safely
        if response.status_code == 200:
            # If accepted, verify no resource exhaustion occurred
            response_data = response.json()
            assert "choices" in response_data
            logger.warning("Zip file was processed - verify decompression limits")
        else:
            # Rejection is preferred security behavior
            assert response.status_code in [400, 422], \
                "Zip bombs should be rejected"
        
        logger.info("MULTIMODAL_ZIPBOMB_001: Zip bomb protection tested")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_mime_spoofing_001(self, http_client: httpx.AsyncClient,
                                   auth_headers: Dict[str, str],
                                   multimodal_fixtures: MultiModalFixtures,
                                   make_request):
        """MULTIMODAL_MIME_001: MIME type spoofing protection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test MIME type spoofing scenarios
        spoofing_scenarios = [
            {
                "declared_type": "image/png",
                "actual_content": b"<!DOCTYPE html><html><script>alert('xss')</script></html>",
                "description": "HTML disguised as PNG"
            },
            {
                "declared_type": "image/jpeg",
                "actual_content": b"<?php system($_GET['cmd']); ?>",
                "description": "PHP disguised as JPEG"
            },
            {
                "declared_type": "image/gif",
                "actual_content": b"\x00\x00\x00\x20ftypmp41",  # MP4 header
                "description": "Video disguised as GIF"
            }
        ]
        
        for scenario in spoofing_scenarios:
            spoofed_base64 = base64.b64encode(scenario["actual_content"]).decode('utf-8')
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": f"Analyze this {scenario['description']}"
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:{scenario['declared_type']};base64,{spoofed_base64}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            if response.status_code == 200:
                response_data = response.json()
                response_text = str(response_data)
                
                # Verify spoofed content is not executed
                assert "<script>" not in response_text
                assert "<?php" not in response_text
                assert "alert(" not in response_text
                
            else:
                # Content validation failure is acceptable
                assert response.status_code in [400, 422], \
                    f"MIME spoofing should be detected: {scenario['description']}"
        
        logger.info("MULTIMODAL_MIME_001: MIME spoofing protection validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_base64_security_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     multimodal_fixtures: MultiModalFixtures,
                                     make_request):
        """MULTIMODAL_BASE64_001: Base64 encoding security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test malicious Base64 patterns
        malicious_base64_scenarios = [
            {
                "name": "Oversized payload",
                "data": "A" * (50 * 1024 * 1024),  # 50MB string
                "description": "Memory exhaustion via large Base64"
            },
            {
                "name": "Invalid Base64",
                "data": "====invalid_base64_with_many_equals====",
                "description": "Malformed Base64 parsing"
            },
            {
                "name": "Null bytes",
                "data": base64.b64encode(b"test\x00\x00\x00malicious").decode(),
                "description": "Null byte injection"
            }
        ]
        
        for scenario in malicious_base64_scenarios:
            if scenario["name"] == "Oversized payload":
                # Test oversized payload (but limit to reasonable size for testing)
                large_data = base64.b64encode(b"A" * 1024 * 1024).decode()  # 1MB
            else:
                large_data = scenario["data"]
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": f"Test: {scenario['description']}"
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{large_data}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            # Should handle malicious Base64 gracefully
            if response.status_code != 200:
                assert response.status_code in [400, 422, 413], \
                    f"Malicious Base64 should be rejected: {scenario['name']}"
            else:
                logger.warning(f"Accepted potentially malicious Base64: {scenario['name']}")
        
        logger.info("MULTIMODAL_BASE64_001: Base64 security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_unicode_attacks_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     multimodal_fixtures: MultiModalFixtures,
                                     make_request):
        """MULTIMODAL_UNICODE_001: Unicode-based attacks"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test Unicode-based security issues
        unicode_attacks = [
            "file\u202e.gnp.exe",  # Right-to-left override
            "file\u200b.txt",      # Zero-width space
            "file\ufeff.txt",      # Byte order mark
            "file\u0000.txt",      # Null character
            "file\u180e.txt",      # Mongolian vowel separator
            "file\u2028.txt",      # Line separator
            "file\u2029.txt",      # Paragraph separator
            "..‥/etc/passwd",      # Lookalike characters
            "file\ud800.txt",      # Unpaired surrogate
        ]
        
        for attack in unicode_attacks:
            # Create image with Unicode filename
            image_data = multimodal_fixtures.create_test_image()
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text", 
                                "text": f"Analyze file: {attack}"
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{image_base64}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            if response.status_code == 200:
                response_data = response.json()
                response_text = str(response_data)
                
                # Verify Unicode attacks are neutralized
                assert "etc/passwd" not in response_text
                assert ".exe" not in response_text.replace(attack, "")  # Don't match our test input
                
            else:
                # Unicode validation failure is acceptable
                assert response.status_code in [400, 422], \
                    f"Unicode attack should be handled: {attack}"
        
        logger.info("MULTIMODAL_UNICODE_001: Unicode attack protection validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_provider_specific_security_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 multimodal_fixtures: MultiModalFixtures,
                                                 make_request):
        """MULTIMODAL_PROVIDER_001: Provider-specific security testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test different providers if multiple are configured
        available_models = config.CHAT_MODELS
        
        for model in available_models[:2]:  # Test first 2 models
            # Create test image
            image_data = multimodal_fixtures.create_test_image()
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            request = {
                "model": model,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": f"Provider security test for {model}"
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{image_base64}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Verify provider-specific security controls
                assert "choices" in response_data
                assert len(response_data["choices"]) > 0
                
                # Check for provider information leakage
                response_text = str(response_data).lower()
                sensitive_terms = ["api_key", "secret", "token", "password", "credential"]
                
                for term in sensitive_terms:
                    assert term not in response_text, \
                        f"Provider information leakage detected: {term}"
                
            elif response.status_code == 422:
                # Model doesn't support multimodal - acceptable
                logger.info(f"Model {model} doesn't support multimodal content")
            else:
                pytest.fail(f"Unexpected response for model {model}: {response.status_code}")
        
        logger.info("MULTIMODAL_PROVIDER_001: Provider-specific security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_resource_exhaustion_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         multimodal_fixtures: MultiModalFixtures,
                                         make_request):
        """MULTIMODAL_RESOURCE_001: Resource exhaustion protection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test multiple large images in single request
        large_images = []
        
        for i in range(3):  # Test with 3 large images
            # Create a reasonably large image (limit size for testing)
            large_image_data = multimodal_fixtures.create_large_test_image(size=(800, 600))
            large_image_base64 = base64.b64encode(large_image_data).decode('utf-8')
            
            large_images.append({
                "type": "image_url",
                "image_url": {
                    "url": f"data:image/png;base64,{large_image_base64}"
                }
            })
        
        content = [{"type": "text", "text": "Analyze these large images"}] + large_images
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [
                {
                    "role": "user",
                    "content": content
                }
            ],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request, track_cost=False
        )
        
        # Should handle multiple large images or reject appropriately
        if response.status_code == 200:
            response_data = response.json()
            assert "choices" in response_data
            logger.info("Multiple large images processed successfully")
        else:
            # Rejection due to size limits is acceptable security behavior
            assert response.status_code in [400, 413, 422], \
                "Large image payload should be handled appropriately"
        
        logger.info("MULTIMODAL_RESOURCE_001: Resource exhaustion protection tested")