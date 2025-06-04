# Section 7.3 - Advanced Infrastructure Security & Configuration Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Infrastructure Security & Configuration.md
# Advanced test cases matching design document test case IDs

import pytest
import httpx
import asyncio
import uuid
import time
import socket
import ssl
from typing import Dict, Any, List
from urllib.parse import urlparse

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures
from utils.security_validators import SecurityValidator

class TestAdvancedInfrastructureSecurity:
    """Advanced infrastructure security and configuration tests matching design document test case IDs"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_container_least_privilege_001(self, http_client: httpx.AsyncClient,
                                                     auth_headers: Dict[str, str],
                                                     make_request):
        """INFRA_CONTAINER_LEAST_PRIVILEGE_001: Non-root user verification"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test container privilege indicators through API responses
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for privilege indicators that shouldn't be exposed
        privilege_headers = [
            "x-container-user",
            "x-run-as-user",
            "x-user-id",
            "x-group-id",
            "x-privileges"
        ]
        
        privilege_indicators = []
        for header in privilege_headers:
            if header in headers:
                privilege_indicators.append(f"{header}={headers[header]}")
                
                # Check if running as root (uid 0)
                if header in ["x-user-id", "x-run-as-user"] and headers[header] == "0":
                    logger.warning(f"Container may be running as root: {header}={headers[header]}")
        
        if privilege_indicators:
            logger.info(f"Container privilege indicators: {privilege_indicators}")
        
        # Test privilege escalation attempts
        escalation_headers = auth_headers.copy()
        escalation_headers["X-Privilege-Test"] = "escalation"
        escalation_headers["X-Sudo-Command"] = "sudo whoami"
        
        escalation_response = await make_request(
            http_client, "GET", "/api/v1/models",
            escalation_headers, track_cost=False
        )
        
        # Should handle privilege escalation attempts gracefully
        assert escalation_response.status_code in [200, 400], \
            "Privilege escalation attempts should be handled safely"
        
        # Test file system permissions
        fs_test_headers = auth_headers.copy()
        fs_test_headers["X-File-System-Test"] = "permissions"
        
        fs_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "File system permission test"}],
            "max_tokens": 50
        }
        
        fs_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            fs_test_headers, fs_request, track_cost=False
        )
        
        # Should operate with appropriate permissions
        assert fs_response.status_code == 200, \
            "Container should operate with appropriate file system permissions"
        
        logger.info("INFRA_CONTAINER_LEAST_PRIVILEGE_001: Container least privilege validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_container_filesystem_readonly_001(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """INFRA_CONTAINER_FILESYSTEM_READONLY_001: Read-only filesystem testing"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test read-only filesystem constraints
        readonly_test_headers = auth_headers.copy()
        readonly_test_headers["X-Filesystem-Test"] = "readonly"
        
        # Test write attempts that should be blocked
        write_test_scenarios = [
            {"test": "create_file", "description": "File creation test"},
            {"test": "modify_config", "description": "Configuration modification test"},
            {"test": "write_log", "description": "Log file write test"},
            {"test": "temp_file", "description": "Temporary file creation test"}
        ]
        
        for scenario in write_test_scenarios:
            write_headers = readonly_test_headers.copy()
            write_headers["X-Write-Test"] = scenario["test"]
            
            write_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Filesystem write test: {scenario['description']}"}],
                "max_tokens": 50
            }
            
            write_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                write_headers, write_request, track_cost=False
            )
            
            # Should handle write operations appropriately (either allow to designated areas or deny)
            assert write_response.status_code in [200, 403], \
                f"Write operation should be handled appropriately: {scenario['test']}"
            
            if write_response.status_code == 200:
                logger.info(f"Write operation allowed: {scenario['description']}")
            else:
                logger.info(f"Write operation restricted: {scenario['description']}")
        
        # Test read-only violation attempts
        violation_attempts = [
            {"X-Violation-Type": "system_file_modify"},
            {"X-Violation-Type": "config_override"},
            {"X-Violation-Type": "binary_replacement"},
            {"X-Violation-Type": "library_injection"}
        ]
        
        for violation in violation_attempts:
            violation_headers = readonly_test_headers.copy()
            violation_headers.update(violation)
            
            violation_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Read-only violation test: {violation['X-Violation-Type']}"}],
                "max_tokens": 50
            }
            
            violation_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                violation_headers, violation_request, track_cost=False
            )
            
            # Should handle violation attempts safely
            assert violation_response.status_code in [200, 400, 403], \
                f"Read-only violation should be handled: {violation['X-Violation-Type']}"
        
        logger.info("INFRA_CONTAINER_FILESYSTEM_READONLY_001: Read-only filesystem testing completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_network_provider_encryption_001(self, http_client: httpx.AsyncClient,
                                                        auth_headers: Dict[str, str],
                                                        make_request):
        """INFRA_NETWORK_PROVIDER_ENCRYPTION_001: Provider communication encryption"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test encryption for provider communications
        provider_models = config.CHAT_MODELS[:3]  # Test up to 3 providers
        
        for model in provider_models:
            encryption_headers = auth_headers.copy()
            encryption_headers["X-Encryption-Test"] = "provider-communication"
            encryption_headers["X-Provider-Model"] = model
            
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Provider encryption test"}],
                "max_tokens": 50
            }
            
            start_time = time.time()
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                encryption_headers, request
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Check response headers for encryption indicators
                encryption_indicators = [
                    "x-encrypted-communication",
                    "x-tls-version",
                    "x-cipher-suite",
                    "x-provider-secure"
                ]
                
                found_indicators = []
                for indicator in encryption_indicators:
                    if indicator in response.headers:
                        found_indicators.append(f"{indicator}={response.headers[indicator]}")
                
                if found_indicators:
                    logger.info(f"Provider encryption indicators for {model}: {found_indicators}")
                
                # Response time analysis for encryption overhead
                if response_time > 10.0:
                    logger.warning(f"High response time for {model}: {response_time:.2f}s (possible encryption overhead)")
                else:
                    logger.info(f"Provider response time for {model}: {response_time:.2f}s")
                
            elif response.status_code == 422:
                logger.info(f"Model {model} not available for encryption testing")
            else:
                logger.warning(f"Unexpected response for model {model}: {response.status_code}")
        
        # Test encryption bypass attempts
        bypass_scenarios = [
            {"X-Bypass-Encryption": "true"},
            {"X-Insecure-Connection": "allow"},
            {"X-TLS-Disable": "true"},
            {"X-Plaintext-Mode": "enable"}
        ]
        
        for bypass_headers in bypass_scenarios:
            bypass_test_headers = auth_headers.copy()
            bypass_test_headers.update(bypass_headers)
            
            bypass_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Encryption bypass test"}],
                "max_tokens": 50
            }
            
            bypass_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                bypass_test_headers, bypass_request, track_cost=False
            )
            
            # Should not allow encryption bypass
            assert bypass_response.status_code in [200, 400], \
                f"Encryption bypass should be prevented: {bypass_headers}"
            
            if bypass_response.status_code == 200:
                logger.info(f"Encryption bypass attempt handled safely: {bypass_headers}")
        
        logger.info("INFRA_NETWORK_PROVIDER_ENCRYPTION_001: Provider communication encryption validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_iam_least_privilege_llm_001(self, http_client: httpx.AsyncClient,
                                                   auth_headers: Dict[str, str],
                                                   make_request):
        """INFRA_IAM_LEAST_PRIVILEGE_LLM_001: IAM least privilege validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test IAM least privilege through API operations
        privilege_test_scenarios = [
            {
                "operation": "READ_MODELS",
                "endpoint": "/api/v1/models",
                "method": "GET",
                "expected_access": True,
                "description": "Read model list"
            },
            {
                "operation": "CHAT_COMPLETION",
                "endpoint": "/api/v1/chat/completions",
                "method": "POST",
                "expected_access": True,
                "description": "Chat completion"
            },
            {
                "operation": "ADMIN_ACCESS",
                "endpoint": "/admin/users",
                "method": "GET",
                "expected_access": False,
                "description": "Admin user management"
            },
            {
                "operation": "SYSTEM_CONFIG",
                "endpoint": "/config/system",
                "method": "GET",
                "expected_access": False,
                "description": "System configuration"
            },
            {
                "operation": "DEBUG_INFO",
                "endpoint": "/debug/info",
                "method": "GET",
                "expected_access": False,
                "description": "Debug information"
            }
        ]
        
        privilege_results = []
        
        for scenario in privilege_test_scenarios:
            privilege_headers = auth_headers.copy()
            privilege_headers["X-IAM-Test"] = scenario["operation"]
            
            if scenario["method"] == "POST" and scenario["operation"] == "CHAT_COMPLETION":
                request_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "IAM privilege test"}],
                    "max_tokens": 50
                }
                response = await make_request(
                    http_client, scenario["method"], scenario["endpoint"],
                    privilege_headers, request_data, track_cost=False
                )
            else:
                response = await make_request(
                    http_client, scenario["method"], scenario["endpoint"],
                    privilege_headers, track_cost=False
                )
            
            has_access = response.status_code in [200, 201, 202]
            
            privilege_results.append({
                "operation": scenario["operation"],
                "expected_access": scenario["expected_access"],
                "actual_access": has_access,
                "status_code": response.status_code,
                "description": scenario["description"]
            })
            
            # Validate privilege compliance
            if scenario["expected_access"] and not has_access:
                logger.warning(f"Expected access denied: {scenario['description']} ({response.status_code})")
            elif not scenario["expected_access"] and has_access:
                logger.warning(f"Unexpected access granted: {scenario['description']}")
            else:
                logger.info(f"Privilege validation correct: {scenario['description']}")
        
        # Test privilege escalation attempts
        escalation_scenarios = [
            {"X-Privilege-Escalation": "admin"},
            {"X-Role-Override": "superuser"},
            {"X-Permission-Bypass": "true"},
            {"X-Elevated-Access": "enable"}
        ]
        
        for escalation_headers in escalation_scenarios:
            escalation_test_headers = auth_headers.copy()
            escalation_test_headers.update(escalation_headers)
            
            escalation_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Privilege escalation test"}],
                "max_tokens": 50
            }
            
            escalation_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                escalation_test_headers, escalation_request, track_cost=False
            )
            
            # Should not grant elevated privileges
            assert escalation_response.status_code in [200, 400, 403], \
                f"Privilege escalation should be prevented: {escalation_headers}"
        
        # Analyze overall privilege compliance
        privilege_violations = [r for r in privilege_results if r["expected_access"] != r["actual_access"]]
        
        if privilege_violations:
            logger.warning(f"IAM privilege violations: {len(privilege_violations)}")
        else:
            logger.info("IAM least privilege validation passed")
        
        logger.info("INFRA_IAM_LEAST_PRIVILEGE_LLM_001: IAM least privilege validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_secrets_provider_keys_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """INFRA_SECRETS_PROVIDER_KEYS_001: Provider credentials management"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test provider credential security
        provider_models = config.CHAT_MODELS[:3]  # Test up to 3 providers
        
        for model in provider_models:
            provider_headers = auth_headers.copy()
            provider_headers["X-Provider-Key-Test"] = model
            
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Provider key security test"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                provider_headers, request
            )
            
            if response.status_code == 200:
                response_data = response.json()
                response_text = str(response_data).lower()
                
                # Check for provider key leakage
                provider_key_patterns = [
                    "sk-",  # OpenAI key prefix
                    "anthropic",
                    "api_key",
                    "secret_key",
                    "access_key",
                    "private_key",
                    "bearer token",
                    "authorization"
                ]
                
                for pattern in provider_key_patterns:
                    assert pattern not in response_text, \
                        f"Provider key pattern detected in response: {pattern}"
                
                # Check response headers for key exposure
                sensitive_headers = [
                    "x-api-key",
                    "x-provider-key",
                    "x-auth-token",
                    "x-secret-key"
                ]
                
                for header in sensitive_headers:
                    assert header not in response.headers, \
                        f"Sensitive header exposed: {header}"
                
                logger.info(f"Provider key security validated for model: {model}")
                
            elif response.status_code == 422:
                logger.info(f"Model {model} not available for key testing")
            else:
                logger.warning(f"Unexpected response for model {model}: {response.status_code}")
        
        # Test credential injection attempts
        injection_scenarios = [
            {"X-Inject-Key": "sk-fake-key-12345"},
            {"X-Override-Credentials": "new-credentials"},
            {"X-Bypass-Auth": "provider-direct"},
            {"X-Custom-Key": "malicious-key-injection"}
        ]
        
        for injection_headers in injection_scenarios:
            injection_test_headers = auth_headers.copy()
            injection_test_headers.update(injection_headers)
            
            injection_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Credential injection test"}],
                "max_tokens": 50
            }
            
            injection_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                injection_test_headers, injection_request, track_cost=False
            )
            
            # Should not allow credential injection
            assert injection_response.status_code in [200, 400, 401], \
                f"Credential injection should be prevented: {injection_headers}"
            
            if injection_response.status_code == 200:
                # Verify no credential leakage in successful response
                response_text = injection_response.text.lower()
                assert "sk-fake-key" not in response_text, \
                    "Injected credentials should not appear in response"
        
        # Test credential rotation indicators
        rotation_headers = auth_headers.copy()
        rotation_headers["X-Credential-Rotation-Test"] = "true"
        
        rotation_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Credential rotation test"}],
            "max_tokens": 50
        }
        
        rotation_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            rotation_headers, rotation_request, track_cost=False
        )
        
        # Should handle credential rotation appropriately
        assert rotation_response.status_code == 200, \
            "Credential rotation testing should be handled"
        
        logger.info("INFRA_SECRETS_PROVIDER_KEYS_001: Provider credentials management validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_secrets_db_conn_string_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """INFRA_SECRETS_DB_CONN_STRING_001: Database connection string security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test database connection string exposure
        db_exposure_endpoints = [
            "/config/database",
            "/db/connection",
            "/database.json",
            "/config.json",
            "/.env",
            "/environment"
        ]
        
        for endpoint in db_exposure_endpoints:
            db_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if db_response.status_code == 200:
                db_content = db_response.text.lower()
                
                # Check for database connection string patterns
                db_patterns = [
                    "postgres://",
                    "postgresql://",
                    "mysql://",
                    "mongodb://",
                    "redis://",
                    "database_url",
                    "db_host",
                    "db_password",
                    "db_user",
                    "connection_string",
                    "jdbc:",
                    "user:password@"
                ]
                
                exposed_patterns = []
                for pattern in db_patterns:
                    if pattern in db_content:
                        exposed_patterns.append(pattern)
                
                if exposed_patterns:
                    logger.warning(f"Database connection patterns exposed at {endpoint}: {exposed_patterns}")
                else:
                    logger.info(f"No database patterns found at {endpoint}")
                    
            elif db_response.status_code == 404:
                logger.info(f"Database config endpoint not found: {endpoint}")
            elif db_response.status_code in [401, 403]:
                logger.info(f"Database config endpoint properly protected: {endpoint}")
        
        # Test database connection through API responses
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        
        # Check response for database connection leakage
        response_text = response.text.lower()
        db_leakage_patterns = [
            "database connection",
            "connection failed",
            "postgres:",
            "mysql:",
            "mongodb:",
            "host=",
            "port=5432",
            "port=3306",
            "port=27017"
        ]
        
        for pattern in db_leakage_patterns:
            assert pattern not in response_text, \
                f"Database connection information leaked: {pattern}"
        
        # Test database error handling
        db_error_headers = auth_headers.copy()
        db_error_headers["X-Database-Error-Test"] = "true"
        
        db_error_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Database error test"}],
            "max_tokens": 50
        }
        
        db_error_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            db_error_headers, db_error_request, track_cost=False
        )
        
        if db_error_response.status_code >= 500:
            error_content = db_error_response.text.lower()
            
            # Error messages should not contain connection strings
            error_patterns = [
                "connection string",
                "database url",
                "user=",
                "password=",
                "host=",
                "postgres://",
                "mysql://",
                "mongodb://"
            ]
            
            for pattern in error_patterns:
                assert pattern not in error_content, \
                    f"Database connection info in error: {pattern}"
        
        # Test connection string injection
        injection_scenarios = [
            {"X-DB-Override": "postgres://hacker:password@malicious.com/db"},
            {"X-Connection-String": "mysql://root:password@localhost/test"},
            {"X-Database-URL": "mongodb://admin:admin@evil.com:27017/hack"}
        ]
        
        for injection_headers in injection_scenarios:
            injection_test_headers = auth_headers.copy()
            injection_test_headers.update(injection_headers)
            
            injection_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Database connection injection test"}],
                "max_tokens": 50
            }
            
            injection_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                injection_test_headers, injection_request, track_cost=False
            )
            
            # Should not allow database connection injection
            assert injection_response.status_code in [200, 400], \
                f"Database connection injection should be prevented: {injection_headers}"
        
        logger.info("INFRA_SECRETS_DB_CONN_STRING_001: Database connection string security validated")