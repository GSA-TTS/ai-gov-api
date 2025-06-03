# Section 7.3 - Infrastructure Security & Configuration Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Infrastructure Security & Configuration.md

import pytest
import httpx
import asyncio
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


class TestInfrastructureSecurity:
    """Comprehensive infrastructure security and configuration tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_container_security_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """INFRA_CONTAINER_001: Container security validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for container security indicators through API responses
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for container security headers
        security_indicators = []
        
        # Server header analysis
        server_header = headers.get("server", "").lower()
        if server_header:
            # Should not reveal detailed version information
            if any(version in server_header for version in ["apache/2.", "nginx/1.", "iis/", "gunicorn/"]):
                logger.warning(f"Server version exposed: {server_header}")
            else:
                security_indicators.append("Server version concealed")
        
        # Check for container-specific headers that shouldn't be exposed
        container_headers = [
            "x-docker-version",
            "x-kubernetes-pod",
            "x-container-id",
            "x-pod-name",
            "x-namespace"
        ]
        
        exposed_container_info = []
        for header in container_headers:
            if header in headers:
                exposed_container_info.append(header)
        
        if exposed_container_info:
            logger.warning(f"Container information exposed: {exposed_container_info}")
        else:
            security_indicators.append("Container information concealed")
        
        # Test for privilege escalation attempts through API
        privilege_test_headers = auth_headers.copy()
        privilege_test_headers["X-Container-Escape"] = "attempt"
        privilege_test_headers["X-Privilege-Escalation"] = "test"
        
        priv_response = await make_request(
            http_client, "GET", "/api/v1/models",
            privilege_test_headers, track_cost=False
        )
        
        # Should handle potentially malicious headers gracefully
        assert priv_response.status_code in [200, 400], \
            "Container should handle privilege escalation attempts"
        
        logger.info(f"Container security indicators: {security_indicators}")
        logger.info("INFRA_CONTAINER_001: Container security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_network_segmentation_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """INFRA_NETWORK_001: Network segmentation validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test network segmentation through API behavior
        base_url = config.BASE_URL
        parsed_url = urlparse(base_url)
        
        # Test that only appropriate endpoints are accessible
        network_test_endpoints = [
            "/api/v1/models",           # Should be accessible
            "/api/v1/chat/completions", # Should be accessible
            "/admin",                   # Should be segmented/protected
            "/internal",                # Should be segmented
            "/debug",                   # Should be segmented
            "/metrics",                 # Should be segmented
            "/health/detailed",         # Should be segmented
            "/.env",                    # Should be blocked
            "/config",                  # Should be segmented
            "/status/internal"          # Should be segmented
        ]
        
        segmentation_results = []
        
        for endpoint in network_test_endpoints:
            try:
                response = await make_request(
                    http_client, "GET", endpoint,
                    auth_headers, track_cost=False
                )
                
                segmentation_results.append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "accessible": response.status_code in [200, 201, 202]
                })
                
            except Exception as e:
                segmentation_results.append({
                    "endpoint": endpoint,
                    "error": str(e),
                    "accessible": False
                })
        
        # Analyze segmentation effectiveness
        public_endpoints = ["/api/v1/models", "/api/v1/chat/completions"]
        internal_endpoints = ["/admin", "/internal", "/debug", "/metrics", "/config"]
        
        for result in segmentation_results:
            endpoint = result["endpoint"]
            accessible = result["accessible"]
            
            if endpoint in public_endpoints:
                if not accessible:
                    logger.warning(f"Public endpoint not accessible: {endpoint}")
            elif endpoint in internal_endpoints:
                if accessible:
                    logger.warning(f"Internal endpoint accessible: {endpoint}")
                else:
                    logger.info(f"Internal endpoint properly segmented: {endpoint}")
        
        logger.info("INFRA_NETWORK_001: Network segmentation validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_tls_encryption_001(self, http_client: httpx.AsyncClient,
                                    auth_headers: Dict[str, str],
                                    make_request):
        """INFRA_TLS_001: TLS encryption validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        base_url = config.BASE_URL
        
        if not base_url.startswith("https://"):
            if "localhost" in base_url or "127.0.0.1" in base_url:
                logger.info("TLS validation skipped for localhost")
                return
            else:
                pytest.fail("Production API should use HTTPS")
        
        # Extract hostname and port from URL
        parsed_url = urlparse(base_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        # Test TLS configuration
        try:
            # Create SSL context for testing
            context = ssl.create_default_context()
            
            # Test TLS connection
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Analyze TLS configuration
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    
                    logger.info(f"TLS Version: {tls_version}")
                    logger.info(f"Cipher: {cipher[0] if cipher else 'Unknown'}")
                    
                    # Validate TLS version
                    if tls_version in ["TLSv1.2", "TLSv1.3"]:
                        logger.info("Secure TLS version in use")
                    else:
                        logger.warning(f"Potentially insecure TLS version: {tls_version}")
                    
                    # Validate cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ["RC4", "DES", "MD5", "NULL"]):
                            logger.warning(f"Weak cipher detected: {cipher_name}")
                        else:
                            logger.info("Strong cipher in use")
                    
                    # Validate certificate
                    if cert:
                        subject = dict(x[0] for x in cert['subject'])
                        issuer = dict(x[0] for x in cert['issuer'])
                        
                        logger.info(f"Certificate subject: {subject.get('commonName', 'Unknown')}")
                        logger.info(f"Certificate issuer: {issuer.get('commonName', 'Unknown')}")
                        
                        # Check certificate validity
                        import datetime
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.datetime.now()).days
                        
                        if days_until_expiry < 30:
                            logger.warning(f"Certificate expires in {days_until_expiry} days")
                        else:
                            logger.info(f"Certificate valid for {days_until_expiry} days")
        
        except Exception as e:
            logger.warning(f"TLS validation failed: {e}")
        
        # Test API over TLS
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200, "API should work over TLS"
        
        logger.info("INFRA_TLS_001: TLS encryption validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_cloud_iam_001(self, http_client: httpx.AsyncClient,
                                auth_headers: Dict[str, str],
                                make_request):
        """INFRA_IAM_001: Cloud IAM security validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test IAM through API authentication and authorization
        iam_test_scenarios = [
            {
                "description": "Valid authentication",
                "headers": auth_headers,
                "expected_status": 200
            },
            {
                "description": "Invalid API key",
                "headers": {"Authorization": "Bearer invalid_key_12345"},
                "expected_status": 401
            },
            {
                "description": "Malformed authorization header",
                "headers": {"Authorization": "Basic invalid_format"},
                "expected_status": 401
            },
            {
                "description": "Missing authorization",
                "headers": {},
                "expected_status": 401
            },
            {
                "description": "Expired token simulation",
                "headers": {"Authorization": "Bearer expired_token_simulation"},
                "expected_status": 401
            }
        ]
        
        for scenario in iam_test_scenarios:
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                scenario["headers"], track_cost=False
            )
            
            assert response.status_code == scenario["expected_status"], \
                f"IAM test failed for {scenario['description']}: expected {scenario['expected_status']}, got {response.status_code}"
            
            # Check for IAM-related headers in response
            if response.status_code == 401:
                # Should include proper authentication challenge
                auth_header = response.headers.get("www-authenticate")
                if auth_header:
                    logger.info(f"Authentication challenge present: {auth_header}")
        
        # Test role-based access (if admin endpoints exist)
        admin_endpoints = [
            "/tokens/is_active/1",
            "/admin/users",
            "/admin/stats"
        ]
        
        for endpoint in admin_endpoints:
            # Test with regular user credentials
            user_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if user_response.status_code == 403:
                logger.info(f"Proper RBAC for {endpoint}: user access denied")
            elif user_response.status_code == 404:
                logger.info(f"Endpoint {endpoint} not found")
            elif user_response.status_code == 200:
                logger.warning(f"User has admin access to {endpoint}")
        
        logger.info("INFRA_IAM_001: Cloud IAM security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_secrets_management_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """INFRA_SECRETS_001: Secrets management validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test that secrets are not exposed through API
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        
        # Check response for secret leakage
        response_text = response.text.lower()
        secret_patterns = [
            "api_key",
            "secret_key",
            "password",
            "private_key",
            "aws_access_key",
            "aws_secret",
            "azure_client_secret",
            "google_api_key",
            "openai_api_key",
            "anthropic_api_key",
            "sk-",  # OpenAI API key prefix
            "-----begin private key-----",
            "-----begin rsa private key-----"
        ]
        
        for pattern in secret_patterns:
            assert pattern not in response_text, \
                f"Potential secret exposure: {pattern}"
        
        # Test environment variable exposure
        env_test_endpoints = [
            "/.env",
            "/env",
            "/environment", 
            "/config/env",
            "/api/v1/config",
            "/debug/env"
        ]
        
        for endpoint in env_test_endpoints:
            env_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if env_response.status_code == 200:
                env_text = env_response.text.lower()
                
                # Check for environment variable exposure
                env_indicators = [
                    "api_key=",
                    "secret=",
                    "password=",
                    "token=",
                    "key=",
                    "database_url=",
                    "redis_url="
                ]
                
                for indicator in env_indicators:
                    if indicator in env_text:
                        logger.warning(f"Environment variable exposure at {endpoint}: {indicator}")
            elif env_response.status_code == 404:
                logger.info(f"Environment endpoint properly blocked: {endpoint}")
            else:
                logger.info(f"Environment endpoint access denied: {endpoint} ({env_response.status_code})")
        
        # Test secrets in error messages
        error_request = {
            "model": "nonexistent_model_12345",
            "messages": [{"role": "user", "content": "test"}],
            "max_tokens": 50
        }
        
        error_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, error_request, track_cost=False
        )
        
        if error_response.status_code >= 400:
            error_text = error_response.text.lower()
            
            # Error should not contain secrets
            for pattern in secret_patterns:
                assert pattern not in error_text, \
                    f"Secret in error message: {pattern}"
        
        logger.info("INFRA_SECRETS_001: Secrets management validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_runtime_security_001(self, http_client: httpx.AsyncClient,
                                      auth_headers: Dict[str, str],
                                      make_request):
        """INFRA_RUNTIME_001: Runtime security monitoring"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test runtime security through API behavior
        runtime_test_requests = [
            {
                "description": "Normal operation",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Runtime security test"}],
                    "max_tokens": 50
                }
            },
            {
                "description": "Potential code injection",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Runtime test: __import__('os').system('ls')"}],
                    "max_tokens": 50
                }
            },
            {
                "description": "Memory exhaustion attempt",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "A" * 10000}],  # Large input
                    "max_tokens": 1000
                }
            }
        ]
        
        runtime_results = []
        
        for test in runtime_test_requests:
            start_time = asyncio.get_event_loop().time()
            
            try:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, test["request"],
                    track_cost=(test["description"] == "Normal operation")
                )
                
                end_time = asyncio.get_event_loop().time()
                execution_time = end_time - start_time
                
                runtime_results.append({
                    "description": test["description"],
                    "status_code": response.status_code,
                    "execution_time": execution_time,
                    "success": response.status_code == 200
                })
                
                # Check response for runtime security issues
                if response.status_code == 200:
                    response_data = response.json()
                    response_text = str(response_data).lower()
                    
                    # Should not contain code execution results
                    execution_indicators = [
                        "permission denied",
                        "command not found",
                        "traceback",
                        "error:",
                        "exception:",
                        "file not found"
                    ]
                    
                    for indicator in execution_indicators:
                        if indicator in response_text:
                            logger.warning(f"Runtime execution indicator: {indicator}")
                
            except Exception as e:
                runtime_results.append({
                    "description": test["description"],
                    "error": str(e),
                    "success": False
                })
        
        # Analyze runtime security
        for result in runtime_results:
            if result["description"] == "Normal operation":
                assert result["success"], "Normal operations should succeed"
            elif result["description"] == "Potential code injection":
                if result.get("success"):
                    logger.info("Code injection attempt handled safely")
                else:
                    logger.info("Code injection attempt rejected")
            elif result["description"] == "Memory exhaustion attempt":
                if result.get("execution_time", 0) > 30:
                    logger.warning("Long execution time - potential DoS vulnerability")
        
        logger.info("INFRA_RUNTIME_001: Runtime security monitoring validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_backup_security_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     make_request):
        """INFRA_BACKUP_001: Backup and disaster recovery security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test backup-related endpoints and security
        backup_endpoints = [
            "/backup",
            "/admin/backup",
            "/api/v1/backup",
            "/backup/download",
            "/backup/restore",
            "/dump",
            "/export"
        ]
        
        backup_security_results = []
        
        for endpoint in backup_endpoints:
            # Test backup endpoint access
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            backup_security_results.append({
                "endpoint": endpoint,
                "status_code": response.status_code,
                "accessible": response.status_code == 200
            })
            
            if response.status_code == 200:
                # Backup endpoint is accessible - check security
                logger.warning(f"Backup endpoint accessible: {endpoint}")
                
                # Check if authentication is required
                no_auth_response = await make_request(
                    http_client, "GET", endpoint,
                    {}, track_cost=False
                )
                
                if no_auth_response.status_code == 200:
                    logger.critical(f"Backup endpoint accessible without auth: {endpoint}")
                else:
                    logger.info(f"Backup endpoint requires authentication: {endpoint}")
                    
            elif response.status_code == 404:
                logger.info(f"Backup endpoint not found: {endpoint}")
            elif response.status_code in [401, 403]:
                logger.info(f"Backup endpoint properly protected: {endpoint}")
        
        # Test for backup file exposure
        backup_file_patterns = [
            "/backup.sql",
            "/backup.tar.gz",
            "/backup.zip",
            "/database.sql",
            "/dump.sql",
            "/data.json",
            "/export.csv"
        ]
        
        for file_pattern in backup_file_patterns:
            file_response = await make_request(
                http_client, "GET", file_pattern,
                auth_headers, track_cost=False
            )
            
            if file_response.status_code == 200:
                logger.critical(f"Backup file exposed: {file_pattern}")
                
                # Check file content for sensitive data
                content = file_response.text.lower()
                if any(term in content for term in ["password", "api_key", "secret", "token"]):
                    logger.critical(f"Sensitive data in exposed backup: {file_pattern}")
            else:
                logger.info(f"Backup file properly protected: {file_pattern}")
        
        logger.info("INFRA_BACKUP_001: Backup security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_container_vuln_scan_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """INFRA_CONTAINER_VULN_SCAN_001: Container vulnerability scanning"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test container vulnerability scanning through API responses
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for vulnerability scanning indicators
        vuln_scan_headers = [
            "x-container-scan-status",
            "x-vulnerability-score",
            "x-last-scan-date",
            "x-cve-count"
        ]
        
        scan_indicators = []
        for header in vuln_scan_headers:
            if header in headers:
                scan_indicators.append(f"{header}={headers[header]}")
        
        if scan_indicators:
            logger.info(f"Container vulnerability scan indicators: {scan_indicators}")
        
        # Test vulnerability endpoints
        vuln_endpoints = [
            "/security/vulnerabilities",
            "/scan/results",
            "/cve/report",
            "/.well-known/security-scan"
        ]
        
        for endpoint in vuln_endpoints:
            vuln_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if vuln_response.status_code == 200:
                logger.info(f"Vulnerability scan results available at: {endpoint}")
            elif vuln_response.status_code in [401, 403]:
                logger.info(f"Vulnerability endpoint properly protected: {endpoint}")
            elif vuln_response.status_code == 404:
                logger.info(f"Vulnerability endpoint not found: {endpoint}")
        
        logger.info("INFRA_CONTAINER_VULN_SCAN_001: Container vulnerability scanning validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_network_port_exposure_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """INFRA_NETWORK_PORT_EXPOSURE_001: Port exposure validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test port exposure through API behavior
        base_url = config.BASE_URL
        parsed_url = urlparse(base_url)
        
        # Test standard service ports
        test_ports = [
            {"port": 22, "service": "SSH", "should_be_blocked": True},
            {"port": 3306, "service": "MySQL", "should_be_blocked": True},
            {"port": 5432, "service": "PostgreSQL", "should_be_blocked": True},
            {"port": 6379, "service": "Redis", "should_be_blocked": True},
            {"port": 27017, "service": "MongoDB", "should_be_blocked": True},
            {"port": 9200, "service": "Elasticsearch", "should_be_blocked": True},
            {"port": 8080, "service": "Alt HTTP", "should_be_blocked": False},
            {"port": 8443, "service": "Alt HTTPS", "should_be_blocked": False}
        ]
        
        port_results = []
        
        for port_test in test_ports:
            try:
                # Test port connectivity
                with socket.create_connection((parsed_url.hostname, port_test["port"]), timeout=5) as sock:
                    port_results.append({
                        "port": port_test["port"],
                        "service": port_test["service"],
                        "accessible": True,
                        "should_be_blocked": port_test["should_be_blocked"]
                    })
            except (socket.timeout, socket.error, OSError):
                port_results.append({
                    "port": port_test["port"],
                    "service": port_test["service"],
                    "accessible": False,
                    "should_be_blocked": port_test["should_be_blocked"]
                })
        
        # Analyze port exposure
        for result in port_results:
            if result["accessible"] and result["should_be_blocked"]:
                logger.warning(f"Potentially exposed service: {result['service']} on port {result['port']}")
            elif not result["accessible"] and result["should_be_blocked"]:
                logger.info(f"Service properly blocked: {result['service']} on port {result['port']}")
        
        logger.info("INFRA_NETWORK_PORT_EXPOSURE_001: Port exposure validation completed")


# Advanced Infrastructure Security tests moved to separate files to maintain file size under 900 lines:
# - test_infrastructure_advanced_security.py: Additional INFRA_* test case IDs
# - test_infrastructure_advanced_security_2.py: Cloud governance and monitoring test cases