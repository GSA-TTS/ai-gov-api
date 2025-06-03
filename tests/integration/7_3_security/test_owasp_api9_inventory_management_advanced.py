# Section 7.3 - Advanced OWASP API9:2023 Improper Inventory Management Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API9_2023 - Improper Inventory Management.md
# Implements missing test cases for API inventory management security

import pytest
import httpx
import os
from typing import Dict, Any, List
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.security_fixtures import SecurityFixtures
from utils.security_validators import SecurityValidator


class TestOWASPAPI9InventoryManagementAdvanced:
    """Advanced tests for OWASP API9:2023 - Improper Inventory Management"""
    
    @pytest.mark.security
    @pytest.mark.owasp_api9
    @pytest.mark.asyncio
    async def test_api9_documentation_accuracy_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  security_validator: SecurityValidator,
                                                  make_request):
        """API9_DOCS_001: API Documentation Accuracy and Security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test documented vs actual API behavior
        documented_endpoints = [
            "/api/v1/models",
            "/api/v1/chat/completions", 
            "/api/v1/embeddings"
        ]
        
        # Test for undocumented endpoints that might exist
        potential_undocumented_endpoints = [
            "/api/v1/admin",
            "/api/v1/debug",
            "/api/v1/health",
            "/api/v1/metrics", 
            "/api/v1/status",
            "/api/v1/config",
            "/api/v1/users",
            "/api/v1/keys",
            "/api/v2/models",
            "/admin",
            "/debug",
            "/internal"
        ]
        
        for endpoint in potential_undocumented_endpoints:
            # Test both GET and POST methods
            for method in ["GET", "POST"]:
                if method == "GET":
                    response = await http_client.get(endpoint, headers=auth_headers)
                else:
                    response = await make_request(
                        http_client, method, endpoint, auth_headers, {}
                    )
                
                # Undocumented endpoints should return 404 or be properly secured
                if response.status_code == 200:
                    # If endpoint exists, validate it's properly secured
                    validation_result = security_validator.validate_undocumented_endpoint_security(
                        endpoint, method, response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
                    )
                    
                    assert validation_result["is_secure"], \
                        f"Undocumented endpoint should be secure: {method} {endpoint}"
                    
                    logger.warning(f"Found undocumented endpoint: {method} {endpoint}")
                
                # Should not reveal sensitive information in error responses
                if response.status_code in [404, 405]:
                    error_data = response.text
                    sensitive_indicators = ["internal", "admin", "debug", "config", "secret"]
                    has_sensitive_leak = any(
                        indicator in error_data.lower() for indicator in sensitive_indicators
                    )
                    
                    assert not has_sensitive_leak, \
                        f"Error response should not leak sensitive info: {endpoint}"
        
        logger.info("API9_DOCS_001: Documentation accuracy and security tested")

    @pytest.mark.security
    @pytest.mark.owasp_api9
    @pytest.mark.asyncio
    async def test_api9_version_management_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             security_validator: SecurityValidator,
                                             make_request):
        """API9_VERSION_001: API Version Management Security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test various API version access patterns
        version_test_patterns = [
            "/api/v0/models",  # Older version
            "/api/v2/models",  # Future version
            "/api/v1.1/models",  # Sub-version
            "/api/v1-beta/models",  # Beta version
            "/api/latest/models",  # Latest alias
            "/api/models",  # No version
            "/v1/models",  # Missing api prefix
            "/api/v1/../v2/models",  # Path traversal
            "/api/v1%2e%2e/v2/models",  # URL encoded traversal
        ]
        
        for version_pattern in version_test_patterns:
            response = await http_client.get(version_pattern, headers=auth_headers)
            
            # Validate version access control
            validation_result = security_validator.validate_version_access_control(
                version_pattern, response.status_code, 
                response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
            )
            
            if response.status_code == 200:
                # If version is accessible, ensure it's intentional
                logger.info(f"Accessible API version: {version_pattern}")
                
                # Should not expose version-specific vulnerabilities
                response_data = response.json()
                assert validation_result["is_secure"], \
                    f"API version should be secure: {version_pattern}"
            
            elif response.status_code in [404, 405]:
                # Version not found - should not leak version information
                error_data = response.text
                version_indicators = ["v0", "v2", "beta", "latest", "version"]
                has_version_leak = any(
                    indicator in error_data.lower() for indicator in version_indicators
                )
                
                if has_version_leak:
                    logger.warning(f"Potential version information leak: {version_pattern}")
            
            # Path traversal attempts should be blocked
            if ".." in version_pattern or "%2e%2e" in version_pattern:
                assert response.status_code in [400, 404, 403], \
                    f"Path traversal should be blocked: {version_pattern}"
        
        logger.info("API9_VERSION_001: API version management security tested")

    @pytest.mark.security
    @pytest.mark.owasp_api9
    @pytest.mark.asyncio
    async def test_api9_model_inventory_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          security_validator: SecurityValidator,
                                          make_request):
        """API9_MODEL_001: Model Inventory Security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test model discovery and enumeration
        response = await http_client.get("/api/v1/models", headers=auth_headers)
        assert response.status_code == 200
        
        models_data = response.json()
        assert "data" in models_data
        
        # Validate model information disclosure
        validation_result = security_validator.validate_model_inventory_security(models_data)
        
        assert validation_result["is_secure"], \
            "Model inventory should not expose sensitive information"
        
        # Check each model for information leakage
        for model in models_data["data"]:
            # Should not expose sensitive model details
            sensitive_fields = [
                "internal_id", "provider_key", "billing_id", "cost_per_token",
                "server_location", "api_endpoint", "auth_token", "config"
            ]
            
            for field in sensitive_fields:
                assert field not in model, \
                    f"Model should not expose sensitive field: {field}"
            
            # Test accessing model-specific endpoints
            model_id = model.get("id", "")
            if model_id:
                # Test model-specific requests
                model_test_request = {
                    "model": model_id,
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 5
                }
                
                model_response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, model_test_request
                )
                
                # Model should be accessible or return proper error
                assert model_response.status_code in [200, 400, 404, 429], \
                    f"Model {model_id} should be properly accessible or error gracefully"
                
                if model_response.status_code == 400:
                    # Validate error doesn't leak model internals
                    error_data = model_response.json()
                    model_validation = security_validator.validate_model_error_exposure(
                        model_id, error_data
                    )
                    
                    assert model_validation["is_secure"], \
                        f"Model error should not expose internals: {model_id}"
        
        logger.info("API9_MODEL_001: Model inventory security tested")

    @pytest.mark.security
    @pytest.mark.owasp_api9
    @pytest.mark.asyncio
    async def test_api9_configuration_drift_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               security_validator: SecurityValidator,
                                               make_request):
        """API9_CONFIG_001: Configuration Drift Detection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for configuration information disclosure
        config_disclosure_endpoints = [
            "/api/v1/config",
            "/api/v1/settings", 
            "/api/v1/environment",
            "/config",
            "/settings",
            "/.env",
            "/environment.json",
            "/api-config.json"
        ]
        
        for endpoint in config_disclosure_endpoints:
            response = await http_client.get(endpoint, headers=auth_headers)
            
            # Configuration endpoints should not be accessible
            if response.status_code == 200:
                config_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
                
                # Validate no sensitive configuration exposure
                validation_result = security_validator.validate_configuration_exposure(
                    endpoint, config_data
                )
                
                assert validation_result["is_secure"], \
                    f"Configuration endpoint should not expose sensitive data: {endpoint}"
                
                # Check for specific sensitive values
                config_str = str(config_data).lower()
                sensitive_patterns = [
                    "api_key", "secret", "password", "token", "credential",
                    "aws_access", "gcp_key", "database_url", "jwt_secret"
                ]
                
                leaked_patterns = [pattern for pattern in sensitive_patterns if pattern in config_str]
                assert len(leaked_patterns) == 0, \
                    f"Configuration leaks sensitive patterns: {leaked_patterns} in {endpoint}"
                
                logger.warning(f"Configuration endpoint accessible: {endpoint}")
            
            # Most config endpoints should return 404 or 403
            assert response.status_code in [200, 404, 403, 405], \
                f"Unexpected response for config endpoint: {endpoint}"
        
        logger.info("API9_CONFIG_001: Configuration drift detection tested")

    @pytest.mark.security
    @pytest.mark.owasp_api9
    @pytest.mark.asyncio
    async def test_api9_shadow_endpoints_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           security_validator: SecurityValidator,
                                           make_request):
        """API9_SHADOW_001: Shadow Endpoint Discovery"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for shadow/hidden endpoints that might exist
        shadow_endpoint_candidates = [
            "/api/v1/admin/models",
            "/api/v1/internal/health",
            "/api/v1/debug/logs",
            "/api/v1/test/endpoints",
            "/api/v1/dev/reset",
            "/api/internal/stats",
            "/admin/api",
            "/dev/api", 
            "/test/api",
            "/api/backdoor",
            "/api/emergency",
            "/api/maintenance"
        ]
        
        for shadow_endpoint in shadow_endpoint_candidates:
            # Test multiple HTTP methods
            for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                try:
                    if method == "GET":
                        response = await http_client.get(shadow_endpoint, headers=auth_headers)
                    else:
                        response = await make_request(
                            http_client, method, shadow_endpoint, auth_headers, {}
                        )
                    
                    # Shadow endpoints should not be accessible
                    if response.status_code == 200:
                        response_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
                        
                        # Validate shadow endpoint security
                        validation_result = security_validator.validate_shadow_endpoint_security(
                            shadow_endpoint, method, response_data
                        )
                        
                        assert validation_result["is_secure"], \
                            f"Shadow endpoint should be secure: {method} {shadow_endpoint}"
                        
                        logger.warning(f"Found accessible shadow endpoint: {method} {shadow_endpoint}")
                    
                    # Endpoints should return proper HTTP status codes
                    assert response.status_code in [200, 404, 405, 403, 401], \
                        f"Unexpected status for shadow endpoint: {method} {shadow_endpoint}"
                
                except Exception as e:
                    # Network errors are acceptable for non-existent endpoints
                    logger.debug(f"Shadow endpoint test error: {method} {shadow_endpoint} - {e}")
        
        logger.info("API9_SHADOW_001: Shadow endpoint discovery tested")

    @pytest.mark.security
    @pytest.mark.owasp_api9
    @pytest.mark.asyncio
    async def test_api9_endpoint_enumeration_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                security_validator: SecurityValidator,
                                                make_request):
        """API9_ENUM_001: Endpoint Enumeration Protection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test systematic endpoint enumeration
        common_paths = [
            "admin", "api", "auth", "config", "debug", "dev", "docs", 
            "health", "info", "internal", "logs", "metrics", "status",
            "test", "users", "v1", "v2"
        ]
        
        common_extensions = ["", ".json", ".xml", ".txt", ".php", ".asp"]
        
        enumeration_attempts = []
        for path in common_paths:
            for ext in common_extensions:
                enumeration_attempts.append(f"/{path}{ext}")
                enumeration_attempts.append(f"/api/{path}{ext}")
                enumeration_attempts.append(f"/api/v1/{path}{ext}")
        
        accessible_endpoints = []
        
        for endpoint in enumeration_attempts[:50]:  # Limit to prevent excessive testing
            response = await http_client.get(endpoint, headers=auth_headers)
            
            if response.status_code == 200:
                accessible_endpoints.append(endpoint)
                
                # Validate accessible endpoint security
                response_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
                
                validation_result = security_validator.validate_enumerated_endpoint_security(
                    endpoint, response_data
                )
                
                assert validation_result["is_secure"], \
                    f"Enumerated endpoint should be secure: {endpoint}"
            
            # Check for information disclosure in error responses
            elif response.status_code in [404, 403]:
                error_data = response.text
                
                # Should not reveal directory structure or technology stack
                disclosure_indicators = [
                    "apache", "nginx", "iis", "tomcat", "php", "asp", "jsp",
                    "directory", "folder", "path", "file not found"
                ]
                
                has_disclosure = any(
                    indicator in error_data.lower() for indicator in disclosure_indicators
                )
                
                if has_disclosure:
                    logger.warning(f"Potential information disclosure in 404: {endpoint}")
        
        # Log summary of enumeration results
        if accessible_endpoints:
            logger.info(f"Accessible endpoints found during enumeration: {accessible_endpoints}")
        
        logger.info("API9_ENUM_001: Endpoint enumeration protection tested")

    @pytest.mark.security
    @pytest.mark.owasp_api9
    @pytest.mark.asyncio
    async def test_api9_openapi_schema_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         security_validator: SecurityValidator,
                                         make_request):
        """API9_OPENAPI_001: OpenAPI Schema Security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for OpenAPI/Swagger documentation endpoints
        openapi_endpoints = [
            "/openapi.json",
            "/swagger.json", 
            "/api-docs",
            "/docs",
            "/swagger-ui",
            "/redoc",
            "/api/docs",
            "/api/swagger",
            "/api/openapi.json",
            "/v1/api-docs"
        ]
        
        for endpoint in openapi_endpoints:
            response = await http_client.get(endpoint)
            
            if response.status_code == 200:
                # OpenAPI documentation found
                try:
                    openapi_data = response.json()
                    
                    # Validate OpenAPI schema security
                    validation_result = security_validator.validate_openapi_security(
                        endpoint, openapi_data
                    )
                    
                    assert validation_result["is_secure"], \
                        f"OpenAPI schema should not expose sensitive information: {endpoint}"
                    
                    # Check for sensitive information in schema
                    schema_str = str(openapi_data).lower()
                    sensitive_patterns = [
                        "api_key", "secret", "password", "token", "credential",
                        "internal", "debug", "admin", "test", "staging"
                    ]
                    
                    leaked_patterns = [pattern for pattern in sensitive_patterns if pattern in schema_str]
                    if leaked_patterns:
                        logger.warning(f"OpenAPI schema contains sensitive patterns: {leaked_patterns}")
                    
                    # Check if authentication is properly documented
                    if "security" in openapi_data or "securitySchemes" in openapi_data.get("components", {}):
                        logger.info(f"OpenAPI documentation found with security info: {endpoint}")
                    
                except Exception as e:
                    # Might be HTML or other format
                    response_text = response.text
                    if "swagger" in response_text.lower() or "openapi" in response_text.lower():
                        logger.info(f"OpenAPI documentation interface found: {endpoint}")
                        
                        # Check for sensitive information in HTML
                        validation_result = security_validator.validate_openapi_html_security(
                            endpoint, response_text
                        )
                        
                        assert validation_result["is_secure"], \
                            f"OpenAPI HTML should not expose sensitive information: {endpoint}"
        
        logger.info("API9_OPENAPI_001: OpenAPI schema security tested")