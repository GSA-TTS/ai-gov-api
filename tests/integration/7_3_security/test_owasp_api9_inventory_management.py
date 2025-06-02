# Section 7.3 - OWASP API9:2023 Improper Inventory Management Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for API9_2023 - Improper Inventory Management.md

import pytest
import httpx
from typing import Dict, Any, List

from config import config, logger


class TestOWASPAPI9InventoryManagement:
    """API9:2023 - Improper Inventory Management tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api9_version_exposure_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """API9_VERSION_EXPOSURE_001: API version information exposure"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test version information exposure in various places
        version_check_locations = [
            # Headers
            {
                "type": "response_headers",
                "endpoint": "/api/v1/models",
                "method": "GET"
            },
            
            # Version endpoints
            {
                "type": "version_endpoint",
                "endpoint": "/version",
                "method": "GET"
            },
            {
                "type": "version_endpoint",
                "endpoint": "/api/version",
                "method": "GET"
            },
            {
                "type": "version_endpoint",
                "endpoint": "/api/v1/version",
                "method": "GET"
            },
            
            # Info endpoints
            {
                "type": "info_endpoint",
                "endpoint": "/info",
                "method": "GET"
            },
            {
                "type": "info_endpoint", 
                "endpoint": "/api/info",
                "method": "GET"
            },
            
            # Root endpoints
            {
                "type": "root_endpoint",
                "endpoint": "/",
                "method": "GET"
            },
            {
                "type": "root_endpoint",
                "endpoint": "/api",
                "method": "GET"
            },
            {
                "type": "root_endpoint",
                "endpoint": "/api/v1",
                "method": "GET"
            }
        ]
        
        version_disclosures = []
        
        for location in version_check_locations:
            # Test with and without authentication
            for use_auth in [True, False]:
                headers = auth_headers if use_auth else {}
                
                response = await make_request(
                    http_client, location["method"], location["endpoint"],
                    headers, track_cost=False
                )
                
                # Check response headers for version information
                response_headers = dict(response.headers)
                version_headers = [
                    "X-API-Version", "API-Version", "Version", 
                    "X-Version", "Server", "X-Powered-By"
                ]
                
                for header in version_headers:
                    if header in response_headers:
                        version_disclosures.append({
                            "location": "header",
                            "header": header,
                            "value": response_headers[header],
                            "endpoint": location["endpoint"],
                            "authenticated": use_auth
                        })
                
                # Check response body for version information
                if response.status_code == 200 and response.content:
                    try:
                        if response.headers.get("content-type", "").startswith("application/json"):
                            response_data = response.json()
                        else:
                            response_data = {"text": response.text}
                        
                        response_text = str(response_data).lower()
                        
                        # Look for version patterns
                        version_patterns = [
                            "version", "v1.", "v2.", "v3.", "build", 
                            "commit", "release", "api version"
                        ]
                        
                        found_patterns = [pattern for pattern in version_patterns if pattern in response_text]
                        
                        if found_patterns:
                            version_disclosures.append({
                                "location": "body",
                                "patterns": found_patterns,
                                "endpoint": location["endpoint"],
                                "authenticated": use_auth,
                                "type": location["type"]
                            })
                    
                    except Exception:
                        # Non-JSON response
                        response_text = response.text.lower()
                        if any(pattern in response_text for pattern in ["version", "build", "commit"]):
                            version_disclosures.append({
                                "location": "body_text",
                                "endpoint": location["endpoint"],
                                "authenticated": use_auth,
                                "contains_version": True
                            })
        
        # Analyze version disclosures
        if version_disclosures:
            logger.warning(f"Version information disclosures found: {len(version_disclosures)}")
            for disclosure in version_disclosures:
                logger.warning(f"Version disclosure: {disclosure}")
        
        # Version information should be minimal in production
        critical_disclosures = [d for d in version_disclosures 
                               if d.get("location") == "header" and d.get("header") in ["Server", "X-Powered-By"]]
        
        if critical_disclosures:
            logger.warning("Critical version disclosures in headers detected")
        
        logger.info("API9_VERSION_EXPOSURE_001: Version exposure check completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api9_deprecated_endpoints_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """API9_DEPRECATED_ENDPOINTS_001: Deprecated endpoint discovery"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for deprecated API versions and endpoints
        deprecated_patterns = [
            # Old API versions
            "/api/v0", "/api/v0/", "/api/v0/models",
            "/v0", "/v0/", "/v0/models",
            
            # Legacy endpoints
            "/legacy", "/legacy/", "/api/legacy",
            "/old", "/old/", "/api/old",
            "/deprecated", "/deprecated/", "/api/deprecated",
            
            # Common deprecated endpoint patterns
            "/api/v1/completions",  # If replaced by chat/completions
            "/api/v1/complete",
            "/api/v1/generate",
            "/api/v1/text-completion",
            
            # Beta/experimental endpoints that should be removed
            "/api/beta", "/api/beta/", "/beta",
            "/api/experimental", "/experimental",
            "/api/preview", "/preview",
            
            # Test/development endpoints that should not be in production
            "/api/test", "/test", "/testing",
            "/api/dev", "/dev", "/development",
            "/api/staging", "/staging",
            
            # Backup/alternative endpoint patterns
            "/api/v1-backup", "/api/v1-old",
            "/api/backup", "/backup"
        ]
        
        deprecated_endpoints = []
        
        for endpoint in deprecated_patterns:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                # Endpoint is accessible
                deprecated_endpoints.append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "response_length": len(response.content) if response.content else 0
                })
                logger.warning(f"Deprecated endpoint accessible: {endpoint}")
            
            elif response.status_code in [301, 302, 307, 308]:
                # Endpoint redirects (might indicate deprecated but still functional)
                location = response.headers.get("Location", "")
                deprecated_endpoints.append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "redirect_location": location,
                    "type": "redirect"
                })
                logger.warning(f"Deprecated endpoint redirects: {endpoint} -> {location}")
            
            elif response.status_code == 410:
                # Gone status (good - explicitly deprecated)
                logger.info(f"Properly deprecated endpoint: {endpoint} (410 Gone)")
            
            # Also test with POST method for API endpoints
            if "/api/" in endpoint:
                post_response = await make_request(
                    http_client, "POST", endpoint,
                    auth_headers, {"test": "data"}, track_cost=False
                )
                
                if post_response.status_code == 200:
                    deprecated_endpoints.append({
                        "endpoint": endpoint,
                        "method": "POST",
                        "status_code": post_response.status_code,
                        "response_length": len(post_response.content) if post_response.content else 0
                    })
                    logger.warning(f"Deprecated POST endpoint accessible: {endpoint}")
        
        # Deprecated endpoints should not be accessible in production
        assert len(deprecated_endpoints) == 0, \
            f"Deprecated endpoints should be removed: {deprecated_endpoints}"
        
        logger.info("API9_DEPRECATED_ENDPOINTS_001: Deprecated endpoint discovery completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api9_documentation_exposure_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """API9_DOCUMENTATION_001: API documentation exposure assessment"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for exposed API documentation
        documentation_endpoints = [
            # Swagger/OpenAPI documentation
            "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/",
            "/swagger-ui.html", "/swagger-ui/index.html",
            "/api/swagger", "/api/swagger-ui",
            "/docs/swagger", "/docs/swagger-ui",
            
            # OpenAPI specifications
            "/openapi.json", "/openapi.yaml", "/openapi.yml",
            "/api/openapi.json", "/api/openapi.yaml",
            "/swagger.json", "/swagger.yaml", "/swagger.yml",
            "/api-docs", "/api-docs/", "/api/docs",
            
            # Redoc documentation
            "/redoc", "/redoc/", "/redoc.html",
            "/api/redoc", "/docs/redoc",
            
            # GraphQL documentation
            "/graphql", "/graphql/", "/graphiql", "/graphiql/",
            "/api/graphql", "/api/graphiql",
            
            # General documentation endpoints
            "/docs", "/docs/", "/documentation", "/documentation/",
            "/api/docs", "/api/documentation",
            "/help", "/help/", "/api/help",
            
            # Framework-specific documentation
            "/api-docs/swagger-config", "/v2/api-docs",
            "/v3/api-docs", "/actuator/swagger-ui",
            
            # Development documentation
            "/dev-docs", "/dev-docs/", "/developer",
            "/api/dev-docs", "/internal-docs"
        ]
        
        exposed_documentation = []
        
        for endpoint in documentation_endpoints:
            # Test without authentication first
            response = await make_request(
                http_client, "GET", endpoint,
                {}, track_cost=False
            )
            
            if response.status_code == 200:
                # Documentation is publicly accessible
                response_text = response.text.lower()
                
                # Check if it's actually API documentation
                doc_indicators = [
                    "swagger", "openapi", "api documentation", "endpoints",
                    "redoc", "graphql", "api reference", "rest api"
                ]
                
                if any(indicator in response_text for indicator in doc_indicators):
                    exposed_documentation.append({
                        "endpoint": endpoint,
                        "authentication": "none",
                        "type": "api_documentation",
                        "response_length": len(response_text)
                    })
                    logger.warning(f"API documentation exposed without auth: {endpoint}")
            
            # Test with authentication
            auth_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if auth_response.status_code == 200 and response.status_code != 200:
                # Documentation requires authentication (better)
                response_text = auth_response.text.lower()
                
                doc_indicators = [
                    "swagger", "openapi", "api documentation", "endpoints",
                    "redoc", "graphql", "api reference", "rest api"
                ]
                
                if any(indicator in response_text for indicator in doc_indicators):
                    exposed_documentation.append({
                        "endpoint": endpoint,
                        "authentication": "required",
                        "type": "api_documentation",
                        "response_length": len(response_text)
                    })
                    logger.info(f"API documentation accessible with auth: {endpoint}")
        
        # Analyze documentation exposure
        public_docs = [doc for doc in exposed_documentation if doc["authentication"] == "none"]
        auth_docs = [doc for doc in exposed_documentation if doc["authentication"] == "required"]
        
        if public_docs:
            logger.warning(f"Publicly accessible API documentation: {len(public_docs)}")
            
            # Check for sensitive information in public documentation
            for doc in public_docs:
                # This would need actual content analysis in a real test
                logger.warning(f"Public API docs should be reviewed for sensitive info: {doc['endpoint']}")
        
        if auth_docs:
            logger.info(f"Authenticated API documentation: {len(auth_docs)}")
        
        # Public API documentation can be a security risk
        sensitive_public_docs = [doc for doc in public_docs 
                                if doc["response_length"] > 1000]  # Substantial documentation
        
        if sensitive_public_docs:
            logger.warning("Substantial API documentation exposed publicly - review for sensitive information")
        
        logger.info("API9_DOCUMENTATION_001: API documentation exposure assessment completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api9_endpoint_enumeration_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """API9_ENDPOINT_ENUMERATION_001: API endpoint enumeration and discovery"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test endpoint discovery through various methods
        enumeration_patterns = [
            # Common API endpoints
            "/api/v1/users", "/api/v1/user", "/users", "/user",
            "/api/v1/admin", "/admin", "/administration",
            "/api/v1/config", "/config", "/configuration",
            "/api/v1/system", "/system", "/sys",
            
            # CRUD operations
            "/api/v1/models/create", "/api/v1/models/update",
            "/api/v1/models/delete", "/api/v1/models/list",
            
            # Management endpoints
            "/api/v1/tokens", "/tokens", "/api-keys",
            "/api/v1/billing", "/billing", "/payments",
            "/api/v1/usage", "/usage", "/metrics",
            "/api/v1/logs", "/logs", "/logging",
            
            # Health and monitoring
            "/api/v1/health", "/health", "/healthz",
            "/api/v1/status", "/status", "/ping",
            "/api/v1/metrics", "/metrics", "/stats",
            
            # File operations
            "/api/v1/files", "/files", "/upload", "/download",
            "/api/v1/exports", "/exports", "/backups",
            
            # Authentication endpoints
            "/api/v1/auth", "/auth", "/authentication",
            "/api/v1/login", "/login", "/signin",
            "/api/v1/logout", "/logout", "/signout",
            "/api/v1/register", "/register", "/signup",
            
            # Integration endpoints
            "/api/v1/webhooks", "/webhooks", "/callbacks",
            "/api/v1/integrations", "/integrations",
            
            # Common REST patterns with IDs
            "/api/v1/models/1", "/api/v1/models/test",
            "/api/v1/users/1", "/api/v1/users/admin"
        ]
        
        discovered_endpoints = []
        
        for endpoint in enumeration_patterns:
            # Test different HTTP methods
            methods_to_test = ["GET", "POST", "PUT", "DELETE", "PATCH"]
            
            for method in methods_to_test:
                # Test without authentication
                response = await make_request(
                    http_client, method, endpoint,
                    {}, track_cost=False
                )
                
                # Endpoint exists if we get something other than 404
                if response.status_code != 404:
                    endpoint_info = {
                        "endpoint": endpoint,
                        "method": method,
                        "status_code": response.status_code,
                        "authentication": "none"
                    }
                    
                    if response.status_code == 200:
                        endpoint_info["accessible"] = True
                    elif response.status_code in [401, 403]:
                        endpoint_info["requires_auth"] = True
                    elif response.status_code == 405:
                        endpoint_info["method_not_allowed"] = True
                    
                    discovered_endpoints.append(endpoint_info)
                
                # Test with authentication if unauthorized
                if response.status_code in [401, 403]:
                    auth_response = await make_request(
                        http_client, method, endpoint,
                        auth_headers, track_cost=False
                    )
                    
                    if auth_response.status_code != 404:
                        auth_endpoint_info = {
                            "endpoint": endpoint,
                            "method": method,
                            "status_code": auth_response.status_code,
                            "authentication": "required"
                        }
                        
                        if auth_response.status_code == 200:
                            auth_endpoint_info["accessible"] = True
                        elif auth_response.status_code == 405:
                            auth_endpoint_info["method_not_allowed"] = True
                        
                        discovered_endpoints.append(auth_endpoint_info)
        
        # Analyze discovered endpoints
        accessible_endpoints = [ep for ep in discovered_endpoints if ep.get("accessible")]
        auth_required_endpoints = [ep for ep in discovered_endpoints if ep.get("requires_auth")]
        
        logger.info(f"Endpoint enumeration results:")
        logger.info(f"  - Accessible endpoints: {len(accessible_endpoints)}")
        logger.info(f"  - Auth required endpoints: {len(auth_required_endpoints)}")
        
        # Check for potentially sensitive endpoints that are accessible
        sensitive_patterns = ["admin", "config", "system", "users", "tokens", "billing"]
        sensitive_accessible = []
        
        for endpoint in accessible_endpoints:
            if any(pattern in endpoint["endpoint"].lower() for pattern in sensitive_patterns):
                sensitive_accessible.append(endpoint)
                logger.warning(f"Potentially sensitive endpoint accessible: {endpoint}")
        
        # Log discovered endpoints for analysis
        if discovered_endpoints:
            logger.info("Discovered endpoints summary:")
            for endpoint in discovered_endpoints[:20]:  # Log first 20
                logger.info(f"  {endpoint['method']} {endpoint['endpoint']} -> {endpoint['status_code']}")
        
        logger.info("API9_ENDPOINT_ENUMERATION_001: Endpoint enumeration completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api9_inventory_consistency_001(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """API9_INVENTORY_CONSISTENCY_001: API inventory consistency validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test consistency between documented and actual API endpoints
        
        # Known/documented endpoints (from the API)
        documented_endpoints = [
            {"endpoint": "/api/v1/models", "methods": ["GET"]},
            {"endpoint": "/api/v1/chat/completions", "methods": ["POST"]},
            {"endpoint": "/api/v1/embeddings", "methods": ["POST"]}
        ]
        
        # Verify documented endpoints work as expected
        endpoint_consistency = []
        
        for doc_endpoint in documented_endpoints:
            for method in doc_endpoint["methods"]:
                if method == "GET":
                    response = await make_request(
                        http_client, method, doc_endpoint["endpoint"],
                        auth_headers, track_cost=False
                    )
                else:
                    # POST endpoints need appropriate data
                    if "chat/completions" in doc_endpoint["endpoint"]:
                        data = {
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": "consistency test"}],
                            "max_tokens": 30
                        }
                    elif "embeddings" in doc_endpoint["endpoint"]:
                        data = {
                            "model": config.get_embedding_model(0),
                            "input": "consistency test"
                        }
                    else:
                        data = {"test": "data"}
                    
                    response = await make_request(
                        http_client, method, doc_endpoint["endpoint"],
                        auth_headers, data, track_cost=False
                    )
                
                consistency_info = {
                    "endpoint": doc_endpoint["endpoint"],
                    "method": method,
                    "expected": "working",
                    "actual_status": response.status_code,
                    "working": response.status_code in [200, 422]  # 422 for validation errors is okay
                }
                
                endpoint_consistency.append(consistency_info)
        
        # Check for undocumented endpoints that respond
        potential_undocumented = [
            "/api/v1", "/api/v1/", "/api", "/api/",
            "/health", "/status", "/ping", "/version",
            "/api/v1/health", "/api/v1/status"
        ]
        
        undocumented_responses = []
        
        for endpoint in potential_undocumented:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                undocumented_responses.append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "response_length": len(response.content) if response.content else 0
                })
        
        # Analyze consistency
        working_documented = [ep for ep in endpoint_consistency if ep["working"]]
        broken_documented = [ep for ep in endpoint_consistency if not ep["working"]]
        
        logger.info(f"API inventory consistency:")
        logger.info(f"  - Working documented endpoints: {len(working_documented)}")
        logger.info(f"  - Broken documented endpoints: {len(broken_documented)}")
        logger.info(f"  - Undocumented responsive endpoints: {len(undocumented_responses)}")
        
        # Documented endpoints should work
        for broken in broken_documented:
            logger.warning(f"Documented endpoint not working: {broken}")
        
        # Log undocumented endpoints
        for undoc in undocumented_responses:
            logger.info(f"Undocumented endpoint found: {undoc}")
        
        # Critical: documented endpoints must work
        assert len(broken_documented) == 0, \
            f"Documented endpoints should work: {broken_documented}"
        
        logger.info("API9_INVENTORY_CONSISTENCY_001: API inventory consistency validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_api9_improper_inventory_comprehensive_001(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """API9_COMPREHENSIVE_001: Comprehensive improper inventory management assessment"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Comprehensive assessment of API inventory management
        inventory_issues = []
        
        # Check 1: Multiple API versions
        version_endpoints = ["/api/v0", "/api/v1", "/api/v2", "/api/v3"]
        
        accessible_versions = []
        for version in version_endpoints:
            response = await make_request(
                http_client, "GET", version,
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                accessible_versions.append(version)
        
        if len(accessible_versions) > 1:
            inventory_issues.append({
                "type": "multiple_versions",
                "description": "Multiple API versions accessible",
                "versions": accessible_versions
            })
        
        # Check 2: Inconsistent authentication requirements
        test_endpoints = [
            "/api/v1/models", "/api/v1/chat/completions",
            "/health", "/status", "/version"
        ]
        
        auth_inconsistencies = []
        for endpoint in test_endpoints:
            # Test without auth
            no_auth_response = await make_request(
                http_client, "GET", endpoint,
                {}, track_cost=False
            )
            
            # Test with auth
            auth_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            # Inconsistency if one works and the other doesn't (unexpectedly)
            if (no_auth_response.status_code == 200 and 
                auth_response.status_code != 200 and 
                endpoint.startswith("/api/")):
                auth_inconsistencies.append({
                    "endpoint": endpoint,
                    "issue": "API endpoint works without auth but fails with auth"
                })
        
        if auth_inconsistencies:
            inventory_issues.append({
                "type": "auth_inconsistency",
                "description": "Inconsistent authentication behavior",
                "details": auth_inconsistencies
            })
        
        # Check 3: Exposed development endpoints
        dev_endpoints = [
            "/test", "/testing", "/dev", "/development",
            "/staging", "/debug", "/admin"
        ]
        
        exposed_dev_endpoints = []
        for endpoint in dev_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                {}, track_cost=False  # Test without auth first
            )
            
            if response.status_code == 200:
                exposed_dev_endpoints.append(endpoint)
        
        if exposed_dev_endpoints:
            inventory_issues.append({
                "type": "development_endpoints",
                "description": "Development endpoints exposed",
                "endpoints": exposed_dev_endpoints
            })
        
        # Check 4: Error message consistency
        error_endpoints = [
            "/api/v1/nonexistent",
            "/api/v1/chat/nonexistent", 
            "/api/v2/models"  # Wrong version
        ]
        
        error_responses = []
        for endpoint in error_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            error_responses.append({
                "endpoint": endpoint,
                "status_code": response.status_code,
                "has_content": len(response.content) > 0 if response.content else False
            })
        
        # Error responses should be consistent
        status_codes = [resp["status_code"] for resp in error_responses]
        if len(set(status_codes)) > 2:  # Allow some variation
            inventory_issues.append({
                "type": "inconsistent_errors",
                "description": "Inconsistent error responses",
                "responses": error_responses
            })
        
        # Report inventory management issues
        if inventory_issues:
            logger.warning(f"API inventory management issues found: {len(inventory_issues)}")
            for issue in inventory_issues:
                logger.warning(f"Inventory issue: {issue}")
        else:
            logger.info("No significant API inventory management issues detected")
        
        # Critical issues should be addressed
        critical_issues = [issue for issue in inventory_issues 
                          if issue["type"] in ["development_endpoints", "multiple_versions"]]
        
        if critical_issues:
            logger.warning("Critical inventory management issues detected")
        
        logger.info("API9_COMPREHENSIVE_001: Comprehensive inventory management assessment completed")